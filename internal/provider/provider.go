// Package provider implements the OpenTofu/Terraform provider for pico.sh pgs.
package provider

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/innoq/terraform-provider-pgs/internal/helperbin"
	"github.com/innoq/terraform-provider-pgs/internal/pgs"
	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

var _ provider.Provider = (*pgsProvider)(nil)

type pgsProvider struct{ version string }

// New returns the provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &pgsProvider{version: version} }
}

type sshModel struct {
	Host                  types.String `tfsdk:"host"`
	Port                  types.Int64  `tfsdk:"port"`
	User                  types.String `tfsdk:"user"`
	PrivateKey            types.String `tfsdk:"private_key"`
	PrivateKeyFile        types.String `tfsdk:"private_key_file"`
	PrivateKeyPassphrase  types.String `tfsdk:"private_key_passphrase"`
	KnownHostsFile        types.String `tfsdk:"known_hosts_file"`
	HostKey               types.String `tfsdk:"host_key"`
	InsecureIgnoreHostKey types.Bool   `tfsdk:"insecure_ignore_host_key"`
	HelperDir             types.String `tfsdk:"helper_dir"`
	Become                types.String `tfsdk:"become"`
}

type providerModel struct {
	DatabasePath      types.String `tfsdk:"database_path"`
	SQLiteCommand     types.String `tfsdk:"sqlite_command"`
	BusyTimeoutMS     types.Int64  `tfsdk:"busy_timeout_ms"`
	ProtectedAccounts types.List   `tfsdk:"protected_accounts"`
	SSH               types.Object `tfsdk:"ssh"`
}

func (p *pgsProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "pgs"
	resp.Version = p.version
}

func (p *pgsProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages accounts of a self-hosted pico.sh pgs installation by editing its SQLite database. " +
			"This provider is independent: it is not affiliated with or endorsed by pico.sh. " +
			"The database is accessed in-process, or through a sqlite3 command run locally or over SSH.",
		Attributes: map[string]schema.Attribute{
			"database_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path of the pgs SQLite database (as seen by the machine that runs sqlite3: the provider host, or the SSH host). Env: PGS_DATABASE_PATH. Not needed when sqlite_command is set.",
			},
			"sqlite_command": schema.StringAttribute{
				Optional: true,
				Description: "Command that opens the database and reads SQL from stdin, e.g. `sqlite3 /srv/pgs/data/pgs.sqlite3` or " +
					"`docker run --rm -i -v /srv/pgs/data:/data keinos/sqlite3 sqlite3 /data/pgs.sqlite3`. Run through `sh -c` locally or on the SSH host. Env: PGS_SQLITE_COMMAND. " +
					"Without it and without an ssh block, the database is opened in-process.",
			},
			"busy_timeout_ms": schema.Int64Attribute{
				Optional:    true,
				Description: "How long to wait for a lock held by pgs, in milliseconds. Default 5000.",
			},
			"protected_accounts": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Account names that are never managed. Accounts holding the `admin` feature flag (created by `pgs init`) are always protected.",
			},
		},
		Blocks: map[string]schema.Block{
			"ssh": schema.SingleNestedBlock{
				Description: "Reach the database on a remote host over SSH. Unless sqlite_command is set, the provider uploads a small embedded SQLite helper (Linux amd64/arm64 hosts), so the host needs no sqlite3.",
				Attributes: map[string]schema.Attribute{
					"host":                     schema.StringAttribute{Optional: true, Description: "SSH host. Env: PGS_SSH_HOST."},
					"port":                     schema.Int64Attribute{Optional: true, Description: "SSH port. Default 22. Env: PGS_SSH_PORT."},
					"user":                     schema.StringAttribute{Optional: true, Description: "SSH user. Env: PGS_SSH_USER."},
					"private_key":              schema.StringAttribute{Optional: true, Sensitive: true, Description: "PEM private key. Without a key the ssh-agent (SSH_AUTH_SOCK) is used."},
					"private_key_file":         schema.StringAttribute{Optional: true, Description: "Path of a PEM private key file; a leading `~/` is expanded. Env: PGS_SSH_PRIVATE_KEY_FILE."},
					"private_key_passphrase":   schema.StringAttribute{Optional: true, Sensitive: true, Description: "Passphrase of an encrypted `private_key` / `private_key_file`. Env: PGS_SSH_PRIVATE_KEY_PASSPHRASE."},
					"known_hosts_file":         schema.StringAttribute{Optional: true, Description: "known_hosts file used to verify the host. Default ~/.ssh/known_hosts."},
					"host_key":                 schema.StringAttribute{Optional: true, Description: "Pin the host key (authorized_keys format); overrides known_hosts_file."},
					"insecure_ignore_host_key": schema.BoolAttribute{Optional: true, Description: "Skip host key verification. Insecure."},
					"become":                   schema.StringAttribute{Optional: true, Description: "Switch to this user on the SSH host via `sudo -n -u <user>` (passwordless sudo required) before touching the database, e.g. the owner of the pgs data directory. Applies to the embedded helper and to sqlite_command. With the helper, set helper_dir to a directory that user can execute from, such as /tmp."},
					"helper_dir":               schema.StringAttribute{Optional: true, Description: "Directory on the SSH host where the embedded SQLite helper binary is stored (must allow executing files). Default: the login directory. "},
				},
			},
		},
	}
}

func envOr(v types.String, env string) string {
	if !v.IsNull() && !v.IsUnknown() {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func (p *pgsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var sm sshModel
	if !cfg.SSH.IsNull() && !cfg.SSH.IsUnknown() {
		resp.Diagnostics.Append(cfg.SSH.As(ctx, &sm, basicObjectOptions)...)
	}
	for name, v := range map[string]interface{ IsUnknown() bool }{
		"database_path": cfg.DatabasePath, "sqlite_command": cfg.SQLiteCommand, "busy_timeout_ms": cfg.BusyTimeoutMS,
		"protected_accounts": cfg.ProtectedAccounts, "ssh": cfg.SSH, "ssh.host": sm.Host, "ssh.user": sm.User,
		"ssh.private_key": sm.PrivateKey, "ssh.private_key_file": sm.PrivateKeyFile, "ssh.host_key": sm.HostKey,
		"ssh.port": sm.Port, "ssh.private_key_passphrase": sm.PrivateKeyPassphrase, "ssh.known_hosts_file": sm.KnownHostsFile,
		"ssh.insecure_ignore_host_key": sm.InsecureIgnoreHostKey, "ssh.helper_dir": sm.HelperDir, "ssh.become": sm.Become,
	} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider configuration",
				fmt.Sprintf("%s is not known yet; the provider needs it to connect to the pgs database.", name))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	dbPath := envOr(cfg.DatabasePath, "PGS_DATABASE_PATH")
	command := envOr(cfg.SQLiteCommand, "PGS_SQLITE_COMMAND")
	timeout := int64(5000)
	if !cfg.BusyTimeoutMS.IsNull() {
		timeout = cfg.BusyTimeoutMS.ValueInt64()
	}

	var protected []string
	if !cfg.ProtectedAccounts.IsNull() {
		resp.Diagnostics.Append(cfg.ProtectedAccounts.ElementsAs(ctx, &protected, false)...)
	}

	sshHost := envOr(sm.Host, "PGS_SSH_HOST")
	var runner sqlrun.Runner
	switch {
	case sshHost != "" || command != "":
		if command == "" && dbPath == "" {
			resp.Diagnostics.AddError("Missing database_path", "Set database_path (or sqlite_command) so the provider knows which database to open.")
			return
		}
		var ex sqlrun.Executor = sqlrun.LocalExec{}
		if sshHost != "" {
			sc := sqlrun.SSHConfig{
				Host:           sshHost,
				User:           envOr(sm.User, "PGS_SSH_USER"),
				KnownHostsFile: sm.KnownHostsFile.ValueString(),
				HostKey:        sm.HostKey.ValueString(),
				InsecureHost:   sm.InsecureIgnoreHostKey.ValueBool(),
			}
			if sc.User == "" {
				resp.Diagnostics.AddError("Missing ssh.user", "Set ssh.user (or PGS_SSH_USER).")
				return
			}
			switch {
			case !sm.Port.IsNull():
				sc.Port = int(sm.Port.ValueInt64())
			case os.Getenv("PGS_SSH_PORT") != "":
				n, err := strconv.Atoi(os.Getenv("PGS_SSH_PORT"))
				if err != nil {
					resp.Diagnostics.AddError("Invalid PGS_SSH_PORT", err.Error())
					return
				}
				sc.Port = n
			}
			keyFile := envOr(sm.PrivateKeyFile, "PGS_SSH_PRIVATE_KEY_FILE")
			switch {
			case !sm.PrivateKey.IsNull():
				sc.PrivateKey = []byte(sm.PrivateKey.ValueString())
			case keyFile != "":
				path, err := sqlrun.ExpandHome(keyFile)
				if err != nil {
					resp.Diagnostics.AddError("Cannot read ssh.private_key_file", err.Error())
					return
				}
				b, err := os.ReadFile(path)
				if err != nil {
					resp.Diagnostics.AddError("Cannot read ssh.private_key_file", err.Error())
					return
				}
				sc.PrivateKey = b
			}
			if pp := envOr(sm.PrivateKeyPassphrase, "PGS_SSH_PRIVATE_KEY_PASSPHRASE"); pp != "" {
				sc.Passphrase = []byte(pp)
			}
			ex = sqlrun.SSHExec{Cfg: sc}
		}
		if command == "" {
			runner = &sqlrun.Remote{SSH: ex.(sqlrun.SSHExec), Path: dbPath, BusyTimeoutMS: int(timeout), HelperDir: sm.HelperDir.ValueString(), Become: sm.Become.ValueString(), Binary: helperbin.Get}
		} else {
			if b := sm.Become.ValueString(); b != "" && sshHost != "" {
				command = "sudo -n -u " + sqlrun.ShellQuote(b) + " sh -c " + sqlrun.ShellQuote(command)
			}
			runner = &sqlrun.CLI{Command: command, Exec: ex, BusyTimeoutMS: int(timeout)}
		}
	default:
		if dbPath == "" {
			resp.Diagnostics.AddError("Missing database_path", "Set database_path (or PGS_DATABASE_PATH), or sqlite_command / an ssh block.")
			return
		}
		runner = &sqlrun.Embedded{Path: dbPath, BusyTimeoutMS: int(timeout)}
	}

	store := pgs.NewStore(runner, protected)
	resp.ResourceData = store
	resp.DataSourceData = store
}

func (p *pgsProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewAccountResource}
}

func (p *pgsProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{NewAccountDataSource}
}

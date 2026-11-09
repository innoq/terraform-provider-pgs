//go:build e2e

// Package e2e runs the provider against a real pgs container.
//
//	make e2e
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	_ "modernc.org/sqlite"

	"github.com/innoq/terraform-provider-pgs/internal/pgs"
	"github.com/innoq/terraform-provider-pgs/internal/provider"
	"github.com/innoq/terraform-provider-pgs/internal/sqlrun"
)

const (
	project    = "pgs-tf-e2e"
	pgsSSHAddr = "127.0.0.1:2222"
	pgsWebAddr = "127.0.0.1:3000"
	dbhostAddr = "127.0.0.1:2223"
)

var (
	dataDir  string
	dbPath   string
	dbhostPK []byte
	dbhostHK string

	factories = map[string]func() (tfprotov6.ProviderServer, error){
		"pgs": providerserver.NewProtocol6WithError(provider.New("e2e")()),
	}
)

func compose(args ...string) ([]byte, error) {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project, "-f", "compose.yml"}, args...)...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func TestMain(m *testing.M) { os.Exit(run(m)) }

func run(m *testing.M) int {
	wd, _ := os.Getwd()
	dataDir = filepath.Join(wd, ".data")
	dbPath = filepath.Join(dataDir, "pgs.sqlite3")
	_ = os.RemoveAll(dataDir)
	_ = os.RemoveAll(filepath.Join(wd, ".ssh"))
	for _, d := range []string{dataDir, filepath.Join(wd, ".ssh")} {
		if err := os.MkdirAll(d, 0o777); err != nil {
			fmt.Println(err)
			return 1
		}
	}
	_ = os.Chmod(dataDir, 0o777)

	// key the provider uses to reach the dbhost
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	dbhostPK = pem.EncodeToMemory(blk)
	sp, _ := ssh.NewPublicKey(pub)
	if err := os.WriteFile(filepath.Join(wd, ".ssh", "authorized_keys"), ssh.MarshalAuthorizedKey(sp), 0o644); err != nil {
		fmt.Println(err)
		return 1
	}

	if out, err := compose("up", "-d", "--build"); err != nil {
		fmt.Printf("compose up: %v\n%s\n", err, out)
		return 1
	}
	defer func() {
		if out, err := compose("down", "-v"); err != nil {
			fmt.Printf("compose down: %v\n%s\n", err, out)
		}
		_ = os.RemoveAll(dataDir)
	}()

	if err := waitReady(); err != nil {
		out, _ := compose("logs")
		fmt.Printf("stack not ready: %v\n%s\n", err, out)
		return 1
	}
	// With a rootful docker the containers create the database as root, but the tests also open it from
	// the host. The dbhost container is root and shares the data directory, so it can open it up.
	if out, err := compose("exec", "-T", "dbhost", "chmod", "-R", "a+rwX", "/data"); err != nil {
		fmt.Printf("chmod data dir: %v\n%s\n", err, out)
		return 1
	}
	var err error
	if dbhostHK, err = scanHostKey(dbhostAddr); err != nil {
		fmt.Println(err)
		return 1
	}
	code := m.Run()
	if code != 0 {
		out, _ := compose("logs", "--tail", "60", "pgs")
		fmt.Printf("---- pgs container logs ----\n%s\n", out)
	}
	return code
}

func waitReady() error {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, a := range []string{pgsSSHAddr, dbhostAddr, pgsWebAddr} {
			c, err := net.DialTimeout("tcp", a, time.Second)
			if err != nil {
				ok = false
				break
			}
			c.Close()
		}
		if ok {
			if db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro"); err == nil {
				var v int
				err = db.QueryRow("PRAGMA user_version").Scan(&v)
				db.Close()
				if err == nil && v >= 1 {
					return nil
				}
			}
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("timeout waiting for pgs and dbhost")
}

func scanHostKey(addr string) (string, error) {
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{User: "root", HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error { got = k; return nil }, Timeout: 5 * time.Second}
	c, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
	}
	if got == nil {
		return "", fmt.Errorf("could not read host key of %s: %v", addr, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got))), nil
}

type userKey struct {
	signer ssh.Signer
	line   string
}

func genKey(t *testing.T) userKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg, _ := ssh.NewSignerFromKey(priv)
	sp, _ := ssh.NewPublicKey(pub)
	return userKey{sg, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))}
}

func (k userKey) dial() (*ssh.Client, error) {
	return ssh.Dial("tcp", pgsSSHAddr, &ssh.ClientConfig{
		User: "whoever", Auth: []ssh.AuthMethod{ssh.PublicKeys(k.signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second,
	})
}

// pgsCmd runs a pgs SSH command (stats, ls, ...) as the owner of the key.
func (k userKey) pgsCmd(cmd string) (string, error) {
	c, err := k.dial()
	if err != nil {
		return "", err
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return string(out), err
}

func (k userKey) upload(path string, data []byte) error {
	c, err := k.dial()
	if err != nil {
		return err
	}
	defer c.Close()
	cl, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer cl.Close()
	_ = cl.MkdirAll(filepath.Dir(path))
	f, err := cl.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (k userKey) loginFails(t *testing.T) {
	t.Helper()
	if c, err := k.dial(); err == nil {
		c.Close()
		t.Fatalf("login with removed/unknown key unexpectedly succeeded")
	}
}

func sqlDo(t *testing.T, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func sqlCount(t *testing.T, q string, args ...any) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func httpGet(host, path string) (int, string) {
	req, _ := http.NewRequest("GET", "http://"+pgsWebAddr+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

const requiredProviders = `terraform {
  required_providers {
    pgs = { source = "registry.opentofu.org/local/pgs" }
  }
}
`

// backends: the same scenarios run through the embedded driver and through SSH + the real sqlite3 CLI.
func providerBlocks() map[string]string {
	return map[string]string{
		"embedded": requiredProviders + fmt.Sprintf("provider \"pgs\" {\n database_path = %q\n}\n", dbPath),
		"ssh": requiredProviders + fmt.Sprintf(`provider "pgs" {
  database_path = "/data/pgs.sqlite3"
  ssh {
    host     = "127.0.0.1"
    port     = 2223
    user     = "root"
    host_key = %q
    private_key = <<-EOT
%sEOT
  }
}
`, dbhostHK, dbhostPK),
	}
}

func TestSchemaMatchesPgs(t *testing.T) {
	want, err := os.ReadFile("../../internal/pgs/testdata/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	norm := func(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }
	db, _ := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	defer db.Close()
	rows, err := db.Query("SELECT sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	wantN := norm(strings.ReplaceAll(string(want), "IF NOT EXISTS ", ""))
	for rows.Next() {
		var ddl string
		_ = rows.Scan(&ddl)
		if !strings.Contains(wantN, norm(ddl)) {
			t.Errorf("table definition used by this pgs version differs from testdata/schema.sql:\n%s", ddl)
		}
	}
}

// caps says what the pgs version under test is able to do by itself, so that the suite only asserts
// provider behaviour that pgs can show. Findings per version are documented in the README.
type caps struct {
	uploads       bool // pgs accepts an upload even from its own `pgs init` admin
	quotaEnforced bool // pgs rejects uploads above storage_max (pgs >= 4.1.0)
}

// imageAtLeast reports whether the pgs image under test (PGS_IMAGE tag, e.g. v4.1.0) is at least the
// given version. Unparsable tags such as "latest" count as new.
func imageAtLeast(major, minor, patch int) bool {
	img := os.Getenv("PGS_IMAGE")
	tag := img[strings.LastIndex(img, ":")+1:]
	var a, b, c int
	if _, err := fmt.Sscanf(tag, "v%d.%d.%d", &a, &b, &c); err != nil {
		return true
	}
	return [3]int{a, b, c} == [3]int{major, minor, patch} || a > major || (a == major && b > minor) || (a == major && b == minor && c > patch)
}

func TestE2E(t *testing.T) {
	// `pgs init` as in the user's existing workflow: creates the admin (user id 1).
	adminKey := genKey(t)
	if out, err := compose("exec", "-T", "pgs", "/app/pgs", "init", "admin", adminKey.line+" admin-key"); err != nil {
		t.Fatalf("pgs init: %v\n%s", err, out)
	}
	adminRowsBefore := sqlCount(t, "SELECT (SELECT count(*) FROM public_keys WHERE user_id = 1) + (SELECT count(*) FROM feature_flags WHERE user_id = 1)")
	if adminRowsBefore != 3 {
		t.Fatalf("unexpected admin rows after init: %d", adminRowsBefore)
	}

	// Control experiment: can pgs itself take an upload from the user it created with `pgs init`?
	c := caps{uploads: true, quotaEnforced: imageAtLeast(4, 1, 0)}
	if err := adminKey.upload("/baseline/index.html", []byte("baseline")); err != nil {
		c.uploads, c.quotaEnforced = false, false
		t.Logf("pgs baseline: upload by the pgs-init admin FAILS on this version (%v); upload assertions are skipped", err)
	}
	t.Logf("pgs capabilities: %+v", c)

	for name, pb := range providerBlocks() {
		t.Run(name, func(t *testing.T) { scenario(t, name, pb, adminKey, c) })
	}
	// the admin's rows are untouched after everything
	if n := sqlCount(t, "SELECT (SELECT count(*) FROM public_keys WHERE user_id = 1) + (SELECT count(*) FROM feature_flags WHERE user_id = 1)"); n != adminRowsBefore {
		t.Fatalf("admin rows changed: %d -> %d", adminRowsBefore, n)
	}
}

func scenario(t *testing.T, backend, pb string, adminKey userKey, c caps) {
	acct := "alice" + backend // letters only
	ka, kb := genKey(t), genKey(t)
	cfg := func(keys, access string) string {
		return pb + fmt.Sprintf("\nresource \"pgs_account\" \"a\" {\n  name = %q\n  public_keys = [%s]\n  %s\n}\n", acct, keys, access)
	}
	both := fmt.Sprintf("{ key = %q, description = \"alice\" },\n{ key = %q, description = \"bob\" }", ka.line, kb.line)
	onlyA := fmt.Sprintf("{ key = %q, description = \"alice\" }", ka.line)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{ // the admin can never be managed, whatever the config says
				Config:      pb + fmt.Sprintf("\nresource \"pgs_account\" \"adm\" {\n  name = \"admin\"\n  public_keys = [{ key = %q }]\n}\n", genKey(t).line),
				ExpectError: regexp.MustCompile(`(?s)protected`),
			},
			{ // admin's key cannot be hijacked either
				Config:      cfg(fmt.Sprintf("{ key = %q }", adminKey.line), ""),
				ExpectError: regexp.MustCompile(`(?s)protected\s+admin`),
			},
			{
				Config: cfg(both, "access = { storage_max = 1000000 }"),
				Check: func(*terraform.State) error {
					if !c.uploads {
						// pgs cannot take uploads on this version: check that both keys log in, and give the
						// account a project so that the destroy-guard step below still has something to guard.
						for _, k := range []userKey{ka, kb} {
							if out, err := k.pgsCmd("ls"); err != nil {
								return fmt.Errorf("login: %v\n%s", err, out)
							}
						}
						sqlDo(t, "INSERT INTO projects (user_id, name) SELECT id, 'site' FROM app_users WHERE name = ?", acct)
						return nil
					}
					// pgs creates a user's storage bucket on the first upload, `stats` needs it
					if err := ka.upload("/site/index.html", []byte("<h1>hello e2e</h1>")); err != nil {
						return fmt.Errorf("upload: %w", err)
					}
					code, body := httpGet(acct+"-site.pgs.test", "/")
					if code != 200 || !strings.Contains(body, "hello e2e") {
						return fmt.Errorf("site not served: %d %q", code, body)
					}
					// both keys log in; stats reflects the quota
					for _, k := range []userKey{ka, kb} {
						out, err := k.pgsCmd("stats")
						if err != nil {
							return fmt.Errorf("stats: %v\n%s", err, out)
						}
						if !strings.Contains(out, "0.0010") {
							return fmt.Errorf("stats does not show the 1 MB quota:\n%s", out)
						}
					}
					if c.quotaEnforced {
						if err := ka.upload("/site/big.bin", bytes.Repeat([]byte("x"), 2_000_000)); err == nil {
							return fmt.Errorf("2 MB upload should exceed the 1 MB quota")
						}
					}
					return nil
				},
			},
			{ // drift: key added directly in the database is reported
				PreConfig: func() {
					sqlDo(t, "INSERT INTO public_keys (user_id, name, public_key) SELECT id, 'rogue', 'ssh-ed25519 ROGUE' FROM app_users WHERE name = ?", acct)
				},
				Config:             cfg(both, "access = { storage_max = 1000000 }"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{ // apply repairs it; then drop key b, rename a description, raise quota
				Config: cfg(onlyA, "access = { storage_max = 2000000 }"),
				Check: func(*terraform.State) error {
					if n := sqlCount(t, "SELECT count(*) FROM public_keys WHERE name = 'rogue'"); n != 0 {
						return fmt.Errorf("rogue key still present")
					}
					if !c.uploads {
						return nil // no storage bucket without a first upload, so `stats` is unavailable
					}
					out, err := ka.pgsCmd("stats")
					if err != nil || !strings.Contains(out, "0.0020") {
						return fmt.Errorf("stats after quota change: %v\n%s", err, out)
					}
					return nil
				},
			},
			{
				PreConfig: func() { kb.loginFails(t) },
				Config:    cfg(onlyA, "access = { storage_max = 2000000 }"),
				PlanOnly:  true,
			},
			{ // destroy refuses while the account has projects
				Config:      cfg(onlyA, "access = { storage_max = 2000000 }"),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`(?s)force_destroy`),
			},
			{
				Config: cfg(onlyA, "access = { storage_max = 2000000 }\n  force_destroy = true"),
			},
			{ // both keys back, so the destroy that follows has two keys to remove
				Config: cfg(both, "access = { storage_max = 2000000 }\n  force_destroy = true"),
				Check: func(*terraform.State) error {
					for _, k := range []userKey{ka, kb} {
						if out, err := k.pgsCmd("ls"); err != nil {
							return fmt.Errorf("login before destroy: %v\n%s", err, out)
						}
					}
					return nil
				},
			},
			{
				Config:  cfg(both, "access = { storage_max = 2000000 }\n  force_destroy = true"),
				Destroy: true,
			},
		},
		CheckDestroy: func(*terraform.State) error {
			ka.loginFails(t)
			kb.loginFails(t)
			for _, k := range []userKey{ka, kb} {
				pk, err := pgs.ParseKey(k.line)
				if err != nil {
					return err
				}
				if n := sqlCount(t, "SELECT count(*) FROM public_keys WHERE public_key = ?", pk.Normalized); n != 0 {
					return fmt.Errorf("key row still present after destroy")
				}
			}
			if n := sqlCount(t, "SELECT count(*) FROM app_users WHERE name = ?", acct); n != 0 {
				return fmt.Errorf("account row still present")
			}
			return nil
		},
	})
}

// TestCLIQuoting pushes hostile values through the real sqlite3 CLI (on the dbhost, over SSH).
// The unit tests only have a stand-in for the CLI; this is the check against the real parser.
func TestCLIQuoting(t *testing.T) {
	runner := &sqlrun.CLI{
		Command:       "sqlite3 /data/pgs.sqlite3",
		Exec:          sqlrun.SSHExec{Cfg: sqlrun.SSHConfig{Host: "127.0.0.1", Port: 2223, User: "root", PrivateKey: dbhostPK, HostKey: dbhostHK}},
		BusyTimeoutMS: 5000,
	}
	// "nobody" is protected only so the store does not require an admin row (this test may run alone).
	st := pgs.NewStore(runner, []string{"nobody"})
	cases := map[string]string{
		"dotcmd":      ".quit",
		"shell":       "x\n.shell touch /data/pwned\n",
		"injection":   "x'; DROP TABLE app_users; --",
		"crlf":        "a\r\nb\rc\n",
		"unicode":     " \u0085 \U0001F600 \x1a\x01\x7f",
		"misc":        "back\\slash ? %s '''' \t trailing ",
		"singlespace": " ",
		"longlines":   strings.Repeat("é'\n", 100000),
	}
	i := 0
	for name, desc := range cases {
		i++
		acct := fmt.Sprintf("quoting%d", i)
		t.Run(name, func(t *testing.T) {
			pk, err := pgs.ParseKey(genKey(t).line)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			acc, err := st.Create(ctx, acct, []pgs.KeyInput{{Normalized: pk.Normalized, Description: desc}}, pgs.AccessInput{ExpiresAt: pgs.DefaultExpiresAt}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := acc.Keys[0].Description; got != desc {
				t.Fatalf("description mangled: got %d bytes, want %d", len(got), len(desc))
			}
			if err := st.Delete(ctx, acc.ID, true); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(dataDir, "pwned")); err == nil {
		t.Fatal("a dot-command in a value was executed")
	}
	if n := sqlCount(t, "SELECT count(*) FROM sqlite_master WHERE name = 'app_users'"); n != 1 {
		t.Fatal("app_users table is gone")
	}
}

# terraform-provider-pgs

OpenTofu/Terraform provider that manages accounts of a **self-hosted [pico.sh pgs](https://github.com/picosh/pico/tree/main/pkg/apps/pgs)** installation.

pgs has no user API, so the provider edits pgs's SQLite database directly: `app_users` (the account), `public_keys` (one or more SSH keys per account, with a description each) and `feature_flags` (upload rights and quotas).

This project is independent. It is **not affiliated with or endorsed by pico.sh** (pico.sh LLC). "pico.sh" and "pgs" are used only to name the software this provider works with.

## Installing locally

The provider is not published to a registry yet, so build it and point OpenTofu/Terraform at the binary with `dev_overrides`. Requires Go and [just](https://github.com/casey/just).

1. Build into `./bin` (also builds the embedded SSH helpers, `just helpers`):
   ```sh
   just install        # writes bin/terraform-provider-pgs
   ```
2. Create a CLI config that overrides the provider address with that directory (see `.tofurc.example`):
   ```hcl
   # ~/.tofurc  (OpenTofu; use ~/.terraformrc for Terraform)
   provider_installation {
     dev_overrides {
       "registry.opentofu.org/local/pgs" = "/absolute/path/to/terraform-provider-pgs/bin"
     }
     direct {}
   }
   ```
   Or keep it per project and select it with an environment variable:
   ```sh
   export TF_CLI_CONFIG_FILE=/absolute/path/to/terraform-provider-pgs/.tofurc.example   # after editing the path
   ```
3. Declare the provider in your configuration, using the same address:
   ```hcl
   terraform {
     required_providers {
       pgs = { source = "registry.opentofu.org/local/pgs" }
     }
   }
   ```
4. Run `tofu plan` / `tofu apply` directly. Skip `tofu init` for this provider: with `dev_overrides` OpenTofu prints a warning and uses the local binary without installing it. Re-run `just install` after changing the code.

With Terraform instead of OpenTofu, the same works with the source `registry.opentofu.org/local/pgs`, since only the override key must match the source address.

## Compatibility

**Tested pgs versions: v4.1.0 and v4.1.2** (`ghcr.io/picosh/pgs`, SQLite backend). Both pass the full e2e suite (`just e2e-all`). Newer versions may work but have not been tested. PostgreSQL-backed pgs is not supported.

pgs does not expose its version in the database, so the provider cannot check it; it only verifies that the tables it needs exist. To check another version before relying on it, run `PGS_IMAGE=ghcr.io/picosh/pgs:<tag> just e2e`.

The e2e suite can test several versions: `just e2e-all` runs it for every tag listed in `test/e2e/pgs-versions.txt`.

## Provider

```hcl
provider "pgs" {
  database_path      = "/srv/pgs/data/pgs.sqlite3"  # env PGS_DATABASE_PATH
  sqlite_command     = "..."                         # optional, env PGS_SQLITE_COMMAND
  busy_timeout_ms    = 5000
  protected_accounts = ["ops"]                       # optional, see below
  ssh { host = "pgs.example.com"  user = "root" }    # optional: run remotely
}
```

| Setup | How the database is reached |
|---|---|
| only `database_path` | in-process (pure-Go SQLite); the file must be local |
| `ssh {}` block | the provider uploads a small embedded pure-Go SQLite helper to the host (Linux amd64/arm64; stored in the login directory, or `ssh.helper_dir`) and runs it over SSH. The host needs no `sqlite3`, only `sh`, `cat`, `chmod`, `mv`, `uname` |
| `sqlite_command` | that command is run instead of the helper (locally, or over SSH if `ssh {}` is set), SQL on stdin, e.g. `docker run --rm -i -v /srv/pgs/data:/data keinos/sqlite3 sqlite3 /data/pgs.sqlite3` |

`ssh.helper_dir` sets where the helper is stored on the host (default: the login directory; must not be mounted `noexec`).

`ssh.become = "<user>"` switches to another user on the host with `sudo -n -u <user>` (passwordless sudo required). Use it when the SSH user cannot write the database, e.g. it is owned by a service account that cannot log in. It applies to the helper and to `sqlite_command`. With the helper, also set `helper_dir` to a directory that user can execute from (such as `/tmp`): the helper is then uploaded world-executable (mode 755), and a private home directory would not work.

SSH auth uses `private_key`, `private_key_file` (with `private_key_passphrase` if the key is encrypted) or the ssh-agent. The host is verified against `known_hosts_file` (default `~/.ssh/known_hosts`), or `host_key` if given.
Every write is one short `BEGIN IMMEDIATE` transaction with a busy timeout, so it is safe while pgs is running.

## `pgs_account`

```hcl
resource "pgs_account" "projectx" {
  name = "projectx"
  public_keys = [
    { key = "ssh-ed25519 AAAA... alice@laptop", description = "alice" },
    { key = file("bob.pub") },   # description defaults to the key comment, else "main"
  ]
  access = { storage_max = 5000000000 }   # optional: only tunes the pgs flag's expiry and quotas
}
```

* `name`: `[a-z0-9]+` only. pgs serves `<account>-<project>.<domain>` and splits on the first `-`. Renaming changes site URLs.
* `public_keys` must contain at least one key. `public_keys[*].description` is pgs's `public_keys.name`, which pgs shows as the login identity. Keys are compared in the form pgs stores (`type base64`), so comments and trailing newlines never cause diffs. A key can belong to one account only. Each `key` must be a single line: for a file with several keys, create one entry per key. `description` must not be empty (omit it to get the default).
* The account's **`pgs` feature flag always exists**: without it the account would have no access to pgs. The provider creates it with the account (expiry `2200-01-01`), recreates it if it disappears (the plan shows this as drift on `access`, and `flag_id` is null meanwhile), and removes it only when the account is destroyed. The optional `access` block only sets that flag's metadata: `expires_at` (`YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`, stored verbatim), `storage_max`, `file_max` and `special_file_max`. Omit the block, or unset an attribute, to get the pgs defaults (50 MB / 10 MB / 5 KB); removing a previously set value resets it. Other flags of the account are never touched, and extra JSON fields in the flag's data are preserved.
* `force_destroy`: without it, destroying an account that has projects fails. Site files in pgs's object storage are **not** removed either way.
* Import: `tofu import pgs_account.x <name>`. An imported account without a `pgs` flag gets one on the next apply.
* Data source `pgs_account` reads an account by name.

### The admin account is never managed
An account with the `admin` feature flag (created by `pgs init`) or listed in `protected_accounts` is off limits: it can't be created, imported, read, changed or deleted, never appears in state, and its keys can't be reused.

Run `pgs init <admin> <key>` before using the provider. If no account has the `admin` flag and `protected_accounts` is empty, the provider refuses to work rather than guess which account is the admin.

### Drift
`tofu plan` refreshes state first, which connects to the installation and reads the real keys, descriptions and quota. Changes made outside OpenTofu appear as drift in the plan (keys added, descriptions or quota changed, flag or account deleted) and are corrected on apply. Plan only reads. If the installation is unreachable, plan fails.

## Development

Go 1.27.3 (the version in `go.mod`, and the newest stable release when this was checked); all tests pass with it. `mise.toml` pins the toolchain (Go 1.27.3, just 1.59.0, OpenTofu 1.13.2); run `mise install` to get it.

```sh
just test       # unit + acceptance tests (needs tofu; real tofu, temporary databases, no containers)
just testacc    # only the acceptance tests, verbose
just e2e        # real pgs container + SSH host with sqlite3 (docker/podman compose)
just e2e-all    # the same for every pgs version in test/e2e/pgs-versions.txt
just install    # build ./bin for dev_overrides, see .tofurc.example
```

The e2e suite starts `ghcr.io/picosh/pgs` (override with `PGS_IMAGE`), runs `pgs init admin`, and checks through real SSH/SFTP/HTTP that keys log in, uploads are served, quotas are enforced, removed keys stop working and the admin rows stay untouched. It also pushes hostile descriptions (quotes, newlines, dot-commands, 100k lines) through the real `sqlite3` CLI, and compares pgs's actual table definitions with `internal/pgs/testdata/schema.sql`, so an upstream schema change fails loudly.

## Limitations

* **An account that becomes protected while managed is not handled.** If a managed account is given the `admin` flag, or its name is added to `protected_accounts`, refresh, plan and destroy fail with a "protected" error until you run `tofu state rm`. The provider assumes this never happens.
* **Moving a key between two managed accounts** fails if the account that gains the key is applied before the account that loses it (a key can belong to one account only). Order them with `depends_on`, or apply in two steps.
* **Checks and writes are separate transactions.** Each write is one short `BEGIN IMMEDIATE` transaction, but decisions such as "name free", "key unused" or "no projects" are read just before it. Concurrent changes to the same account by pgs or another person can still make an apply fail (unique constraints and the admin guards hold; deleting without `force_destroy` never removes projects, even if one appears concurrently). If the connection drops right after a commit, create may fail although the account exists; run `tofu import`.
* **One SSH connection per database call**, with no reuse or retry. Lower `-parallelism` if many accounts hit sshd's `MaxStartups`. The remote host needs a POSIX login shell, and the helper directory must allow executing files (set `ssh.helper_dir` if the home is mounted noexec). Remote hosts other than Linux amd64/arm64 need `sqlite_command`.
* Only OpenTofu has been tested, not Terraform.

Caveats: pgs's schema is an internal detail and may change; pgs creates a user's storage directory on first upload, so `ssh <host> stats` fails for an account that never uploaded.

terraform {
  required_providers {
    pgs = { source = "innoq/pgs" }
  }
}

# Database on a remote host: an embedded SQLite helper is uploaded and run over SSH (no sqlite3 needed there).
provider "pgs" {
  database_path = "/srv/pgs/data/pgs.sqlite3"

  ssh {
    host = "pgs.example.com"
    user = "root"
    # become     = "apps"  # run as another user via `sudo -n -u apps` (e.g. the owner of the data dir)
    # helper_dir = "/tmp"  # where the helper is stored; must be executable by that user
    # private_key_file = "~/.ssh/id_ed25519"  # default: ssh-agent
    # host_key         = "ssh-ed25519 AAAA..."  # default: ~/.ssh/known_hosts
  }

  # Accounts that are never managed, besides the one holding the `admin` flag.
  # protected_accounts = ["ops"]
}

# Alternatives:
#
# - Local database file, opened in-process (no sqlite3 needed):
#     provider "pgs" { database_path = "./data/pgs.sqlite3" }
#
# - Any command that reads SQL on stdin, e.g. sqlite3 in a container:
#     provider "pgs" {
#       sqlite_command = "docker run --rm -i -v /srv/pgs/data:/data keinos/sqlite3 sqlite3 /data/pgs.sqlite3"
#     }

# An account with two keys and a 5 GB quota.
resource "pgs_account" "projectx" {
  name = "projectx"

  public_keys = [
    { key = "ssh-ed25519 AAAA... alice@laptop", description = "alice" },
    { key = file("${path.module}/bob.pub"), description = "bob (CI)" },
  ]

  access = {
    storage_max = 5000000000
  }
}

# The simplest account: one key, default quotas. The description defaults to the key's comment.
resource "pgs_account" "simple" {
  name = "simple"

  public_keys = [
    { key = "ssh-ed25519 AAAA... carol@desktop" },
  ]
}

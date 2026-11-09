data "pgs_account" "projectx" {
  name = "projectx"
}

output "projectx_key_descriptions" {
  value = [for k in data.pgs_account.projectx.public_keys : k.description]
}

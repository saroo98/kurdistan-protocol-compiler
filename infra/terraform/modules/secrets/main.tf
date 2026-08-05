variable "project_id" { type = string }
variable "secret_names" { type = set(string) }

resource "google_secret_manager_secret" "reference" {
  for_each  = var.secret_names
  project   = var.project_id
  secret_id = each.value
  replication {
    auto {}
  }
  lifecycle { prevent_destroy = true }
}

output "ids" { value = { for key, value in google_secret_manager_secret.reference : key => value.id } }

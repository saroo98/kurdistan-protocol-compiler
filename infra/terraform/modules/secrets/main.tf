variable "project_id" { type = string }
variable "secret_names" { type = set(string) }
variable "location" {
  type = string
  validation {
    condition     = can(regex("^europe-", var.location))
    error_message = "Secret Manager authority references must remain in an approved EU region."
  }
}

resource "google_secret_manager_secret" "reference" {
  for_each  = var.secret_names
  project   = var.project_id
  secret_id = each.value
  replication {
    user_managed {
      replicas { location = var.location }
    }
  }
  lifecycle { prevent_destroy = true }
}

output "ids" { value = { for key, value in google_secret_manager_secret.reference : key => value.id } }

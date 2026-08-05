variable "project_id" { type = string }
variable "location" { type = string }
variable "bucket_name" { type = string }
variable "retention_seconds" { type = number }

resource "google_storage_bucket" "audit" {
  project                     = var.project_id
  name                        = var.bucket_name
  location                    = var.location
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning { enabled = true }
  retention_policy {
    retention_period = var.retention_seconds
    is_locked        = false
  }

  lifecycle { prevent_destroy = true }
}

output "name" { value = google_storage_bucket.audit.name }

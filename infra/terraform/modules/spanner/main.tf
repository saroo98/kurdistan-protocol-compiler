variable "project_id" { type = string }
variable "configuration" { type = string }
variable "instance_name" { type = string }
variable "database_name" { type = string }
variable "ddl" { type = list(string) }

resource "google_spanner_instance" "authority" {
  project      = var.project_id
  name         = var.instance_name
  config       = var.configuration
  display_name = "Kurdistan VPN authority"
  num_nodes    = 1
  lifecycle { prevent_destroy = true }
}

resource "google_spanner_database" "authority" {
  project                  = var.project_id
  instance                 = google_spanner_instance.authority.name
  name                     = var.database_name
  database_dialect         = "GOOGLE_STANDARD_SQL"
  version_retention_period = "7d"
  deletion_protection      = true
  ddl                      = var.ddl
  lifecycle { prevent_destroy = true }
}

resource "google_spanner_backup_schedule" "authority_daily" {
  project            = var.project_id
  instance           = google_spanner_instance.authority.name
  database           = google_spanner_database.authority.name
  name               = "authority-daily-full"
  retention_duration = "2592000s"

  spec {
    cron_spec { text = "0 2 * * *" }
  }
  full_backup_spec {}
  encryption_config { encryption_type = "USE_DATABASE_ENCRYPTION" }
}

output "database" { value = google_spanner_database.authority.id }
output "instance_name" { value = google_spanner_instance.authority.name }
output "database_name" { value = google_spanner_database.authority.name }

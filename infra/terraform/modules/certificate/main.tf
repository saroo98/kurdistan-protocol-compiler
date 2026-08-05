variable "project_id" { type = string }
variable "domains" { type = list(string) }

resource "google_compute_managed_ssl_certificate" "publication" {
  project = var.project_id
  name    = "kvpn-publication"
  managed { domains = var.domains }
  lifecycle { prevent_destroy = true }
}

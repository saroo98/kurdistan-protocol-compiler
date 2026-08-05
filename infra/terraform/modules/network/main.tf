variable "project_id" { type = string }
variable "region" { type = string }

resource "google_compute_network" "control" {
  project                 = var.project_id
  name                    = "kvpn-control"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "control" {
  project                  = var.project_id
  region                   = var.region
  name                     = "kvpn-control"
  network                  = google_compute_network.control.id
  ip_cidr_range            = "10.96.0.0/24"
  private_ip_google_access = true
}

output "network" { value = google_compute_network.control.id }
output "subnetwork" { value = google_compute_subnetwork.control.id }

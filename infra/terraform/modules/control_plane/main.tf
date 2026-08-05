variable "project_id" { type = string }
variable "region" { type = string }
variable "images" { type = map(string) }
variable "service_accounts" { type = map(string) }
variable "network" { type = string }
variable "subnetwork" { type = string }

resource "google_cloud_run_v2_service" "service" {
  for_each = var.images
  project  = var.project_id
  location = var.region
  name     = each.key
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  template {
    service_account                  = var.service_accounts[each.key]
    timeout                          = "30s"
    max_instance_request_concurrency = 20
    containers { image = each.value }
    scaling {
      min_instance_count = 0
      max_instance_count = 10
    }
    vpc_access {
      network_interfaces {
        network    = var.network
        subnetwork = var.subnetwork
      }
      egress = "PRIVATE_RANGES_ONLY"
    }
  }

  deletion_protection = true
}

output "uris" { value = { for key, value in google_cloud_run_v2_service.service : key => value.uri } }

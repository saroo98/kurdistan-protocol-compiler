variable "project_id" { type = string }
variable "region" { type = string }
variable "images" { type = map(string) }
variable "service_accounts" { type = map(string) }
variable "network" { type = string }
variable "subnetwork" { type = string }
variable "runtime_secret_id" { type = string }

locals {
  service_names = toset([
    "koperator-api",
    "koperator-worker",
    "koperator-publication",
    "koperator-audit",
    "koperator-emergency",
  ])
  job_names = toset([
    "koperator-ceremony",
    "koperator-drill",
  ])
}

resource "google_cloud_run_v2_service" "service" {
  for_each = { for key, value in var.images : key => value if contains(local.service_names, key) }
  project  = var.project_id
  location = var.region
  name     = each.key
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"

  default_uri_disabled = true
  iap_enabled          = each.key == "koperator-api"
  invoker_iam_disabled = false

  template {
    service_account                  = var.service_accounts[each.key]
    timeout                          = "30s"
    max_instance_request_concurrency = 20
    containers {
      image = each.value
      dynamic "env" {
        for_each = contains(["koperator-api", "koperator-worker"], each.key) ? [1] : []
        content {
          name = "KURDISTAN_OPERATOR_CONFIG"
          value_source {
            secret_key_ref {
              secret  = var.runtime_secret_id
              version = "latest"
            }
          }
        }
      }
    }
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

resource "google_cloud_run_v2_job" "job" {
  for_each = { for key, value in var.images : key => value if contains(local.job_names, key) }
  project  = var.project_id
  location = var.region
  name     = each.key

  template {
    task_count  = 1
    parallelism = 1
    template {
      service_account = var.service_accounts[each.key]
      timeout         = "3600s"
      max_retries     = 0
      containers {
        image = each.value
        dynamic "env" {
          for_each = contains(["koperator-api", "koperator-worker"], each.key) ? [1] : []
          content {
            name = "KURDISTAN_OPERATOR_CONFIG"
            value_source {
              secret_key_ref {
                secret  = var.runtime_secret_id
                version = "latest"
              }
            }
          }
        }
      }
      vpc_access {
        network_interfaces {
          network    = var.network
          subnetwork = var.subnetwork
        }
        egress = "PRIVATE_RANGES_ONLY"
      }
    }
  }

  deletion_protection = true
}

output "uris" { value = { for key, value in google_cloud_run_v2_service.service : key => value.uri } }
output "jobs" { value = { for key, value in google_cloud_run_v2_job.job : key => value.name } }

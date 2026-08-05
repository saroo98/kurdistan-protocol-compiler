variable "projects" { type = map(string) }
variable "region" { type = string }
variable "spanner_configuration" { type = string }
variable "kms_location" { type = string }
variable "bucket_location" { type = string }
variable "bucket_names" { type = map(string) }
variable "images" { type = map(string) }
variable "repository" { type = string }
variable "schema_ddl" { type = list(string) }

locals {
  runtime_services    = toset(["koperator-api", "koperator-worker", "koperator-publication", "koperator-audit", "koperator-emergency", "koperator-ceremony", "koperator-drill"])
  deployment_services = toset(["koperator-tf-plan", "koperator-tf-apply", "koperator-drill-runner"])
  services            = setunion(local.runtime_services, local.deployment_services)
}

module "identity" {
  source           = "../identity"
  project_id       = var.projects.control
  service_accounts = local.services
}

module "network" {
  source     = "../network"
  project_id = var.projects.control
  region     = var.region
}

module "kms" {
  source     = "../kms_hsm"
  project_id = var.projects.trust
  location   = var.kms_location
  key_ring   = "kvpn-authority"
  roles      = toset(["root", "recovery", "issuer", "emergency", "publication", "audit"])
}

module "spanner" {
  source        = "../spanner"
  project_id    = var.projects.control
  configuration = var.spanner_configuration
  instance_name = "kvpn-authority"
  database_name = "authority"
  ddl           = var.schema_ddl
}

module "publication" {
  source            = "../publication"
  project_id        = var.projects.publication
  location          = var.bucket_location
  bucket_name       = var.bucket_names.publication
  retention_seconds = 31536000
}

module "audit" {
  source            = "../audit"
  project_id        = var.projects.audit
  location          = var.bucket_location
  bucket_name       = var.bucket_names.audit
  retention_seconds = 220752000
}

module "backup" {
  source            = "../backup"
  project_id        = var.projects.ops
  location          = var.bucket_location
  bucket_name       = var.bucket_names.backup
  retention_seconds = 31536000
}

module "secrets" {
  source       = "../secrets"
  project_id   = var.projects.control
  secret_names = toset(["operator-runtime-config"])
}

module "control_plane" {
  source           = "../control_plane"
  project_id       = var.projects.control
  region           = var.region
  images           = var.images
  service_accounts = { for key, value in module.identity.emails : key => value if contains(local.runtime_services, key) }
  network          = module.network.network
  subnetwork       = module.network.subnetwork
}

module "workload_identity" {
  source      = "../workload_identity"
  project_id  = var.projects.ops
  pool_id     = "kvpn-github"
  provider_id = "kvpn-main"
  repository  = var.repository
  service_accounts = {
    phase16-production-plan = module.identity.names["koperator-tf-plan"]
    phase16-production      = module.identity.names["koperator-tf-apply"]
    phase16-drill           = module.identity.names["koperator-drill-runner"]
  }
}

module "monitoring" {
  source        = "../monitoring"
  project_id    = var.projects.ops
  service_names = local.runtime_services
}

output "kms_keys" { value = module.kms.key_names }
output "spanner_database" { value = module.spanner.database }
output "publication_bucket" { value = module.publication.name }
output "audit_bucket" { value = module.audit.name }
output "wif_provider" { value = module.workload_identity.provider_name }

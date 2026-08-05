variable "projects" {
  type = object({ trust = string, control = string, publication = string, audit = string, ops = string })
  validation {
    condition     = length(distinct(values(var.projects))) == 5
    error_message = "Qualification projects must be distinct."
  }
}
variable "region" { type = string }
variable "spanner_configuration" { type = string }
variable "kms_location" { type = string }
variable "bucket_location" { type = string }
variable "bucket_names" { type = map(string) }
variable "images" {
  type = map(string)
  validation {
    condition = (
      length(setsubtract(toset(keys(var.images)), toset(["koperator-api", "koperator-worker", "koperator-publication", "koperator-audit", "koperator-emergency", "koperator-ceremony", "koperator-drill"]))) == 0 &&
      length(setsubtract(toset(["koperator-api", "koperator-worker", "koperator-publication", "koperator-audit", "koperator-emergency", "koperator-ceremony", "koperator-drill"]), toset(keys(var.images)))) == 0 &&
      alltrue([for image in values(var.images) : can(regex("@sha256:[0-9a-f]{64}$", image))])
    )
    error_message = "Every required service image, and no unknown image, must be digest pinned."
  }
}

module "production_trust" {
  source                = "../../modules/production_trust"
  projects              = var.projects
  region                = var.region
  spanner_configuration = var.spanner_configuration
  kms_location          = var.kms_location
  bucket_location       = var.bucket_location
  bucket_names          = var.bucket_names
  images                = var.images
  repository            = "saroo98/kurdistan-protocol-compiler"
  schema_ddl            = compact([for statement in split(";", file("${path.module}/../../../../production/migrations/001_initial.sql")) : trimspace(statement)])
}

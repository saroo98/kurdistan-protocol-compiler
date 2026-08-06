variable "projects" {
  type = object({ trust = string, control = string, publication = string, audit = string, ops = string })
  validation {
    condition     = length(distinct(values(var.projects))) == 5
    error_message = "Production projects must be distinct."
  }
}
variable "region" {
  type = string
  validation {
    condition     = var.region == "europe-west2"
    error_message = "Production control-plane region is frozen to europe-west2."
  }
}
variable "spanner_configuration" {
  type = string
  validation {
    condition     = var.spanner_configuration == "eur6"
    error_message = "Production Spanner is frozen to eur6."
  }
}
variable "kms_location" {
  type = string
  validation {
    condition     = can(regex("^(europe-|eu$|EU$)", var.kms_location))
    error_message = "Production KMS must remain in the approved EU boundary."
  }
}
variable "bucket_location" {
  type = string
  validation {
    condition     = can(regex("^(europe-|eu$|EU$)", var.bucket_location))
    error_message = "Production buckets must remain in the approved EU boundary."
  }
}
variable "bucket_names" { type = map(string) }
variable "billing_account" { type = string }
variable "budget_currency_code" { type = string }
variable "budget_monthly_units" { type = number }
variable "notification_channels" { type = list(string) }
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
  schema_ddl = flatten([
    for migration in sort(fileset("${path.module}/../../../../production/migrations", "*.sql")) :
    compact([for statement in split(";", file("${path.module}/../../../../production/migrations/${migration}")) : trimspace(statement)])
  ])
  billing_account       = var.billing_account
  budget_currency_code  = var.budget_currency_code
  budget_monthly_units  = var.budget_monthly_units
  notification_channels = var.notification_channels
}

variable "project_ids" {
  type = object({ trust = string, control = string, publication = string, audit = string })
}
variable "service_accounts" { type = map(string) }
variable "spanner_instance" { type = string }
variable "spanner_database" { type = string }
variable "kms_keys" { type = map(string) }
variable "publication_bucket" { type = string }
variable "audit_bucket" { type = string }
variable "runtime_secret_id" { type = string }
variable "enable_ceremony_access" {
  type    = bool
  default = false
}
variable "ceremony_access_expires_at" {
  type    = string
  default = "1970-01-01T00:00:00Z"
  validation {
    condition     = can(timecmp(var.ceremony_access_expires_at, "1970-01-01T00:00:00Z"))
    error_message = "Ceremony expiry must be an RFC3339 timestamp."
  }
}

locals {
  database_users = toset([
    "koperator-api",
    "koperator-worker",
    "koperator-publication",
    "koperator-audit",
    "koperator-emergency",
  ])
  signer_roles = {
    "koperator-worker"      = "issuer"
    "koperator-publication" = "publication"
    "koperator-audit"       = "audit"
    "koperator-emergency"   = "emergency"
  }
  publication_writers = toset(["koperator-publication", "koperator-emergency"])
}

resource "google_spanner_database_iam_member" "runtime" {
  for_each = local.database_users
  project  = var.project_ids.control
  instance = var.spanner_instance
  database = var.spanner_database
  role     = "roles/spanner.databaseUser"
  member   = "serviceAccount:${var.service_accounts[each.key]}"
}

resource "google_secret_manager_secret_iam_member" "runtime_config" {
  for_each  = toset(["koperator-api", "koperator-worker"])
  project   = var.project_ids.control
  secret_id = var.runtime_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_accounts[each.key]}"
}

resource "google_kms_crypto_key_iam_member" "signer" {
  for_each      = local.signer_roles
  crypto_key_id = var.kms_keys[each.value]
  role          = "roles/cloudkms.signerVerifier"
  member        = "serviceAccount:${var.service_accounts[each.key]}"
}

# The API may only wrap freshly admitted authority source. The worker may only
# unwrap it after leasing the corresponding durable outbox event. Neither
# identity receives the combined encrypter/decrypter role.
resource "google_kms_crypto_key_iam_member" "authority_source_encrypt" {
  crypto_key_id = var.kms_keys["staging"]
  role          = "roles/cloudkms.cryptoKeyEncrypter"
  member        = "serviceAccount:${var.service_accounts["koperator-api"]}"
}

resource "google_kms_crypto_key_iam_member" "authority_source_decrypt" {
  crypto_key_id = var.kms_keys["staging"]
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "serviceAccount:${var.service_accounts["koperator-worker"]}"
}

resource "google_storage_bucket_iam_member" "publication_create" {
  for_each = local.publication_writers
  bucket   = var.publication_bucket
  role     = "roles/storage.objectCreator"
  member   = "serviceAccount:${var.service_accounts[each.key]}"
}

resource "google_storage_bucket_iam_member" "publication_read" {
  for_each = local.publication_writers
  bucket   = var.publication_bucket
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${var.service_accounts[each.key]}"
}

resource "google_storage_bucket_iam_member" "audit_create" {
  bucket = var.audit_bucket
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${var.service_accounts["koperator-audit"]}"
}

resource "google_storage_bucket_iam_member" "audit_read" {
  bucket = var.audit_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.service_accounts["koperator-audit"]}"
}

# Root and recovery keys intentionally have no persistent runtime signer.
# Ceremony administration is absent by default and, when explicitly enabled,
# is both resource-scoped and time-bounded.
resource "google_kms_key_ring_iam_member" "ceremony_admin" {
  count       = var.enable_ceremony_access ? 1 : 0
  key_ring_id = dirname(var.kms_keys["root"])
  role        = "roles/cloudkms.admin"
  member      = "serviceAccount:${var.service_accounts["koperator-ceremony"]}"
  condition {
    title       = "phase16-time-bounded-ceremony"
    description = "Dual-approved ceremony access expires automatically."
    expression  = "request.time < timestamp(\"${var.ceremony_access_expires_at}\")"
  }
}

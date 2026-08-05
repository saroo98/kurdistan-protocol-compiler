variable "project_id" { type = string }
variable "location" { type = string }
variable "key_ring" { type = string }
variable "roles" { type = set(string) }

resource "google_kms_key_ring" "authority" {
  project  = var.project_id
  location = var.location
  name     = var.key_ring
}

resource "google_kms_crypto_key" "authority" {
  for_each = var.roles
  name     = "kvpn-${each.value}"
  key_ring = google_kms_key_ring.authority.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm        = "EC_SIGN_P256_SHA256"
    protection_level = "HSM"
  }

  lifecycle { prevent_destroy = true }
}

output "key_names" { value = { for key, value in google_kms_crypto_key.authority : key => value.id } }

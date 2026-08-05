variable "project_id" { type = string }
variable "service_accounts" { type = set(string) }

resource "google_service_account" "service" {
  for_each     = var.service_accounts
  project      = var.project_id
  account_id   = each.value
  display_name = "Kurdistan VPN ${each.value}"
}

output "emails" { value = { for key, value in google_service_account.service : key => value.email } }

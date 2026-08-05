variable "project_ids" { type = set(string) }
variable "billing_account" { type = string }
variable "organization_id" { type = string }

resource "google_project" "project" {
  for_each        = var.project_ids
  project_id      = each.value
  name            = each.value
  billing_account = var.billing_account
  org_id          = var.organization_id
  deletion_policy = "PREVENT"
}

output "ids" { value = keys(google_project.project) }

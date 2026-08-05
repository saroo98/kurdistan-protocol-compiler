variable "project_id" { type = string }
variable "pool_id" { type = string }
variable "provider_id" { type = string }
variable "repository" { type = string }
variable "service_accounts" {
  type = map(string)
  validation {
    condition = (
      length(setsubtract(toset(keys(var.service_accounts)), toset(["phase16-production-plan", "phase16-production", "phase16-drill"]))) == 0 &&
      length(setsubtract(toset(["phase16-production-plan", "phase16-production", "phase16-drill"]), toset(keys(var.service_accounts)))) == 0
    )
    error_message = "The exact protected Phase 16 environments must have distinct service accounts."
  }
}

resource "google_iam_workload_identity_pool" "github" {
  project                   = var.project_id
  workload_identity_pool_id = var.pool_id
  display_name              = "Kurdistan VPN GitHub"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.provider_id
  display_name                       = "Kurdistan VPN GitHub Actions"
  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.ref"              = "assertion.ref"
    "attribute.environment"      = "assertion.environment"
    "attribute.job_workflow_ref" = "assertion.job_workflow_ref"
  }
  attribute_condition = <<-EOT
    assertion.repository == '${var.repository}' &&
    assertion.ref == 'refs/heads/main' &&
    ((assertion.environment == 'phase16-production-plan' && assertion.job_workflow_ref == '${var.repository}/.github/workflows/phase16-production-plan.yml@refs/heads/main') ||
     (assertion.environment == 'phase16-production' && assertion.job_workflow_ref == '${var.repository}/.github/workflows/phase16-production-apply.yml@refs/heads/main') ||
     (assertion.environment == 'phase16-drill' && assertion.job_workflow_ref == '${var.repository}/.github/workflows/phase16-drill.yml@refs/heads/main'))
  EOT
  oidc { issuer_uri = "https://token.actions.githubusercontent.com" }
}

resource "google_service_account_iam_member" "github" {
  for_each           = var.service_accounts
  service_account_id = each.value
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.environment/${each.key}"
}

output "provider_name" { value = google_iam_workload_identity_pool_provider.github.name }

variable "billing_account" {
  type = string
  validation {
    condition     = can(regex("^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$", var.billing_account))
    error_message = "Billing account must use the canonical 000000-000000-000000 form."
  }
}
variable "project_ids" { type = map(string) }
variable "currency_code" {
  type = string
  validation {
    condition     = can(regex("^[A-Z]{3}$", var.currency_code))
    error_message = "Budget currency must be an ISO-4217 code."
  }
}
variable "monthly_units" {
  type = number
  validation {
    condition     = var.monthly_units > 0 && floor(var.monthly_units) == var.monthly_units
    error_message = "Monthly budget units must be a positive integer."
  }
}
variable "notification_channels" {
  type = list(string)
  validation {
    condition     = length(var.notification_channels) >= 1 && length(var.notification_channels) <= 8
    error_message = "At least one and at most eight monitoring channels are required."
  }
}

data "google_project" "project" {
  for_each   = var.project_ids
  project_id = each.value
}

resource "google_billing_budget" "project" {
  for_each        = var.project_ids
  billing_account = var.billing_account
  display_name    = "Kurdistan VPN ${each.key} monthly budget"

  budget_filter {
    projects               = ["projects/${data.google_project.project[each.key].number}"]
    credit_types_treatment = "INCLUDE_ALL_CREDITS"
  }
  amount {
    specified_amount {
      currency_code = var.currency_code
      units         = tostring(var.monthly_units)
    }
  }
  threshold_rules { threshold_percent = 0.5 }
  threshold_rules { threshold_percent = 0.8 }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "FORECASTED_SPEND"
  }
  threshold_rules { threshold_percent = 1.0 }
  all_updates_rule {
    monitoring_notification_channels = var.notification_channels
    disable_default_iam_recipients   = true
  }
}

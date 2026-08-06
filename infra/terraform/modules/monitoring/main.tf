variable "project_id" { type = string }
variable "service_names" { type = set(string) }
variable "notification_channels" {
  type = list(string)
  validation {
    condition     = length(var.notification_channels) >= 1 && length(var.notification_channels) <= 8
    error_message = "Production alerting requires one to eight notification channels."
  }
}

resource "google_monitoring_alert_policy" "service_errors" {
  for_each              = var.service_names
  project               = var.project_id
  display_name          = "${each.value} error rate"
  combiner              = "OR"
  notification_channels = var.notification_channels
  conditions {
    display_name = "${each.value} server errors"
    condition_threshold {
      filter          = "resource.type = \"cloud_run_revision\" AND resource.labels.service_name = \"${each.value}\" AND metric.type = \"run.googleapis.com/request_count\" AND metric.labels.response_code_class = \"5xx\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
}

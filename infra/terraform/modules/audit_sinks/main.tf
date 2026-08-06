variable "source_project_ids" { type = map(string) }
variable "audit_bucket" { type = string }

resource "google_logging_project_sink" "audit" {
  for_each               = var.source_project_ids
  project                = each.value
  name                   = "kvpn-${each.key}-audit"
  destination            = "storage.googleapis.com/${var.audit_bucket}"
  unique_writer_identity = true
  filter                 = "log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/system_event\") OR log_id(\"cloudaudit.googleapis.com/policy\") OR log_id(\"cloudaudit.googleapis.com/access_transparency\")"
}

resource "google_storage_bucket_iam_member" "audit_writer" {
  for_each = google_logging_project_sink.audit
  bucket   = var.audit_bucket
  role     = "roles/storage.objectCreator"
  member   = each.value.writer_identity
}

output "writer_identities" {
  value = { for key, value in google_logging_project_sink.audit : key => value.writer_identity }
}

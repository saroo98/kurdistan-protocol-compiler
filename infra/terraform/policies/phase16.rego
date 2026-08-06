package phase16

# Phase 16 production plans are denied unless every security-sensitive
# resource remains private, immutable where required, and least privileged.

sensitive_types := {
	"google_cloud_run_v2_service",
	"google_cloud_run_v2_job",
	"google_kms_crypto_key",
	"google_kms_key_ring",
	"google_spanner_database",
	"google_spanner_instance",
	"google_storage_bucket",
	"google_iam_workload_identity_pool",
	"google_iam_workload_identity_pool_provider",
}

forbidden_roles := {
	"roles/owner",
	"roles/editor",
	"roles/iam.securityAdmin",
	"roles/iam.serviceAccountAdmin",
	"roles/resourcemanager.projectIamAdmin",
}

allowed_runtime_roles := {
	"roles/cloudkms.admin",
	"roles/cloudkms.cryptoKeyDecrypter",
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.signerVerifier",
	"roles/iam.workloadIdentityUser",
	"roles/secretmanager.secretAccessor",
	"roles/spanner.databaseUser",
	"roles/storage.objectCreator",
	"roles/storage.objectViewer",
}

has_action(change, expected) if {
	some action in change.change.actions
	action == expected
}

is_iam_member(change) if {
	regex.match("_iam_member$", change.type)
}

deny contains message if {
	some change in input.resource_changes
	change.type in sensitive_types
	has_action(change, "delete")
	message := sprintf("protected resource %s is deleted or replaced", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	is_iam_member(change)
	member := object.get(change.change.after, "member", "")
	member in {"allUsers", "allAuthenticatedUsers"}
	message := sprintf("IAM member %s grants public access", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_service_account_key"
	message := sprintf("persistent service-account key %s is forbidden", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	is_iam_member(change)
	role := object.get(change.change.after, "role", "")
	role in forbidden_roles
	message := sprintf("IAM member %s grants forbidden broad role %s", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	is_iam_member(change)
	role := object.get(change.change.after, "role", "")
	not role in allowed_runtime_roles
	message := sprintf("IAM member %s grants an unapproved role %s", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_storage_bucket"
	after := change.change.after
	object.get(after, "public_access_prevention", "") != "enforced"
	message := sprintf("bucket %s does not enforce public access prevention", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_storage_bucket"
	after := change.change.after
	object.get(after, "uniform_bucket_level_access", false) != true
	message := sprintf("bucket %s does not enforce uniform access", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_storage_bucket"
	object.get(change.change.after, "force_destroy", true) != false
	message := sprintf("bucket %s permits destructive teardown", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_cloud_run_v2_service"
	after := change.change.after
	object.get(after, "ingress", "") != "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
	message := sprintf("service %s is not restricted to internal load-balancer ingress", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_cloud_run_v2_service"
	after := change.change.after
	object.get(after, "default_uri_disabled", false) != true
	message := sprintf("service %s exposes its default URI", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type in {"google_cloud_run_v2_service", "google_cloud_run_v2_job"}
	object.get(change.change.after, "deletion_protection", false) != true
	message := sprintf("runtime %s lacks deletion protection", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type in {"google_cloud_run_v2_service", "google_cloud_run_v2_job"}
	after := change.change.after
	templates := object.get(after, "template", [])
	some template in templates
	containers := object.get(template, "containers", [])
	some container in containers
	image := object.get(container, "image", "")
	not regex.match("@sha256:[0-9a-f]{64}$", image)
	message := sprintf("runtime %s image is not digest pinned", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	after := change.change.after
	purpose := object.get(after, "purpose", "")
	not purpose in {"ASYMMETRIC_SIGN", "ENCRYPT_DECRYPT"}
	message := sprintf("key %s has an unapproved purpose", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	after := change.change.after
	object.get(after, "purpose", "") == "ASYMMETRIC_SIGN"
	some template in object.get(after, "version_template", [])
	object.get(template, "algorithm", "") != "EC_SIGN_P256_SHA256"
	message := sprintf("key %s uses an unapproved algorithm", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	after := change.change.after
	object.get(after, "purpose", "") == "ENCRYPT_DECRYPT"
	not contains(change.address, "staging")
	message := sprintf("symmetric key %s is outside the authority-source staging boundary", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	after := change.change.after
	object.get(after, "purpose", "") == "ENCRYPT_DECRYPT"
	some template in object.get(after, "version_template", [])
	object.get(template, "algorithm", "") != "GOOGLE_SYMMETRIC_ENCRYPTION"
	message := sprintf("staging key %s uses an unapproved algorithm", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_kms_crypto_key"
	after := change.change.after
	some template in object.get(after, "version_template", [])
	object.get(template, "protection_level", "") != "HSM"
	message := sprintf("key %s is not HSM protected", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_spanner_database"
	object.get(change.change.after, "deletion_protection", false) != true
	message := sprintf("Spanner resource %s lacks deletion protection", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_spanner_instance"
	object.get(change.change.after, "config", "") != "eur6"
	message := sprintf("Spanner instance %s is outside the approved eur6 boundary", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_storage_bucket"
	location := object.get(change.change.after, "location", "")
	not regex.match("^(EU|eu|europe-)", location)
	message := sprintf("bucket %s is outside the approved EU boundary", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_secret_manager_secret"
	replication := object.get(change.change.after, "replication", [])
	some item in replication
	count(object.get(item, "auto", [])) > 0
	message := sprintf("secret %s uses unrestricted automatic replication", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_billing_budget"
	rules := object.get(change.change.after, "all_updates_rule", [])
	count(rules) != 1
	message := sprintf("budget %s lacks an exact notification rule", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_billing_budget"
	some rule in object.get(change.change.after, "all_updates_rule", [])
	count(object.get(rule, "monitoring_notification_channels", [])) == 0
	message := sprintf("budget %s has no monitoring destination", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_logging_project_sink"
	object.get(change.change.after, "unique_writer_identity", false) != true
	message := sprintf("audit sink %s lacks an isolated writer identity", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_logging_project_sink"
	not startswith(object.get(change.change.after, "destination", ""), "storage.googleapis.com/")
	message := sprintf("audit sink %s does not target the immutable audit store", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_monitoring_alert_policy"
	count(object.get(change.change.after, "notification_channels", [])) == 0
	message := sprintf("alert policy %s has no notification destination", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_spanner_backup_schedule"
	object.get(change.change.after, "retention_duration", "") != "2592000s"
	message := sprintf("backup schedule %s has an unapproved retention", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_iam_workload_identity_pool_provider"
	condition := object.get(change.change.after, "attribute_condition", "")
	not contains(condition, "saroo98/kurdistan-protocol-compiler")
	message := sprintf("WIF provider %s is not repository bound", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_iam_workload_identity_pool_provider"
	condition := object.get(change.change.after, "attribute_condition", "")
	not contains(condition, "refs/heads/main")
	message := sprintf("WIF provider %s is not main-ref bound", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	change.type == "google_iam_workload_identity_pool_provider"
	condition := object.get(change.change.after, "attribute_condition", "")
	not contains(condition, "job_workflow_ref")
	message := sprintf("WIF provider %s is not workflow bound", [change.address])
}

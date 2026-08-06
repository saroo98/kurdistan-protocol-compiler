package phase16

test_empty_plan_is_allowed if {
	result := deny with input as {"resource_changes": []}
	count(result) == 0
}

test_public_iam_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_storage_bucket_iam_member.public",
		"type": "google_storage_bucket_iam_member",
		"change": {"actions": ["create"], "after": {
			"member": "allUsers",
			"role": "roles/storage.objectViewer",
		}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_protected_delete_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_spanner_database.authority",
		"type": "google_spanner_database",
		"change": {"actions": ["delete", "create"], "after": {"deletion_protection": true}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_unpinned_runtime_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_cloud_run_v2_service.api",
		"type": "google_cloud_run_v2_service",
		"change": {"actions": ["create"], "after": {
			"ingress": "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
			"default_uri_disabled": true,
			"deletion_protection": true,
			"template": [{"containers": [{"image": "registry.invalid/api:latest"}]}],
		}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_exact_runtime_member_is_allowed if {
	plan := {"resource_changes": [{
		"address": "google_spanner_database_iam_member.api",
		"type": "google_spanner_database_iam_member",
		"change": {"actions": ["create"], "after": {
			"member": "serviceAccount:api@example.invalid",
			"role": "roles/spanner.databaseUser",
		}},
	}]}
	result := deny with input as plan
	count(result) == 0
}

test_service_account_key_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_service_account_key.legacy",
		"type": "google_service_account_key",
		"change": {"actions": ["create"], "after": {}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_automatic_secret_replication_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_secret_manager_secret.runtime",
		"type": "google_secret_manager_secret",
		"change": {"actions": ["create"], "after": {"replication": [{"auto": [{}]}]}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_unrouted_budget_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_billing_budget.production",
		"type": "google_billing_budget",
		"change": {"actions": ["create"], "after": {"all_updates_rule": []}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_non_eu_spanner_is_denied if {
	plan := {"resource_changes": [{
		"address": "google_spanner_instance.authority",
		"type": "google_spanner_instance",
		"change": {"actions": ["create"], "after": {"config": "regional-us-central1"}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

test_hsm_staging_key_is_allowed if {
	plan := {"resource_changes": [{
		"address": "module.kms.google_kms_crypto_key.staging",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"purpose": "ENCRYPT_DECRYPT",
			"version_template": [{"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "HSM"}],
		}},
	}]}
	result := deny with input as plan
	count(result) == 0
}

test_unscoped_symmetric_key_is_denied if {
	plan := {"resource_changes": [{
		"address": "module.kms.google_kms_crypto_key.general",
		"type": "google_kms_crypto_key",
		"change": {"actions": ["create"], "after": {
			"purpose": "ENCRYPT_DECRYPT",
			"version_template": [{"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "HSM"}],
		}},
	}]}
	result := deny with input as plan
	count(result) == 1
}

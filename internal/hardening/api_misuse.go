// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

func APIMisuseCases() []string {
	return []string{
		"nil_profile_rejected_by_carrier",
		"empty_security_secret_rejected",
		"all_zero_security_secret_rejected",
		"unknown_carrier_family_rejected",
		"unknown_proxy_target_rejected",
		"invalid_runtime_config_rejected",
		"empty_session_id_rejected",
		"malformed_profile_json_rejected",
		"invalid_adapter_config_rejected",
		"invalid_adapter_flow_rejected",
		"adapter_capability_downgrade_rejected",
	}
}

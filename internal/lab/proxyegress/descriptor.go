// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func RequestDescriptorFor(s EgressLifecycleScenario) EgressRequestDescriptor {
	desc := EgressRequestDescriptor{
		RequestID:         "egress_req_" + s.ScenarioID,
		IngressRequestID:  "ingress_req_" + s.ScenarioID,
		StreamID:          "stream_" + s.ScenarioID,
		CandidateID:       "candidate_safe_" + s.ScenarioID,
		BundleID:          "bundle_safe_" + s.ScenarioID,
		ActivePathID:      "active_path_" + s.ScenarioID,
		TargetClass:       s.TargetClass,
		RequestClass:      "metadata_only_request",
		ResponseClass:     s.ExpectedResponse,
		BackpressureClass: backpressureBucket(s.TargetClass),
		ErrorPolicyClass:  "safe_error_bucket",
		ResetPolicyClass:  "safe_reset_bucket",
	}
	desc.DescriptorHash = HashValue(desc)
	return desc
}

func ValidateRequestDescriptor(desc EgressRequestDescriptor) error {
	if desc.RequestID == "" || desc.IngressRequestID == "" || desc.StreamID == "" {
		return safeError("invalid_request_descriptor")
	}
	if desc.CandidateID == "" || desc.BundleID == "" || desc.ActivePathID == "" {
		return safeError("missing_adaptive_binding")
	}
	if !IsSyntheticTargetClass(desc.TargetClass) {
		return safeError("target_not_synthetic")
	}
	if desc.PayloadLogged || desc.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(desc)
}

func ValidateTargetDescriptor(desc EgressTargetDescriptor) error {
	if desc.TargetID == "" || !IsSyntheticTargetClass(desc.TargetClass) {
		return safeError("invalid_target_descriptor")
	}
	if desc.PayloadLogged || desc.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(desc)
}

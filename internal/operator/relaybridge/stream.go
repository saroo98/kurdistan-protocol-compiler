// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func StreamFor(s RelayBridgeScenario, session RelayBridgeSession) RelayBridgeStream {
	stream := RelayBridgeStream{
		StreamID:         "bridge_stream_" + s.ScenarioID,
		BridgeID:         session.BridgeID,
		IngressRequestID: "ingress_req_" + s.ScenarioID,
		EgressRequestID:  "egress_req_" + s.ScenarioID,
		TargetID:         "target_" + s.ScenarioID,
		StreamClass:      s.IngressRequestClass,
		WindowClass:      "bounded_window_bucket",
		SchedulerClass:   "scheduler_policy_bucket",
		ResetPolicyClass: "safe_reset_bucket",
		ErrorPolicyClass: "safe_error_bucket",
	}
	stream.StreamHash = HashValue(stream)
	return stream
}

func ValidateStream(stream RelayBridgeStream) error {
	if stream.StreamID == "" || stream.BridgeID == "" || stream.IngressRequestID == "" || stream.EgressRequestID == "" || stream.TargetID == "" {
		return safeError("invalid_bridge_stream")
	}
	if stream.PayloadLogged || stream.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(stream)
}

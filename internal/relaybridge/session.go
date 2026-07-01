// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func SessionFor(s RelayBridgeScenario) RelayBridgeSession {
	state := BridgeStateOpen
	if s.ExpectedFinalBridgeState == BridgeStateFailed {
		state = BridgeStateFailed
	}
	session := RelayBridgeSession{
		BridgeID:          "bridge_" + s.ScenarioID,
		SessionID:         "bridge_session_" + s.ScenarioID,
		BundleID:          "bundle_safe_" + s.ScenarioID,
		CandidateID:       "candidate_safe_" + s.ScenarioID,
		ActivePathID:      "active_path_" + s.ScenarioID,
		RelayID:           "synthetic_relay_" + s.ScenarioID,
		SyntheticHostID:   "synthetic_host_" + s.ScenarioID,
		StreamPolicyClass: "profile_stream_policy",
		BackpressureClass: "bridge_pressure_bucket",
		IsolationClass:    "per_stream_isolated",
		CurrentState:      state,
	}
	session.SessionHash = HashValue(session)
	return session
}

func ValidateSession(session RelayBridgeSession) error {
	if session.BridgeID == "" || session.SessionID == "" || session.BundleID == "" || session.CandidateID == "" || session.ActivePathID == "" {
		return safeError("invalid_bridge_session")
	}
	if session.IsolationClass != "per_stream_isolated" {
		return safeError("bridge_stream_isolation_broken")
	}
	if session.PayloadLogged || session.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(session)
}

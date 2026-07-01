// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import "kurdistan/internal/proxyegress"

func DefaultScenarios() []RelayBridgeScenario {
	return []RelayBridgeScenario{
		{ScenarioID: "single_stream_echo", IngressRequestClass: "single_request", EgressTargetClass: proxyegress.EgressTargetEchoSynthetic, BridgeSessionClass: "single_stream", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "multi_stream_chunked", IngressRequestClass: "multi_stream", EgressTargetClass: proxyegress.EgressTargetChunkedResponse, BridgeSessionClass: "multi_stream", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 2, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "slow_target_backpressure", IngressRequestClass: "slow", EgressTargetClass: proxyegress.EgressTargetSlowResponse, BridgeSessionClass: "backpressure", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 1, ExpectedBackpressure: 2, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "large_response_window_pressure", IngressRequestClass: "large", EgressTargetClass: proxyegress.EgressTargetLargeObject, BridgeSessionClass: "window_pressure", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 1, ExpectedBackpressure: 3, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "reset_one_stream", IngressRequestClass: "reset", EgressTargetClass: proxyegress.EgressTargetResetMidstream, BridgeSessionClass: "reset_isolated", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateReset, ExpectedReset: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "error_one_stream", IngressRequestClass: "error", EgressTargetClass: proxyegress.EgressTargetErrorResponse, BridgeSessionClass: "error_isolated", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "bridge_session_failure", IngressRequestClass: "bridge_failure", EgressTargetClass: proxyegress.EgressTargetBlackholeSynthetic, BridgeSessionClass: "bridge_failure", AdaptiveBindingClass: "safe_primary", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "active_path_failed_before_mapping", IngressRequestClass: "failover_before_mapping", EgressTargetClass: proxyegress.EgressTargetFixedResponse, BridgeSessionClass: "remapped", AdaptiveBindingClass: "failed_health_blocked", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "active_path_failover_midstream", IngressRequestClass: "failover_midstream", EgressTargetClass: proxyegress.EgressTargetSlowResponse, BridgeSessionClass: "failover_midstream", AdaptiveBindingClass: "failover_summary", ExpectedFinalBridgeState: BridgeStateClosed, ExpectedCompleted: 1, ExpectedBackpressure: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "candidate_high_risk_blocked", IngressRequestClass: "high_risk", EgressTargetClass: proxyegress.EgressTargetFixedResponse, BridgeSessionClass: "blocked", AdaptiveBindingClass: "high_risk_blocked", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "candidate_experimental_blocked", IngressRequestClass: "experimental", EgressTargetClass: proxyegress.EgressTargetFixedResponse, BridgeSessionClass: "blocked", AdaptiveBindingClass: "experimental_blocked", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "all_alternates_failed", IngressRequestClass: "all_failed", EgressTargetClass: proxyegress.EgressTargetBlackholeSynthetic, BridgeSessionClass: "all_alternates_failed", AdaptiveBindingClass: "no_safe_alternate", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, ExpectedTraceHygiene: "passed"},
		{ScenarioID: "control_fifo_only_scheduler", EgressTargetClass: proxyegress.EgressTargetControlCollapsed, BridgeSessionClass: "control", AdaptiveBindingClass: "control", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, Control: true, ExpectedTraceHygiene: "failed"},
		{ScenarioID: "control_no_stream_isolation", EgressTargetClass: proxyegress.EgressTargetControlCollapsed, BridgeSessionClass: "control", AdaptiveBindingClass: "control", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, Control: true, ExpectedTraceHygiene: "failed"},
		{ScenarioID: "control_all_targets_same_shape", EgressTargetClass: proxyegress.EgressTargetControlCollapsed, BridgeSessionClass: "control", AdaptiveBindingClass: "control", ExpectedFinalBridgeState: BridgeStateFailed, ExpectedFailed: 1, Control: true, ExpectedTraceHygiene: "failed"},
	}
}

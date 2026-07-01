// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

func DefaultScenarios() []PipelineScenario {
	return []PipelineScenario{
		scenario("single_flow_echo", ScenarioSingleFlowEcho, "connect_like_small", "echo_synthetic", "single_bridge_stream", "runtime_single_stream", "stream_carrier", StateCompleted, 1, 1, 0, 0, 0, false),
		scenario("many_small_requests", ScenarioManySmallRequests, "many_small", "fixed_response", "multi_bridge_stream", "runtime_multi_stream", "message_carrier", StateCompleted, 6, 6, 0, 0, 0, false),
		scenario("large_response_backpressure", ScenarioLargeBackpressure, "large_request", "large_object", "pressure_bridge", "runtime_backpressure", "chunked_carrier", StateCompleted, 2, 2, 5, 0, 0, false),
		scenario("slow_chunked_response", ScenarioSlowChunkedResponse, "slow_request", "chunked_response", "draining_bridge", "runtime_drip", "batch_carrier", StateDraining, 3, 3, 3, 0, 0, false),
		scenario("reset_isolation", ScenarioResetIsolation, "mixed_reset", "reset_midstream", "reset_isolated_bridge", "runtime_reset_isolated", "stream_carrier", StateReset, 4, 4, 1, 0, 1, false),
		scenario("target_error_isolation", ScenarioTargetErrorIsolation, "mixed_error", "error_response", "error_isolated_bridge", "runtime_error_isolated", "message_carrier", StateFailed, 4, 4, 1, 1, 0, false),
		scenario("bridge_backpressure", ScenarioBridgeBackpressure, "pressure_source", "slow_response", "bridge_pressure_chain", "runtime_pressure_chain", "long_poll_style_carrier", StateCompleted, 5, 5, 7, 0, 0, false),
		scenario("path_failover", ScenarioPathFailover, "adaptive_source", "fixed_response", "failover_bridge", "runtime_failover", "interactive_carrier", StateCompleted, 3, 3, 2, 0, 0, false),
		scenario("descriptor_rejection", ScenarioDescriptorRejection, "malformed_descriptor", "control_rejected", "rejected_bridge", "runtime_rejected", "control_carrier", StateRejected, 1, 0, 0, 1, 0, false),
		scenario("mixed_synthetic_targets", ScenarioMixedSyntheticTargets, "mixed_local", "mixed_synthetic", "mixed_bridge", "runtime_mixed", "mixed_carrier", StateCompleted, 8, 8, 4, 1, 1, false),
		scenario("collapsed_control", ScenarioCollapsedControl, "collapsed", "control_collapsed", "collapsed_bridge", "runtime_collapsed", "control_carrier", StateFailed, 4, 4, 0, 4, 0, true),
		scenario("leak_control", ScenarioLeakControl, "leak_control", "control_rejected", "quarantined_bridge", "runtime_quarantine", "control_carrier", StateRejected, 1, 0, 0, 1, 0, true),
	}
}

func scenario(id string, kind ScenarioKind, ingress, egress, bridge, runtimeClass, carrier string, final PipelineState, flows, streams, pressure, errors, resets int, control bool) PipelineScenario {
	return PipelineScenario{
		ScenarioID:             id,
		Kind:                   kind,
		IngressClass:           ingress,
		EgressClass:            egress,
		BridgeClass:            bridge,
		RuntimeClass:           runtimeClass,
		CarrierClass:           carrier,
		ExpectedFinalState:     final,
		ExpectedFlows:          flows,
		ExpectedRuntimeStreams: streams,
		ExpectedBackpressure:   pressure,
		ExpectedErrors:         errors,
		ExpectedResets:         resets,
		Control:                control,
	}
}

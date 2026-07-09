// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// LOOM: engine-helper -- cross-package enum/descriptor lists consumed only by
// renderGoFiles to fill generated-code template placeholders. Extracted from
// generator.go (Stage 4) to isolate the code generator's fan-out into the
// model/contract packages.
package codegen

import (
	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
	"kurdistan/internal/contracts/carrier/httpslikecarrier"
	"kurdistan/internal/contracts/lab/labegress"
	"kurdistan/internal/contracts/lab/localpipeline"
	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/contracts/lab/loopbackrelay"
	"kurdistan/internal/contracts/readiness/measurementreview"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/contracts/readiness/productionreadiness"
	"kurdistan/internal/proxyegress"
	"kurdistan/internal/operator/relaybridge"
	"kurdistan/internal/transportbundle"
)

func localProxyIngressAdversarialDescriptorClasses(cases []localproxyingressadversary.DescriptorAbuseCase) []string {
	classes := make([]string, 0, len(cases))
	for _, tc := range cases {
		classes = append(classes, tc.InputClass)
	}
	return classes
}

func adaptivePathCandidateFamilies() []string {
	out := []string{}
	for _, desc := range adaptivepath.FamilyDescriptors() {
		out = append(out, string(desc.Family))
	}
	return out
}

func adaptivePathConditionClasses() []string {
	out := []string{}
	for _, condition := range adaptivepath.DefaultConditions() {
		out = append(out, condition.ConditionClass)
	}
	return out
}

func adaptivePathObservationKinds() []string {
	return []string{
		string(adaptivepath.ObservationHandshakeOK),
		string(adaptivepath.ObservationHandshakeFailed),
		string(adaptivepath.ObservationFirstUsefulByteOK),
		string(adaptivepath.ObservationStallAfterHandshake),
		string(adaptivepath.ObservationStallAfterData),
		string(adaptivepath.ObservationResetLikeFailure),
		string(adaptivepath.ObservationBlackholeLikeFailure),
		string(adaptivepath.ObservationPoisoningLikeSignal),
		string(adaptivepath.ObservationTruncationLikeSignal),
		string(adaptivepath.ObservationRelayBurnRisk),
		string(adaptivepath.ObservationShortSuccess),
		string(adaptivepath.ObservationShortFailure),
	}
}

func adaptivePathFreshnessClasses() []string {
	return []string{adaptivepath.FreshSeconds, adaptivepath.FreshShort, adaptivepath.StaleShort, adaptivepath.StaleMedium, adaptivepath.Expired, adaptivepath.FreshUnknown}
}

func adaptivePathTTLClasses() []string {
	return []string{adaptivepath.TTLSeconds, adaptivepath.TTLOneMinute, adaptivepath.TTLFiveMinutes, adaptivepath.TTLShortSession, adaptivepath.TTLExpired}
}

func adaptivePathUncertaintyBuckets() []string {
	return []string{adaptivepath.LowUncertainty, adaptivepath.MediumUncertainty, adaptivepath.HighUncertainty, adaptivepath.UnknownUncertainty}
}

func adaptivePathViabilityStates() []string {
	return []string{
		string(adaptivepath.CandidateUnknown),
		string(adaptivepath.CandidateLikelyUsable),
		string(adaptivepath.CandidateDegraded),
		string(adaptivepath.CandidateUnstable),
		string(adaptivepath.CandidateBlocked),
		string(adaptivepath.CandidateBurned),
		string(adaptivepath.CandidateQuarantined),
		string(adaptivepath.CandidateRejected),
	}
}

func adaptivePathHighRiskFamilies() []string {
	out := []string{}
	for _, desc := range adaptivepath.FamilyDescriptors() {
		if desc.HighRisk {
			out = append(out, string(desc.Family))
		}
	}
	return out
}

func adaptivePathGatedFamilies() []string {
	out := []string{}
	for _, desc := range adaptivepath.FamilyDescriptors() {
		if desc.Gated {
			out = append(out, string(desc.Family))
		}
	}
	return out
}

func transportBundleModeStrings() []string {
	out := make([]string, 0, len(transportbundle.RequiredBundleModes()))
	for _, mode := range transportbundle.RequiredBundleModes() {
		out = append(out, string(mode))
	}
	return out
}

func transportBundleCandidateRoles() []string {
	return []string{
		string(transportbundle.CandidateRolePrimaryEligible),
		string(transportbundle.CandidateRoleFallback),
		string(transportbundle.CandidateRoleSurvival),
		string(transportbundle.CandidateRoleExperimental),
		string(transportbundle.CandidateRoleHighRiskGated),
		string(transportbundle.CandidateRoleControl),
		string(transportbundle.CandidateRoleRejected),
	}
}

func pathRaceModeStrings() []string {
	return []string{
		string(pathrace.RaceModeFirstUsable),
		string(pathrace.RaceModeVerifiedUsable),
		string(pathrace.RaceModeConservative),
		string(pathrace.RaceModeSurvivalFallback),
		string(pathrace.RaceModeExperimentalGated),
		string(pathrace.RaceModeControlCollapsed),
	}
}

func pathRaceEventKindStrings() []string {
	return []string{
		string(pathrace.RaceEventCandidateStarted),
		string(pathrace.RaceEventHandshakeObserved),
		string(pathrace.RaceEventFirstUsefulByte),
		string(pathrace.RaceEventCandidateStalled),
		string(pathrace.RaceEventCandidateFailed),
		string(pathrace.RaceEventCandidateVerified),
		string(pathrace.RaceEventCandidateRejected),
		string(pathrace.RaceEventRaceCompleted),
	}
}

func pathRaceStateStrings() []string {
	return []string{
		string(pathrace.RaceStatePending),
		string(pathrace.RaceStateStarted),
		string(pathrace.RaceStateVerifying),
		string(pathrace.RaceStateVerified),
		string(pathrace.RaceStateStalled),
		string(pathrace.RaceStateFailed),
		string(pathrace.RaceStateRejected),
		string(pathrace.RaceStateGated),
	}
}

func carrierReviewFamilies() []string {
	out := []string{}
	for _, desc := range carrierreview.DefaultDescriptors() {
		out = append(out, desc.Family)
	}
	return out
}

func carrierReviewReadinessClasses() []string {
	return []string{
		carrierreview.ReadinessReadySynthetic,
		carrierreview.ReadinessGatedSurvival,
		carrierreview.ReadinessExperimentalGated,
		carrierreview.ReadinessManualReviewOnly,
		carrierreview.ReadinessBlockedByRisk,
	}
}

func measurementReviewObservationFields() []string {
	out := []string{}
	for _, field := range measurementreview.DefaultObservationFields() {
		out = append(out, field.Name)
	}
	return out
}

func proxyEgressTargetClasses() []string {
	return []string{
		string(proxyegress.EgressTargetEchoSynthetic),
		string(proxyegress.EgressTargetFixedResponse),
		string(proxyegress.EgressTargetChunkedResponse),
		string(proxyegress.EgressTargetSlowResponse),
		string(proxyegress.EgressTargetLargeObject),
		string(proxyegress.EgressTargetResetMidstream),
		string(proxyegress.EgressTargetErrorResponse),
		string(proxyegress.EgressTargetDripResponse),
		string(proxyegress.EgressTargetBlackholeSynthetic),
		string(proxyegress.EgressTargetControlCollapsed),
	}
}

func proxyEgressLifecycleStates() []string {
	return []string{
		string(proxyegress.EgressStateCreated),
		string(proxyegress.EgressStateMapped),
		string(proxyegress.EgressStateTargetBound),
		string(proxyegress.EgressStateStreaming),
		string(proxyegress.EgressStateBackpressured),
		string(proxyegress.EgressStateCompleted),
		string(proxyegress.EgressStateReset),
		string(proxyegress.EgressStateFailed),
		string(proxyegress.EgressStateQuarantined),
	}
}

func relayBridgeStates() []string {
	return []string{
		string(relaybridge.BridgeStateCreated),
		string(relaybridge.BridgeStateBound),
		string(relaybridge.BridgeStateOpen),
		string(relaybridge.BridgeStateDraining),
		string(relaybridge.BridgeStateBackpressured),
		string(relaybridge.BridgeStateFailed),
		string(relaybridge.BridgeStateReset),
		string(relaybridge.BridgeStateClosed),
	}
}

func relayBridgeScenarioClasses() []string {
	return []string{
		"single_stream",
		"multi_stream",
		"slow_large_backpressure",
		"reset_error_isolation",
		"path_failure_failover",
		"gated_control",
	}
}

func localPipelineScenarioKinds() []string {
	return []string{
		string(localpipeline.ScenarioSingleFlowEcho),
		string(localpipeline.ScenarioManySmallRequests),
		string(localpipeline.ScenarioLargeBackpressure),
		string(localpipeline.ScenarioSlowChunkedResponse),
		string(localpipeline.ScenarioResetIsolation),
		string(localpipeline.ScenarioTargetErrorIsolation),
		string(localpipeline.ScenarioBridgeBackpressure),
		string(localpipeline.ScenarioPathFailover),
		string(localpipeline.ScenarioDescriptorRejection),
		string(localpipeline.ScenarioMixedSyntheticTargets),
	}
}

func localPipelineStates() []string {
	return []string{
		string(localpipeline.StateCreated),
		string(localpipeline.StateIngressBound),
		string(localpipeline.StateEgressBound),
		string(localpipeline.StateBridgeOpen),
		string(localpipeline.StateRunning),
		string(localpipeline.StateDraining),
		string(localpipeline.StateCompleted),
		string(localpipeline.StateReset),
		string(localpipeline.StateFailed),
		string(localpipeline.StateRejected),
	}
}

func productionReadinessContracts() []string {
	return []string{"M36", "M37", "M38", "M39"}
}

func productionReadinessBoundaries() []string {
	return []string{
		productionreadiness.BoundaryStrictLocalOnly,
		productionreadiness.BoundaryNoRealNetworkIO,
		productionreadiness.BoundaryNoDeployment,
		productionreadiness.BoundaryNoPayloadLogging,
		productionreadiness.BoundaryNoProductionKeyXchg,
	}
}

func concreteLocalAdapterScenarios() []string {
	return []string{
		concretelocaladapter.ScenarioSingleFlowEcho,
		concretelocaladapter.ScenarioManySmallFlows,
		concretelocaladapter.ScenarioLargeBackpressure,
		concretelocaladapter.ScenarioResetIsolation,
		concretelocaladapter.ScenarioTargetErrorMapping,
		concretelocaladapter.ScenarioTargetResetMapping,
		concretelocaladapter.ScenarioLoopbackBindPolicy,
		concretelocaladapter.ScenarioMalformedLocalEvent,
	}
}

func localProtocolAdapterFamilies() []string {
	return []string{
		localprotocoladapter.ProtocolFamilyConnectLikeMetadata,
		localprotocoladapter.ProtocolFamilySocks5LikeMetadata,
	}
}

func localProtocolAdapterScenarios() []string {
	return []string{
		localprotocoladapter.ScenarioConnectSynthetic,
		localprotocoladapter.ScenarioSocks5Synthetic,
		localprotocoladapter.ScenarioSocks5AuthRejected,
		localprotocoladapter.ScenarioConnectSmuggling,
		localprotocoladapter.ScenarioPipelineMapping,
		localprotocoladapter.ScenarioConcreteAdapterMapping,
	}
}

func localProtocolAdapterParserStates() []string {
	return []string{
		localprotocoladapter.ParserStateCreated,
		localprotocoladapter.ParserStateHeaderParsed,
		localprotocoladapter.ParserStateTargetRedacted,
		localprotocoladapter.ParserStateMapped,
		localprotocoladapter.ParserStateClosed,
		localprotocoladapter.ParserStateRejected,
	}
}

func loopbackRelayScenarios() []string {
	return []string{
		loopbackrelay.ScenarioHandshake,
		loopbackrelay.ScenarioFrameExchange,
		loopbackrelay.ScenarioStreamBackpressure,
		loopbackrelay.ScenarioResetIsolation,
		loopbackrelay.ScenarioMalformedFrame,
		loopbackrelay.ScenarioQueuePressure,
		loopbackrelay.ScenarioGeneratedParity,
		loopbackrelay.ScenarioTraceHygiene,
	}
}

func labEgressScenarios() []string {
	return []string{
		labegress.ScenarioAllowlistValidation,
		labegress.ScenarioFixtureExchange,
		labegress.ScenarioSlowBackpressure,
		labegress.ScenarioResetIsolation,
		labegress.ScenarioErrorIsolation,
		labegress.ScenarioHalfClose,
		labegress.ScenarioQueuePressure,
		labegress.ScenarioGeneratedParity,
	}
}

func labEgressTargetClasses() []string {
	return []string{
		labegress.TargetClassEchoSynthetic,
		labegress.TargetClassFixedSynthetic,
		labegress.TargetClassSlowSynthetic,
		labegress.TargetClassResetSynthetic,
		labegress.TargetClassErrorSynthetic,
		labegress.TargetClassLargeSynthetic,
	}
}

func carrierReadinessFutureMilestones() []string {
	return []string{"M41", "M42", "M43"}
}

func carrierReadinessBoundaryNames() []string {
	return []string{
		"no external targets",
		"no deployment behavior",
		"no payload logging",
		"no production key exchange",
		"no live carrier implementation",
	}
}

func httpsCarrierReviewRequestShapeNames() []string {
	return []string{"request_marker_compact", "request_marker_split", "request_marker_bucketed", "request_marker_state_derived"}
}

func httpsCarrierReviewResponseShapeNames() []string {
	return []string{"response_marker_compact", "response_marker_chunked", "response_marker_error_bucket", "response_marker_state_derived"}
}

func httpsCarrierReviewBlockedBehaviorNames() []string {
	return []string{
		"real_tls_behavior",
		"real_https_client_behavior",
		"real_sni_routing",
		"real_host_header_routing",
		"real_domain_dependency",
		"real_cdn_provider_integration",
		"public_network_egress",
		"arbitrary_target_proxying",
		"payload_logging",
		"packet_capture",
	}
}

func httpsCarrierReviewM42Criteria() []string {
	return []string{
		"bounded_request_shape_markers",
		"bounded_response_shape_markers",
		"stream_mapping",
		"backpressure_mapping",
		"local_integration",
		"measurement_review_enforcement",
		"real_tls_blocked",
		"public_network_blocked",
		"trace_hygiene",
		"generated_parity",
	}
}

func httpsLikeCarrierBlockedScopes() []string {
	return []string{
		"real_tls",
		"real_https_client",
		"sni_routing",
		"host_header_routing",
		"domain_dependency",
		"cdn_provider_integration",
		"public_network_egress",
		"arbitrary_destination_proxying",
		"payload_logging",
		"packet_capture",
		"measurement_upload",
	}
}

func httpsLikeCarrierRequestShapeClasses() []string {
	return []string{
		"short_request_marker",
		"chunked_request_marker",
		"large_object_request_marker",
		"reset_error_request_marker",
	}
}

func httpsLikeCarrierResponseShapeClasses() []string {
	return []string{
		"fixed_response_marker",
		"chunked_response_marker",
		"delayed_large_response_marker",
		"reset_error_response_marker",
	}
}

func httpsLikeCarrierSessionStates() []string {
	return []string{
		httpslikecarrier.SessionConfigured,
		httpslikecarrier.SessionSelected,
		httpslikecarrier.SessionOpening,
		httpslikecarrier.SessionActive,
		httpslikecarrier.SessionBackpressured,
		httpslikecarrier.SessionDraining,
		httpslikecarrier.SessionReset,
		httpslikecarrier.SessionClosed,
		httpslikecarrier.SessionFailed,
		httpslikecarrier.SessionRejected,
	}
}

func httpsLikeCarrierStreamStates() []string {
	return []string{
		httpslikecarrier.StreamOpening,
		httpslikecarrier.StreamActive,
		httpslikecarrier.StreamBackpressure,
		httpslikecarrier.StreamDraining,
		httpslikecarrier.StreamReset,
		httpslikecarrier.StreamClosed,
		httpslikecarrier.StreamError,
	}
}

func httpsLikeCarrierMisuseControls() []string {
	return []string{
		"httpslikecarrier_real_tls_allowed",
		"httpslikecarrier_sni_allowed",
		"httpslikecarrier_host_header_allowed",
		"httpslikecarrier_domain_dependency_allowed",
		"httpslikecarrier_cdn_provider_allowed",
		"httpslikecarrier_public_network_allowed",
		"httpslikecarrier_arbitrary_egress_allowed",
		"httpslikecarrier_payload_forwarding_allowed",
		"httpslikecarrier_payload_logging_allowed",
		"httpslikecarrier_packet_capture_allowed",
		"httpslikecarrier_measurement_upload_allowed",
		"httpslikecarrier_fixed_shape",
		"httpslikecarrier_padding_only_variation",
		"httpslikecarrier_profile_insensitive",
		"httpslikecarrier_backpressure_ignored",
		"httpslikecarrier_reset_swallowed",
		"httpslikecarrier_cross_stream_leak",
		"httpslikecarrier_pathhealth_bypass",
		"httpslikecarrier_measurementreview_bypass",
		"httpslikecarrier_carrierreview_bypass",
		"httpslikecarrier_generated_backend_drift",
		"httpslikecarrier_payload_leak",
		"httpslikecarrier_secret_leak",
	}
}

func httpsCarrierAdversaryScenarios() []string {
	return []string{
		httpscarrieradversary.ScenarioAcceptedDiversity,
		httpscarrieradversary.ScenarioFixedShapeControl,
		httpscarrieradversary.ScenarioPaddingOnlyControl,
		httpscarrieradversary.ScenarioProfileInsensitive,
		httpscarrieradversary.ScenarioUnsafeFallback,
		httpscarrieradversary.ScenarioTraceLeakControl,
		httpscarrieradversary.ScenarioReplayControl,
		httpscarrieradversary.ScenarioStreamIsolation,
		httpscarrieradversary.ScenarioBackpressureControl,
		httpscarrieradversary.ScenarioResetErrorControl,
		httpscarrieradversary.ScenarioIntegrationBypass,
		httpscarrieradversary.ScenarioGeneratedParity,
		httpscarrieradversary.ScenarioPublicClaimSafety,
	}
}

func httpsCarrierAdversaryCollapseControls() []string {
	return []string{
		"httpscarrieradversary_fixed_shape",
		"httpscarrieradversary_fixed_request_sequence",
		"httpscarrieradversary_fixed_response_sequence",
		"httpscarrieradversary_padding_only_variation",
		"httpscarrieradversary_profile_insensitive",
		"httpscarrieradversary_generated_profile_ignored",
	}
}

func httpsCarrierAdversaryUnsafeFallbackControls() []string {
	return []string{
		"httpscarrieradversary_public_network_fallback",
		"httpscarrieradversary_arbitrary_egress_fallback",
		"httpscarrieradversary_real_tls_fallback",
		"httpscarrieradversary_sni_fallback",
		"httpscarrieradversary_host_header_fallback",
		"httpscarrieradversary_domain_fallback",
		"httpscarrieradversary_payload_forwarding_fallback",
		"httpscarrieradversary_measurement_upload_fallback",
	}
}

func httpsCarrierAdversaryReplayControls() []string {
	return []string{
		"httpscarrieradversary_replay_marker_accepted",
		"duplicate_carrier_marker",
		"replayed_session_marker",
		"replayed_stream_marker",
		"stale_reset_marker",
		"duplicated_backpressure_marker",
	}
}

func httpsCarrierAdversaryStreamControls() []string {
	return []string{
		"httpscarrieradversary_cross_stream_reset",
		"httpscarrieradversary_backpressure_ignored",
		"httpscarrieradversary_reset_swallowed",
		"httpscarrieradversary_pipeline_bypass",
	}
}

func httpsCarrierAdversaryForbiddenControls() []string {
	return append(append(append([]string{},
		httpsCarrierAdversaryCollapseControls()...),
		httpsCarrierAdversaryUnsafeFallbackControls()...),
		[]string{
			"httpscarrieradversary_raw_fixture_leak",
			"httpscarrieradversary_payload_leak",
			"httpscarrieradversary_secret_leak",
			"httpscarrieradversary_replay_marker_accepted",
			"httpscarrieradversary_cross_stream_reset",
			"httpscarrieradversary_backpressure_ignored",
			"httpscarrieradversary_reset_swallowed",
			"httpscarrieradversary_pipeline_bypass",
			"httpscarrieradversary_generated_backend_drift",
			"httpscarrieradversary_public_claim_overstatement",
		}...)
}

func constrainedCarrierReviewBlockedBehaviors() []string {
	return []string{
		"public_resolver_use",
		"real_query_default",
		"resolver_dialing",
		"tunneling_runtime",
		"exact_query_logging",
		"resolver_address_logging",
		"wildcard_resolver_configuration",
		"domain_dependence",
		"public_network_egress",
		"arbitrary_proxying",
		"payload_forwarding",
		"packet_capture",
		"payload_logging",
		"measurement_upload",
	}
}

func constrainedCarrierReviewResolverBuckets() []string {
	return []string{"loopback_harness", "fixture_resolver", "failure_fixture", "poison_fixture"}
}

func constrainedCarrierReviewQueryShapeClasses() []string {
	return []string{
		"small_query_marker",
		"chunked_query_marker",
		"repeated_query_marker",
		"delayed_query_marker",
		"truncated_query_marker",
		"retry_query_marker",
		"failure_query_marker",
		"control_exact_query_leak",
		"control_domain_leak",
		"control_resolver_leak",
	}
}

func constrainedCarrierReviewResponseShapeClasses() []string {
	return []string{
		"small_response_marker",
		"truncated_response_marker",
		"delayed_response_marker",
		"failure_response_marker",
		"retry_response_marker",
		"poisoning_failure_marker",
		"reset_response_marker",
		"control_payload_leak",
		"control_resolver_leak",
	}
}

func constrainedCarrierReviewM45Requirements() []string {
	return []string{"quick_full_verify_compare", "generated_parity", "trace_hygiene", "fixture_drift", "mutation_detection"}
}

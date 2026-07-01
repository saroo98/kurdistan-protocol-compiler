// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package mutant

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
	"kurdistan/internal/wiregen"
)

const (
	ModeFixedFirstContact                           = "fixed_first_contact"
	ModeFixedFrameGrammar                           = "fixed_frame_grammar"
	ModeCosmeticSymbolsOnly                         = "cosmetic_symbols_only"
	ModeFixedScheduler                              = "fixed_scheduler"
	ModeFixedInvalidInput                           = "fixed_invalid_input"
	ModePaddingNoiseOnly                            = "padding_noise_only"
	ModeFixedStreamIDStrategy                       = "fixed_stream_id_strategy"
	ModeFixedWindowUpdatePolicy                     = "fixed_window_update_policy"
	ModeFIFOSchedulerOnly                           = "fifo_scheduler_only"
	ModeFixedResetClosePolicy                       = "fixed_reset_close_policy"
	ModeNoBackpressure                              = "no_backpressure"
	ModePaddingOnlyStreamDiversity                  = "padding_only_stream_diversity"
	ModeFixedTargetDescriptorEncoding               = "fixed_target_descriptor_encoding"
	ModeFixedTargetOpenSequence                     = "fixed_target_open_sequence"
	ModeFixedTargetErrorPolicy                      = "fixed_target_error_policy"
	ModeFixedTargetClosePolicy                      = "fixed_target_close_policy"
	ModeFixedResponseChunking                       = "fixed_response_chunking"
	ModeNoTargetBackpressure                        = "no_target_backpressure"
	ModePaddingOnlyProxyDiversity                   = "padding_only_proxy_diversity"
	ModeFixedCarrierFamily                          = "fixed_carrier_family"
	ModeFixedEnvelopeEncoding                       = "fixed_envelope_encoding"
	ModeFixedFlushPolicy                            = "fixed_flush_policy"
	ModeFixedBatchPolicy                            = "fixed_batch_policy"
	ModeFixedChunkingPolicy                         = "fixed_chunking_policy"
	ModeNoCarrierBackpressure                       = "no_carrier_backpressure"
	ModeNoReorderRecovery                           = "no_reorder_recovery"
	ModePaddingOnlyCarrierDiversity                 = "padding_only_carrier_diversity"
	ModeNoTranscriptBinding                         = "no_transcript_binding"
	ModeReusedNonce                                 = "reused_nonce"
	ModeAcceptsReplay                               = "accepts_replay"
	ModeAcceptsDowngrade                            = "accepts_downgrade"
	ModeCapabilityMismatchAccepted                  = "capability_mismatch_accepted"
	ModeProfileMismatchAccepted                     = "profile_mismatch_accepted"
	ModeUnsafeConfigAllowed                         = "unsafe_config_allowed"
	ModeSecretTraceLeak                             = "secret_trace_leak"
	ModeRuntimeAcceptsCapabilityDowngrade           = "runtime_accepts_capability_downgrade"
	ModeRuntimeAcceptsProfileMismatch               = "runtime_accepts_profile_mismatch"
	ModeRuntimeAcceptsReplay                        = "runtime_accepts_replay"
	ModeRuntimeIgnoresBackpressure                  = "runtime_ignores_backpressure"
	ModeRuntimeLeaksSecretTrace                     = "runtime_leaks_secret_trace"
	ModeRuntimeLeaksPayloadTrace                    = "runtime_leaks_payload_trace"
	ModeRuntimeNoStateValidation                    = "runtime_no_state_validation"
	ModeRuntimePaddingOnlyDiversity                 = "runtime_padding_only_diversity"
	ModePanicOnMalformedFrame                       = "panic_on_malformed_frame"
	ModeUnboundedTraceEvents                        = "unbounded_trace_events"
	ModeTraceSecretLeakHardening                    = "trace_secret_leak_hardening"
	ModeIgnoresMaxStreams                           = "ignores_max_streams"
	ModeIgnoresMaxCarrierQueue                      = "ignores_max_carrier_queue"
	ModeAcceptsInvalidProfileHash                   = "accepts_invalid_profile_hash"
	ModeGeneratedParityDrift                        = "generated_parity_drift"
	ModeAPIMisusePanic                              = "api_misuse_panic"
	ModeAdapterAcceptsInvalidFlow                   = "adapter_accepts_invalid_flow"
	ModeAdapterIgnoresBackpressure                  = "adapter_ignores_backpressure"
	ModeAdapterLeaksPayloadTrace                    = "adapter_leaks_payload_trace"
	ModeAdapterLeaksSecretTrace                     = "adapter_leaks_secret_trace"
	ModeAdapterAcceptsCapabilityDowngrade           = "adapter_accepts_capability_downgrade"
	ModeAdapterIgnoresMaxFlows                      = "adapter_ignores_max_flows"
	ModeAdapterWrongResetMapping                    = "adapter_wrong_reset_mapping"
	ModeAdapterPaddingOnlyDiversity                 = "adapter_padding_only_diversity"
	ModeLocalAdapterIgnoresSourceBackpressure       = "local_adapter_ignores_source_backpressure"
	ModeLocalAdapterAcceptsPostCloseWrite           = "local_adapter_accepts_post_close_write"
	ModeLocalAdapterDropsFinalChunk                 = "local_adapter_drops_final_chunk"
	ModeLocalAdapterDuplicatesChunk                 = "local_adapter_duplicates_chunk"
	ModeLocalAdapterWrongFlowStreamMapping          = "local_adapter_wrong_flow_stream_mapping"
	ModeLocalAdapterPayloadTraceLeak                = "local_adapter_payload_trace_leak"
	ModeLocalAdapterSecretTraceLeak                 = "local_adapter_secret_trace_leak"
	ModeLocalAdapterPaddingOnlyDiversity            = "local_adapter_padding_only_diversity"
	ModeByteTransportAcceptsMalformedFrame          = "byte_transport_accepts_malformed_frame"
	ModeByteTransportIgnoresMaxFrameSize            = "byte_transport_ignores_max_frame_size"
	ModeByteTransportIgnoresBackpressure            = "byte_transport_ignores_backpressure"
	ModeByteTransportReusesSequence                 = "byte_transport_reuses_sequence"
	ModeByteTransportAcceptsCorruption              = "byte_transport_accepts_corruption"
	ModeByteTransportDropsFragmentSilently          = "byte_transport_drops_fragment_silently"
	ModeByteTransportPayloadTraceLeak               = "byte_transport_payload_trace_leak"
	ModeByteTransportPaddingOnlyDiversity           = "byte_transport_padding_only_diversity"
	ModeProtocolCorpusMissingPhaseTaxonomy          = "protocorpus_missing_phase_taxonomy"
	ModeProtocolCorpusInvalidFieldVisibility        = "protocorpus_invalid_field_visibility"
	ModeProtocolCorpusUnsafePayloadFeature          = "protocorpus_unsafe_payload_feature"
	ModeWireFeaturesIdenticalFirstNShape            = "wirefeatures_identical_firstn_shape"
	ModeWireFeaturesPaddingOnlyVariation            = "wirefeatures_padding_only_variation"
	ModeWireFeaturesMissingMetadataExposure         = "wirefeatures_missing_metadata_exposure"
	ModeWireFeaturesGeneratedInterpretedDrift       = "wirefeatures_generated_interpreted_drift"
	ModeWireFeaturesSecretLeak                      = "wirefeatures_secret_leak"
	ModeWireGenFixedCorpusFamily                    = "wiregen_fixed_corpus_family"
	ModeWireGenFixedFirstNShape                     = "wiregen_fixed_firstn_shape"
	ModeWireGenFixedFrameSizePlan                   = "wiregen_fixed_frame_size_plan"
	ModeWireGenFixedFragmentRhythm                  = "wiregen_fixed_fragment_rhythm"
	ModeWireGenFixedMetadataExposure                = "wiregen_fixed_metadata_exposure"
	ModeWireGenLengthOnlyDiversity                  = "wiregen_length_only_diversity"
	ModeWireGenPayloadLeakFeature                   = "wiregen_payload_leak_feature"
	ModeWireGenGeneratedInterpretedDrift            = "wiregen_generated_interpreted_drift"
	ModeWireEvalRawPayloadColumn                    = "wireeval_raw_payload_column"
	ModeWireEvalRawBytesColumn                      = "wireeval_raw_bytes_column"
	ModeWireEvalEndpointLeak                        = "wireeval_endpoint_leak"
	ModeWireEvalTrainTestSeedOverlap                = "wireeval_train_test_seed_overlap"
	ModeWireEvalOODSeedOverlap                      = "wireeval_ood_seed_overlap"
	ModeWireEvalMissingRequiredFeature              = "wireeval_missing_required_feature"
	ModeWireEvalUnstableRecordID                    = "wireeval_unstable_record_id"
	ModeWireEvalPaddingOnlyDataset                  = "wireeval_padding_only_dataset"
	ModeWireEvalCollapsedFirstNDataset              = "wireeval_collapsed_firstn_dataset"
	ModeWireEvalControlNotDetected                  = "wireeval_control_not_detected"
	ModeWireEvalGeneratedBackendDatasetDrift        = "wireeval_generated_backend_dataset_drift"
	ModeWireEvalSecretLeak                          = "wireeval_secret_leak"
	ModeHostDetectSameFeatureEveryHost              = "hostdetect_same_feature_every_host"
	ModeHostDetectSameFirstNEveryHost               = "hostdetect_same_firstn_every_host"
	ModeHostDetectIgnoresObservationCount           = "hostdetect_ignores_observation_count"
	ModeHostDetectIgnoresProfileReuse               = "hostdetect_ignores_profile_reuse"
	ModeHostDetectIgnoresPaddingOnlyHosts           = "hostdetect_ignores_padding_only_hosts"
	ModeHostDetectControlNotDetected                = "hostdetect_control_not_detected"
	ModeHostDetectTrainTestHostOverlap              = "hostdetect_train_test_host_overlap"
	ModeHostDetectEndpointLeak                      = "hostdetect_endpoint_leak"
	ModeHostDetectPayloadLeak                       = "hostdetect_payload_leak"
	ModeHostDetectSecretLeak                        = "hostdetect_secret_leak"
	ModeHostDetectGeneratedBackendDrift             = "hostdetect_generated_backend_drift"
	ModeHostDetectUnstableHostAssignment            = "hostdetect_unstable_host_assignment"
	ModeRelayFleetReusesSameProfile                 = "relayfleet_reuses_same_profile"
	ModeRelayFleetReusesSameWirePolicy              = "relayfleet_reuses_same_wire_policy"
	ModeRelayFleetNeverChurns                       = "relayfleet_never_churns"
	ModeRelayFleetOverChurns                        = "relayfleet_over_churns"
	ModeRelayFleetIgnoresHostRisk                   = "relayfleet_ignores_host_risk"
	ModeRelayFleetKeepsBurnedRelayActive            = "relayfleet_keeps_burned_relay_active"
	ModeRelayFleetMigratesToRetiredRelay            = "relayfleet_migrates_to_retired_relay"
	ModeRelayFleetIgnoresProfileReuseLimit          = "relayfleet_ignores_profile_reuse_limit"
	ModeRelayFleetIgnoresPolicyReuseLimit           = "relayfleet_ignores_policy_reuse_limit"
	ModeRelayFleetControlNotDetected                = "relayfleet_control_not_detected"
	ModeRelayFleetEndpointLeak                      = "relayfleet_endpoint_leak"
	ModeRelayFleetPayloadLeak                       = "relayfleet_payload_leak"
	ModeRelayFleetSecretLeak                        = "relayfleet_secret_leak"
	ModeRelayFleetGeneratedBackendDrift             = "relayfleet_generated_backend_drift"
	ModeRelayFleetUnstableSchedule                  = "relayfleet_unstable_schedule"
	ModeProxyIngressAcceptsRealEndpoint             = "proxyingress_accepts_real_endpoint"
	ModeProxyIngressAcceptsDomainTarget             = "proxyingress_accepts_domain_target"
	ModeProxyIngressAcceptsURLTarget                = "proxyingress_accepts_url_target"
	ModeProxyIngressUnboundedDescriptor             = "proxyingress_unbounded_descriptor"
	ModeProxyIngressMissingTraceHygiene             = "proxyingress_missing_trace_hygiene"
	ModeProxyIngressMissingSecurityPrecondition     = "proxyingress_missing_security_precondition"
	ModeProxyIngressMissingBackpressureMapping      = "proxyingress_missing_backpressure_mapping"
	ModeProxyIngressMissingResetMapping             = "proxyingress_missing_reset_mapping"
	ModeProxyIngressAllRequestsSameMapping          = "proxyingress_all_requests_same_mapping"
	ModeProxyIngressLifecycleViolationAllowed       = "proxyingress_lifecycle_violation_allowed"
	ModeProxyIngressPayloadLeak                     = "proxyingress_payload_leak"
	ModeProxyIngressSecretLeak                      = "proxyingress_secret_leak"
	ModeProxyIngressReviewGoDespiteBlocker          = "proxyingress_review_go_despite_blocker"
	ModeProxyIngressGeneratedBackendDrift           = "proxyingress_generated_backend_drift"
	ModeLocalProxyIngressAcceptsInvalidTarget       = "localproxyingress_accepts_invalid_target"
	ModeLocalProxyIngressAcceptsRealEndpoint        = "localproxyingress_accepts_real_endpoint"
	ModeLocalProxyIngressUnboundedQueue             = "localproxyingress_unbounded_queue"
	ModeLocalProxyIngressIgnoresBackpressure        = "localproxyingress_ignores_backpressure"
	ModeLocalProxyIngressDataAfterClose             = "localproxyingress_data_after_close"
	ModeLocalProxyIngressResetBeforeOpen            = "localproxyingress_reset_before_open"
	ModeLocalProxyIngressErrorBeforeDescriptor      = "localproxyingress_error_before_descriptor"
	ModeLocalProxyIngressDuplicateEventAllowed      = "localproxyingress_duplicate_event_allowed"
	ModeLocalProxyIngressResetLeaksAcrossRequests   = "localproxyingress_reset_leaks_across_requests"
	ModeLocalProxyIngressTargetErrorLeaksDescriptor = "localproxyingress_target_error_leaks_descriptor"
	ModeLocalProxyIngressAllRequestsSameMapping     = "localproxyingress_all_requests_same_mapping"
	ModeLocalProxyIngressPayloadLeak                = "localproxyingress_payload_leak"
	ModeLocalProxyIngressSecretLeak                 = "localproxyingress_secret_leak"
	ModeLocalProxyIngressGeneratedBackendDrift      = "localproxyingress_generated_backend_drift"
	ModeLocalProxyIngressAdvAcceptsDescriptorAbuse  = "localproxyingressadv_accepts_descriptor_abuse"
	ModeLocalProxyIngressAdvAcceptsDataBeforeOpen   = "localproxyingressadv_accepts_data_before_open"
	ModeLocalProxyIngressAdvAcceptsDataAfterClose   = "localproxyingressadv_accepts_data_after_close"
	ModeLocalProxyIngressAdvAcceptsTerminalReopen   = "localproxyingressadv_accepts_terminal_reopen"
	ModeLocalProxyIngressAdvUnboundedQueueGrowth    = "localproxyingressadv_unbounded_queue_growth"
	ModeLocalProxyIngressAdvIgnoresBackpressure     = "localproxyingressadv_ignores_backpressure"
	ModeLocalProxyIngressAdvResetCrossRequestLeak   = "localproxyingressadv_reset_cross_request_leak"
	ModeLocalProxyIngressAdvErrorCrossRequestLeak   = "localproxyingressadv_error_cross_request_leak"
	ModeLocalProxyIngressAdvDescriptorLeak          = "localproxyingressadv_descriptor_leak"
	ModeLocalProxyIngressAdvFixedMapping            = "localproxyingressadv_fixed_mapping"
	ModeLocalProxyIngressAdvCollapseNotDetected     = "localproxyingressadv_collapse_not_detected"
	ModeLocalProxyIngressAdvReviewGoDespiteBlocker  = "localproxyingressadv_review_go_despite_blocker"
	ModeLocalProxyIngressAdvPayloadLeak             = "localproxyingressadv_payload_leak"
	ModeLocalProxyIngressAdvSecretLeak              = "localproxyingressadv_secret_leak"
	ModeLocalProxyIngressAdvGeneratedBackendDrift   = "localproxyingressadv_generated_backend_drift"
	ModeAdaptivePathAllCandidatesSameFamily         = "adaptivepath_all_candidates_same_family"
	ModeAdaptivePathStaleSuccessIsFresh             = "adaptivepath_stale_success_is_fresh"
	ModeAdaptivePathIgnoresRecentFailure            = "adaptivepath_ignores_recent_failure"
	ModeAdaptivePathIgnoresRelayBurn                = "adaptivepath_ignores_relay_burn"
	ModeAdaptivePathIgnoresDNSPoisoning             = "adaptivepath_ignores_dns_poisoning"
	ModeAdaptivePathIgnoresTCPBlackhole             = "adaptivepath_ignores_tcp_blackhole"
	ModeAdaptivePathIgnoresUDPBlock                 = "adaptivepath_ignores_udp_block"
	ModeAdaptivePathHighRiskDefaultEligible         = "adaptivepath_high_risk_default_eligible"
	ModeAdaptivePathUnknownMarkedUsable             = "adaptivepath_unknown_marked_usable"
	ModeAdaptivePathEndpointLeak                    = "adaptivepath_endpoint_leak"
	ModeAdaptivePathPayloadLeak                     = "adaptivepath_payload_leak"
	ModeAdaptivePathSecretLeak                      = "adaptivepath_secret_leak"
	ModeAdaptivePathGeneratedBackendDrift           = "adaptivepath_generated_backend_drift"
	ModeTransportBundleMissingRequiredFamily        = "transportbundle_missing_required_family"
	ModeTransportBundleAllCandidatesSameFamily      = "transportbundle_all_candidates_same_family"
	ModeTransportBundleAllCandidatesSameProfile     = "transportbundle_all_candidates_same_profile"
	ModeTransportBundleAllCandidatesSameWirePolicy  = "transportbundle_all_candidates_same_wire_policy"
	ModeTransportBundleHighRiskPrimary              = "transportbundle_high_risk_primary"
	ModeTransportBundleExperimentalPrimary          = "transportbundle_experimental_primary"
	ModeTransportBundleBurnedRelayPrimary           = "transportbundle_burned_relay_primary"
	ModeTransportBundleMissingFallbackPlan          = "transportbundle_missing_fallback_plan"
	ModeTransportBundleFinalWinnerSelected          = "transportbundle_final_winner_selected"
	ModeTransportBundleEndpointLeak                 = "transportbundle_endpoint_leak"
	ModeTransportBundleResolverLeak                 = "transportbundle_resolver_leak"
	ModeTransportBundlePayloadLeak                  = "transportbundle_payload_leak"
	ModeTransportBundleSecretLeak                   = "transportbundle_secret_leak"
	ModeTransportBundleGeneratedBackendDrift        = "transportbundle_generated_backend_drift"
	ModeTransportBundleControlNotDetected           = "transportbundle_control_not_detected"
	ModePathRaceAlwaysFirstCandidate                = "pathrace_always_first_candidate"
	ModePathRaceSerialOnly                          = "pathrace_serial_only"
	ModePathRaceStaleSuccessWins                    = "pathrace_stale_success_wins"
	ModePathRaceIgnoresRecentFailure                = "pathrace_ignores_recent_failure"
	ModePathRaceIgnoresStall                        = "pathrace_ignores_stall"
	ModePathRaceIgnoresRelayBurn                    = "pathrace_ignores_relay_burn"
	ModePathRaceHighRiskWins                        = "pathrace_high_risk_wins"
	ModePathRaceExperimentalWins                    = "pathrace_experimental_wins"
	ModePathRaceBurnedRelayWins                     = "pathrace_burned_relay_wins"
	ModePathRaceBlockedCandidateVerified            = "pathrace_blocked_candidate_verified"
	ModePathRaceAllScoresIdentical                  = "pathrace_all_scores_identical"
	ModePathRaceUnstableTieBreak                    = "pathrace_unstable_tiebreak"
	ModePathRaceEndpointLeak                        = "pathrace_endpoint_leak"
	ModePathRacePayloadLeak                         = "pathrace_payload_leak"
	ModePathRaceSecretLeak                          = "pathrace_secret_leak"
	ModePathRaceGeneratedBackendDrift               = "pathrace_generated_backend_drift"
	ModePathHealthNoHealthMonitoring                = "pathhealth_no_health_monitoring"
	ModePathHealthOverEagerFailover                 = "pathhealth_over_eager_failover"
	ModePathHealthUnderEagerFailover                = "pathhealth_under_eager_failover"
	ModePathHealthIgnoresStallAfterHandshake        = "pathhealth_ignores_stall_after_handshake"
	ModePathHealthIgnoresStallAfterData             = "pathhealth_ignores_stall_after_data"
	ModePathHealthIgnoresResetBurst                 = "pathhealth_ignores_reset_burst"
	ModePathHealthIgnoresBlackhole                  = "pathhealth_ignores_blackhole"
	ModePathHealthIgnoresRelayBurn                  = "pathhealth_ignores_relay_burn"
	ModePathHealthFailoverToBurnedRelay             = "pathhealth_failover_to_burned_relay"
	ModePathHealthHighRiskDefaultFailover           = "pathhealth_high_risk_default_failover"
	ModePathHealthExperimentalDefaultFailover       = "pathhealth_experimental_default_failover"
	ModePathHealthNoScoreDecay                      = "pathhealth_no_score_decay"
	ModePathHealthNoConfidenceExpiry                = "pathhealth_no_confidence_expiry"
	ModePathHealthPayloadLeak                       = "pathhealth_payload_leak"
	ModePathHealthSecretLeak                        = "pathhealth_secret_leak"
	ModePathHealthGeneratedBackendDrift             = "pathhealth_generated_backend_drift"
	ModeCarrierReviewClaimsGuaranteedBypass         = "carrierreview_claims_guaranteed_bypass"
	ModeCarrierReviewClaimsUndetectable             = "carrierreview_claims_undetectable"
	ModeCarrierReviewFieldReadyCarrier              = "carrierreview_field_ready_carrier"
	ModeCarrierReviewRealTLSClaim                   = "carrierreview_real_tls_claim"
	ModeCarrierReviewResolverQueryClaim             = "carrierreview_resolver_query_claim"
	ModeCarrierReviewQUICCompatibilityClaim         = "carrierreview_quic_compatibility_claim"
	ModeCarrierReviewDomesticDefault                = "carrierreview_domestic_default"
	ModeCarrierReviewHighRiskUngated                = "carrierreview_high_risk_ungated"
	ModeCarrierReviewExperimentalUngated            = "carrierreview_experimental_ungated"
	ModeCarrierReviewRelayEndpointLeak              = "carrierreview_relay_endpoint_leak"
	ModeCarrierReviewMissingTracePrecondition       = "carrierreview_missing_trace_precondition"
	ModeCarrierReviewGoDespiteBlocker               = "carrierreview_go_despite_blocker"
	ModeCarrierReviewPayloadLeak                    = "carrierreview_payload_leak"
	ModeCarrierReviewSecretLeak                     = "carrierreview_secret_leak"
	ModeCarrierReviewGeneratedBackendDrift          = "carrierreview_generated_backend_drift"
	ModeMeasurementReviewAllowsRawPayload           = "measurementreview_allows_raw_payload"
	ModeMeasurementReviewAllowsEndpointData         = "measurementreview_allows_endpoint_data"
	ModeMeasurementReviewAllowsDNSQuery             = "measurementreview_allows_dns_query"
	ModeMeasurementReviewAllowsResolverIP           = "measurementreview_allows_resolver_ip"
	ModeMeasurementReviewAllowsLocation             = "measurementreview_allows_location"
	ModeMeasurementReviewAllowsPhoneSIMDevice       = "measurementreview_allows_phone_sim_device"
	ModeMeasurementReviewUploadsWithoutOptIn        = "measurementreview_uploads_without_opt_in"
	ModeMeasurementReviewBackgroundMeasurement      = "measurementreview_background_measurement"
	ModeMeasurementReviewUnboundedRetention         = "measurementreview_unbounded_retention"
	ModeMeasurementReviewHashesEndpoint             = "measurementreview_hashes_endpoint"
	ModeMeasurementReviewExportWithoutRedaction     = "measurementreview_export_without_redaction"
	ModeMeasurementReviewDomesticNotManual          = "measurementreview_domestic_not_manual"
	ModeMeasurementReviewPayloadLeak                = "measurementreview_payload_leak"
	ModeMeasurementReviewSecretLeak                 = "measurementreview_secret_leak"
	ModeMeasurementReviewGeneratedBackendDrift      = "measurementreview_generated_backend_drift"
	ModeProxyEgressContainsEndpoint                 = "proxyegress_contains_endpoint"
	ModeProxyEgressContainsDNSQuery                 = "proxyegress_contains_dns_query"
	ModeProxyEgressContainsResolver                 = "proxyegress_contains_resolver"
	ModeProxyEgressContainsURL                      = "proxyegress_contains_url"
	ModeProxyEgressContainsPayload                  = "proxyegress_contains_payload"
	ModeProxyEgressContainsSecret                   = "proxyegress_contains_secret"
	ModeProxyEgressTargetNotSynthetic               = "proxyegress_target_not_synthetic"
	ModeProxyEgressDescriptorAbuseAccepted          = "proxyegress_descriptor_abuse_accepted"
	ModeProxyEgressHighRiskDefault                  = "proxyegress_high_risk_default"
	ModeProxyEgressExperimentalDefault              = "proxyegress_experimental_default"
	ModeProxyEgressFailedHealthAllowed              = "proxyegress_failed_health_allowed"
	ModeProxyEgressBackpressureIgnored              = "proxyegress_backpressure_ignored"
	ModeProxyEgressResetSwallowed                   = "proxyegress_reset_swallowed"
	ModeProxyEgressErrorLeaksTarget                 = "proxyegress_error_leaks_target"
	ModeProxyEgressAllTargetsSameShape              = "proxyegress_all_targets_same_shape"
	ModeProxyEgressGeneratedBackendDrift            = "proxyegress_generated_backend_drift"
	ModeRelayBridgeContainsEndpoint                 = "relaybridge_contains_endpoint"
	ModeRelayBridgeContainsPayload                  = "relaybridge_contains_payload"
	ModeRelayBridgeContainsSecret                   = "relaybridge_contains_secret"
	ModeRelayBridgeDialsRealRelay                   = "relaybridge_dials_real_relay"
	ModeRelayBridgeStreamIsolationBroken            = "relaybridge_stream_isolation_broken"
	ModeRelayBridgeBackpressureIgnored              = "relaybridge_backpressure_ignored"
	ModeRelayBridgeResetSwallowed                   = "relaybridge_reset_swallowed"
	ModeRelayBridgeErrorLeaksTarget                 = "relaybridge_error_leaks_target"
	ModeRelayBridgeHighRiskDefault                  = "relaybridge_high_risk_default"
	ModeRelayBridgeExperimentalDefault              = "relaybridge_experimental_default"
	ModeRelayBridgeFailedHealthAllowed              = "relaybridge_failed_health_allowed"
	ModeRelayBridgeAllStreamsSameShape              = "relaybridge_all_streams_same_shape"
	ModeRelayBridgeGeneratedBackendDrift            = "relaybridge_generated_backend_drift"
	ModeLocalPipelineIngressMappingBroken           = "localpipeline_ingress_mapping_broken"
	ModeLocalPipelineEgressMappingBroken            = "localpipeline_egress_mapping_broken"
	ModeLocalPipelineBridgeIntegrationBroken        = "localpipeline_bridge_integration_broken"
	ModeLocalPipelineIgnoresBackpressure            = "localpipeline_ignores_backpressure"
	ModeLocalPipelineSwallowsReset                  = "localpipeline_swallows_reset"
	ModeLocalPipelineSwallowsTargetError            = "localpipeline_swallows_target_error"
	ModeLocalPipelineAcceptsUnsafeDescriptor        = "localpipeline_accepts_unsafe_descriptor"
	ModeLocalPipelinePayloadTraceLeak               = "localpipeline_payload_trace_leak"
	ModeLocalPipelineSecretTraceLeak                = "localpipeline_secret_trace_leak"
	ModeLocalPipelinePaddingOnlyDiversity           = "localpipeline_padding_only_diversity"
	ModeLocalPipelineGeneratedBackendDrift          = "localpipeline_generated_backend_drift"
	ModeProductionReadinessMissingBoundary          = "productionreadiness_missing_boundary"
	ModeProductionReadinessAllowsRealIO             = "productionreadiness_allows_real_io"
	ModeProductionReadinessAllowsDeployment         = "productionreadiness_allows_deployment"
	ModeProductionReadinessPayloadTraceLeak         = "productionreadiness_payload_trace_leak"
	ModeProductionReadinessSecretTraceLeak          = "productionreadiness_secret_trace_leak"
	ModeProductionReadinessMissingM36Contract       = "productionreadiness_missing_m36_contract"
	ModeProductionReadinessIgnoresBlockers          = "productionreadiness_ignores_blockers"
	ModeProductionReadinessGeneratedBackendDrift    = "productionreadiness_generated_backend_drift"
	ModeConcreteLocalAdapterAllowsExternalBind      = "concretelocaladapter_allows_external_bind"
	ModeConcreteLocalAdapterAcceptsWildcardBind     = "concretelocaladapter_accepts_wildcard_bind"
	ModeConcreteLocalAdapterIgnoresBackpressure     = "concretelocaladapter_ignores_backpressure"
	ModeConcreteLocalAdapterPayloadTraceLeak        = "concretelocaladapter_payload_trace_leak"
	ModeConcreteLocalAdapterSecretTraceLeak         = "concretelocaladapter_secret_trace_leak"
	ModeConcreteLocalAdapterWrongRuntimeMapping     = "concretelocaladapter_wrong_runtime_mapping"
	ModeConcreteLocalAdapterAcceptsMalformedEvent   = "concretelocaladapter_accepts_malformed_event"
	ModeConcreteLocalAdapterGeneratedBackendDrift   = "concretelocaladapter_generated_backend_drift"
	ModeLocalProtocolAdapterAllowsOutboundDial      = "localprotocoladapter_allows_outbound_dial"
	ModeLocalProtocolAdapterAllowsDNSResolution     = "localprotocoladapter_allows_dns_resolution"
	ModeLocalProtocolAdapterAllowsPayloadForwarding = "localprotocoladapter_allows_payload_forwarding"
	ModeLocalProtocolAdapterPersistsTarget          = "localprotocoladapter_persists_target"
	ModeLocalProtocolAdapterAcceptsCredentials      = "localprotocoladapter_accepts_credentials"
	ModeLocalProtocolAdapterAcceptsUDPAssociate     = "localprotocoladapter_accepts_udp_associate"
	ModeLocalProtocolAdapterHeaderSmuggling         = "localprotocoladapter_header_smuggling"
	ModeLocalProtocolAdapterGeneratedBackendDrift   = "localprotocoladapter_generated_backend_drift"

	ModeLoopbackRelayAllowsExternalBind    = "loopbackrelay_allows_external_bind"
	ModeLoopbackRelayAllowsExternalDial    = "loopbackrelay_allows_external_dial"
	ModeLoopbackRelayAllowsDNSResolution   = "loopbackrelay_allows_dns_resolution"
	ModeLoopbackRelayLogsPayload           = "loopbackrelay_logs_payload"
	ModeLoopbackRelayIgnoresBackpressure   = "loopbackrelay_ignores_backpressure"
	ModeLoopbackRelayAcceptsMalformedFrame = "loopbackrelay_accepts_malformed_frame"
	ModeLoopbackRelayGeneratedBackendDrift = "loopbackrelay_generated_backend_drift"
)

func Modes() []string {
	return []string{
		ModeFixedFirstContact,
		ModeFixedFrameGrammar,
		ModeCosmeticSymbolsOnly,
		ModeFixedScheduler,
		ModeFixedInvalidInput,
		ModePaddingNoiseOnly,
		ModeFixedStreamIDStrategy,
		ModeFixedWindowUpdatePolicy,
		ModeFIFOSchedulerOnly,
		ModeFixedResetClosePolicy,
		ModeNoBackpressure,
		ModePaddingOnlyStreamDiversity,
		ModeFixedTargetDescriptorEncoding,
		ModeFixedTargetOpenSequence,
		ModeFixedTargetErrorPolicy,
		ModeFixedTargetClosePolicy,
		ModeFixedResponseChunking,
		ModeNoTargetBackpressure,
		ModePaddingOnlyProxyDiversity,
		ModeFixedCarrierFamily,
		ModeFixedEnvelopeEncoding,
		ModeFixedFlushPolicy,
		ModeFixedBatchPolicy,
		ModeFixedChunkingPolicy,
		ModeNoCarrierBackpressure,
		ModeNoReorderRecovery,
		ModePaddingOnlyCarrierDiversity,
		ModeNoTranscriptBinding,
		ModeReusedNonce,
		ModeAcceptsReplay,
		ModeAcceptsDowngrade,
		ModeCapabilityMismatchAccepted,
		ModeProfileMismatchAccepted,
		ModeUnsafeConfigAllowed,
		ModeSecretTraceLeak,
		ModeRuntimeAcceptsCapabilityDowngrade,
		ModeRuntimeAcceptsProfileMismatch,
		ModeRuntimeAcceptsReplay,
		ModeRuntimeIgnoresBackpressure,
		ModeRuntimeLeaksSecretTrace,
		ModeRuntimeLeaksPayloadTrace,
		ModeRuntimeNoStateValidation,
		ModeRuntimePaddingOnlyDiversity,
		ModePanicOnMalformedFrame,
		ModeUnboundedTraceEvents,
		ModeTraceSecretLeakHardening,
		ModeIgnoresMaxStreams,
		ModeIgnoresMaxCarrierQueue,
		ModeAcceptsInvalidProfileHash,
		ModeGeneratedParityDrift,
		ModeAPIMisusePanic,
		ModeAdapterAcceptsInvalidFlow,
		ModeAdapterIgnoresBackpressure,
		ModeAdapterLeaksPayloadTrace,
		ModeAdapterLeaksSecretTrace,
		ModeAdapterAcceptsCapabilityDowngrade,
		ModeAdapterIgnoresMaxFlows,
		ModeAdapterWrongResetMapping,
		ModeAdapterPaddingOnlyDiversity,
		ModeLocalAdapterIgnoresSourceBackpressure,
		ModeLocalAdapterAcceptsPostCloseWrite,
		ModeLocalAdapterDropsFinalChunk,
		ModeLocalAdapterDuplicatesChunk,
		ModeLocalAdapterWrongFlowStreamMapping,
		ModeLocalAdapterPayloadTraceLeak,
		ModeLocalAdapterSecretTraceLeak,
		ModeLocalAdapterPaddingOnlyDiversity,
		ModeByteTransportAcceptsMalformedFrame,
		ModeByteTransportIgnoresMaxFrameSize,
		ModeByteTransportIgnoresBackpressure,
		ModeByteTransportReusesSequence,
		ModeByteTransportAcceptsCorruption,
		ModeByteTransportDropsFragmentSilently,
		ModeByteTransportPayloadTraceLeak,
		ModeByteTransportPaddingOnlyDiversity,
		ModeProtocolCorpusMissingPhaseTaxonomy,
		ModeProtocolCorpusInvalidFieldVisibility,
		ModeProtocolCorpusUnsafePayloadFeature,
		ModeWireFeaturesIdenticalFirstNShape,
		ModeWireFeaturesPaddingOnlyVariation,
		ModeWireFeaturesMissingMetadataExposure,
		ModeWireFeaturesGeneratedInterpretedDrift,
		ModeWireFeaturesSecretLeak,
		ModeWireGenFixedCorpusFamily,
		ModeWireGenFixedFirstNShape,
		ModeWireGenFixedFrameSizePlan,
		ModeWireGenFixedFragmentRhythm,
		ModeWireGenFixedMetadataExposure,
		ModeWireGenLengthOnlyDiversity,
		ModeWireGenPayloadLeakFeature,
		ModeWireGenGeneratedInterpretedDrift,
		ModeWireEvalRawPayloadColumn,
		ModeWireEvalRawBytesColumn,
		ModeWireEvalEndpointLeak,
		ModeWireEvalTrainTestSeedOverlap,
		ModeWireEvalOODSeedOverlap,
		ModeWireEvalMissingRequiredFeature,
		ModeWireEvalUnstableRecordID,
		ModeWireEvalPaddingOnlyDataset,
		ModeWireEvalCollapsedFirstNDataset,
		ModeWireEvalControlNotDetected,
		ModeWireEvalGeneratedBackendDatasetDrift,
		ModeWireEvalSecretLeak,
		ModeHostDetectSameFeatureEveryHost,
		ModeHostDetectSameFirstNEveryHost,
		ModeHostDetectIgnoresObservationCount,
		ModeHostDetectIgnoresProfileReuse,
		ModeHostDetectIgnoresPaddingOnlyHosts,
		ModeHostDetectControlNotDetected,
		ModeHostDetectTrainTestHostOverlap,
		ModeHostDetectEndpointLeak,
		ModeHostDetectPayloadLeak,
		ModeHostDetectSecretLeak,
		ModeHostDetectGeneratedBackendDrift,
		ModeHostDetectUnstableHostAssignment,
		ModeRelayFleetReusesSameProfile,
		ModeRelayFleetReusesSameWirePolicy,
		ModeRelayFleetNeverChurns,
		ModeRelayFleetOverChurns,
		ModeRelayFleetIgnoresHostRisk,
		ModeRelayFleetKeepsBurnedRelayActive,
		ModeRelayFleetMigratesToRetiredRelay,
		ModeRelayFleetIgnoresProfileReuseLimit,
		ModeRelayFleetIgnoresPolicyReuseLimit,
		ModeRelayFleetControlNotDetected,
		ModeRelayFleetEndpointLeak,
		ModeRelayFleetPayloadLeak,
		ModeRelayFleetSecretLeak,
		ModeRelayFleetGeneratedBackendDrift,
		ModeRelayFleetUnstableSchedule,
		ModeProxyIngressAcceptsRealEndpoint,
		ModeProxyIngressAcceptsDomainTarget,
		ModeProxyIngressAcceptsURLTarget,
		ModeProxyIngressUnboundedDescriptor,
		ModeProxyIngressMissingTraceHygiene,
		ModeProxyIngressMissingSecurityPrecondition,
		ModeProxyIngressMissingBackpressureMapping,
		ModeProxyIngressMissingResetMapping,
		ModeProxyIngressAllRequestsSameMapping,
		ModeProxyIngressLifecycleViolationAllowed,
		ModeProxyIngressPayloadLeak,
		ModeProxyIngressSecretLeak,
		ModeProxyIngressReviewGoDespiteBlocker,
		ModeProxyIngressGeneratedBackendDrift,
		ModeLocalProxyIngressAcceptsInvalidTarget,
		ModeLocalProxyIngressAcceptsRealEndpoint,
		ModeLocalProxyIngressUnboundedQueue,
		ModeLocalProxyIngressIgnoresBackpressure,
		ModeLocalProxyIngressDataAfterClose,
		ModeLocalProxyIngressResetBeforeOpen,
		ModeLocalProxyIngressErrorBeforeDescriptor,
		ModeLocalProxyIngressDuplicateEventAllowed,
		ModeLocalProxyIngressResetLeaksAcrossRequests,
		ModeLocalProxyIngressTargetErrorLeaksDescriptor,
		ModeLocalProxyIngressAllRequestsSameMapping,
		ModeLocalProxyIngressPayloadLeak,
		ModeLocalProxyIngressSecretLeak,
		ModeLocalProxyIngressGeneratedBackendDrift,
		ModeLocalProxyIngressAdvAcceptsDescriptorAbuse,
		ModeLocalProxyIngressAdvAcceptsDataBeforeOpen,
		ModeLocalProxyIngressAdvAcceptsDataAfterClose,
		ModeLocalProxyIngressAdvAcceptsTerminalReopen,
		ModeLocalProxyIngressAdvUnboundedQueueGrowth,
		ModeLocalProxyIngressAdvIgnoresBackpressure,
		ModeLocalProxyIngressAdvResetCrossRequestLeak,
		ModeLocalProxyIngressAdvErrorCrossRequestLeak,
		ModeLocalProxyIngressAdvDescriptorLeak,
		ModeLocalProxyIngressAdvFixedMapping,
		ModeLocalProxyIngressAdvCollapseNotDetected,
		ModeLocalProxyIngressAdvReviewGoDespiteBlocker,
		ModeLocalProxyIngressAdvPayloadLeak,
		ModeLocalProxyIngressAdvSecretLeak,
		ModeLocalProxyIngressAdvGeneratedBackendDrift,
		ModeAdaptivePathAllCandidatesSameFamily,
		ModeAdaptivePathStaleSuccessIsFresh,
		ModeAdaptivePathIgnoresRecentFailure,
		ModeAdaptivePathIgnoresRelayBurn,
		ModeAdaptivePathIgnoresDNSPoisoning,
		ModeAdaptivePathIgnoresTCPBlackhole,
		ModeAdaptivePathIgnoresUDPBlock,
		ModeAdaptivePathHighRiskDefaultEligible,
		ModeAdaptivePathUnknownMarkedUsable,
		ModeAdaptivePathEndpointLeak,
		ModeAdaptivePathPayloadLeak,
		ModeAdaptivePathSecretLeak,
		ModeAdaptivePathGeneratedBackendDrift,
		ModeTransportBundleMissingRequiredFamily,
		ModeTransportBundleAllCandidatesSameFamily,
		ModeTransportBundleAllCandidatesSameProfile,
		ModeTransportBundleAllCandidatesSameWirePolicy,
		ModeTransportBundleHighRiskPrimary,
		ModeTransportBundleExperimentalPrimary,
		ModeTransportBundleBurnedRelayPrimary,
		ModeTransportBundleMissingFallbackPlan,
		ModeTransportBundleFinalWinnerSelected,
		ModeTransportBundleEndpointLeak,
		ModeTransportBundleResolverLeak,
		ModeTransportBundlePayloadLeak,
		ModeTransportBundleSecretLeak,
		ModeTransportBundleGeneratedBackendDrift,
		ModeTransportBundleControlNotDetected,
		ModePathRaceAlwaysFirstCandidate,
		ModePathRaceSerialOnly,
		ModePathRaceStaleSuccessWins,
		ModePathRaceIgnoresRecentFailure,
		ModePathRaceIgnoresStall,
		ModePathRaceIgnoresRelayBurn,
		ModePathRaceHighRiskWins,
		ModePathRaceExperimentalWins,
		ModePathRaceBurnedRelayWins,
		ModePathRaceBlockedCandidateVerified,
		ModePathRaceAllScoresIdentical,
		ModePathRaceUnstableTieBreak,
		ModePathRaceEndpointLeak,
		ModePathRacePayloadLeak,
		ModePathRaceSecretLeak,
		ModePathRaceGeneratedBackendDrift,
		ModePathHealthNoHealthMonitoring,
		ModePathHealthOverEagerFailover,
		ModePathHealthUnderEagerFailover,
		ModePathHealthIgnoresStallAfterHandshake,
		ModePathHealthIgnoresStallAfterData,
		ModePathHealthIgnoresResetBurst,
		ModePathHealthIgnoresBlackhole,
		ModePathHealthIgnoresRelayBurn,
		ModePathHealthFailoverToBurnedRelay,
		ModePathHealthHighRiskDefaultFailover,
		ModePathHealthExperimentalDefaultFailover,
		ModePathHealthNoScoreDecay,
		ModePathHealthNoConfidenceExpiry,
		ModePathHealthPayloadLeak,
		ModePathHealthSecretLeak,
		ModePathHealthGeneratedBackendDrift,
		ModeCarrierReviewClaimsGuaranteedBypass,
		ModeCarrierReviewClaimsUndetectable,
		ModeCarrierReviewFieldReadyCarrier,
		ModeCarrierReviewRealTLSClaim,
		ModeCarrierReviewResolverQueryClaim,
		ModeCarrierReviewQUICCompatibilityClaim,
		ModeCarrierReviewDomesticDefault,
		ModeCarrierReviewHighRiskUngated,
		ModeCarrierReviewExperimentalUngated,
		ModeCarrierReviewRelayEndpointLeak,
		ModeCarrierReviewMissingTracePrecondition,
		ModeCarrierReviewGoDespiteBlocker,
		ModeCarrierReviewPayloadLeak,
		ModeCarrierReviewSecretLeak,
		ModeCarrierReviewGeneratedBackendDrift,
		ModeMeasurementReviewAllowsRawPayload,
		ModeMeasurementReviewAllowsEndpointData,
		ModeMeasurementReviewAllowsDNSQuery,
		ModeMeasurementReviewAllowsResolverIP,
		ModeMeasurementReviewAllowsLocation,
		ModeMeasurementReviewAllowsPhoneSIMDevice,
		ModeMeasurementReviewUploadsWithoutOptIn,
		ModeMeasurementReviewBackgroundMeasurement,
		ModeMeasurementReviewUnboundedRetention,
		ModeMeasurementReviewHashesEndpoint,
		ModeMeasurementReviewExportWithoutRedaction,
		ModeMeasurementReviewDomesticNotManual,
		ModeMeasurementReviewPayloadLeak,
		ModeMeasurementReviewSecretLeak,
		ModeMeasurementReviewGeneratedBackendDrift,
		ModeProxyEgressContainsEndpoint,
		ModeProxyEgressContainsDNSQuery,
		ModeProxyEgressContainsResolver,
		ModeProxyEgressContainsURL,
		ModeProxyEgressContainsPayload,
		ModeProxyEgressContainsSecret,
		ModeProxyEgressTargetNotSynthetic,
		ModeProxyEgressDescriptorAbuseAccepted,
		ModeProxyEgressHighRiskDefault,
		ModeProxyEgressExperimentalDefault,
		ModeProxyEgressFailedHealthAllowed,
		ModeProxyEgressBackpressureIgnored,
		ModeProxyEgressResetSwallowed,
		ModeProxyEgressErrorLeaksTarget,
		ModeProxyEgressAllTargetsSameShape,
		ModeProxyEgressGeneratedBackendDrift,
		ModeRelayBridgeContainsEndpoint,
		ModeRelayBridgeContainsPayload,
		ModeRelayBridgeContainsSecret,
		ModeRelayBridgeDialsRealRelay,
		ModeRelayBridgeStreamIsolationBroken,
		ModeRelayBridgeBackpressureIgnored,
		ModeRelayBridgeResetSwallowed,
		ModeRelayBridgeErrorLeaksTarget,
		ModeRelayBridgeHighRiskDefault,
		ModeRelayBridgeExperimentalDefault,
		ModeRelayBridgeFailedHealthAllowed,
		ModeRelayBridgeAllStreamsSameShape,
		ModeRelayBridgeGeneratedBackendDrift,
		ModeLocalPipelineIngressMappingBroken,
		ModeLocalPipelineEgressMappingBroken,
		ModeLocalPipelineBridgeIntegrationBroken,
		ModeLocalPipelineIgnoresBackpressure,
		ModeLocalPipelineSwallowsReset,
		ModeLocalPipelineSwallowsTargetError,
		ModeLocalPipelineAcceptsUnsafeDescriptor,
		ModeLocalPipelinePayloadTraceLeak,
		ModeLocalPipelineSecretTraceLeak,
		ModeLocalPipelinePaddingOnlyDiversity,
		ModeLocalPipelineGeneratedBackendDrift,
		ModeProductionReadinessMissingBoundary,
		ModeProductionReadinessAllowsRealIO,
		ModeProductionReadinessAllowsDeployment,
		ModeProductionReadinessPayloadTraceLeak,
		ModeProductionReadinessSecretTraceLeak,
		ModeProductionReadinessMissingM36Contract,
		ModeProductionReadinessIgnoresBlockers,
		ModeProductionReadinessGeneratedBackendDrift,
		ModeConcreteLocalAdapterAllowsExternalBind,
		ModeConcreteLocalAdapterAcceptsWildcardBind,
		ModeConcreteLocalAdapterIgnoresBackpressure,
		ModeConcreteLocalAdapterPayloadTraceLeak,
		ModeConcreteLocalAdapterSecretTraceLeak,
		ModeConcreteLocalAdapterWrongRuntimeMapping,
		ModeConcreteLocalAdapterAcceptsMalformedEvent,
		ModeConcreteLocalAdapterGeneratedBackendDrift,
		ModeLocalProtocolAdapterAllowsOutboundDial,
		ModeLocalProtocolAdapterAllowsDNSResolution,
		ModeLocalProtocolAdapterAllowsPayloadForwarding,
		ModeLocalProtocolAdapterPersistsTarget,
		ModeLocalProtocolAdapterAcceptsCredentials,
		ModeLocalProtocolAdapterAcceptsUDPAssociate,
		ModeLocalProtocolAdapterHeaderSmuggling,
		ModeLocalProtocolAdapterGeneratedBackendDrift,
		ModeLoopbackRelayAllowsExternalBind,
		ModeLoopbackRelayAllowsExternalDial,
		ModeLoopbackRelayAllowsDNSResolution,
		ModeLoopbackRelayLogsPayload,
		ModeLoopbackRelayIgnoresBackpressure,
		ModeLoopbackRelayAcceptsMalformedFrame,
		ModeLoopbackRelayGeneratedBackendDrift,
	}
}

func GenerateProfiles(mode string, startSeed int64, count int) ([]*ir.Profile, error) {
	if count < 0 {
		return nil, fmt.Errorf("count must be non-negative")
	}
	if !knownMode(mode) {
		return nil, fmt.Errorf("unknown mutant mode %q", mode)
	}
	base, err := compiler.Generate(startSeed)
	if err != nil {
		return nil, err
	}
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		seed := startSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return nil, err
		}
		switch mode {
		case ModeFixedFirstContact:
			applyFixedFirstContact(p, base)
			renameWireSymbols(p, mode, i)
		case ModeFixedFrameGrammar:
			p.FrameGrammar = cloneFrameGrammar(base.FrameGrammar)
		case ModeCosmeticSymbolsOnly:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
		case ModeFixedScheduler:
			p.Scheduler = base.Scheduler
		case ModeFixedInvalidInput:
			p.InvalidInput = base.InvalidInput
		case ModePaddingNoiseOnly:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeFixedStreamIDStrategy:
			p.Stream.IDStrategy = base.Stream.IDStrategy
			p.Stream.IDEncodingMode = base.Stream.IDEncodingMode
		case ModeFixedWindowUpdatePolicy:
			p.Stream.WindowUpdatePolicy = base.Stream.WindowUpdatePolicy
			p.Stream.InitialStreamWindowBytes = base.Stream.InitialStreamWindowBytes
			p.Stream.InitialSessionWindowBytes = base.Stream.InitialSessionWindowBytes
		case ModeFIFOSchedulerOnly:
			p.Stream.PriorityPolicy = "fifo"
			p.Scheduler.PriorityMode = "fifo"
		case ModeFixedResetClosePolicy:
			p.Stream.ClosePolicy = base.Stream.ClosePolicy
			p.Stream.ResetPolicy = base.Stream.ResetPolicy
		case ModeNoBackpressure:
			p.Stream.InitialStreamWindowBytes = 128 * 1024
			p.Stream.InitialSessionWindowBytes = min(2*1024*1024, 128*1024*max(4, p.Stream.MaxConcurrentStreams))
		case ModePaddingOnlyStreamDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeFixedTargetDescriptorEncoding:
			p.ProxySemantics.TargetDescriptorEncoding = base.ProxySemantics.TargetDescriptorEncoding
			p.ProxySemantics.TargetClassMapping = base.ProxySemantics.TargetClassMapping
		case ModeFixedTargetOpenSequence:
			p.ProxySemantics.RelayIntentEncoding = base.ProxySemantics.RelayIntentEncoding
			p.ProxySemantics.RelayOpenOrderingPolicy = base.ProxySemantics.RelayOpenOrderingPolicy
		case ModeFixedTargetErrorPolicy:
			p.ProxySemantics.TargetErrorPolicy = base.ProxySemantics.TargetErrorPolicy
		case ModeFixedTargetClosePolicy:
			p.ProxySemantics.TargetClosePolicy = base.ProxySemantics.TargetClosePolicy
		case ModeFixedResponseChunking:
			p.ProxySemantics.ResponseModeEncoding = base.ProxySemantics.ResponseModeEncoding
			p.FrameGrammar.FragmentationMode = base.FrameGrammar.FragmentationMode
		case ModeNoTargetBackpressure:
			p.ProxySemantics.TargetMetadataPolicy = base.ProxySemantics.TargetMetadataPolicy
			p.Stream.InitialStreamWindowBytes = 128 * 1024
			p.Stream.InitialSessionWindowBytes = min(2*1024*1024, 128*1024*max(4, p.Stream.MaxConcurrentStreams))
		case ModePaddingOnlyProxyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeFixedCarrierFamily:
			p.CarrierPolicy.CarrierFamily = base.CarrierPolicy.CarrierFamily
		case ModeFixedEnvelopeEncoding:
			p.CarrierPolicy.EnvelopeEncoding = base.CarrierPolicy.EnvelopeEncoding
		case ModeFixedFlushPolicy:
			p.CarrierPolicy.FlushPolicy = base.CarrierPolicy.FlushPolicy
		case ModeFixedBatchPolicy:
			p.CarrierPolicy.BatchPolicy = base.CarrierPolicy.BatchPolicy
			p.CarrierPolicy.MaxMessagesPerEnvelope = base.CarrierPolicy.MaxMessagesPerEnvelope
		case ModeFixedChunkingPolicy:
			p.CarrierPolicy.ChunkingPolicy = base.CarrierPolicy.ChunkingPolicy
			p.CarrierPolicy.MaxEnvelopeBytes = base.CarrierPolicy.MaxEnvelopeBytes
		case ModeNoCarrierBackpressure:
			p.CarrierPolicy.MaxCarrierQueueDepth = 128
			p.CarrierPolicy.BackpressurePolicy = "carrier_queue_backpressure"
		case ModeNoReorderRecovery:
			p.CarrierPolicy.ReliabilityPolicy = "ordered_only"
			p.CarrierPolicy.ReorderPolicy = "none"
			p.CarrierPolicy.MaxRetryCount = 0
		case ModePaddingOnlyCarrierDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeNoTranscriptBinding:
			p.Security.TranscriptMode = "canonical_v1"
		case ModeReusedNonce:
			p.Security.NonceMode = "counter_xor_base"
			p.Security.MaxSessionMessages = 64
			p.Security.MaxKeyLifetimeMessages = 32
		case ModeAcceptsReplay:
			p.Security.ReplayPolicy = "windowed_replay"
			p.InvalidInput.Replay = "ordinary_error_shaped_response"
		case ModeAcceptsDowngrade:
			p.Security.DowngradePolicy = "strict_capabilities"
		case ModeCapabilityMismatchAccepted:
			p.Security.CapabilityNegotiationPolicy = "intersection_with_required"
		case ModeProfileMismatchAccepted:
			p.Security.ProfileCompatibilityPolicy = "strict_schema"
		case ModeUnsafeConfigAllowed:
			p.Security.ConfigValidationPolicy = "strict_required"
		case ModeSecretTraceLeak:
			p.Security.SecureEnvelopeMode = "metadata_authenticated"
		case ModeRuntimeAcceptsCapabilityDowngrade:
			p.Security.CapabilityNegotiationPolicy = "intersection_with_required"
		case ModeRuntimeAcceptsProfileMismatch:
			p.Security.ProfileCompatibilityPolicy = "strict_schema"
		case ModeRuntimeAcceptsReplay:
			p.Security.ReplayPolicy = "windowed_replay"
			p.InvalidInput.Replay = "ordinary_error_shaped_response"
		case ModeRuntimeIgnoresBackpressure:
			p.Stream.InitialStreamWindowBytes = 128 * 1024
			p.Stream.InitialSessionWindowBytes = min(2*1024*1024, 128*1024*max(4, p.Stream.MaxConcurrentStreams))
			p.CarrierPolicy.MaxCarrierQueueDepth = 128
		case ModeRuntimeLeaksSecretTrace:
			p.Security.ConfigValidationPolicy = "strict_required"
		case ModeRuntimeLeaksPayloadTrace:
			p.Security.SecureEnvelopeMode = "metadata_authenticated"
		case ModeRuntimeNoStateValidation:
			p.InvalidInput.UnknownFirstMessage = "ordinary_error_shaped_response"
		case ModeRuntimePaddingOnlyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModePanicOnMalformedFrame:
			p.InvalidInput.MalformedFrame = "generated_malformed_response"
		case ModeUnboundedTraceEvents:
			p.Limits.MaxSessionMillis = max(p.Limits.MaxSessionMillis, 60_000)
		case ModeTraceSecretLeakHardening:
			p.Security.ConfigValidationPolicy = "strict_required"
		case ModeIgnoresMaxStreams:
			p.Stream.MaxConcurrentStreams = min(16, max(2, p.Stream.MaxConcurrentStreams))
			p.Compatibility.MaxStreamCount = p.Stream.MaxConcurrentStreams
		case ModeIgnoresMaxCarrierQueue:
			p.CarrierPolicy.MaxCarrierQueueDepth = 128
		case ModeAcceptsInvalidProfileHash:
			p.Security.ProfileCompatibilityPolicy = "strict_schema"
		case ModeGeneratedParityDrift:
			p.Security.SecureEnvelopeMode = "metadata_authenticated"
		case ModeAPIMisusePanic:
			p.InvalidInput.UnknownFirstMessage = "ordinary_error_shaped_response"
		case ModeAdapterAcceptsInvalidFlow:
			p.AdapterPolicy.FlowLifecyclePolicy = "strict"
		case ModeAdapterIgnoresBackpressure:
			p.AdapterPolicy.BackpressurePolicy = "adapter_queue"
			p.AdapterPolicy.MaxBufferedBytes = 2 * 1024 * 1024
		case ModeAdapterLeaksPayloadTrace:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeAdapterLeaksSecretTrace:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeAdapterAcceptsCapabilityDowngrade:
			p.AdapterPolicy.RequiredCapabilities = []string{"adapter_ingress", "flow_lifecycle"}
		case ModeAdapterIgnoresMaxFlows:
			p.AdapterPolicy.MaxFlows = p.Stream.MaxConcurrentStreams
		case ModeAdapterWrongResetMapping:
			p.AdapterPolicy.ErrorMappingPolicy = "close_with_error"
		case ModeAdapterPaddingOnlyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeLocalAdapterIgnoresSourceBackpressure:
			p.AdapterPolicy.BackpressurePolicy = "adapter_queue"
			p.AdapterPolicy.MaxBufferedBytes = 2 * 1024 * 1024
		case ModeLocalAdapterAcceptsPostCloseWrite:
			p.AdapterPolicy.FlowLifecyclePolicy = "strict"
		case ModeLocalAdapterDropsFinalChunk:
			p.AdapterPolicy.RuntimeMappingPolicy = "one_flow_one_stream"
		case ModeLocalAdapterDuplicatesChunk:
			p.AdapterPolicy.RuntimeMappingPolicy = "one_flow_one_stream"
		case ModeLocalAdapterWrongFlowStreamMapping:
			p.AdapterPolicy.RuntimeMappingPolicy = "metadata_bound_stream"
		case ModeLocalAdapterPayloadTraceLeak:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeLocalAdapterSecretTraceLeak:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeLocalAdapterPaddingOnlyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeByteTransportAcceptsMalformedFrame:
			p.InvalidInput.MalformedFrame = "generated_malformed_response"
		case ModeByteTransportIgnoresMaxFrameSize:
			p.Limits.MaxFrameBytes = max(p.Limits.MaxFrameBytes, 256*1024)
		case ModeByteTransportIgnoresBackpressure:
			p.CarrierPolicy.MaxCarrierQueueDepth = 128
			p.AdapterPolicy.MaxBufferedBytes = 2 * 1024 * 1024
		case ModeByteTransportReusesSequence:
			p.Security.ReplayPolicy = "windowed_replay"
		case ModeByteTransportAcceptsCorruption:
			p.Security.SecureEnvelopeMode = "metadata_authenticated"
		case ModeByteTransportDropsFragmentSilently:
			p.FrameGrammar.FragmentationMode = base.FrameGrammar.FragmentationMode
		case ModeByteTransportPayloadTraceLeak:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeByteTransportPaddingOnlyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeProtocolCorpusMissingPhaseTaxonomy:
			p.InvalidInput.UnknownFirstMessage = "ordinary_error_shaped_response"
		case ModeProtocolCorpusInvalidFieldVisibility:
			p.InvalidInput.MalformedFrame = "generated_malformed_response"
		case ModeProtocolCorpusUnsafePayloadFeature:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeWireFeaturesIdenticalFirstNShape:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
		case ModeWireFeaturesPaddingOnlyVariation:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			p.Padding = paddingForIndex(i)
		case ModeWireFeaturesMissingMetadataExposure:
			p.FrameGrammar.TypeMode = base.FrameGrammar.TypeMode
		case ModeWireFeaturesGeneratedInterpretedDrift:
			p.Security.SecureEnvelopeMode = "metadata_authenticated"
		case ModeWireFeaturesSecretLeak:
			p.Security.ConfigValidationPolicy = "strict_required"
		case ModeWireGenFixedCorpusFamily:
			p.WireShape.SelectedFamily = base.WireShape.SelectedFamily
			p.WireShape.SelectedCorpusEntry = base.WireShape.SelectedCorpusEntry
		case ModeWireGenFixedFirstNShape:
			p.WireShape.FirstNPlan = base.WireShape.FirstNPlan
		case ModeWireGenFixedFrameSizePlan:
			p.WireShape.FrameSizePlan = base.WireShape.FrameSizePlan
		case ModeWireGenFixedFragmentRhythm:
			p.WireShape.FragmentRhythmPlan = base.WireShape.FragmentRhythmPlan
		case ModeWireGenFixedMetadataExposure:
			p.WireShape.MetadataExposurePlan = base.WireShape.MetadataExposurePlan
		case ModeWireGenLengthOnlyDiversity:
			p = cloneProfile(base)
			renameWireSymbols(p, mode, i)
			buckets := []string{"size_4_8", "size_9_16", "size_17_32", "size_33_64"}
			p.WireShape.FrameSizePlan.SizeBuckets = []string{buckets[i%len(buckets)]}
		case ModeWireGenPayloadLeakFeature:
			p.AdapterPolicy.TracePolicy = "metadata_only"
		case ModeWireGenGeneratedInterpretedDrift:
			p.WireShape.ControlPlan.Richness = base.WireShape.ControlPlan.Richness
		}
		refreshMetadata(p, mode, seed, i)
		if err := ir.Validate(p); err != nil {
			return nil, fmt.Errorf("%s mutant %d invalid: %w", mode, i, err)
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func TraceFixtures(mode string, profiles []*ir.Profile) [][]ktrace.Event {
	switch mode {
	case ModeFixedFirstContact:
		return fixedProtocolShapeTraces(mode, profiles, false)
	case ModePaddingNoiseOnly:
		return fixedProtocolShapeTraces(mode, profiles, true)
	default:
		return profileShapeTraces(mode, profiles)
	}
}

func applyFixedFirstContact(p, base *ir.Profile) {
	p.States = cloneStates(base.States)
	p.Transitions = cloneTransitions(base.Transitions)
	p.FirstContact = cloneFirstContact(base.FirstContact)
	p.Auth.ProofMessage = base.Auth.ProofMessage
}

func renameWireSymbols(p *ir.Profile, mode string, index int) {
	used := map[string]bool{}
	for i := range p.Messages {
		symbol := symbolFor(mode, "msg", index, i, 14)
		p.Messages[i].WireSymbol = symbol
		used[symbol] = true
	}
	for i := range p.FirstContact.Steps {
		symbol := symbolFor(mode, "fc", index, i, 12)
		for used[symbol] {
			symbol = symbolFor(mode, "fcx", index, i, 12)
		}
		p.FirstContact.Steps[i].WireSymbol = symbol
		used[symbol] = true
	}
}

func refreshMetadata(p *ir.Profile, mode string, seed int64, index int) {
	refreshWireShapeHash(p)
	p.ID = fmt.Sprintf("mutant_%s_%03d", strings.ReplaceAll(mode, "-", "_"), index)
	p.Seed = seed
	p.GenerationHash = ""
	p.Auth.KeyID = fmt.Sprintf("test-only-mutant-%s-%03d", shortMode(mode), index)
	p.Auth.TestKeyHex = testKeyHex(mode, seed, index)
	hash, err := ir.CanonicalHash(p)
	if err == nil {
		p.GenerationHash = hash
	}
}

func refreshWireShapeHash(p *ir.Profile) {
	if p == nil || p.WireShape.Version == "" {
		return
	}
	policy := wiregen.FromIRPolicy(p.WireShape)
	policy.PolicyHash = ""
	hash, err := wiregen.PolicyHash(policy)
	if err == nil {
		p.WireShape.PolicyHash = hash
	}
}

func paddingForIndex(index int) ir.PaddingPolicy {
	minPad := index % 8
	return ir.PaddingPolicy{
		Mode:            "bounded",
		MinPaddingBytes: minPad,
		MaxPaddingBytes: minPad + 8 + (index % 5),
		Probability:     1,
	}
}

func profileShapeTraces(mode string, profiles []*ir.Profile) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, len(profiles))
	for i, p := range profiles {
		var events []ktrace.Event
		for j, step := range p.FirstContact.Steps {
			events = append(events, ktrace.Event{
				TimeUnixNano:  fixtureTime(j),
				ProfileID:     p.ID,
				EventType:     "first_contact",
				State:         step.ToState,
				Semantic:      step.Message,
				Direction:     step.Direction,
				FrameBytes:    contactFrameBytes(step),
				PayloadBytes:  step.PayloadSize,
				SchedulerMode: p.Scheduler.Mode,
			})
		}
		events = append(events,
			ktrace.Event{TimeUnixNano: fixtureTime(20), ProfileID: p.ID, EventType: "frame_encode", State: p.FirstContact.RelayReadyState, Semantic: ir.SemanticData, Direction: "client_to_server", FrameBytes: 80 + i%17, PayloadBytes: 64, PaddingBytes: p.Padding.MinPaddingBytes, SchedulerMode: p.Scheduler.Mode},
			ktrace.Event{TimeUnixNano: fixtureTime(21), ProfileID: p.ID, EventType: "frame_decode", State: p.FirstContact.RelayReadyState, Semantic: ir.SemanticData, Direction: "server_to_client", FrameBytes: 82 + i%19, PayloadBytes: 64, PaddingBytes: p.Padding.MinPaddingBytes, SchedulerMode: p.Scheduler.Mode},
			ktrace.Event{TimeUnixNano: fixtureTime(22), ProfileID: p.ID, EventType: "invalid_input", Note: p.InvalidInput.FailedAuth},
			ktrace.Event{TimeUnixNano: fixtureTime(23), ProfileID: p.ID, EventType: "malformed_frame", Note: p.InvalidInput.MalformedFrame},
			ktrace.Event{TimeUnixNano: fixtureTime(24), ProfileID: p.ID, EventType: "close", Note: p.InvalidInput.UnknownFirstMessage},
		)
		traces = append(traces, events)
	}
	return traces
}

func fixedProtocolShapeTraces(mode string, profiles []*ir.Profile, noisyPadding bool) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, len(profiles))
	for i, p := range profiles {
		padA, padB := 0, 0
		if noisyPadding {
			padA = (i * 7) % 24
			padB = (i * 11) % 24
		}
		traces = append(traces, []ktrace.Event{
			{TimeUnixNano: fixtureTime(0), ProfileID: p.ID, EventType: "first_contact", State: "s0", Semantic: "setup", Direction: "client_to_server", FrameBytes: 36, PayloadBytes: 20, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(1), ProfileID: p.ID, EventType: "first_contact", State: "s1", Semantic: "reply", Direction: "server_to_client", FrameBytes: 32, PayloadBytes: 16, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(2), ProfileID: p.ID, EventType: "first_contact", State: "s2", Semantic: "proof", Direction: "client_to_server", FrameBytes: 48, PayloadBytes: 32, PaddingBytes: 0, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(3), ProfileID: p.ID, EventType: "frame_encode", State: "s2", Semantic: ir.SemanticData, Direction: "client_to_server", FrameBytes: 96 + padA, PayloadBytes: 64, PaddingBytes: padA, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(4), ProfileID: p.ID, EventType: "frame_decode", State: "s2", Semantic: ir.SemanticData, Direction: "server_to_client", FrameBytes: 96 + padB, PayloadBytes: 64, PaddingBytes: padB, SchedulerMode: p.Scheduler.Mode},
			{TimeUnixNano: fixtureTime(5), ProfileID: p.ID, EventType: "invalid_input", Note: "fixed_invalid"},
			{TimeUnixNano: fixtureTime(6), ProfileID: p.ID, EventType: "malformed_frame", Note: "fixed_malformed"},
			{TimeUnixNano: fixtureTime(7), ProfileID: p.ID, EventType: "close", Note: "fixed_close"},
		})
	}
	return traces
}

func contactFrameBytes(step ir.FirstContactStep) int {
	return 1 + len(step.WireSymbol) + 2 + step.PayloadSize
}

func fixtureTime(index int) int64 {
	return 1_700_000_000_000_000_000 + int64(index)*1_000_000
}

func cloneProfile(p *ir.Profile) *ir.Profile {
	raw, _ := json.Marshal(p)
	var out ir.Profile
	_ = json.Unmarshal(raw, &out)
	return &out
}

func cloneFrameGrammar(in ir.FrameGrammar) ir.FrameGrammar {
	out := in
	out.HeaderOrder = append([]string(nil), in.HeaderOrder...)
	return out
}

func cloneStates(in []ir.State) []ir.State {
	return append([]ir.State(nil), in...)
}

func cloneTransitions(in []ir.Transition) []ir.Transition {
	return append([]ir.Transition(nil), in...)
}

func cloneFirstContact(in ir.FirstContactSpec) ir.FirstContactSpec {
	out := in
	out.Steps = append([]ir.FirstContactStep(nil), in.Steps...)
	return out
}

func symbolFor(mode, kind string, index, ordinal, length int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:%d", mode, kind, index, ordinal)))
	raw := hex.EncodeToString(sum[:])
	if length < 2 {
		length = 2
	}
	return "m" + raw[:length-1]
}

func testKeyHex(mode string, seed int64, index int) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("mutant-test-key:%s:%d:%d", mode, seed, index)))
	return hex.EncodeToString(sum[:])
}

func shortMode(mode string) string {
	clean := strings.ReplaceAll(mode, "_", "-")
	if len(clean) <= 20 {
		return clean
	}
	return clean[:20]
}

func knownMode(mode string) bool {
	modes := Modes()
	sort.Strings(modes)
	i := sort.SearchStrings(modes, mode)
	return i < len(modes) && modes[i] == mode
}

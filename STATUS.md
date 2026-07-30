<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Protocol Compiler Status

> Staged product-development program. Phases 8-11 add bounded profile cryptography, protected Android state, a reserved-range `VpnService`/TUN runtime, and authenticated Kurd-over-TLS/TCP owned-loopback conformance. Owned-network, public-relay, field-resilience, production-safety, deployment, and release evidence remains **[UNVERIFIED]**.

> Legend: `[live]` executes real behavior locally (current network I/O remains owned-loopback-only) · `[model]` deterministic in-memory contract, not live · `[plan]` design spec only. The audit table includes many historical `[model]`/`[plan]` gates; the separate Phase 9-11 Android and transport boundary is enforced by `go run ./cmd/gate -android` and `docs/PHASE11_EVIDENCE_INDEX.md`. The security and runtime mutant gates report real lab fault-injection detector sensitivity with paired controls. A pass does not prove defect absence, production security, field resilience, release readiness, or authorization to merge or deploy.

- Latest audit mode: `full`
- Profile count: `1000`
- Trace count: `100`
- Conclusion: `passed`

## Gate Results

| Gate | Result | Severity | Summary |
| --- | --- | --- | --- |
| `profile_corpus_diversity` | PASS | `required` | 1000 profiles checked; 0 failures |
| `black_box_trace_diversity` | PASS | `required` | 100 traces scanned; 0 suspicious metrics |
| `adversarial_black_box_clustering` | PASS | `required` | 100 traces clustered into 3 groups; 0 failures |
| `fixed_signature` | PASS | `required` | 7 fixed-signature metrics checked; 0 failures |
| `cosmetic_difference` | PASS | `required` | cosmetic profile and timestamp-only trace controls evaluated |
| `same_profile_consistency` | PASS | `required` | suspiciously similar |
| `different_profile_separation` | PASS | `required` | 4950/4950 trace pairs separated |
| `malformed_probe_behavior` | PASS | `required` | invalid-input behavior distribution checked |
| `multi_stream_semantics` | PASS | `required` | 4 profiles exercised with local multi-stream echo |
| `multi_stream_diversity` | PASS | `required` | 980 stream policy combinations across 1000 profiles |
| `multi_stream_backpressure` | PASS | `required` | 1 profile backpressure scenarios exercised |
| `multi_stream_adversarial_scenarios` | PASS | `required` | 9 scenario runs checked; 0 correctness failures |
| `multi_stream_collapse_resistance` | PASS | `required` | 2 scenarios scanned; 0 suspicious metrics |
| `multi_stream_mutant_detection` | PASS | `required` | 6/6 stream mutant modes detected |
| `proxy_semantics_correctness` | PASS | `required` | 9 proxy scenario runs checked; 0 failures |
| `proxy_semantics_diversity` | PASS | `required` | 999 proxy policy combinations across 1000 profiles |
| `proxy_target_backpressure` | PASS | `required` | 11 target-induced backpressure events observed |
| `proxy_error_reset_isolation` | PASS | `required` | 2 target errors and 2 target resets observed |
| `proxy_mutant_detection` | PASS | `required` | 7/7 proxy mutant modes detected |
| `proxy_generated_backend_parity` | PASS | `required` | generated backend proxysem support markers checked |
| `carrier_semantics_correctness` | PASS | `required` | 9 carrier scenario runs checked; 0 failures |
| `carrier_diversity` | PASS | `required` | 999 carrier policy combinations across 1000 profiles |
| `carrier_backpressure_preservation` | PASS | `required` | 23 carrier/target backpressure events observed |
| `carrier_loss_reorder_recovery` | PASS | `required` | 40 reorder and 12 retry events observed |
| `carrier_proxysem_parity` | PASS | `required` | 2 proxysem carrier parity runs checked |
| `carrier_mutant_detection` | PASS | `required` | 8/8 carrier mutant modes detected |
| `carrier_generated_backend_parity` | PASS | `required` | generated backend carrier support markers checked |
| `security_transcript_binding` | PASS | `required` | 3 profiles checked for transcript binding |
| `security_key_schedule` | PASS | `required` | 1 security suites exercised |
| `security_nonce_uniqueness` | PASS | `required` | 2 nonce modes exercised |
| `security_replay_rejection` | PASS | `required` | duplicate and out-of-order replay checks evaluated |
| `security_downgrade_resistance` | PASS | `required` | 2 downgrade policies exercised |
| `security_capability_negotiation` | PASS | `required` | 3 capability policies exercised |
| `security_profile_compatibility` | PASS | `required` | 6 compatibility checks run |
| `security_config_hygiene` | PASS | `required` | 6 config hygiene checks run |
| `security_secret_trace_hygiene` | PASS | `required` | 3 secret trace hygiene checks run |
| `security_mutant_detection` | PASS | `required` | 8/8 real lab fault-injection detector sensitivity pairs passed; a pass proves only that each named detector turns red under its bounded deliberate fault and stays green in its control; it does not prove defect absence, production security, product integration, release readiness, or authorization to merge or deploy |
| `security_generated_backend_parity` | PASS | `required` | generated security markers and bounded M0 G1-G13 integration evidence checked |
| `runtime_session_lifecycle` | PASS | `required` | 9 runtime sessions checked |
| `runtime_capability_negotiation` | PASS | `required` | 3 capability downgrade attempts rejected |
| `runtime_profile_compatibility` | PASS | `required` | 3 profile mismatch attempts rejected |
| `runtime_security_context` | PASS | `required` | 6 security contexts created and matched |
| `runtime_replay_rejection` | PASS | `required` | 3 replay attempts rejected |
| `runtime_stream_management` | PASS | `required` | 72 runtime stream messages managed |
| `runtime_backpressure` | PASS | `required` | 137 runtime backpressure events observed |
| `runtime_error_reset_isolation` | PASS | `required` | 6 target errors and 6 target resets isolated |
| `runtime_trace_hygiene` | PASS | `required` | 3 runtime traces checked for payload/secret hygiene |
| `runtime_mutant_detection` | PASS | `required` | 8/8 real lab fault-injection detector sensitivity pairs passed; a pass proves only that each named detector turns red under its bounded deliberate fault and stays green in its control; it does not prove defect absence, production security, product integration, release readiness, or authorization to merge or deploy |
| `runtime_generated_backend_parity` | PASS | `required` | generated runtime markers plus exact 29-row generated/interpreted policy evidence registry checked |
| `adapter_interface_contracts` | PASS | `required` | adapter ingress/egress contract inputs validated |
| `adapter_config_validation` | PASS | `required` | adapter config validation and redaction checks run |
| `adapter_flow_lifecycle` | PASS | `required` | adapter flow lifecycle transitions checked |
| `adapter_runtime_boundary` | PASS | `required` | 9 adapter/runtime scenario runs checked |
| `adapter_capability_compatibility` | PASS | `required` | adapter capability compatibility and downgrade checks run |
| `adapter_backpressure` | PASS | `required` | 18 adapter backpressure events observed |
| `adapter_error_reset_mapping` | PASS | `required` | 3 target errors and 3 target resets mapped to adapter-safe outcomes |
| `adapter_trace_hygiene` | PASS | `required` | 3 adapter traces checked for payload/secret hygiene |
| `adapter_collapse_resistance` | PASS | `required` | 2 adapter collapse reports evaluated |
| `adapter_mutant_detection` | PASS | `required` | 8/8 adapter mutant modes detected |
| `adapter_generated_backend_parity` | PASS | `required` | generated backend adapter support markers checked |
| `local_adapter_correctness` | PASS | `required` | 9 local adapter scenario runs checked |
| `local_adapter_flow_lifecycle` | PASS | `required` | 3 local adapter lifecycle runs checked |
| `local_adapter_runtime_integration` | PASS | `required` | 9 runtime/local adapter mappings checked |
| `local_adapter_backpressure` | PASS | `required` | 36 local adapter backpressure events observed |
| `local_adapter_error_reset_isolation` | PASS | `required` | 3 target errors and 3 target resets mapped locally |
| `local_adapter_sequence_integrity` | PASS | `required` | 3 malformed local chunks rejected |
| `local_adapter_trace_hygiene` | PASS | `required` | 3 local adapter traces checked |
| `local_adapter_collapse_resistance` | PASS | `required` | 2 local adapter collapse reports evaluated |
| `local_adapter_mutant_detection` | PASS | `required` | 8/8 local adapter mutant modes detected |
| `local_adapter_generated_backend_parity` | PASS | `required` | generated backend local adapter support markers checked |
| `byte_transport_encoding_correctness` | PASS | `required` | 9 byte transport scenario runs checked |
| `byte_transport_fragmentation_reassembly` | PASS | `required` | 105 fragments created; 0 reassemblies observed |
| `byte_transport_pipe_backpressure` | PASS | `required` | 54 byte pipe backpressure events observed |
| `byte_transport_sequence_integrity` | PASS | `required` | 3 replay/sequence frames rejected |
| `byte_transport_corruption_rejection` | PASS | `required` | 3 corrupted frames rejected |
| `byte_transport_runtime_integration` | PASS | `required` | 9 byte runtime mappings checked |
| `byte_transport_error_reset_isolation` | PASS | `required` | 0 byte reset/error paths observed |
| `byte_transport_trace_hygiene` | PASS | `required` | 3 byte transport traces checked |
| `byte_transport_collapse_resistance` | PASS | `required` | 2 byte collapse reports evaluated |
| `byte_transport_mutant_detection` | PASS | `required` | 8/8 byte transport mutant modes detected |
| `byte_transport_generated_backend_parity` | PASS | `required` | generated backend byte transport support markers checked |
| `fixture_bytepath_drift` | PASS | `required` | 21 bytepath fixtures checked for drift |
| `bytepath_fixture_stability` | PASS | `required` | 21 bytepath fixtures match committed golden set |
| `bytepath_generated_interpreted_parity` | PASS | `required` | 21/21 generated/interpreted bytepath summaries match semantically |
| `bytepath_malformed_corpus` | PASS | `required` | 21 malformed byte corpus cases checked |
| `bytepath_regression_baselines` | PASS | `required` | 21 entries across 3 seeds and 7 scenarios |
| `bytepath_fixture_trace_hygiene` | PASS | `required` | 21 bytepath fixture entries scanned for payload/secret leakage |
| `protocorpus_schema_valid` | PASS | `required` | 12 protocol corpus entries validated |
| `protocorpus_feature_taxonomy` | PASS | `required` | 12 field kinds and 6 phase kinds checked |
| `protocorpus_entry_coverage` | PASS | `required` | 12 entries across 9 families |
| `protocorpus_trace_hygiene` | PASS | `required` | protocol corpus scanned for unsafe feature material |
| `wirefeatures_extraction` | PASS | `required` | 21 wire feature vectors extracted from 21 fixtures |
| `wirefeatures_firstn_model` | PASS | `required` | 3 unique first-n packet shapes found |
| `wirefeatures_corpus_comparison` | PASS | `required` | 2 corpus families matched by generated features |
| `wirefeatures_collapse_resistance` | PASS | `required` | 21 feature hashes and 3 first-n shapes checked |
| `wirefeatures_generated_backend_parity` | PASS | `required` | generated backend protocol corpus and wirefeature markers checked |
| `wirefeatures_mutant_detection` | PASS | `required` | 8/8 wirefeature mutant modes detected |
| `wirefeatures_baseline_fixtures` | PASS | `required` | 21 wirefeature baseline entries checked |
| `wiregen_policy_generation` | PASS | `required` | 1000 policies and 1000 unique hashes |
| `wiregen_policy_validation` | PASS | `required` | 1000 policies validated |
| `wiregen_corpus_selection` | PASS | `required` | 12 entries across 9 families selected from 12 corpus entries |
| `wiregen_profile_integration` | PASS | `required` | 1000 profiles include wire-shape policy sections |
| `wiregen_bytepath_application` | PASS | `required` | 7000 bytepath feature vectors carry wire-shape metadata |
| `wiregen_feature_expectation_match` | PASS | `required` | 7000 policy-feature pairs compared |
| `wiregen_firstn_diversity` | PASS | `required` | 18 unique first-n policy shapes |
| `wiregen_metadata_exposure_diversity` | PASS | `required` | 5 metadata exposure classes |
| `wiregen_collapse_resistance` | PASS | `required` | 1000 policy hashes, 9 families, 2 fragment rhythms |
| `wiregen_mutant_detection` | PASS | `required` | 8/8 wiregen mutant modes detected |
| `wiregen_generated_backend_parity` | PASS | `required` | generated backend wire-shape markers checked |
| `wiregen_trace_hygiene` | PASS | `required` | 1000 policies and 7000 feature vectors scanned |
| `wiregen_baseline_fixtures` | PASS | `required` | 35 wiregen baseline entries checked |
| `wireeval_dataset_build` | PASS | `required` | 72 records across 8 profiles |
| `wireeval_dataset_schema` | PASS | `required` | 72 records validated against wireeval-v1 |
| `wireeval_split_integrity` | PASS | `required` | train=14 test=14 ood=14 holdout=30 |
| `wireeval_export_consistency` | PASS | `required` | 72 records exported as CSV and JSONL |
| `wireeval_observable_diversity` | PASS | `required` | 68 unique feature hashes and 8 first-n shapes |
| `wireeval_control_detection` | PASS | `required` | 12 collapsed controls and 4 padding-only controls detected |
| `wireeval_classifier_readiness` | PASS | `required` | 72 records, 23 feature columns |
| `wireeval_dataset_drift` | PASS | `required` | 72 old records compared to 72 new records |
| `wireeval_generated_backend_parity` | PASS | `required` | generated backend wireeval markers checked |
| `wireeval_trace_hygiene` | PASS | `required` | 72 records and classifier exports scanned |
| `wireeval_mutant_detection` | PASS | `required` | 12/12 wireeval mutant modes detected |
| `hostdetect_observation_build` | PASS | `required` | 72 observations across 9 synthetic hosts |
| `hostdetect_assignment_integrity` | PASS | `required` | 3 assignment modes checked |
| `hostdetect_timeline_integrity` | PASS | `required` | 2 timeline windows checked |
| `hostdetect_confidence_model` | PASS | `required` | 3/9 hosts flagged |
| `hostdetect_resistance_metrics` | PASS | `required` | 9 hosts, 0.51 average consistency |
| `hostdetect_collapse_detection` | PASS | `required` | 0 high-consistency hosts, 1 padding-only hosts |
| `hostdetect_control_detection` | PASS | `required` | 3 control hosts flagged |
| `hostdetect_generated_backend_parity` | PASS | `required` | generated backend hostdetect markers checked |
| `hostdetect_trace_hygiene` | PASS | `required` | 72 host observations scanned |
| `hostdetect_mutant_detection` | PASS | `required` | 12/12 hostdetect mutant modes detected |
| `hostdetect_fixture_drift` | PASS | `required` | 72 old observations compared to 72 new observations |
| `relayfleet_lifecycle_integrity` | PASS | `required` | 9 relays, 4 active |
| `relayfleet_profile_assignment` | PASS | `required` | 8 profile seeds, 8 wire policies |
| `relayfleet_churn_schedule` | PASS | `required` | 6 churn events using mixed_policy_churn |
| `relayfleet_migration_model` | PASS | `required` | 2 migration events using risk_triggered_migration |
| `relayfleet_burn_risk` | PASS | `required` | 1 high-risk and 2 critical relays |
| `relayfleet_collapse_detection` | PASS | `required` | 8 profile seeds, 8 wire policies, 0.85 diversity |
| `relayfleet_control_detection` | PASS | `required` | 3/3 control relays high-risk |
| `relayfleet_generated_backend_parity` | PASS | `required` | generated backend relayfleet markers checked |
| `relayfleet_trace_hygiene` | PASS | `required` | 9 relay records scanned |
| `relayfleet_mutant_detection` | PASS | `required` | 15/15 relayfleet mutant modes detected |
| `relayfleet_fixture_drift` | PASS | `required` | 9 old relays compared to 9 new relays |
| `proxyingress_contract_validation` | PASS | `required` | proxyingress_contract_v1 |
| `proxyingress_target_descriptor_safety` | PASS | `required` | 3 valid targets checked |
| `proxyingress_capability_mapping` | PASS | `required` | 13 required capabilities |
| `proxyingress_runtime_mapping` | PASS | `required` | 3 mapping plans |
| `proxyingress_lifecycle_integrity` | PASS | `required` | 12 lifecycle events |
| `proxyingress_failure_mode_matrix` | PASS | `required` | 19 failure modes |
| `proxyingress_design_review` | PASS | `required` | go_for_deterministic_prototype |
| `proxyingress_misuse_detection` | PASS | `required` | 3 requests scanned |
| `proxyingress_generated_backend_parity` | PASS | `required` | 1 contracts compared |
| `proxyingress_trace_hygiene` | PASS | `required` | contract and fixtures are metadata-only |
| `proxyingress_mutant_detection` | PASS | `required` | 14 mutants represented |
| `proxyingress_fixture_drift` | PASS | `required` | passed |
| `localproxyingress_contract_compliance` | PASS | `required` | 3 scenarios |
| `localproxyingress_target_validation` | PASS | `required` | synthetic targets only |
| `localproxyingress_lifecycle_execution` | PASS | `required` | terminal states enforced |
| `localproxyingress_runtime_mapping` | PASS | `required` | 6 mappings |
| `localproxyingress_backpressure` | PASS | `required` | 1 pressure events |
| `localproxyingress_error_reset_isolation` | PASS | `required` | reset and error summaries are request-scoped |
| `localproxyingress_queue_bounds` | PASS | `required` | bounded queues |
| `localproxyingress_collapse_resistance` | PASS | `required` | 3 unique summaries |
| `localproxyingress_generated_backend_parity` | PASS | `required` | 3 scenarios compared |
| `localproxyingress_trace_hygiene` | PASS | `required` | summaries contain safe metadata only |
| `localproxyingress_mutant_detection` | PASS | `required` | 14 mutants represented |
| `localproxyingress_fixture_drift` | PASS | `required` | passed |
| `localproxyingressadv_corpus_validation` | PASS | `required` | localproxyingressadv-v1: 30 scenarios |
| `localproxyingressadv_descriptor_abuse` | PASS | `required` | 22 descriptor cases rejected |
| `localproxyingressadv_lifecycle_hardening` | PASS | `required` | 14/14 invalid transitions rejected |
| `localproxyingressadv_pressure_hardening` | PASS | `required` | 14 pressure scenarios; 4 overflows rejected |
| `localproxyingressadv_reset_error_isolation` | PASS | `required` | 5 resets and 5 errors isolated |
| `localproxyingressadv_mapping_collapse` | PASS | `required` | 3 unique target bindings; control findings=11 |
| `localproxyingressadv_generated_backend_parity` | PASS | `required` | 30 scenarios compared |
| `localproxyingressadv_m27_readiness` | PASS | `required` | go_for_local_proxy_egress_model |
| `localproxyingressadv_trace_hygiene` | PASS | `required` | adversarial fixtures contain safe metadata only |
| `localproxyingressadv_mutant_detection` | PASS | `required` | 15 mutants represented |
| `localproxyingressadv_fixture_drift` | PASS | `required` | passed |
| `adaptivepath_candidate_taxonomy` | PASS | `required` | 7 candidate families checked |
| `adaptivepath_condition_model` | PASS | `required` | 21 synthetic conditions checked |
| `adaptivepath_freshness_uncertainty` | PASS | `required` | 6 fresh, 2 stale, 5 expired observations |
| `adaptivepath_viability_evaluation` | PASS | `required` | 7 viability reports generated |
| `adaptivepath_decision_inputs` | PASS | `required` | 7 decision inputs built; no winner selected |
| `adaptivepath_misuse_detection` | PASS | `required` | healthy findings=0; control findings=2 |
| `adaptivepath_generated_backend_parity` | PASS | `required` | 7 candidates and 21 conditions compared |
| `adaptivepath_trace_hygiene` | PASS | `required` | adaptive path fixtures contain safe metadata only |
| `adaptivepath_mutant_detection` | PASS | `required` | 13 mutants represented |
| `adaptivepath_fixture_drift` | PASS | `required` | passed |
| `adaptivepath_roadmap_public_docs` | PASS | `required` | public adaptive site, roadmap, links, and claim-safety checked |
| `transportbundle_policy_validation` | PASS | `required` | 6 bundle policy modes checked |
| `transportbundle_seed_planning` | PASS | `required` | 6 unique profile seeds |
| `transportbundle_family_coverage` | PASS | `required` | 5 families covered |
| `transportbundle_adaptivepath_mapping` | PASS | `required` | 6 candidates mapped to adaptivepath |
| `transportbundle_relay_binding` | PASS | `required` | 6 synthetic relays and 5 synthetic hosts |
| `transportbundle_fallback_hints` | PASS | `required` | 6 fallback hints checked |
| `transportbundle_collapse_detection` | PASS | `required` | diversity score 0.94; control findings=3 |
| `transportbundle_generated_backend_parity` | PASS | `required` | 6 candidates compared |
| `transportbundle_trace_hygiene` | PASS | `required` | transport bundle fixtures contain safe metadata only |
| `transportbundle_mutant_detection` | PASS | `required` | 15 mutants represented |
| `transportbundle_fixture_drift` | PASS | `required` | passed |
| `pathrace_scenario_validation` | PASS | `required` | 14 scenarios checked |
| `pathrace_parallel_scheduler` | PASS | `required` | 14 race runs scheduled |
| `pathrace_candidate_verification` | PASS | `required` | 10 verified candidate outcomes |
| `pathrace_short_lived_scoring` | PASS | `required` | 75 score buckets checked |
| `pathrace_ranking_tiebreak` | PASS | `required` | 6 ranked candidates |
| `pathrace_misuse_detection` | PASS | `required` | 6 control findings |
| `pathrace_generated_backend_parity` | PASS | `required` | 14 scenarios compared |
| `pathrace_trace_hygiene` | PASS | `required` | pathrace fixtures contain safe metadata only |
| `pathrace_mutant_detection` | PASS | `required` | 16 mutants represented |
| `pathrace_fixture_drift` | PASS | `required` | passed |
| `pathhealth_active_monitor` | PASS | `required` | 17 active-path scenarios checked |
| `pathhealth_degradation_detection` | PASS | `required` | 13 severe/critical and 2 degraded reports |
| `pathhealth_score_decay` | PASS | `required` | 5 low and 9 zero score outcomes |
| `pathhealth_failover_decision` | PASS | `required` | 7 completed and 3 blocked failover outcomes |
| `pathhealth_relay_burn_quarantine` | PASS | `required` | 1 quarantine decisions |
| `pathhealth_control_detection` | PASS | `required` | 6 control findings |
| `pathhealth_generated_backend_parity` | PASS | `required` | 17 scenarios compared |
| `pathhealth_trace_hygiene` | PASS | `required` | pathhealth fixtures contain safe metadata only |
| `pathhealth_mutant_detection` | PASS | `required` | 16/16 pathhealth mutant modes detected |
| `pathhealth_fixture_drift` | PASS | `required` | passed |
| `carrierreview_family_descriptors` | PASS | `required` | 5 carrier families reviewed |
| `carrierreview_readiness_matrix` | PASS | `required` | 12 matrix layers checked |
| `carrierreview_risk_gating` | PASS | `required` | 3 manual and 2 gated families |
| `carrierreview_misuse_detection` | PASS | `required` | 5 descriptors scanned |
| `carrierreview_generated_backend_parity` | PASS | `required` | 5 families compared |
| `carrierreview_trace_hygiene` | PASS | `required` | carrier review fixtures contain safe metadata only |
| `carrierreview_mutant_detection` | PASS | `required` | 15/15 carrierreview mutant modes detected |
| `carrierreview_fixture_drift` | PASS | `required` | passed |
| `measurementreview_observation_schema` | PASS | `required` | 18 observation fields checked |
| `measurementreview_redaction_policy` | PASS | `required` | 18 bucketed fields |
| `measurementreview_consent_retention` | PASS | `required` | local_only/session_only |
| `measurementreview_local_diagnostics` | PASS | `required` | 18 diagnostic fields |
| `measurementreview_privacy_readiness` | PASS | `required` | M33: local proxy egress and relay bridge model |
| `measurementreview_misuse_detection` | PASS | `required` | 18 fields scanned |
| `measurementreview_generated_backend_parity` | PASS | `required` | 18 fields compared |
| `measurementreview_trace_hygiene` | PASS | `required` | measurement review fixtures contain safe metadata only |
| `measurementreview_mutant_detection` | PASS | `required` | 15/15 measurementreview mutant modes detected |
| `measurementreview_fixture_drift` | PASS | `required` | passed |
| `proxyegress_contract_validation` | PASS | `required` | 13 requests checked |
| `proxyegress_target_model` | PASS | `required` | 8 target classes |
| `proxyegress_ingress_mapping` | PASS | `required` | 13 streams mapped |
| `proxyegress_adaptive_binding` | PASS | `required` | 16 bindings checked |
| `proxyegress_lifecycle_execution` | PASS | `required` | 16 lifecycle reports |
| `proxyegress_backpressure` | PASS | `required` | 6 pressure events |
| `proxyegress_reset_error_isolation` | PASS | `required` | 1 resets, 8 errors |
| `proxyegress_misuse_detection` | PASS | `required` | 1 objects scanned |
| `proxyegress_generated_backend_parity` | PASS | `required` | 16 scenarios compared |
| `proxyegress_trace_hygiene` | PASS | `required` | proxy egress summaries contain safe metadata only |
| `proxyegress_mutant_detection` | PASS | `required` | 16/16 proxyegress mutant modes detected |
| `proxyegress_fixture_drift` | PASS | `required` | passed |
| `relaybridge_session_validation` | PASS | `required` | 12 sessions checked |
| `relaybridge_stream_mapping` | PASS | `required` | 12 streams mapped |
| `relaybridge_adaptive_runtime_binding` | PASS | `required` | 15 bindings checked |
| `relaybridge_backpressure` | PASS | `required` | 6 backpressure events |
| `relaybridge_reset_error_isolation` | PASS | `required` | 1 resets, 8 errors |
| `relaybridge_stream_isolation` | PASS | `required` | 12 streams isolated |
| `relaybridge_misuse_detection` | PASS | `required` | 1 objects scanned |
| `relaybridge_generated_backend_parity` | PASS | `required` | 15 scenarios compared |
| `relaybridge_trace_hygiene` | PASS | `required` | relay bridge summaries contain safe metadata only |
| `relaybridge_mutant_detection` | PASS | `required` | 13/13 relaybridge mutant modes detected |
| `relaybridge_fixture_drift` | PASS | `required` | passed |
| `localpipeline_correctness` | PASS | `required` | 12 runs checked |
| `localpipeline_boundary_integration` | PASS | `required` | 12 scenarios bound |
| `localpipeline_backpressure` | PASS | `required` | 23 pressure events |
| `localpipeline_error_reset_isolation` | PASS | `required` | 8 errors, 2 resets |
| `localpipeline_descriptor_rejection` | PASS | `required` | 2 descriptor rejections |
| `localpipeline_trace_hygiene` | PASS | `required` | local pipeline summaries contain safe metadata only |
| `localpipeline_collapse_resistance` | PASS | `required` | diversity 0.83 |
| `localpipeline_generated_backend_parity` | PASS | `required` | 12 scenarios compared |
| `localpipeline_mutant_detection` | PASS | `required` | 11/11 localpipeline mutant modes detected |
| `localpipeline_fixture_drift` | PASS | `required` | passed |
| `productionreadiness_inventory` | PASS | `required` | 20 readiness items checked |
| `productionreadiness_dependency_graph` | PASS | `required` | 15 dependency edges checked |
| `productionreadiness_real_io_boundary` | PASS | `required` | 5 closed boundaries checked |
| `productionreadiness_future_contracts` | PASS | `required` | 4 future contracts checked |
| `productionreadiness_blocker_register` | PASS | `required` | 5 blockers tracked; 4 required blockers unresolved |
| `productionreadiness_trace_hygiene` | PASS | `required` | production readiness review contains safe metadata only |
| `productionreadiness_generated_backend_parity` | PASS | `required` | 20 items and 4 contracts compared |
| `productionreadiness_mutant_detection` | PASS | `required` | 8/8 productionreadiness mutant modes detected |
| `productionreadiness_fixture_drift` | PASS | `required` | passed |
| `concretelocaladapter_bind_policy` | PASS | `required` | 6 unsafe bind controls checked |
| `concretelocaladapter_loopback_listener` | PASS | `required` | 3 loopback connections accepted |
| `concretelocaladapter_flow_lifecycle` | PASS | `required` | 18 opened flows; 18 terminal flows |
| `concretelocaladapter_runtime_mapping` | PASS | `required` | 18 runtime stream mappings checked |
| `concretelocaladapter_backpressure` | PASS | `required` | 4 backpressure events observed |
| `concretelocaladapter_error_reset_isolation` | PASS | `required` | 1 errors and 4 resets mapped safely |
| `concretelocaladapter_trace_hygiene` | PASS | `required` | socket summaries contain safe metadata only |
| `concretelocaladapter_no_external_io` | PASS | `required` | external and wildcard binds are rejected |
| `concretelocaladapter_generated_backend_parity` | PASS | `required` | 10 summaries compared |
| `concretelocaladapter_mutant_detection` | PASS | `required` | 8/8 concrete local adapter mutant modes detected |
| `concretelocaladapter_fixture_drift` | PASS | `required` | passed |
| `localprotocoladapter_config_validation` | PASS | `required` | 8 configs checked |
| `localprotocoladapter_connect_like_parser` | PASS | `required` | 5 CONNECT-like parser runs |
| `localprotocoladapter_socks5_like_parser` | PASS | `required` | 4 SOCKS5-like parser runs |
| `localprotocoladapter_target_redaction` | PASS | `required` | 5 targets redacted |
| `localprotocoladapter_state_machine` | PASS | `required` | 9 parser transitions checked |
| `localprotocoladapter_concrete_adapter_integration` | PASS | `required` | 5 local connection descriptors checked |
| `localprotocoladapter_localpipeline_mapping` | PASS | `required` | 3 localpipeline mappings |
| `localprotocoladapter_resource_limits` | PASS | `required` | 2 resource limit controls |
| `localprotocoladapter_error_redaction` | PASS | `required` | parser errors are stable classes |
| `localprotocoladapter_misuse_detection` | PASS | `required` | 8 unsafe controls detected |
| `localprotocoladapter_generated_backend_parity` | PASS | `required` | 5 requests compared |
| `localprotocoladapter_trace_hygiene` | PASS | `required` | local protocol fixtures contain safe metadata only |
| `localprotocoladapter_mutant_detection` | PASS | `required` | 8/8 localprotocoladapter mutant modes detected |
| `localprotocoladapter_fixture_drift` | PASS | `required` | passed |
| `loopbackrelay_bind_policy` | PASS | `required` | 4 unsafe controls rejected |
| `loopbackrelay_session_lifecycle` | PASS | `required` | 8 sessions closed |
| `loopbackrelay_handshake` | PASS | `required` | 8 handshakes completed |
| `loopbackrelay_frame_round_trip` | PASS | `required` | 44 frames round-tripped |
| `loopbackrelay_backpressure` | PASS | `required` | 2 backpressure events |
| `loopbackrelay_reset_isolation` | PASS | `required` | 1 resets observed |
| `loopbackrelay_malformed_input` | PASS | `required` | 1 malformed inputs rejected |
| `loopbackrelay_resource_limits` | PASS | `required` | bounded sessions, frames, queues, and events |
| `loopbackrelay_trace_hygiene` | PASS | `required` | loopback relay summaries contain safe metadata only |
| `loopbackrelay_generated_backend_parity` | PASS | `required` | 8 sessions compared |
| `loopbackrelay_mutant_detection` | PASS | `required` | 7/7 loopback relay mutant modes detected |
| `loopbackrelay_fixture_drift` | PASS | `required` | passed |
| `labegress_allowlist_validation` | PASS | `required` | 4 unsafe targets rejected |
| `labegress_connector_lifecycle` | PASS | `required` | 8 connections closed |
| `labegress_fixture_exchange` | PASS | `required` | 15/20 chunks written/read |
| `labegress_target_backpressure` | PASS | `required` | 2 backpressure events |
| `labegress_error_reset_isolation` | PASS | `required` | 1 errors, 1 resets |
| `labegress_half_close` | PASS | `required` | half-close metadata checked |
| `labegress_queue_limits` | PASS | `required` | 1 queue pressure events |
| `labegress_trace_hygiene` | PASS | `required` | lab egress summaries contain safe metadata only |
| `labegress_generated_backend_parity` | PASS | `required` | 8 exchanges compared |
| `labegress_mutant_detection` | PASS | `required` | 7/7 lab egress mutant modes detected |
| `labegress_fixture_drift` | PASS | `required` | passed |
| `carrierreadiness_inventory` | PASS | `required` | 6 inventory items checked |
| `carrierreadiness_dependency_graph` | PASS | `required` | 5 dependency edges checked |
| `carrierreadiness_boundary_policy` | PASS | `required` | 5 boundaries enforced |
| `carrierreadiness_future_contracts` | PASS | `required` | 3 future contracts scoped |
| `carrierreadiness_blocker_register` | PASS | `required` | 5 blockers tracked |
| `carrierreadiness_risk_matrix` | PASS | `required` | 4 risk items checked |
| `carrierreadiness_checklist` | PASS | `required` | 6 checklist items checked |
| `carrierreadiness_public_claim_safety` | PASS | `required` | public claim safety markers checked |
| `carrierreadiness_generated_backend_parity` | PASS | `required` | 6 inventory items compared |
| `carrierreadiness_mutant_detection` | PASS | `required` | 7/7 carrier readiness mutant modes detected |
| `carrierreadiness_fixture_drift` | PASS | `required` | passed |
| `httpscarrierreview_scope_contract` | PASS | `required` | 12 blocked behaviors checked |
| `httpscarrierreview_shape_taxonomy` | PASS | `required` | 8 shape descriptors checked |
| `httpscarrierreview_stream_mapping` | PASS | `required` | stream open close reset and error mappings locked |
| `httpscarrierreview_backpressure_contract` | PASS | `required` | 3 carrier pressure signals |
| `httpscarrierreview_reset_error_contract` | PASS | `required` | 3 safe error buckets |
| `httpscarrierreview_integration_contract` | PASS | `required` | 6 integration contracts checked |
| `httpscarrierreview_m42_contract` | PASS | `required` | 11 M42 criteria locked |
| `httpscarrierreview_blocker_matrix` | PASS | `required` | 12 blockers enforced |
| `httpscarrierreview_risk_model` | PASS | `required` | 5 risks checked |
| `httpscarrierreview_checklist` | PASS | `required` | 10 checklist items checked |
| `httpscarrierreview_misuse_detection` | PASS | `required` | 10 unsafe controls detected |
| `httpscarrierreview_generated_backend_parity` | PASS | `required` | 5 generated markers checked |
| `httpscarrierreview_trace_hygiene` | PASS | `required` | fixture trace hygiene scanned |
| `httpscarrierreview_public_claim_safety` | PASS | `required` | public claim safety markers checked |
| `httpscarrierreview_mutant_detection` | PASS | `required` | 27/27 HTTPS carrier review mutant modes detected |
| `httpscarrierreview_fixture_drift` | PASS | `required` | passed |
| `httpslikecarrier_scope` | PASS | `required` | 20 blocked scopes checked |
| `httpslikecarrier_shape_selection` | PASS | `required` | 18 shape events and 18 diversity fingerprints |
| `httpslikecarrier_session_lifecycle` | PASS | `required` | 4 sessions checked |
| `httpslikecarrier_stream_lifecycle` | PASS | `required` | 4 streams opened; 1 reset |
| `httpslikecarrier_fixture_exchange` | PASS | `required` | 12 fixtures; marker bucket <=96 |
| `httpslikecarrier_backpressure` | PASS | `required` | 4 pressure events |
| `httpslikecarrier_reset_error` | PASS | `required` | 1 resets and 1 target errors |
| `httpslikecarrier_relay_integration` | PASS | `required` | loopbackrelay labegress relaybridge proxyegress mappings checked |
| `httpslikecarrier_pipeline_integration` | PASS | `required` | localpipeline pathhealth carrierreview measurementreview mappings checked |
| `httpslikecarrier_runtime_security` | PASS | `required` | passed |
| `httpslikecarrier_resource_limits` | PASS | `required` | sessions=3 streams=8 marker=96 |
| `httpslikecarrier_misuse_detection` | PASS | `required` | 23 misuse controls detected |
| `httpslikecarrier_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `httpslikecarrier_trace_hygiene` | PASS | `required` | fixtures and summaries scanned for unsafe material |
| `httpslikecarrier_mutant_detection` | PASS | `required` | 23/23 HTTPS-like carrier mutant modes detected |
| `httpslikecarrier_fixture_drift` | PASS | `required` | passed |
| `httpscarrieradversary_collapse_detection` | PASS | `required` | diversity=0.83 dominant=0.34 pairs=8 |
| `httpscarrieradversary_profile_sensitivity` | PASS | `required` | 18 fingerprints; 3 generated markers |
| `httpscarrieradversary_padding_only_rejection` | PASS | `required` | 8 structural classes |
| `httpscarrieradversary_unsafe_fallback_detection` | PASS | `required` | 8 fallback categories blocked |
| `httpscarrieradversary_trace_hygiene` | PASS | `required` | 24 fixtures and 3 generated outputs scanned |
| `httpscarrieradversary_replay_controls` | PASS | `required` | 5 control marker classes |
| `httpscarrieradversary_stream_isolation` | PASS | `required` | 4 multi-stream fixtures |
| `httpscarrieradversary_backpressure` | PASS | `required` | 4 bounded pressure summaries |
| `httpscarrieradversary_reset_error` | PASS | `required` | 3 safe error classes |
| `httpscarrieradversary_integration_bypass` | PASS | `required` | 10 bypass controls rejected |
| `httpscarrieradversary_public_claim_safety` | PASS | `required` | 4 public docs scanned |
| `httpscarrieradversary_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `httpscarrieradversary_mutant_detection` | PASS | `required` | 24/24 HTTPS carrier adversary mutant modes detected |
| `httpscarrieradversary_fixture_drift` | PASS | `required` | passed |
| `constrainedcarrierreview_scope_contract` | PASS | `required` | 14 blocked behaviors |
| `constrainedcarrierreview_resolver_harness_contract` | PASS | `required` | 4 resolver buckets |
| `constrainedcarrierreview_query_shape_taxonomy` | PASS | `required` | 10 query shapes; 3 controls |
| `constrainedcarrierreview_response_shape_taxonomy` | PASS | `required` | 9 response shapes; 2 controls |
| `constrainedcarrierreview_size_truncation_contract` | PASS | `required` | 3 truncation buckets |
| `constrainedcarrierreview_retry_failure_contract` | PASS | `required` | 3 retry buckets |
| `constrainedcarrierreview_stream_mapping` | PASS | `required` | 4 stream mappings |
| `constrainedcarrierreview_privacy_measurement` | PASS | `required` | 6 safe fields |
| `constrainedcarrierreview_m45_contract` | PASS | `required` | 5 acceptance requirements |
| `constrainedcarrierreview_blocker_matrix` | PASS | `required` | 8 blockers resolved |
| `constrainedcarrierreview_risk_model` | PASS | `required` | 6 risks gated |
| `constrainedcarrierreview_checklist` | PASS | `required` | 10 checklist items |
| `constrainedcarrierreview_misuse_detection` | PASS | `required` | 23 misuse controls |
| `constrainedcarrierreview_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `constrainedcarrierreview_trace_hygiene` | PASS | `required` | fixture trace hygiene scanned |
| `constrainedcarrierreview_public_claim_safety` | PASS | `required` | public claim safety markers checked |
| `constrainedcarrierreview_mutant_detection` | PASS | `required` | 23/23 constrained carrier review mutant modes detected |
| `constrainedcarrierreview_fixture_drift` | PASS | `required` | passed |
| `constrainedcarrier_harness` | PASS | `required` | 3 resolver buckets |
| `constrainedcarrier_query_shapes` | PASS | `required` | 8 query shapes |
| `constrainedcarrier_response_shapes` | PASS | `required` | 7 response shapes |
| `constrainedcarrier_capacity_truncation` | PASS | `required` | 3 truncation buckets |
| `constrainedcarrier_retry_failure` | PASS | `required` | 3 retry buckets |
| `constrainedcarrier_profile_sensitivity` | PASS | `required` | diversity=0.88 fingerprints=12 |
| `constrainedcarrier_stream_mapping` | PASS | `required` | 4 streams mapped |
| `constrainedcarrier_backpressure` | PASS | `required` | 4 backpressure events |
| `constrainedcarrier_reset_error` | PASS | `required` | 1 resets and 2 errors |
| `constrainedcarrier_relay_integration` | PASS | `required` | loopbackrelay labegress relaybridge proxyegress mappings checked |
| `constrainedcarrier_pipeline_integration` | PASS | `required` | localpipeline pathhealth carrierreview measurementreview mappings checked |
| `constrainedcarrier_local_diagnostics` | PASS | `required` | 8 safe diagnostic fields |
| `constrainedcarrier_resource_limits` | PASS | `required` | sessions=3 streams=8 retries=3 |
| `constrainedcarrier_misuse_detection` | PASS | `required` | 26 misuse controls detected |
| `constrainedcarrier_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `constrainedcarrier_trace_hygiene` | PASS | `required` | fixtures and summaries scanned for unsafe material |
| `constrainedcarrier_mutant_detection` | PASS | `required` | 26/26 constrained carrier mutant modes detected |
| `constrainedcarrier_fixture_drift` | PASS | `required` | passed |
| `multicarrierselect_inventory` | PASS | `required` | 5 carrier families |
| `multicarrierselect_candidate_bundle` | PASS | `required` | 9 candidates; 6 blocked |
| `multicarrierselect_policy` | PASS | `required` | 10 decision classes |
| `multicarrierselect_profile_sensitivity` | PASS | `required` | diversity=0.89 hashes=9 |
| `multicarrierselect_pathrace_integration` | PASS | `required` | 3 raced candidates |
| `multicarrierselect_pathhealth_integration` | PASS | `required` | 9 health reports |
| `multicarrierselect_failover_fallback` | PASS | `required` | primary=carrier_candidate_https_primary backup=carrier_candidate_dns_survival_backup |
| `multicarrierselect_measurementreview_composition` | PASS | `required` | measurementreview constraints enforced |
| `multicarrierselect_carrierreview_composition` | PASS | `required` | carrierreview constraints enforced |
| `multicarrierselect_runtime_composition` | PASS | `required` | pathrace pathhealth transportbundle relaybridge labegress localpipeline runtime security mappings checked |
| `multicarrierselect_misuse_detection` | PASS | `required` | 15 misuse controls detected |
| `multicarrierselect_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `multicarrierselect_trace_hygiene` | PASS | `required` | selection fixtures scanned for unsafe material |
| `multicarrierselect_public_claim_safety` | PASS | `required` | 4 public docs scanned |
| `multicarrierselect_mutant_detection` | PASS | `required` | 15/15 multi-carrier selection mutant modes detected |
| `multicarrierselect_fixture_drift` | PASS | `required` | passed |
| `carriercollapse_family_diversity` | PASS | `required` | 3 carrier families |
| `carriercollapse_shape_diversity` | PASS | `required` | 12 shape classes |
| `carriercollapse_profile_sensitivity` | PASS | `required` | 9 profile hashes |
| `carriercollapse_bundle_sensitivity` | PASS | `required` | transport bundle sensitivity checked |
| `carriercollapse_pathrace_enforcement` | PASS | `required` | pathrace bypasses rejected=1 |
| `carriercollapse_pathhealth_enforcement` | PASS | `required` | pathhealth bypasses rejected=1 |
| `carriercollapse_measurementreview_enforcement` | PASS | `required` | measurementreview bypasses rejected=1 |
| `carriercollapse_carrierreview_enforcement` | PASS | `required` | carrierreview bypasses rejected=1 |
| `carriercollapse_labegress_enforcement` | PASS | `required` | labegress bypasses rejected=1 |
| `carriercollapse_fallback_safety` | PASS | `required` | 3 fallback classes blocked |
| `carriercollapse_runtime_security_metadata` | PASS | `required` | runtime/security metadata consistent |
| `carriercollapse_stream_isolation` | PASS | `required` | stream isolation preserved |
| `carriercollapse_backpressure_visibility` | PASS | `required` | backpressure visible |
| `carriercollapse_reset_propagation` | PASS | `required` | reset propagation checked |
| `carriercollapse_generated_backend_parity` | PASS | `required` | 4 generated markers checked |
| `carriercollapse_trace_hygiene` | PASS | `required` | 19 fixtures scanned |
| `carriercollapse_public_claim_safety` | PASS | `required` | 5 docs checked |
| `carriercollapse_mutant_detection` | PASS | `required` | 16/16 carrier collapse mutant modes detected |
| `carriercollapse_fixture_drift` | PASS | `required` | passed |
| `localproxyadapterreview_scope_contract` | PASS | `required` | 11 blocked behaviors |
| `localproxyadapterreview_protocol_acceptance` | PASS | `required` | 2 accepted local protocol classes |
| `localproxyadapterreview_payload_contract` | PASS | `required` | byte_counts_buckets_and_flags_only |
| `localproxyadapterreview_stream_mapping` | PASS | `required` | 4 stream classes |
| `localproxyadapterreview_backpressure_reset` | PASS | `required` | 4 pressure signals; 4 reset signals |
| `localproxyadapterreview_target_redaction` | PASS | `required` | 7 forbidden fields |
| `localproxyadapterreview_carrier_selector_integration` | PASS | `required` | 7 required gates |
| `localproxyadapterreview_resource_limits` | PASS | `required` | 5 panic-safety targets |
| `localproxyadapterreview_misuse_detection` | PASS | `required` | 16/16 misuse controls detected |
| `localproxyadapterreview_public_claim_safety` | PASS | `required` | 5 docs checked |
| `localproxyadapterreview_m49_contract` | PASS | `required` | 7 acceptance requirements |
| `localproxyadapterreview_generated_backend_parity` | PASS | `required` | 5 generated markers checked |
| `localproxyadapterreview_trace_hygiene` | PASS | `required` | 10 fixtures scanned |
| `localproxyadapterreview_fixture_drift` | PASS | `required` | passed |
| `localproxyadapter_session_lifecycle` | PASS | `required` | 1 session opened and 1 closed |
| `localproxyadapter_request_stream_mapping` | PASS | `required` | 3 accepted requests |
| `localproxyadapter_opaque_content` | PASS | `required` | 11 stream classes |
| `localproxyadapter_stream_lifecycle` | PASS | `required` | 8 opened, 7 closed, 1 reset |
| `localproxyadapter_backpressure_reset` | PASS | `required` | 1 pressure events; 1 resets |
| `localproxyadapter_carrier_selection` | PASS | `required` | 8 carrier selections |
| `localproxyadapter_pipeline_integration` | PASS | `required` | 8 localpipeline mappings |
| `localproxyadapter_labegress_connector` | PASS | `required` | 8 labegress exchanges |
| `localproxyadapter_measurementreview_enforcement` | PASS | `required` | 8 measurement reviews |
| `localproxyadapter_resource_limits` | PASS | `required` | 3 rejected controls |
| `localproxyadapter_misuse_detection` | PASS | `required` | 17/17 misuse controls detected |
| `localproxyadapter_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `localproxyadapter_trace_hygiene` | PASS | `required` | 11 stream runs scanned |
| `localproxyadapter_fixture_drift` | PASS | `required` | passed |
| `vpnsemantics_scope_contract` | PASS | `required` | 11 blocked behaviors |
| `vpnsemantics_packet_flow_taxonomy` | PASS | `required` | 6 packet flow classes |
| `vpnsemantics_flow_stream_mapping` | PASS | `required` | 4 mapping rules |
| `vpnsemantics_mtu_fragmentation` | PASS | `required` | 3 mtu buckets |
| `vpnsemantics_retry_reset_backpressure` | PASS | `required` | 3 retry buckets; 4 pressure buckets |
| `vpnsemantics_dns_boundary_policy` | PASS | `required` | 3 DNS boundary classes |
| `vpnsemantics_kill_switch_semantics` | PASS | `required` | 3 kill-switch policy classes |
| `vpnsemantics_diagnostics_privacy` | PASS | `required` | aggregate_buckets_only |
| `vpnsemantics_m51_contract` | PASS | `required` | 7 acceptance requirements |
| `vpnsemantics_misuse_detection` | PASS | `required` | 13/13 misuse controls detected |
| `vpnsemantics_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `vpnsemantics_trace_hygiene` | PASS | `required` | 10 fixtures scanned |
| `vpnsemantics_fixture_drift` | PASS | `required` | passed |
| `localvpnadapter_lifecycle` | PASS | `required` | 1 session opened and 1 closed |
| `localvpnadapter_flow_descriptor_taxonomy` | PASS | `required` | 11 descriptors |
| `localvpnadapter_flow_stream_mapping` | PASS | `required` | 7 runtime streams mapped |
| `localvpnadapter_mtu_fragmentation` | PASS | `required` | 7 MTU decisions |
| `localvpnadapter_retry_reset_backpressure` | PASS | `required` | 7 retry decisions; 4 pressure events; 1 resets |
| `localvpnadapter_killswitch_policy` | PASS | `required` | 7 decisions |
| `localvpnadapter_dns_boundary` | PASS | `required` | 7 checks |
| `localvpnadapter_integration` | PASS | `required` | 10 integration gates |
| `localvpnadapter_resource_limits` | PASS | `required` | 4 rejected controls |
| `localvpnadapter_panic_safety` | PASS | `required` | 6 panic-safety targets |
| `localvpnadapter_misuse_detection` | PASS | `required` | 17/17 misuse controls detected |
| `localvpnadapter_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `localvpnadapter_trace_hygiene` | PASS | `required` | 22 fixtures scanned |
| `localvpnadapter_fixture_drift` | PASS | `required` | passed |
| `relayprocess_role_inventory` | PASS | `required` | 3 process roles |
| `relayprocess_config_contract` | PASS | `required` | explicit_lab_config_only |
| `relayprocess_profile_bundle_contract` | PASS | `required` | signed_manifest_placeholder_no_key_exchange_change |
| `relayprocess_lifecycle_contract` | PASS | `required` | 5 lifecycle contracts |
| `relayprocess_logging_observability` | PASS | `required` | structured_safe_metadata_only |
| `relayprocess_shutdown_recovery` | PASS | `required` | bounded_graceful_shutdown |
| `relayprocess_compatibility_policy` | PASS | `required` | versioned_capability_floor |
| `relayprocess_resource_policy` | PASS | `required` | bounded_process_resources |
| `relayprocess_abuse_control_placeholder` | PASS | `required` | placeholder_only_rate_bucket_and_reset_bucket_no_user_accounts |
| `relayprocess_m53_preconditions` | PASS | `required` | 5 preconditions |
| `relayprocess_misuse_detection` | PASS | `required` | 15/15 misuse controls detected |
| `relayprocess_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `relayprocess_trace_hygiene` | PASS | `required` | 13 fixtures scanned |
| `relayprocess_public_claim_safety` | PASS | `required` | 5 docs checked |
| `relayprocess_fixture_drift` | PASS | `required` | passed |
| `keyexchangeplan_design_inventory` | PASS | `required` | 10 design items |
| `keyexchangeplan_transcript_binding` | PASS | `required` | 7 bound components |
| `keyexchangeplan_identity_binding` | PASS | `required` | profile_and_relay_identity_bound_before_session_open |
| `keyexchangeplan_nonce_replay` | PASS | `required` | bounded_replay_window_reject_duplicate_old_and_future_jump |
| `keyexchangeplan_downgrade_resistance` | PASS | `required` | named_suite_registry_only_no_custom_primitive_design |
| `keyexchangeplan_key_separation` | PASS | `required` | context_labeled_key_schedule_contract_no_custom_primitives |
| `keyexchangeplan_rotation_readiness` | PASS | `required` | rotation_interfaces_defined_for_m54_no_key_material_in_fixtures |
| `keyexchangeplan_generated_transport_compatibility` | PASS | `required` | generated_transport_compatibility_hash_bound_to_handshake |
| `keyexchangeplan_external_crypto_review_readiness` | PASS | `required` | m62-independent-cryptography-review-package-precondition |
| `keyexchangeplan_misuse_detection` | PASS | `required` | 13/13 misuse controls detected |
| `keyexchangeplan_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `keyexchangeplan_trace_hygiene` | PASS | `required` | 12 reports scanned |
| `keyexchangeplan_public_claim_safety` | PASS | `required` | 5 docs checked |
| `keyexchangeplan_fixture_drift` | PASS | `required` | passed |
| `relayauthplan_inventory` | PASS | `required` | 15 auth items |
| `relayauthplan_identity_binding` | PASS | `required` | relay_and_profile_identity_required_before_session_open |
| `relayauthplan_compatibility_matrix` | PASS | `required` | relay_profile_transport_carrier_compatibility_checked_before_session_open |
| `relayauthplan_rotation_policy` | PASS | `required` | bounded_epoch_rotation_with_required_overlap_window |
| `relayauthplan_expiry_revocation` | PASS | `required` | expiry_and_revocation_checked_before_session_open |
| `relayauthplan_safe_failure` | PASS | `required` | fail_closed_with_safe_bucketed_diagnostics |
| `relayauthplan_downgrade_rejection` | PASS | `required` | silent_downgrade_rejected_before_relay_session_open |
| `relayauthplan_unknown_stale_profile` | PASS | `required` | unknown_and_stale_profiles_fail_closed_with_safe_diagnostics |
| `relayauthplan_m55_prerequisites` | PASS | `required` | m55-relay-operational-hardening-preconditions |
| `relayauthplan_misuse_detection` | PASS | `required` | 12/12 misuse controls detected |
| `relayauthplan_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `relayauthplan_trace_hygiene` | PASS | `required` | 12 reports scanned |
| `relayauthplan_public_claim_safety` | PASS | `required` | 5 docs checked |
| `relayauthplan_fixture_drift` | PASS | `required` | passed |
| `operationalhardening_report` | PASS | `required` | decision=ready_for_android_architecture_review blockers=0 risks=5 checklist_failed=0 |
| `operationalhardening_resource_limits` | PASS | `required` | 8 bounds |
| `operationalhardening_config_validation` | PASS | `required` | strict_operational_config_validation_with_safe_error_classes |
| `operationalhardening_lifecycle` | PASS | `required` | deterministic_bounded_shutdown_restart |
| `operationalhardening_safe_logging` | PASS | `required` | state_failure_version_resource_redacted_only |
| `operationalhardening_rollback_boundaries` | PASS | `required` | rollback_boundaries_fail_closed_on_ambiguity |
| `operationalhardening_health_summary` | PASS | `required` | redacted_android_ready_operational_health_summary |
| `operationalhardening_compatibility_integration` | PASS | `required` | operational_hardening_preserves_prior_safety_gates |
| `operationalhardening_misuse_detection` | PASS | `required` | 12/12 misuse controls detected |
| `operationalhardening_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `operationalhardening_trace_hygiene` | PASS | `required` | 10 reports scanned |
| `operationalhardening_public_claim_safety` | PASS | `required` | 5 docs checked |
| `operationalhardening_fixture_drift` | PASS | `required` | passed |
| `androidreview_report` | PASS | `required` | decision=ready_for_android_local_runtime_port blockers=0 risks=6 checklist_failed=0 |
| `androidreview_user_flows` | PASS | `required` | 11 flows |
| `androidreview_permission_model` | PASS | `required` | platform_permission_first_foreground_service_bounded |
| `androidreview_ui_states` | PASS | `required` | 15 states |
| `androidreview_diagnostics_privacy` | PASS | `required` | local_user_export_only_redacted_diagnostic_bundle |
| `androidreview_kill_switch` | PASS | `required` | fail_closed_on_profile_permission_runtime_or_carrier_invalid |
| `androidreview_runtime_composition` | PASS | `required` | android_state_composes_with_existing_runtime_gates |
| `androidreview_m57_m58_contracts` | PASS | `required` | M57=6 M58=6 |
| `androidreview_misuse_detection` | PASS | `required` | 10/10 misuse controls detected |
| `androidreview_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `androidreview_trace_hygiene` | PASS | `required` | 12 reports scanned |
| `androidreview_public_claim_safety` | PASS | `required` | 5 docs checked |
| `androidreview_fixture_drift` | PASS | `required` | passed |
| `androidruntime_report` | PASS | `required` | decision=ready_for_android_vpnservice_prototype blockers=0 risks=6 checklist_failed=0 |
| `androidruntime_initialization` | PASS | `required` | validated_profile_android_local_runtime_startup |
| `androidruntime_lifecycle` | PASS | `required` | 11 lifecycle events |
| `androidruntime_storage_boundaries` | PASS | `required` | android_private_storage_with_ephemeral_runtime_state |
| `androidruntime_diagnostics` | PASS | `required` | bounded_redacted_local_runtime_diagnostics |
| `androidruntime_concurrency` | PASS | `required` | tasks=6 lifecycle_events=64 diagnostic_events=128 |
| `androidruntime_compatibility` | PASS | `required` | android_local_runtime_preserves_existing_gates |
| `androidruntime_shutdown` | PASS | `required` | safe_idempotent_android_local_runtime_shutdown |
| `androidruntime_misuse_detection` | PASS | `required` | 10/10 misuse controls detected |
| `androidruntime_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `androidruntime_trace_hygiene` | PASS | `required` | 14 reports scanned |
| `androidruntime_public_claim_safety` | PASS | `required` | 5 docs checked |
| `androidruntime_fixture_drift` | PASS | `required` | passed |
| `androidvpnservice_report` | PASS | `required` | decision=ready_for_android_carrier_integration blockers=0 risks=7 checklist_failed=0 |
| `androidvpnservice_permission_model` | PASS | `required` | android_vpn_permission_first_fail_closed |
| `androidvpnservice_lifecycle` | PASS | `required` | 10 states |
| `androidvpnservice_packet_flow_mapping` | PASS | `required` | android_packet_flow_maps_to_kurdistan_stream_runtime |
| `androidvpnservice_kill_switch` | PASS | `required` | android_vpnservice_fail_closed_kill_switch_policy |
| `androidvpnservice_diagnostics` | PASS | `required` | bounded_redacted_android_vpnservice_diagnostics |
| `androidvpnservice_reconnect_hooks` | PASS | `required` | bounded_android_vpnservice_reconnect_hooks |
| `androidvpnservice_integration` | PASS | `required` | android_vpnservice_preserves_reviewed_runtime_boundaries |
| `androidvpnservice_shutdown` | PASS | `required` | safe_idempotent_android_vpnservice_shutdown |
| `androidvpnservice_misuse_detection` | PASS | `required` | 12/12 misuse controls detected |
| `androidvpnservice_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `androidvpnservice_trace_hygiene` | PASS | `required` | 17 reports scanned |
| `androidvpnservice_public_claim_safety` | PASS | `required` | 6 docs checked |
| `androidvpnservice_fixture_drift` | PASS | `required` | passed |
| `androidcarrier_report` | PASS | `required` | decision=ready_for_android_adversarial_safety_audit blockers=0 risks=8 checklist_failed=0 |
| `androidcarrier_runtime_path` | PASS | `required` | android_carrier_runtime_path_validated_before_connect |
| `androidcarrier_ui_states` | PASS | `required` | 9 states |
| `androidcarrier_carrier_selection` | PASS | `required` | android_carrier_selection_uses_reviewed_runtime_constraints |
| `androidcarrier_relay_compatibility` | PASS | `required` | relay_compatibility_checked_before_android_connected_state |
| `androidcarrier_flow_integration` | PASS | `required` | 8 runtime streams, 13 carrier envelopes |
| `androidcarrier_failure_diagnostics` | PASS | `required` | 10 failure classes |
| `androidcarrier_reconnect_fallback` | PASS | `required` | bounded_android_carrier_reconnect_and_fallback |
| `androidcarrier_profile_validation` | PASS | `required` | profile_validation_and_relay_compatibility_before_android_connected |
| `androidcarrier_shutdown_safety` | PASS | `required` | android_carrier_integration_safe_shutdown |
| `androidcarrier_misuse_detection` | PASS | `required` | 14/14 misuse controls detected |
| `androidcarrier_generated_backend_parity` | PASS | `required` | 6 generated markers checked |
| `androidcarrier_trace_hygiene` | PASS | `required` | 19 reports scanned |
| `androidcarrier_public_claim_safety` | PASS | `required` | 6 docs checked |
| `androidcarrier_fixture_drift` | PASS | `required` | passed |
| `hardening_invariant_registry` | PASS | `required` | 19 invariants checks run; 0 failures |
| `hardening_api_contracts` | PASS | `required` | 9 api_contracts checks run; 0 failures |
| `hardening_panic_safety` | PASS | `required` | 12 panic_safety checks run; 0 failures |
| `hardening_resource_limits` | PASS | `required` | 9 resource_limits checks run; 0 failures |
| `hardening_trace_hygiene` | PASS | `required` | 20 trace/security hygiene checks run; 0 failures |
| `hardening_concurrency_safety` | PASS | `required` | 4 concurrency checks run; 0 failures |
| `hardening_generated_parity` | PASS | `required` | 3 generated_parity checks run; 0 failures |
| `hardening_pre_adapter_readiness` | PASS | `required` | 27 pre_adapter_readiness checks run; 0 failures |
| `hardening_mutant_detection` | PASS | `required` | 8/8 hardening mutant modes detected |
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Volatile wall-clock timings are omitted from the committed status snapshot. Use the audit JSON or command output for local performance diagnostics.

## Corpus Diversity Summary

- `number_of_profiles`: `1000`
- `unique_first_contact_patterns`: `4`
- `unique_frame_grammar_combinations`: `828`
- `unique_scheduler_combinations`: `562`
- `unique_stream_policy_combinations`: `980`
- `unique_proxy_policy_combinations`: `1000`
- `unique_carrier_policy_combinations`: `1000`
- `unique_security_policy_combinations`: `1000`
- `unique_padding_combinations`: `551`
- `unique_invalid_input_policy_combinations`: `997`
- `structurally_different_pairs`: `499500`

## Trace Diversity Summary

- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.

## Adversarial Black-Box Summary

- Gate result: `true`
- `cluster_count`: `3`
- `largest_cluster_ratio`: `0.53`
- `generated_cluster_conclusion`: `multiple clusters`

## Baseline Comparison

- No baseline comparison was run.
- Run `go run ./cmd/kcheck --quick --status STATUS.md --baseline testdata/audit/baseline-small.json` to include longitudinal deltas.

## Generated Source Backend

- Generated-backend audit was not run in this report.
- Run `go run ./cmd/kcheck codegen --quick` for generated source checks.

## Multi-Stream Adversary

- Gate result: `true`
- `profile_count`: `3`
- `scenario_count`: `3`
- `correct_runs`: `9`
- `scenario_runs`: `9`
- `multi_stream_collapse_resistance`: `passed`
- `multi_stream_mutant_detection`: `passed`

## Proxy Semantics

- Gate result: `true`
- `profile_count`: `3`
- `scenario_count`: `3`
- `correct_runs`: `9`
- `scenario_runs`: `9`
- `target_classes`: `[echo error_response fixed_response slow_response]`
- `proxy_semantics_diversity`: `passed`
- `proxy_target_backpressure`: `passed`
- `proxy_error_reset_isolation`: `passed`
- `proxy_mutant_detection`: `passed`
- `proxy_generated_backend_parity`: `passed`

## Carrier Abstraction

- Gate result: `true`
- `profile_count`: `3`
- `scenario_count`: `3`
- `carrier_families`: `[batch_carrier lossy_reordered_carrier stream_carrier]`
- `correct_runs`: `9`
- `scenario_runs`: `9`
- `carrier_diversity`: `passed`
- `carrier_backpressure_preservation`: `passed`
- `carrier_loss_reorder_recovery`: `passed`
- `carrier_proxysem_parity`: `passed`
- `carrier_mutant_detection`: `passed`
- `carrier_generated_backend_parity`: `passed`

## Security Prerequisites

- Gate result: `true`
- `security_transcript_binding`: `passed`
- `security_key_schedule`: `passed`
- `security_nonce_uniqueness`: `passed`
- `security_replay_rejection`: `passed`
- `security_downgrade_resistance`: `passed`
- `security_capability_negotiation`: `passed`
- `security_profile_compatibility`: `passed`
- `security_config_hygiene`: `passed`
- `security_secret_trace_hygiene`: `passed`
- `security_mutant_detection`: `passed`
- `security_generated_backend_parity`: `passed`

## Runtime Session Architecture

- Gate result: `true`
- `sessions`: `9`
- `runtime_session_lifecycle`: `passed`
- `runtime_capability_negotiation`: `passed`
- `runtime_profile_compatibility`: `passed`
- `runtime_security_context`: `passed`
- `runtime_replay_rejection`: `passed`
- `runtime_stream_management`: `passed`
- `runtime_backpressure`: `passed`
- `runtime_error_reset_isolation`: `passed`
- `runtime_trace_hygiene`: `passed`
- `runtime_mutant_detection`: `passed`
- `runtime_generated_backend_parity`: `passed`

## Implementation Hardening

- Gate result: `true`
- `hardening_invariant_registry`: `passed`
- `hardening_api_contracts`: `passed`
- `hardening_panic_safety`: `passed`
- `hardening_resource_limits`: `passed`
- `hardening_trace_hygiene`: `passed`
- `hardening_concurrency_safety`: `passed`
- `hardening_generated_parity`: `passed`
- `hardening_pre_adapter_readiness`: `passed`
- `hardening_mutant_detection`: `passed`

## Adapter Interface Architecture

- Gate result: `true`
- `adapter_interface_contracts`: `passed`
- `adapter_config_validation`: `passed`
- `adapter_flow_lifecycle`: `passed`
- `adapter_runtime_boundary`: `passed`
- `adapter_capability_compatibility`: `passed`
- `adapter_backpressure`: `passed`
- `adapter_error_reset_mapping`: `passed`
- `adapter_trace_hygiene`: `passed`
- `adapter_collapse_resistance`: `passed`
- `adapter_mutant_detection`: `passed`
- `adapter_generated_backend_parity`: `passed`

## Byte-Path Fixture Freeze

- Gate result: `true`
- `fixture_bytepath_drift`: `passed`
- `bytepath_fixture_stability`: `passed`
- `bytepath_generated_interpreted_parity`: `passed`
- `bytepath_malformed_corpus`: `passed`
- `bytepath_regression_baselines`: `passed`
- `bytepath_fixture_trace_hygiene`: `passed`

## Protocol Feature Corpus

- Gate result: `true`
- `protocorpus_schema_valid`: `passed`
- `protocorpus_feature_taxonomy`: `passed`
- `protocorpus_entry_coverage`: `passed`
- `protocorpus_trace_hygiene`: `passed`

## Wire Feature Baselines

- Gate result: `true`
- `wirefeatures_extraction`: `passed`
- `wirefeatures_firstn_model`: `passed`
- `wirefeatures_corpus_comparison`: `passed`
- `wirefeatures_collapse_resistance`: `passed`
- `wirefeatures_generated_backend_parity`: `passed`
- `wirefeatures_mutant_detection`: `passed`

## Wire-Shape Generator

- Gate result: `true`
- `wiregen_policy_generation`: `passed`
- `wiregen_policy_validation`: `passed`
- `wiregen_corpus_selection`: `passed`
- `wiregen_profile_integration`: `passed`
- `wiregen_bytepath_application`: `passed`
- `wiregen_feature_expectation_match`: `passed`
- `wiregen_firstn_diversity`: `passed`
- `wiregen_metadata_exposure_diversity`: `passed`
- `wiregen_collapse_resistance`: `passed`
- `wiregen_mutant_detection`: `passed`
- `wiregen_generated_backend_parity`: `passed`
- `wiregen_trace_hygiene`: `passed`
- `wiregen_baseline_fixtures`: `passed`

## Relay Fleet Lifecycle

- Gate result: `true`
- `relayfleet_lifecycle_integrity`: `passed`
- `relayfleet_profile_assignment`: `passed`
- `relayfleet_churn_schedule`: `passed`
- `relayfleet_migration_model`: `passed`
- `relayfleet_burn_risk`: `passed`
- `relayfleet_collapse_detection`: `passed`
- `relayfleet_control_detection`: `passed`
- `relayfleet_generated_backend_parity`: `passed`
- `relayfleet_trace_hygiene`: `passed`
- `relayfleet_mutant_detection`: `passed`
- `relayfleet_fixture_drift`: `passed`

## Adaptive Path Model

- Gate result: `true`
- `adaptivepath_candidate_taxonomy`: `passed`
- `adaptivepath_condition_model`: `passed`
- `adaptivepath_freshness_uncertainty`: `passed`
- `adaptivepath_viability_evaluation`: `passed`
- `adaptivepath_decision_inputs`: `passed`
- `adaptivepath_misuse_detection`: `passed`
- `adaptivepath_generated_backend_parity`: `passed`
- `adaptivepath_trace_hygiene`: `passed`
- `adaptivepath_mutant_detection`: `passed`
- `adaptivepath_roadmap_public_docs`: `passed`

## Transport Bundle Compiler

- Gate result: `true`
- `transportbundle_policy_validation`: `passed`
- `transportbundle_seed_planning`: `passed`
- `transportbundle_family_coverage`: `passed`
- `transportbundle_adaptivepath_mapping`: `passed`
- `transportbundle_relay_binding`: `passed`
- `transportbundle_fallback_hints`: `passed`
- `transportbundle_collapse_detection`: `passed`
- `transportbundle_generated_backend_parity`: `passed`
- `transportbundle_trace_hygiene`: `passed`
- `transportbundle_mutant_detection`: `passed`
- `transportbundle_fixture_drift`: `passed`

## Path Racing and Short-Lived Scoring

- Gate result: `true`
- `pathrace_scenario_validation`: `passed`
- `pathrace_parallel_scheduler`: `passed`
- `pathrace_candidate_verification`: `passed`
- `pathrace_short_lived_scoring`: `passed`
- `pathrace_ranking_tiebreak`: `passed`
- `pathrace_misuse_detection`: `passed`
- `pathrace_generated_backend_parity`: `passed`
- `pathrace_trace_hygiene`: `passed`
- `pathrace_mutant_detection`: `passed`
- `pathrace_fixture_drift`: `passed`

## Android Architecture Review

- Gate result: `true`
- `androidreview_report`: `passed`
- `androidreview_user_flows`: `passed`
- `androidreview_permission_model`: `passed`
- `androidreview_ui_states`: `passed`
- `androidreview_diagnostics_privacy`: `passed`
- `androidreview_kill_switch`: `passed`
- `androidreview_runtime_composition`: `passed`
- `androidreview_m57_m58_contracts`: `passed`
- `androidreview_misuse_detection`: `passed`
- `androidreview_generated_backend_parity`: `passed`
- `androidreview_trace_hygiene`: `passed`
- `androidreview_public_claim_safety`: `passed`
- `androidreview_fixture_drift`: `passed`

## Android Local Runtime Port

- Gate result: `true`
- `androidruntime_report`: `passed`
- `androidruntime_initialization`: `passed`
- `androidruntime_lifecycle`: `passed`
- `androidruntime_storage_boundaries`: `passed`
- `androidruntime_diagnostics`: `passed`
- `androidruntime_concurrency`: `passed`
- `androidruntime_compatibility`: `passed`
- `androidruntime_shutdown`: `passed`
- `androidruntime_misuse_detection`: `passed`
- `androidruntime_generated_backend_parity`: `passed`
- `androidruntime_trace_hygiene`: `passed`
- `androidruntime_public_claim_safety`: `passed`
- `androidruntime_fixture_drift`: `passed`

## Android VpnService Prototype

- Gate result: `true`
- `androidvpnservice_report`: `passed`
- `androidvpnservice_permission_model`: `passed`
- `androidvpnservice_lifecycle`: `passed`
- `androidvpnservice_packet_flow_mapping`: `passed`
- `androidvpnservice_kill_switch`: `passed`
- `androidvpnservice_diagnostics`: `passed`
- `androidvpnservice_reconnect_hooks`: `passed`
- `androidvpnservice_integration`: `passed`
- `androidvpnservice_shutdown`: `passed`
- `androidvpnservice_misuse_detection`: `passed`
- `androidvpnservice_generated_backend_parity`: `passed`
- `androidvpnservice_trace_hygiene`: `passed`
- `androidvpnservice_public_claim_safety`: `passed`
- `androidvpnservice_fixture_drift`: `passed`

## Known Limitations

- Multi-stream support is a loopback-only lab harness, not SOCKS, VPN, HTTP proxying, or external networking.
- Proxy-semantics support uses synthetic target descriptors and in-memory target behavior.
- Carrier abstraction models envelope shapes, retry/reorder metadata, and queue pressure without real carrier integrations.
- Security prerequisites model transcript binding, key schedules, nonce/replay checks, compatibility, and secure envelope metadata before real adapter integration.
- Runtime session architecture uses deterministic in-memory links and synthetic scenarios, not OS sockets or live peers.
- Adapter interface architecture defines contracts and an in-memory harness, not concrete adapter implementations.
- Byte-path fixtures freeze safe metadata and hashes, not raw packet captures or production wire behavior.
- Wire-shape generation is deterministic and fixture-driven; classifier/dataset evaluation is separate future work.
- Relay fleet modeling uses synthetic relays, schedule ticks, and safe summaries only; it does not provision relays or rotate real infrastructure.
- Transport bundle compiler output is a local candidate bundle and fallback hint model, not a live selector or path-racing runtime.
- Path racing uses local synthetic observations and short-lived scoring only; it does not probe, dial, resolve, or select a production active path.
- Android architecture review defines user flows, permission boundaries, diagnostics, kill-switch behavior, and M57/M58 contracts.
- Android local runtime port checks local initialization, lifecycle, profile loading, diagnostics, storage boundaries, compatibility, and safe shutdown.
- The historical Android VpnService audit gates are models; the separately gated Phase 10/11 Android implementation carries only reserved-range test traffic through the authenticated owned-loopback Kurd transport.
- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.
- Phase 8 locally implements deterministic profile framing, signed admission, optional recipient sealing, lifecycle activation, and local tooling with non-production fixtures. It has no production key custody, production signer, Android keystore, HSM/KMS, live delivery, deployment, pilot, or release evidence.
- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.
- There is no unrestricted Internet egress, public relay, SOCKS or HTTP proxy service, TLS mimicry, CDN behavior, deployment automation, or non-loopback field evidence.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Milestone Frontier

The latest modelled surface in this audit table is the Android carrier integration path (`androidcarrier_*`). Separately, Phases 8-11 implement and gate profile cryptography, protected Android state, reserved-range TUN behavior, and authenticated owned-loopback Kurd transport. Owned-LAN, owned-relay, physical-device matrix, capacity, handover, field-resilience, deployment, and release evidence remains **[UNVERIFIED]**.

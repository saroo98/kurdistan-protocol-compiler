<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `quick`
- Generated at: `2026-07-01T22:32:41Z`
- Profile count: `100`
- Trace count: `20`
- Conclusion: `passed`

## Gate Results

| Gate | Result | Severity | Summary |
| --- | --- | --- | --- |
| `profile_corpus_diversity` | PASS | `required` | 100 profiles checked; 0 failures |
| `black_box_trace_diversity` | PASS | `required` | 20 traces scanned; 0 suspicious metrics |
| `adversarial_black_box_clustering` | PASS | `required` | 20 traces clustered into 4 groups; 0 failures |
| `fixed_signature` | PASS | `required` | 7 fixed-signature metrics checked; 0 failures |
| `cosmetic_difference` | PASS | `required` | cosmetic profile and timestamp-only trace controls evaluated |
| `same_profile_consistency` | PASS | `required` | suspiciously similar |
| `different_profile_separation` | PASS | `required` | 190/190 trace pairs separated |
| `malformed_probe_behavior` | PASS | `required` | invalid-input behavior distribution checked |
| `multi_stream_semantics` | PASS | `required` | 4 profiles exercised with local multi-stream echo |
| `multi_stream_diversity` | PASS | `required` | 100 stream policy combinations across 100 profiles |
| `multi_stream_backpressure` | PASS | `required` | 1 profile backpressure scenarios exercised |
| `multi_stream_adversarial_scenarios` | PASS | `required` | 9 scenario runs checked; 0 correctness failures |
| `multi_stream_collapse_resistance` | PASS | `required` | 2 scenarios scanned; 0 suspicious metrics |
| `multi_stream_mutant_detection` | PASS | `required` | 6/6 stream mutant modes detected |
| `proxy_semantics_correctness` | PASS | `required` | 9 proxy scenario runs checked; 0 failures |
| `proxy_semantics_diversity` | PASS | `required` | 100 proxy policy combinations across 100 profiles |
| `proxy_target_backpressure` | PASS | `required` | 11 target-induced backpressure events observed |
| `proxy_error_reset_isolation` | PASS | `required` | 2 target errors and 2 target resets observed |
| `proxy_mutant_detection` | PASS | `required` | 7/7 proxy mutant modes detected |
| `proxy_generated_backend_parity` | PASS | `required` | generated backend proxysem support markers checked |
| `carrier_semantics_correctness` | PASS | `required` | 9 carrier scenario runs checked; 0 failures |
| `carrier_diversity` | PASS | `required` | 100 carrier policy combinations across 100 profiles |
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
| `security_mutant_detection` | PASS | `required` | 8/8 security mutant modes detected |
| `security_generated_backend_parity` | PASS | `required` | generated backend security support markers checked |
| `runtime_session_lifecycle` | PASS | `required` | 9 runtime sessions checked |
| `runtime_capability_negotiation` | PASS | `required` | 3 capability downgrade attempts rejected |
| `runtime_profile_compatibility` | PASS | `required` | 3 profile mismatch attempts rejected |
| `runtime_security_context` | PASS | `required` | 6 security contexts created and matched |
| `runtime_replay_rejection` | PASS | `required` | 3 replay attempts rejected |
| `runtime_stream_management` | PASS | `required` | 72 runtime stream messages managed |
| `runtime_backpressure` | PASS | `required` | 137 runtime backpressure events observed |
| `runtime_error_reset_isolation` | PASS | `required` | 6 target errors and 6 target resets isolated |
| `runtime_trace_hygiene` | PASS | `required` | 3 runtime traces checked for payload/secret hygiene |
| `runtime_mutant_detection` | PASS | `required` | 8/8 runtime mutant modes detected |
| `runtime_generated_backend_parity` | PASS | `required` | generated backend runtime support markers checked |
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
| `wiregen_policy_generation` | PASS | `required` | 100 policies and 100 unique hashes |
| `wiregen_policy_validation` | PASS | `required` | 100 policies validated |
| `wiregen_corpus_selection` | PASS | `required` | 12 entries across 9 families selected from 12 corpus entries |
| `wiregen_profile_integration` | PASS | `required` | 100 profiles include wire-shape policy sections |
| `wiregen_bytepath_application` | PASS | `required` | 700 bytepath feature vectors carry wire-shape metadata |
| `wiregen_feature_expectation_match` | PASS | `required` | 700 policy-feature pairs compared |
| `wiregen_firstn_diversity` | PASS | `required` | 17 unique first-n policy shapes |
| `wiregen_metadata_exposure_diversity` | PASS | `required` | 5 metadata exposure classes |
| `wiregen_collapse_resistance` | PASS | `required` | 100 policy hashes, 9 families, 2 fragment rhythms |
| `wiregen_mutant_detection` | PASS | `required` | 8/8 wiregen mutant modes detected |
| `wiregen_generated_backend_parity` | PASS | `required` | generated backend wire-shape markers checked |
| `wiregen_trace_hygiene` | PASS | `required` | 100 policies and 700 feature vectors scanned |
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
| `hardening_invariant_registry` | PASS | `required` | 19 invariants checks run; 0 failures |
| `hardening_api_contracts` | PASS | `required` | 9 api_contracts checks run; 0 failures |
| `hardening_panic_safety` | PASS | `required` | 12 panic_safety checks run; 0 failures |
| `hardening_resource_limits` | PASS | `required` | 9 resource_limits checks run; 0 failures |
| `hardening_trace_hygiene` | PASS | `required` | 20 trace/security hygiene checks run; 0 failures |
| `hardening_concurrency_safety` | PASS | `required` | 4 concurrency checks run; 0 failures |
| `hardening_generated_parity` | PASS | `required` | 3 generated_parity checks run; 0 failures |
| `hardening_pre_adapter_readiness` | PASS | `required` | 24 pre_adapter_readiness checks run; 0 failures |
| `hardening_mutant_detection` | PASS | `required` | 8/8 hardening mutant modes detected |
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Profile generation: `85 ms`
- Trace generation: `20 ms`
- Total audit runtime: `2202 ms`

## Corpus Diversity Summary

- `number_of_profiles`: `100`
- `unique_first_contact_patterns`: `4`
- `unique_frame_grammar_combinations`: `99`
- `unique_scheduler_combinations`: `94`
- `unique_stream_policy_combinations`: `100`
- `unique_proxy_policy_combinations`: `100`
- `unique_carrier_policy_combinations`: `100`
- `unique_security_policy_combinations`: `100`
- `unique_padding_combinations`: `67`
- `unique_invalid_input_policy_combinations`: `100`
- `structurally_different_pairs`: `4950`

## Trace Diversity Summary

- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.

## Adversarial Black-Box Summary

- Gate result: `true`
- `cluster_count`: `4`
- `largest_cluster_ratio`: `0.55`
- `different_profile_average_distance`: `0.31816371549844846`
- `same_profile_distance`: `0`
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
- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.
- Test-only key material and no production key exchange.
- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 30 should focus on continuous health monitoring and failover over already-selected synthetic paths.

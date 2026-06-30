<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `quick`
- Generated at: `2026-06-30T15:39:29Z`
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
| `adaptivepath_roadmap_public_docs` | PASS | `required` | public README/site status table cleanup and adaptive roadmap checked |
| `hardening_invariant_registry` | PASS | `required` | 17 invariants checks run; 0 failures |
| `hardening_api_contracts` | PASS | `required` | 9 api_contracts checks run; 0 failures |
| `hardening_panic_safety` | PASS | `required` | 12 panic_safety checks run; 0 failures |
| `hardening_resource_limits` | PASS | `required` | 9 resource_limits checks run; 0 failures |
| `hardening_trace_hygiene` | PASS | `required` | 18 trace/security hygiene checks run; 0 failures |
| `hardening_concurrency_safety` | PASS | `required` | 4 concurrency checks run; 0 failures |
| `hardening_generated_parity` | PASS | `required` | 3 generated_parity checks run; 0 failures |
| `hardening_pre_adapter_readiness` | PASS | `required` | 24 pre_adapter_readiness checks run; 0 failures |
| `hardening_mutant_detection` | PASS | `required` | 8/8 hardening mutant modes detected |
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Profile generation: `91 ms`
- Trace generation: `20 ms`
- Total audit runtime: `1255 ms`

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
- `different_profile_average_distance`: `0.319765850804996`
- `same_profile_distance`: `0.007462686567164179`
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
- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.
- Test-only key material and no production key exchange.
- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 28 should focus on the generated transport bundle compiler.

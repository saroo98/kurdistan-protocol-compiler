<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `quick`
- Generated at: `2026-06-29T14:32:36Z`
- Profile count: `100`
- Trace count: `20`
- Conclusion: `passed`

## Gate Results

| Gate | Result | Severity | Summary |
| --- | --- | --- | --- |
| `profile_corpus_diversity` | PASS | `required` | 100 profiles checked; 0 failures |
| `black_box_trace_diversity` | PASS | `required` | 20 traces scanned; 0 suspicious metrics |
| `adversarial_black_box_clustering` | PASS | `required` | 20 traces clustered into 3 groups; 0 failures |
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
| `byte_transport_fragmentation_reassembly` | PASS | `required` | 96 fragments created; 0 reassemblies observed |
| `byte_transport_pipe_backpressure` | PASS | `required` | 48 byte pipe backpressure events observed |
| `byte_transport_sequence_integrity` | PASS | `required` | 3 replay/sequence frames rejected |
| `byte_transport_corruption_rejection` | PASS | `required` | 3 corrupted frames rejected |
| `byte_transport_runtime_integration` | PASS | `required` | 9 byte runtime mappings checked |
| `byte_transport_error_reset_isolation` | PASS | `required` | 0 byte reset/error paths observed |
| `byte_transport_trace_hygiene` | PASS | `required` | 3 byte transport traces checked |
| `byte_transport_collapse_resistance` | PASS | `required` | 2 byte collapse reports evaluated |
| `byte_transport_mutant_detection` | PASS | `required` | 8/8 byte transport mutant modes detected |
| `byte_transport_generated_backend_parity` | PASS | `required` | generated backend byte transport support markers checked |
| `hardening_invariant_registry` | PASS | `required` | 11 invariants checks run; 0 failures |
| `hardening_api_contracts` | PASS | `required` | 9 api_contracts checks run; 0 failures |
| `hardening_panic_safety` | PASS | `required` | 12 panic_safety checks run; 0 failures |
| `hardening_resource_limits` | PASS | `required` | 9 resource_limits checks run; 0 failures |
| `hardening_trace_hygiene` | PASS | `required` | 8 trace/security hygiene checks run; 0 failures |
| `hardening_concurrency_safety` | PASS | `required` | 4 concurrency checks run; 0 failures |
| `hardening_generated_parity` | PASS | `required` | 3 generated_parity checks run; 0 failures |
| `hardening_pre_adapter_readiness` | PASS | `required` | 18 pre_adapter_readiness checks run; 0 failures |
| `hardening_mutant_detection` | PASS | `required` | 8/8 hardening mutant modes detected |
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Profile generation: `8 ms`
- Trace generation: `11 ms`
- Total audit runtime: `457 ms`

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
- `cluster_count`: `3`
- `largest_cluster_ratio`: `0.6`
- `different_profile_average_distance`: `0.3138657964210455`
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

## Known Limitations

- Multi-stream support is a loopback-only lab harness, not SOCKS, VPN, HTTP proxying, or external networking.
- Proxy-semantics support uses synthetic target descriptors and in-memory target behavior.
- Carrier abstraction models envelope shapes, retry/reorder metadata, and queue pressure without real carrier integrations.
- Security prerequisites model transcript binding, key schedules, nonce/replay checks, compatibility, and secure envelope metadata before real adapter integration.
- Runtime session architecture uses deterministic in-memory links and synthetic scenarios, not OS sockets or live peers.
- Adapter interface architecture defines contracts and an in-memory harness, not concrete adapter implementations.
- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.
- Test-only key material and no production key exchange.
- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 16 should focus on a deterministic local adapter prototype with adapter, hardening, runtime, and generated-backend gates kept mandatory.

# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `quick`
- Generated at: `2026-06-28T09:48:19Z`
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
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Profile generation: `6 ms`
- Trace generation: `21 ms`
- Total audit runtime: `141 ms`

## Corpus Diversity Summary

- `number_of_profiles`: `100`
- `unique_first_contact_patterns`: `4`
- `unique_frame_grammar_combinations`: `98`
- `unique_scheduler_combinations`: `94`
- `unique_stream_policy_combinations`: `100`
- `unique_padding_combinations`: `64`
- `unique_invalid_input_policy_combinations`: `100`
- `structurally_different_pairs`: `4950`

## Trace Diversity Summary

- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.

## Adversarial Black-Box Summary

- Gate result: `true`
- `cluster_count`: `3`
- `largest_cluster_ratio`: `0.6`
- `different_profile_average_distance`: `0.31370012509091877`
- `same_profile_distance`: `0.015151515151515152`
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

## Known Limitations

- Multi-stream support is a loopback-only lab harness, not SOCKS, VPN, HTTP proxying, or external networking.
- Test-only key material and no production key exchange.
- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 10 should focus on lab-only proxy-semantics modeling without adding SOCKS, VPN mode, HTTP carriers, deployment, external targets, or live-network testing.

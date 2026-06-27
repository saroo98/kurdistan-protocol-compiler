# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `quick`
- Generated at: `2026-06-27T17:57:36Z`
- Profile count: `100`
- Trace count: `20`
- Conclusion: `passed`

## Gate Results

| Gate | Result | Severity | Summary |
| --- | --- | --- | --- |
| `profile_corpus_diversity` | PASS | `required` | 100 profiles checked; 0 failures |
| `black_box_trace_diversity` | PASS | `required` | 20 traces scanned; 0 suspicious metrics |
| `adversarial_black_box_clustering` | PASS | `required` | 20 traces clustered into 5 groups; 0 failures |
| `fixed_signature` | PASS | `required` | 7 fixed-signature metrics checked; 0 failures |
| `cosmetic_difference` | PASS | `required` | cosmetic profile and timestamp-only trace controls evaluated |
| `same_profile_consistency` | PASS | `required` | suspiciously similar |
| `different_profile_separation` | PASS | `required` | 190/190 trace pairs separated |
| `malformed_probe_behavior` | PASS | `required` | invalid-input behavior distribution checked |
| `fuzz_presence` | PASS | `required` | 4 fuzz target files checked |

## Benchmark Highlights

- Profile generation: `4 ms`
- Trace generation: `13 ms`
- Total audit runtime: `74 ms`

## Corpus Diversity Summary

- `number_of_profiles`: `100`
- `unique_first_contact_patterns`: `4`
- `unique_frame_grammar_combinations`: `98`
- `unique_scheduler_combinations`: `94`
- `unique_padding_combinations`: `63`
- `unique_invalid_input_policy_combinations`: `100`
- `structurally_different_pairs`: `4950`

## Trace Diversity Summary

- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.

## Adversarial Black-Box Summary

- Gate result: `true`
- `cluster_count`: `5`
- `largest_cluster_ratio`: `0.55`
- `different_profile_average_distance`: `0.3569484046924118`
- `same_profile_distance`: `0.008771929824561403`
- `generated_cluster_conclusion`: `multiple clusters`

## Known Limitations

- Single-stream loopback-only runtime.
- Test-only key material and no production key exchange.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 5 should focus on richer lab-only probe corpora, regression fixtures for malformed sessions, and longitudinal comparisons across compiler changes.

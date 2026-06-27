# Kurdistan Protocol Compiler Status

> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.

- Latest audit mode: `codegen-quick`
- Generated at: `2026-06-27T19:32:37Z`
- Profile count: `3`
- Trace count: `3`
- Conclusion: `passed`

## Gate Results

| Gate | Result | Severity | Summary |
| --- | --- | --- | --- |
| `generated_backend_codegen` | PASS | `required` | 3 generated modules checked; 0 failures |
| `generated_semantic_equivalence` | PASS | `required` | 3 generated/interpreted profile pairs checked; 0 failures |
| `generated_profile_diversity` | PASS | `required` | 3/3 generated trace pairs separated |
| `generated_fixed_signature` | PASS | `required` | 5 trace stability metrics checked; 0 failures |
| `generated_vs_interpreted_divergence` | PASS | `informational` | equally diverse |
| `generated_mutant_detection` | PASS | `required` | 4/4 mutant modes detected |
| `generated_source_scanner` | PASS | `required` | 3 generated modules scanned; 0 failures |

## Benchmark Highlights

- Profile generation: `0 ms`
- Trace generation: `0 ms`
- Total audit runtime: `7413 ms`

## Corpus Diversity Summary

- See audit JSON for corpus details.

## Trace Diversity Summary

- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.

## Adversarial Black-Box Summary

- Adversarial clustering gate has not been run.

## Baseline Comparison

- No baseline comparison was run.
- Run `go run ./cmd/kcheck --quick --status STATUS.md --baseline testdata/audit/baseline-small.json` to include longitudinal deltas.

## Generated Source Backend

- Gate result: `true`
- `generated_module_count`: `3`
- `generated_tests_run`: `3`
- `interpreted_traces_checked`: `3`
- `generated_traces_checked`: `3`
- `round_trip_exercised_by`: `generated-trace command and generated protocol tests`
- `generated_semantic_equivalence`: `passed`
- `generated_profile_diversity`: `passed`
- `generated_fixed_signature`: `passed`
- `generated_mutant_detection`: `passed`
- `generated_source_scanner`: `passed`
- `semantic_equivalence`: `passed`
- `generated_profile_diversity`: `passed`
- `fixed_signature`: `passed`
- `mutant_detection`: `passed`
- `source_scanner`: `passed`

## Known Limitations

- Single-stream loopback-only runtime.
- Test-only key material and no production key exchange.
- Generated source still reuses shared lab helpers for IO, framing, scheduling, padding, auth, and traces.
- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.
- The audit detects local regressions; it cannot prove undetectability or real-world robustness.

## Next Milestone

Milestone 7 should focus on generated-backend trace comparison depth, richer lab-only malformed-session corpora, and clearer explanations for gate failures.

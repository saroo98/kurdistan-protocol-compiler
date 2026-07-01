<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0035: Path Racing and Short-Lived Scoring

## Purpose

Milestone 29 adds a deterministic path racing and short-lived scoring harness.
It consumes generated transport bundle candidates and models how a future
runtime could race candidates, verify synthetic usable states, decay stale
evidence, and rank candidates without using live network behavior.

The result is a local synthetic race report. It is not an active production path
selector.

## Relationship to Adaptive Path and Bundles

`internal/adaptivepath` defines candidate families, synthetic conditions,
freshness, uncertainty, and viability metadata.

`internal/transportbundle` compiles those candidates into deterministic bundle
manifests with profile seeds, wire-policy references, roles, fallback hints, and
synthetic relay binding metadata.

`internal/pathrace` races the bundle candidates against deterministic synthetic
scenario events and produces safe reports, score buckets, ranking summaries, and
misuse-control results.

## Boundary

Path racing remains local and synthetic. It does not perform real probing, DNS
lookups, resolver testing, endpoint handling, relay dialing, socket I/O, packet
capture, carrier integration, or production active-path mutation.

Fixtures and reports store safe classes, counters, buckets, synthetic IDs, and
hashes only.

## Race Scenarios

The committed fixture set covers:

- `all_candidates_unknown`
- `https_like_fast_success`
- `dns_survival_slow_success`
- `tcp_blackhole_then_dns_success`
- `udp_blocked_https_success`
- `relay_burn_rejects_candidate`
- `handshake_ok_data_stalls`
- `brief_success_then_failure`
- `high_risk_candidate_gated`
- `experimental_candidate_gated`
- `all_candidates_fail`
- `control_first_candidate_always_wins`
- `control_stale_success_wins`
- `control_high_risk_wins`

Controls are expected to fail misuse scanning.

## Parallel Scheduler

The scheduler starts multiple candidates at deterministic logical ticks,
enforces a parallelism cap, records candidate-start events, applies deterministic
tie-breaks, and gates high-risk or experimental candidates unless policy
explicitly permits them.

No wall-clock timers are used.

## Candidate Verification

Verification checks whether the synthetic event stream reached handshake,
first useful byte, and verified usable states without an immediate stall, relay
burn, family-sensitive block signal, high-risk default win, or experimental
default win.

Brief success followed by a failure is scored as recent but not accepted as a
verified usable winner.

## Short-Lived Scoring

Scores are bucketed and deterministic. Fresh useful-byte success improves a
candidate. Stale success decays quickly. Recent failure, stalls, relay burn,
high-risk status, and experimental status lower or gate a candidate.

This model is intentionally short-lived because path evidence in volatile
filtering environments can become stale quickly.

## Ranking and Tie-Breaking

Ranking prioritizes verified usable candidates, fresh evidence, safer relay-risk
buckets, non-experimental candidates, and deterministic candidate ID ordering for
ties. Rejected and gated candidates remain in audit output but are not default
winners.

Any winner is marked synthetic-only.

## Misuse Scanner

The pathrace misuse scanner detects collapsed or unsafe behavior such as:

- always selecting the first candidate
- stale success beating fresh success
- high-risk or experimental candidates winning by default
- burned relay candidates winning
- blocked or stalling candidates being verified
- identical scores across candidates
- unstable tie-breaks
- endpoint, payload, resolver, cloud metadata, or secret leakage
- generated backend drift

## Fixtures

Committed fixtures live under `testdata/pathrace/`:

- `race-scenarios-golden.json`
- `race-events-golden.json`
- `race-outcomes-golden.json`
- `scoring-policy-golden.json`
- `candidate-scores-golden.json`
- `ranking-report-golden.json`
- `pathrace-report-golden.json`
- `pathrace-misuse-report.json`
- `pathrace-controls.json`

They are deterministic drift baselines and contain no real endpoints, payloads,
raw bytes, resolver data, packet captures, keys, nonces, auth tags, or secrets.

## Generated Backend Parity

`kgen` emits pathrace markers and tests:

- `protocol/pathrace_generated.go`
- `protocol/pathrace_test.go`
- `protocol/pathrace_parity_test.go`
- `protocol/pathrace_hygiene_test.go`

Generated modules check pathrace schema version, mode/event/state constants,
forbidden-field markers, fixture generation, generated/interpreted parity, and
hygiene behavior.

## Audit Gates

Milestone 29 adds:

- `pathrace_scenario_validation`
- `pathrace_parallel_scheduler`
- `pathrace_candidate_verification`
- `pathrace_short_lived_scoring`
- `pathrace_ranking_tiebreak`
- `pathrace_misuse_detection`
- `pathrace_generated_backend_parity`
- `pathrace_trace_hygiene`
- `pathrace_mutant_detection`
- `pathrace_fixture_drift`

Default quick audit includes these gates.

## Commands

```bash
go run ./cmd/kcheck pathrace --quick
go run ./cmd/kcheck pathrace --full --out testdata/audit/pathrace.json
go run ./cmd/kcheck pathrace generate --out testdata/pathrace/pathrace-report-golden.json --force
go run ./cmd/kcheck pathrace verify
go run ./cmd/kcheck pathrace compare --old testdata/pathrace/pathrace-report-golden.json --new testdata/pathrace/pathrace-report-golden.json
go run ./cmd/kcheck --quick --status STATUS.md
```

## Known Limitations

Path racing is a deterministic harness. It does not monitor a selected path over
time, fail over between active paths, allocate relays, run carrier probes, or
perform public network measurement.

The scoring model is evidence for regression testing and research iteration, not
a field decision engine.

## Next Milestone

Milestone 30 should add continuous health monitoring and failover over
already-selected synthetic paths, still using local observations and safe
metadata only.

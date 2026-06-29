<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0020: Implementation Hardening

## Summary

Milestone 14 adds implementation hardening and pre-adapter review gates. The goal is to check local compiler, runtime, security, carrier, proxy-semantics, stream, trace, and generated-backend invariants before future adapter work.

This milestone is about misuse resistance and regression detection. It does not add deployment adapters or external target behavior.

## Hardening Model

The `internal/hardening` package provides reusable checks:

- invariant registry
- API contract and misuse checks
- panic-safety wrappers for malformed bounded inputs
- resource-limit checks
- trace hygiene scanner
- deterministic concurrency/race-prep checks
- compatibility checks
- generated/interpreted parity checks
- pre-adapter readiness matrix
- adapter interface checks

Each check returns a structured result with category, severity, evidence, and pass/fail state.

## Invariant Registry

The registry checks critical assumptions across:

- compiler/profile generation
- IR validation
- framing round trips and malformed frame rejection
- stream limits and terminal states
- proxy target validation and isolation
- carrier envelope validation and queue bounds
- security transcript, nonce, replay, compatibility, and redaction behavior
- runtime lifecycle, profile compatibility, replay injection, link queues, and trace hygiene

The registry is intentionally deterministic so regressions are reproducible from a seed range.

## API Contract Tests

Hardening tests intentionally misuse APIs with nil, zero-value, unknown, malformed, or oversized inputs. Expected behavior is a clear error or documented safe zero-value behavior. Panics are treated as failures unless explicitly documented, and no current critical path uses a panic contract.

## Panic Safety

The `MustNotPanic` helper wraps bounded malformed inputs for profile validation, frame decoding, proxy descriptor validation, carrier envelope validation, secure envelope opening, runtime link validation, trace parsing, and audit JSON parsing.

## Resource Limits

Resource checks cover audit profile counts, frame sizes, stream and session limits, memory-link queue depth, target request and response sizes, carrier envelope limits, replay windows, and generated module counts in quick audits.

## Trace Hygiene

The trace hygiene scanner rejects forbidden structured fields or marker classes such as raw secrets, derived keys, nonce bases, proof material, payload fields, raw byte fields, client/server write keys, exporter secrets, and leak flags. It scans trace events, JSON summaries, audit reports, generated traces, fixture manifests, parity reports, malformed corpus metadata, and error strings.

Allowed safe metadata includes byte counts, buckets, hygiene booleans, and redacted values.

## Concurrency And Race Prep

The hardening layer adds deterministic checks for nonce-manager concurrent uniqueness and replay-window duplicate rejection. Components that are intentionally single-session or deterministic-only are documented as such. The CLI can print race-test advice:

```bash
go run ./cmd/kcheck hardening --race-advice
```

## Generated Backend Parity

Generated modules now include:

```text
protocol/hardening_generated.go
protocol/hardening_test.go
```

Generated hardening tests cover config misuse, replay/profile mismatch fixtures, malformed frames, trace hygiene, generated hardening summaries, byte-path fixture tests, and generated/interpreted bytepath parity. The generated backend version is now `0.18.0-lab`.

## Hardening Mutants

Milestone 14 adds test-only hardening mutant modes for panic-on-malformed-frame, unbounded trace events, trace secret leaks, ignored stream limits, ignored carrier queue limits, accepted invalid profile hashes, generated parity drift, and API misuse panics. Audit gates must detect these as hardening regressions.

## Audit Gates

`kcheck` includes:

```text
hardening_invariant_registry
hardening_api_contracts
hardening_panic_safety
hardening_resource_limits
hardening_trace_hygiene
hardening_concurrency_safety
hardening_generated_parity
hardening_pre_adapter_readiness
hardening_mutant_detection
```

Run:

```bash
go run ./cmd/kcheck hardening --quick
go run ./cmd/kcheck hardening --full --out testdata/audit/hardening.json
go run ./cmd/kcheck --quick --status STATUS.md
```

## Readiness Matrix

The companion matrix is in:

```text
docs/PRE_ADAPTER_READINESS.md
```

It records review status, evidence, remaining risk, and next action for compiler, profile validation, framing, streams, proxy semantics, carrier abstraction, security context, runtime lifecycle, deterministic byte transport, byte-path fixtures and parity, generated backend parity, trace hygiene, resource bounds, panic safety, API misuse resistance, concurrency/race prep, and documentation.

## Limitations

Hardening gates prove local deterministic behavior only. They do not prove production readiness, traffic-analysis resistance, real-world censorship resistance, or adapter safety. Future adapter work still needs separate threat modeling, code review, negative testing, and operational risk analysis.

## Next Milestone

Milestone 15 adds the adapter interface architecture described in [KIP-0021](KIP-0021-adapter-interface-architecture.md). The next milestone should build a deterministic local adapter prototype that treats adapter and hardening gates as mandatory preconditions.

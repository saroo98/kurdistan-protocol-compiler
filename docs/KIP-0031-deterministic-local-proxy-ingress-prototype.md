<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0031: Deterministic Local Proxy Ingress Prototype

## Purpose

Milestone 25 turns the proxy ingress design review into a deterministic local prototype. The prototype accepts synthetic CONNECT-like request events, validates safe target descriptors, maps requests into runtime stream metadata, exercises bounded queue behavior, and emits payload-free summaries.

The research question is whether a local ingress-style flow can move through the existing runtime boundary while preserving backpressure, reset/error isolation, trace hygiene, generated-backend parity, and deterministic fixture stability.

## Architecture

```text
synthetic local request source
        |
        v
local proxy ingress runner
        |
        v
target descriptor validation
        |
        v
runtime stream mapping
        |
        v
bounded queue / backpressure model
        |
        v
safe trace summary and audit gates
```

The prototype remains deterministic and in-memory. It does not open sockets, listen for real proxy traffic, parse public protocols, or contact external targets.

## Package Layout

`internal/localproxyingress` provides:

- config validation
- synthetic source events
- bounded request queues
- dispatcher summaries
- target binding through `internal/proxyingress`
- runtime stream bridge metadata
- lifecycle execution
- backpressure reports
- error/reset isolation reports
- fixture generation and comparison
- safe trace events

`internal/localproxyingressadversary` provides:

- scenario features
- collapse scanning
- synthetic collapsed controls
- adversarial reports

## Scenarios

The fixture set and audit runner cover:

- `single_connect_echo`
- `many_small_connects`
- `large_request_fragmented`
- `mixed_request_classes`
- `slow_drip_request`
- `reset_mid_request`
- `target_error_after_open`
- `backpressure_pressure`
- `invalid_target_rejection`
- `lifecycle_violation_rejection`
- `queue_overflow_rejection`
- `duplicate_event_rejection`

These scenarios use request classes, target classes, byte-count buckets, lifecycle states, and result buckets only.

## Collapse Controls

Controls cover suspicious fixed behavior:

- fixed target descriptors
- fixed stream mappings
- fixed lifecycle patterns
- ignored backpressure
- reset leakage across requests
- target error descriptor leakage
- invalid target acceptance
- unbounded queues
- payload trace leakage
- secret trace leakage

The collapse scanner reports suspicious metrics and a deterministic diversity score.

## Fixtures

Fixtures under `testdata/localproxyingress/` freeze:

- scenario summaries
- scenario metadata
- backpressure summaries
- error/reset summaries
- collapse reports
- collapsed controls

Fixtures contain counts, buckets, classes, hashes, and expected results only.

## Audit Gates

`kcheck localproxyingress` evaluates:

- `localproxyingress_contract_compliance`
- `localproxyingress_target_validation`
- `localproxyingress_lifecycle_execution`
- `localproxyingress_runtime_mapping`
- `localproxyingress_backpressure`
- `localproxyingress_error_reset_isolation`
- `localproxyingress_queue_bounds`
- `localproxyingress_collapse_resistance`
- `localproxyingress_generated_backend_parity`
- `localproxyingress_trace_hygiene`
- `localproxyingress_mutant_detection`
- `localproxyingress_fixture_drift`

The default quick audit includes local proxy ingress gates.

## Commands

```bash
go run ./cmd/kcheck localproxyingress --quick
go run ./cmd/kcheck localproxyingress --full --out testdata/audit/localproxyingress.json
go run ./cmd/kcheck localproxyingress generate --out testdata/localproxyingress/localproxyingress-summary-golden.json --force
go run ./cmd/kcheck localproxyingress verify
go run ./cmd/kcheck localproxyingress compare --old testdata/localproxyingress/localproxyingress-summary-golden.json --new testdata/localproxyingress/localproxyingress-summary-golden.json
```

## Generated Backend Parity

Generated modules include local proxy ingress constants and tests:

```text
protocol/localproxyingress_generated.go
protocol/localproxyingress_test.go
protocol/localproxyingress_parity_test.go
protocol/localproxyingress_hygiene_test.go
```

The generated backend version is `0.25.0-lab`.

## Limitations

This prototype is an in-memory deterministic harness. It does not implement concrete proxy ingress, socket handling, DNS behavior, HTTP carrier behavior, TLS mimicry, VPN/TUN semantics, deployment, external targets, or live measurement.

The prototype validates local contracts and regression gates. It does not prove real-world censorship resistance or production readiness.

## Next Milestone

Milestone 26 should harden proxy ingress parity and adversarial checks across interpreted and generated backends before any concrete adapter work.

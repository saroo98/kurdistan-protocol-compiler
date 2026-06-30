<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0030: Concrete Local Proxy Ingress Design Review

## Purpose

Milestone 24 defines the contract a future concrete local proxy ingress must satisfy before implementation. It is a design-review and regression-baseline milestone, not a network adapter milestone.

The review asks whether local proxy-style request metadata can be represented safely, mapped into runtime stream intent, checked for misuse, and audited without introducing raw destinations, payload logging, or fixed external behavior.

## Scope

The milestone adds:

- `internal/proxyingress` for request contracts, target descriptors, capability mappings, lifecycle constraints, runtime mapping metadata, and safe summaries.
- `internal/proxyingressreview` for design-review checklists, failure-mode matrices, misuse controls, readiness decisions, and stable hashes.
- `testdata/proxyingress/` for small safe fixture baselines.
- `kcheck proxyingress` commands for audit, fixture generation, verification, and comparison.
- Generated-backend markers and tests for proxy ingress parity.

It does not add concrete SOCKS, TUN, VPN, HTTP, TLS, WebSocket, CDN, deployment, external-network, or live-traffic behavior.

## Contract Model

The proxy ingress contract models safe metadata only:

- request class
- target class
- priority class
- lifecycle state
- capability set
- runtime mapping result
- bounded request/response sizes
- trace hygiene flags

Target descriptors are synthetic and class-based. They intentionally avoid raw destination addresses, URLs, host headers, SNI values, resolver configuration, cloud metadata, credentials, and payload contents.

## Failure-Mode Matrix

The design-review matrix covers expected rejection or containment behavior for malformed requests, unknown target classes, unsupported capabilities, lifecycle violations, oversize limits, replay-like duplicates, reset/error propagation, trace hygiene failures, and generated/interpreted drift.

The matrix is committed as safe metadata under `testdata/proxyingress/failure-mode-matrix.json`.

## Fixtures

Fixtures under `testdata/proxyingress/` freeze:

- contract metadata
- request class metadata
- target class metadata
- mapping summaries
- lifecycle summaries
- design-review outcomes
- failure-mode expectations
- collapsed controls

Fixtures contain safe classes, buckets, hashes, and counts only.

## Audit Gates

`kcheck proxyingress` evaluates:

- `proxyingress_contract_validation`
- `proxyingress_target_descriptor_safety`
- `proxyingress_capability_mapping`
- `proxyingress_runtime_mapping`
- `proxyingress_lifecycle_integrity`
- `proxyingress_failure_mode_matrix`
- `proxyingress_design_review`
- `proxyingress_misuse_detection`
- `proxyingress_generated_backend_parity`
- `proxyingress_trace_hygiene`
- `proxyingress_mutant_detection`
- `proxyingress_fixture_drift`

The default quick audit includes proxy ingress gates.

## Commands

```bash
go run ./cmd/kcheck proxyingress --quick
go run ./cmd/kcheck proxyingress --full --out testdata/audit/proxyingress.json
go run ./cmd/kcheck proxyingress generate --out testdata/proxyingress/proxyingress-contract-golden.json --force
go run ./cmd/kcheck proxyingress verify
go run ./cmd/kcheck proxyingress compare --old testdata/proxyingress/proxyingress-contract-golden.json --new testdata/proxyingress/proxyingress-contract-golden.json
```

## Generated Backend Parity

Generated modules include proxy ingress constants and tests:

```text
protocol/proxyingress_generated.go
protocol/proxyingress_test.go
protocol/proxyingress_parity_test.go
protocol/proxyingress_hygiene_test.go
```

The codegen audit checks that generated modules include proxy ingress schema markers and pass the interpreted/generated parity spot checks.

## Limitations

This milestone is a design review and contract freeze. It cannot prove that a future concrete local ingress adapter is correct, secure, deployable, or resistant to real-world filtering. It only proves that the project has a deterministic, trace-safe contract and failure-mode baseline before prototype work.

## Next Milestone

Milestone 25 implements the deterministic local proxy ingress prototype using these contracts.

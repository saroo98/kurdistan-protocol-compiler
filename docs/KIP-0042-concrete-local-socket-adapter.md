<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0042: Concrete Local Socket Adapter

Milestone 36 adds the first concrete local socket adapter harness for Kurdistan. It is intentionally narrow: a deterministic loopback-only socket layer that proves the adapter boundary can bind, accept, echo, summarize, reject unsafe bind policy, and feed audit/generation parity without introducing public-network behavior.

## Purpose

Earlier milestones modeled adapter interfaces, in-memory local adapters, byte transport, proxy ingress/egress, relay bridge composition, local pipeline fixtures, and production readiness. Those layers showed what should happen semantically. M36 checks the next boundary: whether a concrete local socket can exercise the adapter contract while preserving trace hygiene, bounds, reset/error isolation, backpressure evidence, and generated-backend parity.

## Scope

Implemented scope:

- strict loopback-only bind validation
- ephemeral local listener probe
- deterministic source and sink summary metadata
- flow lifecycle and runtime stream mapping summaries
- backpressure counters
- target error/reset mapping counters
- external and wildcard bind rejection controls
- malformed local event rejection controls
- fixture drift checks
- generated/interpreted parity checks

Out of scope:

- SOCKS
- TUN
- VPN
- HTTP, TLS, WebSocket, CDN, or carrier mimicry
- deployment
- external targets
- public-network relay behavior
- production key exchange
- payload logging

## Package

`internal/concretelocaladapter` provides:

- `BindConfig` for bounded loopback-only configuration
- `SocketScenario` for deterministic scenario metadata
- `SocketRunSummary` for payload-free execution summaries
- `SocketFixtureSet` for committed golden fixtures
- `ValidateBindConfig` for strict bind policy
- `RunLoopbackProbe` for ephemeral loopback listener validation
- `GenerateFixtureSet`, `CompareFixtureSets`, and `ScanForLeak`

The loopback probe uses deterministic byte slices internally only to validate local echo mechanics. Traces, fixtures, errors, summaries, and generated outputs store counts, buckets, flags, hashes, and class names only.

## Audit Gates

`kcheck concretelocaladapter --quick` reports:

- `concretelocaladapter_bind_policy`
- `concretelocaladapter_loopback_listener`
- `concretelocaladapter_flow_lifecycle`
- `concretelocaladapter_runtime_mapping`
- `concretelocaladapter_backpressure`
- `concretelocaladapter_error_reset_isolation`
- `concretelocaladapter_trace_hygiene`
- `concretelocaladapter_no_external_io`
- `concretelocaladapter_generated_backend_parity`
- `concretelocaladapter_mutant_detection`
- `concretelocaladapter_fixture_drift`

These gates are also included in the default quick audit.

## Fixtures

Committed fixtures live under:

```text
testdata/concretelocaladapter/
```

They include a golden fixture set plus companion scenario, summary, misuse, parity, and collapse JSON files. The fixture schema records no raw payloads, raw socket bytes, endpoint inventories, secrets, keys, nonces, auth tags, proof material, or packet captures.

## Commands

```bash
go run ./cmd/kcheck concretelocaladapter --quick
go run ./cmd/kcheck concretelocaladapter --full --out testdata/audit/concretelocaladapter.json
go run ./cmd/kcheck concretelocaladapter generate --out testdata/concretelocaladapter/concretelocaladapter-golden.json --force
go run ./cmd/kcheck concretelocaladapter verify
go run ./cmd/kcheck concretelocaladapter compare --old testdata/concretelocaladapter/concretelocaladapter-golden.json --new testdata/concretelocaladapter/concretelocaladapter-golden.json
```

## Generated Backend Parity

`kgen` now emits concrete local adapter constants and tests:

```text
protocol/concretelocaladapter_generated.go
protocol/concretelocaladapter_test.go
protocol/concretelocaladapter_parity_test.go
protocol/concretelocaladapter_hygiene_test.go
```

The generated source scanner checks for `ConcreteLocalAdapterSchemaVersion`, and `kcheck codegen --quick` includes `concretelocaladapter_generated_backend_parity`.

## Limitations

The milestone proves that the local adapter boundary can be exercised through loopback-only socket mechanics with safe summaries. It does not validate a production proxy, carrier family, deployment model, mobile client, or real-world censorship resistance. Any future adapter that binds public interfaces, dials external targets, or handles user traffic needs a separate design review and additional hardening.

## Next Milestone

Recommended next milestone: M37, concrete local socket adversarial hardening. It should add deeper malformed socket event sequences, queue pressure, connection churn, half-close/reset races, byte-path interaction controls, and stricter generated parity checks.

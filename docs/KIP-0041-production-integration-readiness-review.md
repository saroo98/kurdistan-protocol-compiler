<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0041: Production Integration Readiness Review

Milestone 35 adds a structured production integration readiness review. It converts the accumulated compiler, runtime, adapter, proxy, carrier, byte-path, fixture, generated-backend, and hardening evidence into a deterministic review inventory before any concrete socket adapter work.

This milestone is a review and gate layer only. It does not add a concrete network adapter, deployment system, public relay, SOCKS adapter, VPN adapter, HTTP carrier, TLS mimicry, WebSocket carrier, CDN behavior, field measurement path, mobile client, or live-network testing.

## Purpose

The readiness review checks whether the local research stack has enough deterministic evidence to design the next local-only adapter milestone without weakening existing invariants.

It tracks:

- readiness inventory items
- dependency graph edges
- real-I/O boundary reviews
- future milestone contracts
- blocker-register entries
- misuse controls
- generated/interpreted parity
- fixture drift
- trace hygiene

## Review Inventory

`internal/productionreadiness` builds deterministic review items for the compiler, profile validation, framing, stream semantics, proxy semantics, carrier abstraction, security context, runtime session lifecycle, adapter interfaces, local adapter prototype, byte transport harness, byte-path fixtures, wire baselines, host and relay risk models, local proxy ingress, proxy egress, relay bridge, local pipeline, trace hygiene, generated backend parity, and documentation.

Each item records:

- layer
- readiness status
- evidence
- remaining risk
- next action

## Boundaries

The review keeps these boundaries closed:

- `no_real_network_io`
- `no_deployment`
- `no_payload_logging`
- `no_production_key_exchange`
- `strict_local_only`

The blocker register intentionally keeps production key exchange, concrete carrier families, field measurement, client architecture, and deployment operations unresolved until separately reviewed.

## Future Contracts

M35 creates safe contracts for later milestones:

- M36: concrete local socket adapter
- M37: socket adapter adversarial hardening
- M38: adapter readiness consolidation
- M39: client architecture review

The M36 contract allows only a loopback-only local socket harness and continues to forbid external targets, public relays, and deployment behavior.

## Audit Gates

M35 adds:

- `productionreadiness_inventory`
- `productionreadiness_dependency_graph`
- `productionreadiness_real_io_boundary`
- `productionreadiness_future_contracts`
- `productionreadiness_blocker_register`
- `productionreadiness_trace_hygiene`
- `productionreadiness_generated_backend_parity`
- `productionreadiness_mutant_detection`
- `productionreadiness_fixture_drift`

The default quick audit includes these gates.

## Commands

```bash
go run ./cmd/kcheck productionreadiness --quick
go run ./cmd/kcheck productionreadiness --full --out testdata/audit/productionreadiness.json
go run ./cmd/kcheck productionreadiness generate --out testdata/productionreadiness/productionreadiness-golden.json --force
go run ./cmd/kcheck productionreadiness verify
go run ./cmd/kcheck productionreadiness compare --old testdata/productionreadiness/productionreadiness-golden.json --new testdata/productionreadiness/productionreadiness-golden.json
```

## Fixtures

Committed fixtures live under `testdata/productionreadiness/`. They contain safe inventory, dependency, boundary, contract, blocker, misuse, parity, and hash metadata only.

## Generated Backend Parity

`kgen` emits:

- `protocol/productionreadiness_generated.go`
- `protocol/productionreadiness_test.go`
- `protocol/productionreadiness_parity_test.go`
- `protocol/productionreadiness_hygiene_test.go`

The generated source includes profile-specific readiness constants so codegen audit can detect generated-backend drift.

## Limitations

Readiness review does not mean production readiness. It is evidence that the local deterministic architecture is ready for the next local-only adapter design and test milestone.

## Next Milestone

The recommended next milestone is M36: concrete local socket adapter. That milestone should remain loopback-only and must keep every safety boundary enforced by this review.

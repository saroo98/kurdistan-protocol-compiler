<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0046: Carrier Prototype Readiness Gate

## Purpose

Milestone 40 freezes a readiness gate before any carrier prototype design work. It inventories prerequisite layers, records dependency edges, enforces boundary checks, scopes M41-M43 contracts, tracks blockers and risks, validates public-claim safety, and verifies generated-backend parity.

This milestone does not implement a carrier, deployment path, public relay, DNS resolver, TLS/WebSocket transport, CDN behavior, SOCKS/HTTP adapter, VPN, or external-network behavior.

## Readiness Model

`internal/carrierreadiness` records:

- prerequisite inventory
- dependency graph
- boundary policy matrix
- future contracts for M41, M42, and M43
- blocker register
- risk matrix
- readiness checklist
- generated/interpreted parity
- fixture drift baseline

The review decision is:

```text
ready_for_next_design_review
```

That decision means the next milestone can review carrier prototype design contracts. It does not mean carrier implementation readiness.

## Commands

```bash
go run ./cmd/kcheck carrierreadiness --quick
go run ./cmd/kcheck carrierreadiness --full --out testdata/audit/carrierreadiness.json
go run ./cmd/kcheck carrierreadiness generate --out testdata/carrierreadiness/carrierreadiness-golden.json --force
go run ./cmd/kcheck carrierreadiness verify
go run ./cmd/kcheck carrierreadiness compare --old testdata/carrierreadiness/carrierreadiness-golden.json --new testdata/carrierreadiness/carrierreadiness-golden.json
```

## Audit Gates

Milestone 40 adds gates for:

- readiness inventory
- dependency graph
- boundary policy
- future contracts
- blocker register
- risk matrix
- readiness checklist
- public claim safety
- generated-backend parity
- mutant detection
- fixture drift

## Generated Backend

`kgen` emits:

```text
protocol/carrierreadiness_generated.go
protocol/carrierreadiness_test.go
protocol/carrierreadiness_parity_test.go
protocol/carrierreadiness_hygiene_test.go
```

Generated constants specialize profile ID, seed, readiness decision, runtime policy, future milestone list, boundary names, and next milestone text.

## Limitations

This readiness gate is a review artifact and deterministic fixture set. It does not create carrier code or approve field deployment.

## Next Milestone

The recommended next milestone is M41: HTTPS-like carrier lab design lock. See [KIP-0047](KIP-0047-https-like-carrier-lab-design-lock.md).

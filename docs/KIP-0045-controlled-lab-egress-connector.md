<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0045: Controlled Lab Egress Connector

## Purpose

Milestone 39 adds a controlled lab egress connector model. It validates allowlisted loopback target classes, connector lifecycle, fixture exchange, target-induced backpressure, error/reset isolation, half-close metadata, queue bounds, trace hygiene, fixture drift, and generated-backend parity.

This is not a public egress connector, production relay, DNS resolver, SOCKS/HTTP adapter, TLS carrier, VPN component, or deployment feature.

## Model

`internal/labegress` models:

- loopback allowlist validation
- synthetic target classes
- connector lifecycle summaries
- fixture exchange counts
- slow-target and queue backpressure
- target error and reset isolation
- half-close metadata
- safe summary hashes
- generated/interpreted parity

The connector records only safe metadata:

```text
allowlisted synthetic target class
        ↓
lab egress connector lifecycle
        ↓
fixture exchange summary
        ↓
backpressure / reset / error buckets
        ↓
fixture drift and generated parity
```

## Commands

```bash
go run ./cmd/kcheck labegress --quick
go run ./cmd/kcheck labegress --full --out testdata/audit/labegress.json
go run ./cmd/kcheck labegress generate --out testdata/labegress/labegress-report-golden.json --force
go run ./cmd/kcheck labegress verify
go run ./cmd/kcheck labegress compare --old testdata/labegress/labegress-report-golden.json --new testdata/labegress/labegress-report-golden.json
```

## Audit Gates

Milestone 39 adds gates for:

- allowlist validation
- connector lifecycle
- fixture exchange
- target-induced backpressure
- error/reset isolation
- half-close metadata
- queue limits
- trace hygiene
- generated-backend parity
- mutant detection
- fixture drift

## Generated Backend

`kgen` emits:

```text
protocol/labegress_generated.go
protocol/labegress_test.go
protocol/labegress_parity_test.go
protocol/labegress_hygiene_test.go
```

Generated constants specialize profile ID, seed, connector policy, response limits, runtime policy, scenario names, and target class buckets.

## Limitations

The egress connector is controlled and synthetic. It does not dial public targets, resolve names, capture packets, store payloads, or expose a deployable relay.

## Next Milestone

The recommended next milestone is M40: carrier prototype readiness gate.

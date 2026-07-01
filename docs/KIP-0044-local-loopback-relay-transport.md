<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0044: Local Loopback Relay Transport

## Purpose

Milestone 38 adds a deterministic loopback relay transport harness. It validates that local loopback bind/dial policy, relay session lifecycle, handshake metadata, frame exchange, bounded queues, backpressure, reset isolation, malformed-input rejection, fixture drift, and generated-backend parity are all represented before any later connector work.

This milestone does not add a public relay, remote transport, deployment path, DNS resolver, TLS/WebSocket carrier, SOCKS proxy, VPN, or external target.

## Model

`internal/loopbackrelay` models:

- loopback-only bind policy
- loopback-only dial policy
- relay session summaries
- handshake completion
- frame encode/decode counts
- stream mapping counts
- queue pressure and backpressure
- reset isolation
- malformed frame rejection
- safe trace hygiene
- generated/interpreted parity

The harness stores only safe metadata:

```text
loopback bind class
        ↓
relay session class
        ↓
handshake and frame summaries
        ↓
backpressure/reset/malformed event buckets
        ↓
fixture hash and parity report
```

## Commands

```bash
go run ./cmd/kcheck loopbackrelay --quick
go run ./cmd/kcheck loopbackrelay --full --out testdata/audit/loopbackrelay.json
go run ./cmd/kcheck loopbackrelay generate --out testdata/loopbackrelay/loopbackrelay-report-golden.json --force
go run ./cmd/kcheck loopbackrelay verify
go run ./cmd/kcheck loopbackrelay compare --old testdata/loopbackrelay/loopbackrelay-report-golden.json --new testdata/loopbackrelay/loopbackrelay-report-golden.json
```

## Audit Gates

Milestone 38 adds gates for:

- loopback bind policy
- session lifecycle
- handshake completion
- frame round trip
- backpressure
- reset isolation
- malformed input rejection
- resource limits
- trace hygiene
- generated-backend parity
- mutant detection
- fixture drift

## Generated Backend

`kgen` emits:

```text
protocol/loopbackrelay_generated.go
protocol/loopbackrelay_test.go
protocol/loopbackrelay_parity_test.go
protocol/loopbackrelay_hygiene_test.go
```

Generated constants specialize profile ID, seed, loopback bind/dial policy, session/frame limits, runtime mapping policy, and scenario list.

## Limitations

The loopback relay is a deterministic local harness. It does not create external listeners, connect to public targets, probe networks, or deploy relays.

## Next Milestone

The recommended next milestone is M39: controlled lab egress connector.

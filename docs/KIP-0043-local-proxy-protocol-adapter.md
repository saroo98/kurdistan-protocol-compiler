<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0043: Local Proxy Protocol Adapter

## Purpose

Milestone 37 adds a local protocol metadata adapter above the concrete local socket harness. It parses CONNECT-like and SOCKS5-like control metadata into safe internal relay descriptors without forwarding payload bytes, resolving names, dialing targets, or preserving raw target strings in traces.

The adapter is a deterministic parser and mapping layer. It is not a production proxy, SOCKS server, HTTP CONNECT server, DNS resolver, or network egress adapter.

## Model

The package `internal/localprotocoladapter` defines:

- local protocol adapter configuration and validation
- CONNECT-like metadata parsing
- SOCKS5-like metadata parsing
- parser lifecycle states
- target class redaction and port bucketing
- local concrete-adapter and pipeline mapping summaries
- misuse detection for forbidden behavior
- generated/interpreted parity summaries
- fixture drift comparison

Accepted metadata is converted into payload-free request summaries:

```text
local connection metadata
        ↓
CONNECT-like or SOCKS5-like parser
        ↓
target class and port bucket
        ↓
concrete local adapter mapping
        ↓
local pipeline mapping
        ↓
safe fixture summary
```

## Safety Boundary

The adapter rejects:

- outbound dialing
- DNS resolution
- payload forwarding
- credential-bearing modes
- UDP associate and bind-like commands
- header smuggling controls
- raw target persistence
- exact port persistence
- payload or secret logging

Fixture summaries store classes, buckets, counts, parser states, and hashes only.

## Commands

```bash
go run ./cmd/kcheck localprotocoladapter --quick
go run ./cmd/kcheck localprotocoladapter --full --out testdata/audit/localprotocoladapter.json
go run ./cmd/kcheck localprotocoladapter generate --out testdata/localprotocoladapter/localprotocoladapter-report-golden.json --force
go run ./cmd/kcheck localprotocoladapter verify
go run ./cmd/kcheck localprotocoladapter compare --old testdata/localprotocoladapter/localprotocoladapter-report-golden.json --new testdata/localprotocoladapter/localprotocoladapter-report-golden.json
```

## Audit Gates

Milestone 37 adds gates for:

- config validation
- CONNECT-like parser behavior
- SOCKS5-like parser behavior
- target redaction
- parser state machine behavior
- concrete adapter integration
- local pipeline mapping
- resource limits
- error redaction
- misuse detection
- generated-backend parity
- trace hygiene
- mutant detection
- fixture drift

## Generated Backend

`kgen` emits:

```text
protocol/localprotocoladapter_generated.go
protocol/localprotocoladapter_test.go
protocol/localprotocoladapter_parity_test.go
protocol/localprotocoladapter_hygiene_test.go
```

The generated source specializes profile ID, seed, runtime mapping policy, request limits, parser transition limits, protocol family constants, scenario names, and parser states.

## Limitations

This milestone validates local metadata parsing only. It does not implement concrete SOCKS, HTTP CONNECT, DNS, UDP, TLS, carrier, deployment, or external-network behavior.

## Next Milestone

The recommended next milestone is M38: local loopback relay transport.

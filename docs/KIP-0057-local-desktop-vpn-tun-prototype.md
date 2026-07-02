<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0057: Local Desktop VPN/TUN Prototype

Milestone 51 implements the first controlled desktop packet-style adapter prototype. It follows the M50 semantics contract and remains a deterministic local prototype. It does not create a real TUN interface, change host routes, capture packets, implement Android VpnService behavior, perform field testing, or add public deployment behavior.

## Scope

The `internal/localvpnadapter` package models packet-style adapter behavior through descriptors and summaries:

- packet-flow descriptor lifecycle
- flow-to-stream mapping
- stream-to-flow result mapping
- MTU and fragmentation bucket handling
- retry, reset, and backpressure handling
- kill-switch policy summaries
- DNS boundary enforcement
- privacy-preserving diagnostics
- local proxy adapter composition
- multi-carrier selection composition
- relay bridge and local pipeline integration
- pathhealth and measurementreview enforcement
- resource-limit and panic-safety checks
- trace hygiene and generated parity

## Blocked Behavior

The prototype blocks:

- Android VpnService behavior
- public deployment
- field testing
- unreviewed OS route mutation
- payload logging
- packet dumps
- credential storage
- per-app identity logging by default
- precise endpoint logging
- unrestricted DNS interception
- public-network egress defaults

## Fixture Set

Committed fixtures live in `testdata/localvpnadapter/`:

- `localvpnadapter-report-golden.json`
- `flow-descriptors.json`
- `flow-runs.json`
- `integration-report.json`
- `resource-report.json`
- `panic-safety-report.json`
- `trace-hygiene-report.json`
- `misuse-report.json`
- `localvpnadapter-parity-report.json`

The fixture set contains safe classes, counts, hashes, and hygiene flags. It does not contain raw packet bytes, payloads, app identity, exact endpoints, DNS queries, resolver addresses, secrets, keys, nonces, auth tags, or proof material.

## Audit Gates

Run:

```bash
go run ./cmd/kcheck localvpnadapter --quick
go run ./cmd/kcheck localvpnadapter --full --out testdata/audit/localvpnadapter.json
go run ./cmd/kcheck localvpnadapter generate --out testdata/localvpnadapter/localvpnadapter-report-golden.json --force
go run ./cmd/kcheck localvpnadapter verify
go run ./cmd/kcheck localvpnadapter compare --old testdata/localvpnadapter/localvpnadapter-report-golden.json --new testdata/localvpnadapter/localvpnadapter-report-golden.json
```

`testdata/audit/localvpnadapter.json` is an ignored local audit artifact.

## Generated Backend

Generated modules include local packet adapter constants and tests through `protocol/localvpnadapter_generated.go`, `protocol/localvpnadapter_test.go`, `protocol/localvpnadapter_parity_test.go`, and `protocol/localvpnadapter_hygiene_test.go`. Generated constants use neutral packet-adapter markers to avoid universal protocol strings in generated source.

## Limitations

M51 proves that packet-style flow descriptors can enter the stream/runtime/carrier path under local deterministic controls. It does not prove field readiness, Android readiness, production safety, censorship bypass, or deployment readiness.

## Next Milestone

M52 defines the long-running relay process architecture: configuration, lifecycle, logging boundaries, shutdown, compatibility, profile loading, relay policy, observability without payload logging, crash behavior, and safe process-review interfaces.

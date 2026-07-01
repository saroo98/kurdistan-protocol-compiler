<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0047: HTTPS-Like Carrier Lab Design Lock

## Purpose

Milestone 41 converts the broad carrier readiness evidence from M40 into a precise implementation contract for one future carrier family: an HTTPS-like lab carrier. This is a design lock only. It defines the M42 implementation boundary, shape taxonomy, stream mappings, backpressure rules, reset/error isolation, fixtures, misuse controls, and generated-backend parity expectations.

M41 does not implement real TLS, real HTTPS requests, SNI routing, Host header routing, CDN/provider behavior, public-network egress, arbitrary target proxying, payload forwarding, payload logging, packet capture, or measurement upload.

## Contract Package

`internal/httpscarrierreview` records:

- allowed lab-only behavior
- blocked behavior matrix
- bounded request-shape marker classes
- bounded response-shape marker classes
- stream open/close/reset/error mapping contract
- backpressure mapping contract
- fixture schema and drift baseline
- trace hygiene contract
- misuse controls
- M42 acceptance criteria

The review decision is:

```text
ready_for_m42_lab_prototype
```

That decision means the M42 lab prototype contract is locked. It does not mean an HTTPS carrier exists yet.

## Fixtures

Fixtures live under:

```text
testdata/httpscarrierreview/
```

They contain safe metadata only: shape classes, bounded marker names, fixture hashes, blocker status, and M42 acceptance criteria. They do not contain raw payloads, encoded bytes, endpoints, domains, packet captures, secrets, keys, nonce bases, auth tags, or proof material.

## Commands

```bash
go run ./cmd/kcheck httpscarrierreview --quick
go run ./cmd/kcheck httpscarrierreview --full --out testdata/audit/httpscarrierreview.json
go run ./cmd/kcheck httpscarrierreview generate --out testdata/httpscarrierreview/httpscarrierreview-report-golden.json --force
go run ./cmd/kcheck httpscarrierreview verify
go run ./cmd/kcheck httpscarrierreview compare --old testdata/httpscarrierreview/httpscarrierreview-report-golden.json --new testdata/httpscarrierreview/httpscarrierreview-report-golden.json
```

## Audit Gates

M41 adds gates for:

- HTTPS carrier scope contract
- request/response shape taxonomy
- stream mapping contract
- backpressure contract
- reset/error contract
- integration contract
- M42 implementation contract
- blocker matrix
- risk model
- readiness checklist
- misuse detection
- generated-backend parity
- trace hygiene
- public claim safety
- mutant detection
- fixture drift

## Generated Backend

`kgen` emits:

```text
protocol/httpscarrierreview_generated.go
protocol/httpscarrierreview_test.go
protocol/httpscarrierreview_parity_test.go
protocol/httpscarrierreview_hygiene_test.go
```

Generated constants specialize the profile ID, seed, runtime policy, request/response shape counts, blocked behavior list, M42 criteria, schema version, and backend version.

## M42 Acceptance Criteria

M42 must implement bounded request and response shape markers, stream open/close/reset/error mapping, backpressure propagation, local integration with existing lab layers, measurement-review enforcement, generated/interpreted parity, and trace hygiene.

M42 must still reject real TLS, real HTTPS client behavior, public-network egress, provider integration, arbitrary target proxying, payload logging, and packet capture.

## Limitations

This milestone freezes a contract. It is not a carrier implementation, not a deployment design, and not evidence of field readiness.

## Next Milestone

The recommended next milestone is M42: HTTPS-like carrier lab prototype.

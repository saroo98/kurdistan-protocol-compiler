<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0039: Local Proxy Egress And Relay Bridge Model

Milestone 33 adds the local proxy egress and relay bridge model. It connects the already deterministic local proxy ingress side to synthetic egress target behavior through trace-safe descriptors, bridge sessions, bridge streams, and audit gates.

This is a local synthetic model. It does not dial relays, resolve names, capture packets, add deployment behavior, or implement a concrete proxy/VPN adapter.

## Purpose

The goal is to prove that an ingress request can be mapped to a safe egress descriptor and a relay bridge stream without leaking payloads, destinations, endpoint data, resolver data, DNS queries, secrets, or real carrier information.

The model checks:

- egress request descriptor validation
- synthetic target descriptor validation
- ingress-to-egress mapping preservation
- adaptive prerequisite binding
- egress lifecycle execution
- bridge session and stream validation
- backpressure propagation
- reset and error isolation
- misuse and leak detection
- fixture drift detection
- generated backend parity

## Proxy Egress Model

`internal/proxyegress` defines deterministic fixtures for:

- egress request descriptors
- synthetic egress target descriptors
- egress mapping plans
- lifecycle scenarios and reports
- adaptive binding reports
- ingress-to-egress mapping reports
- backpressure reports
- reset/error isolation reports
- misuse reports
- generated/interpreted parity reports

Synthetic target classes include echo, fixed response, chunked response, slow response, large object, reset midstream, error response, drip response, blackhole control, and collapsed control.

## Relay Bridge Model

`internal/relaybridge` models:

- bridge sessions
- bridge streams
- request-to-stream mapping
- synthetic relay identity classes
- stream policy classes
- scheduler classes
- bridge backpressure
- reset and error propagation
- stream isolation
- adaptive runtime binding

The bridge uses synthetic identifiers and bucketed classes only.

## Audit Gates

M33 adds these proxy egress gates:

- `proxyegress_contract_validation`
- `proxyegress_target_model`
- `proxyegress_ingress_mapping`
- `proxyegress_adaptive_binding`
- `proxyegress_lifecycle_execution`
- `proxyegress_backpressure`
- `proxyegress_reset_error_isolation`
- `proxyegress_misuse_detection`
- `proxyegress_generated_backend_parity`
- `proxyegress_trace_hygiene`
- `proxyegress_mutant_detection`
- `proxyegress_fixture_drift`

It also adds these relay bridge gates:

- `relaybridge_session_validation`
- `relaybridge_stream_mapping`
- `relaybridge_adaptive_runtime_binding`
- `relaybridge_backpressure`
- `relaybridge_reset_error_isolation`
- `relaybridge_stream_isolation`
- `relaybridge_misuse_detection`
- `relaybridge_generated_backend_parity`
- `relaybridge_trace_hygiene`
- `relaybridge_mutant_detection`
- `relaybridge_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck proxyegress --quick
go run ./cmd/kcheck proxyegress --full --out testdata/audit/proxyegress.json
go run ./cmd/kcheck proxyegress generate --out testdata/proxyegress/egress-lifecycle-golden.json --force
go run ./cmd/kcheck proxyegress verify

go run ./cmd/kcheck relaybridge --quick
go run ./cmd/kcheck relaybridge --full --out testdata/audit/relaybridge.json
go run ./cmd/kcheck relaybridge generate --out testdata/relaybridge/relaybridge-report-golden.json --force
go run ./cmd/kcheck relaybridge verify
```

## Fixtures

Committed fixtures live under:

- `testdata/proxyegress/`
- `testdata/relaybridge/`

They contain safe descriptors, counts, hashes, lifecycle states, and summary metadata only. They do not contain raw payloads, raw bytes, endpoint data, resolver data, DNS queries, keys, nonces, auth tags, proof material, or secrets.

## Generated Backend Parity

`kgen` emits:

- `protocol/proxyegress_generated.go`
- `protocol/proxyegress_test.go`
- `protocol/proxyegress_parity_test.go`
- `protocol/proxyegress_hygiene_test.go`
- `protocol/relaybridge_generated.go`
- `protocol/relaybridge_test.go`
- `protocol/relaybridge_parity_test.go`
- `protocol/relaybridge_hygiene_test.go`

Generated modules expose profile-specific constants and deterministic fixture accessors so the codegen audit can verify the generated backend has not drifted from the interpreted fixture model.

## Limitations

This milestone is a model and regression gate layer only. It does not implement a concrete egress adapter, real relay bridge, socket listener, outbound dialer, SOCKS adapter, VPN adapter, HTTP carrier, TLS mimicry, WebSocket carrier, CDN behavior, deployment system, or live network testing.

## Next Milestone

The recommended next milestone is M34: end-to-end local proxy pipeline. That milestone should connect the ingress, egress, relay bridge, byte transport, runtime, and generated backend evidence into one deterministic local pipeline without adding concrete network adapters.

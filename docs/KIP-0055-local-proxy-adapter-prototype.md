<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0055: Local Proxy Adapter Prototype

Milestone 49 implements the first controlled local proxy adapter prototype. It takes accepted local metadata from the local protocol adapter, opens a safe internal stream descriptor, carries opaque local fixture content through the runtime and carrier path, and reports only payload-free metadata.

This is a local lab prototype. It does not add public deployment, unrestricted outbound proxying, Android behavior, transparent VPN behavior, packet capture, DNS resolution by default, credential storage, browser or OS configuration automation, or field testing.

## Scope

The prototype covers:

- accepted local SOCKS-like and CONNECT-like metadata summaries from `localprotocoladapter`
- one accepted local request mapped to one internal runtime stream class
- symbolic opaque content classes instead of raw stream bytes
- stream open, close, reset, half-close, drain, and backpressure summaries
- carrier selector, pathhealth, pathrace, carrierreview, relaybridge, localpipeline, labegress, measurementreview, hardening, and codegen composition
- deterministic fixtures, drift checks, misuse controls, trace hygiene, and generated/interpreted parity

## Stream Classes

The fixture set uses symbolic stream classes:

```text
no_content_marker
small_stream_marker
chunked_stream_marker
long_lived_stream_marker
slow_stream_marker
reset_stream_marker
halfclose_stream_marker
backpressure_stream_marker
control_payload_leak
control_unbounded_stream
control_target_leak
```

Control classes must be rejected before unsafe behavior reaches the runtime path.

## Trace Hygiene

Fixtures and summaries may include:

- request class buckets
- target class buckets
- port class buckets
- stream class names
- byte-count buckets
- chunk-count buckets
- safe content hashes
- backpressure, reset, half-close, and lifecycle counters

They must not include raw payload bodies, raw stream bytes, packet captures, credentials, exact non-loopback targets, exact ports, SNI, Host header values, DNS queries, resolver addresses, keys, nonces, auth tags, proof material, or secrets.

## Gates

Run:

```bash
go run ./cmd/kcheck localproxyadapter --quick
go run ./cmd/kcheck localproxyadapter --full --out testdata/audit/localproxyadapter.json
go run ./cmd/kcheck localproxyadapter generate --out testdata/localproxyadapter/localproxyadapter-report-golden.json --force
go run ./cmd/kcheck localproxyadapter verify
go run ./cmd/kcheck localproxyadapter compare --old testdata/localproxyadapter/localproxyadapter-report-golden.json --new testdata/localproxyadapter/localproxyadapter-report-golden.json
```

## Limitations

The prototype is intentionally bounded and deterministic. It proves the adapter path can preserve redaction, stream isolation, backpressure, reset behavior, resource bounds, and generated parity under controlled local conditions. It is not a public proxy adapter and does not make field-readiness claims.

## Next Milestone

M50 defines the local TUN/VPN packet-flow semantics needed before a future desktop packet-style adapter. It remains a model/review step and does not create a TUN device, capture packets, change OS routes, intercept app traffic, or implement Android VpnService behavior.

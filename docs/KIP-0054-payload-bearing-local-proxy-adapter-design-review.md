<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0054: Payload-Bearing Local Proxy Adapter Design Review

Milestone 48 defines the design contract for moving from metadata-only local proxy parsing into controlled local stream-content handling. It does not implement payload forwarding. The purpose is to freeze what M49 may build: a local-only proxy adapter prototype that can carry opaque local stream bytes through Kurdistan without logging payloads, persisting exact targets, bypassing carrier gates, or claiming public deployment readiness.

## Scope

M48 covers:

- Local-only SOCKS-like stream adapter semantics.
- Local-only HTTP CONNECT-like stream adapter semantics.
- Opaque stream-content handling without payload logging.
- Stream segmentation and reassembly classes.
- Flow-control and backpressure boundaries.
- Reset and half-close behavior.
- Target redaction preservation.
- Composition with `localprotocoladapter`, `loopbackrelay`, `multicarrierselect`, `labegress`, `localpipeline`, and `measurementreview`.
- Resource limits, panic safety, misuse controls, and public-claim limits.

The fixtures are design artifacts. They use symbolic stream-content classes and safe buckets only.

## Decisions

M49 may carry opaque local stream bytes only inside a bounded local prototype. It may accept the reviewed local SOCKS-like and HTTP CONNECT-like parser states from M37. Parser states can open a runtime stream only after target redaction, capability checks, and carrier-selection preconditions pass.

Exact targets and exact ports remain excluded from reports. Public artifacts may contain target class buckets, port class buckets, request classes, priority classes, and policy buckets only.

Payload bytes remain internal to the future M49 prototype. Traces, fixtures, audit reports, errors, summaries, and generated artifacts may contain byte counts, buckets, flags, and symbolic classes only.

## Blocked Behavior

M49 remains blocked from:

- Public deployment.
- External target proxying beyond controlled policy.
- DNS resolution by default.
- Transparent OS-wide VPN behavior.
- TUN/VPN packet capture.
- Android behavior.
- Payload logging.
- Packet capture.
- Credential storage.
- Browser or OS configuration automation.
- Field testing.

## Fixtures

Fixtures live under:

```text
testdata/localproxyadapterreview/
```

The primary fixture is:

```text
localproxyadapterreview-report-golden.json
```

Companion reports cover scope, protocol acceptance, payload handling, stream mapping, backpressure/reset behavior, target redaction, carrier-selector integration, resource limits, misuse controls, public-claim safety, M49 acceptance, and generated parity.

## Gates

M48 adds these gates:

```text
localproxyadapterreview_scope_contract
localproxyadapterreview_protocol_acceptance
localproxyadapterreview_payload_contract
localproxyadapterreview_stream_mapping
localproxyadapterreview_backpressure_reset
localproxyadapterreview_target_redaction
localproxyadapterreview_carrier_selector_integration
localproxyadapterreview_resource_limits
localproxyadapterreview_misuse_detection
localproxyadapterreview_public_claim_safety
localproxyadapterreview_m49_contract
localproxyadapterreview_generated_backend_parity
localproxyadapterreview_trace_hygiene
localproxyadapterreview_fixture_drift
```

## Commands

```bash
go run ./cmd/kcheck localproxyadapterreview --quick
go run ./cmd/kcheck localproxyadapterreview --full --out testdata/audit/localproxyadapterreview.json
go run ./cmd/kcheck localproxyadapterreview generate --out testdata/localproxyadapterreview/localproxyadapterreview-report-golden.json --force
go run ./cmd/kcheck localproxyadapterreview verify
go run ./cmd/kcheck localproxyadapterreview compare --old testdata/localproxyadapterreview/localproxyadapterreview-report-golden.json --new testdata/localproxyadapterreview/localproxyadapterreview-report-golden.json
```

The full audit output under `testdata/audit/` is an ignored local artifact.

## Generated Backend Parity

Generated modules include local proxy adapter review constants and tests. The generated source scanner verifies profile-specific review files, parity tests, and hygiene tests. The generated backend version for this milestone is `0.48.0-lab`.

## Limitations

M48 is a design review. It does not implement a working proxy, arbitrary target forwarding, DNS resolution, public-network egress, payload forwarding, packet capture, browser/OS configuration automation, Android behavior, field testing, or deployment tooling.

## Next Milestone

M49 should implement the local-only proxy adapter prototype according to this contract.

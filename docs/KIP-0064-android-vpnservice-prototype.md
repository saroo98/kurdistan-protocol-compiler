<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0064: Android VpnService Prototype

Milestone 58 introduces a deterministic Android VpnService prototype boundary above the Android local runtime port. The package models Android VPN permission state, VpnService lifecycle state, packet-flow descriptor mapping, fail-closed behavior, redacted diagnostics, reconnect hooks, integration gates, fixtures, and generated-backend parity without connecting Android traffic to a carrier.

## Purpose

M56 defined the Android architecture contract and M57 proved that Kurdistan runtime initialization can be modeled in an Android-shaped local environment. M58 checks whether a VpnService-style boundary can be represented as safe deterministic state and metadata before any carrier-connected Android traffic work.

## State Model

The prototype records these safe states:

- `permission_required`
- `permission_granted`
- `vpn_starting`
- `vpn_active`
- `vpn_stopping`
- `vpn_stopped`
- `reconnecting`
- `failed`
- `blocked_by_policy`
- `diagnostic_ready`

Invalid transitions are rejected. Repeated starts and stops are idempotent. Terminal states do not accept packet-flow descriptors.

## Permission Boundary

The permission model keeps Android VPN consent explicit. Startup is blocked until permission is granted, revocation moves the prototype into fail-closed state, and no fallback path is allowed to bypass profile validation, relay compatibility, carrier availability, or platform policy.

## Packet-Flow Mapping

M58 maps packet-flow descriptors to the existing stream/runtime model using the reviewed local TUN/VPN semantics. The mapping stores only flow classes, stream buckets, byte-count buckets, lifecycle states, and result flags. It does not store raw packets, raw destinations, application identity, DNS queries, or payload contents.

## Kill Switch

Fail-closed behavior is required for:

- invalid profile material
- carrier runtime unavailable
- relay compatibility failure
- Android VPN permission revocation
- lifecycle transition failure
- background or battery policy block

The kill-switch report records only failure classes and policy outcomes.

## Diagnostics

Diagnostics summarize lifecycle events, runtime transitions, failure classes, network-change events, battery/background restrictions, reconnect attempts, crash-recovery state, and hygiene flags. Diagnostic output is bounded, payload-free, and secret-free.

## Reconnect Hooks

Reconnect hooks cover network switching, sleep/wake, permission changes, runtime restarts, profile refresh, and carrier review changes. Attempts are bounded, deterministic, and auditable.

## Integration Gates

The prototype preserves prior layers:

- profile validation
- Android local runtime
- operational hardening
- local VPN/TUN semantics
- pathhealth
- measurement review
- hardening checks
- generated-backend parity
- public-claim safety

## Fixtures

Committed fixtures under `testdata/androidvpnservice/` contain only deterministic safe metadata:

```text
testdata/androidvpnservice/androidvpnservice-report-golden.json
testdata/androidvpnservice/permission.json
testdata/androidvpnservice/lifecycle.json
testdata/androidvpnservice/packet-flow.json
testdata/androidvpnservice/kill-switch.json
testdata/androidvpnservice/diagnostics.json
testdata/androidvpnservice/reconnect.json
testdata/androidvpnservice/integration.json
testdata/androidvpnservice/shutdown.json
testdata/androidvpnservice/checklist-report.json
testdata/androidvpnservice/misuse-report.json
testdata/androidvpnservice/trace-hygiene-report.json
testdata/androidvpnservice/public-claim-safety-report.json
testdata/androidvpnservice/androidvpnservice-parity-report.json
```

## Audit Gates

`kcheck androidvpnservice` reports:

- `androidvpnservice_report`
- `androidvpnservice_permission_model`
- `androidvpnservice_lifecycle`
- `androidvpnservice_packet_flow_mapping`
- `androidvpnservice_kill_switch`
- `androidvpnservice_diagnostics`
- `androidvpnservice_reconnect_hooks`
- `androidvpnservice_integration`
- `androidvpnservice_shutdown`
- `androidvpnservice_misuse_detection`
- `androidvpnservice_generated_backend_parity`
- `androidvpnservice_trace_hygiene`
- `androidvpnservice_public_claim_safety`
- `androidvpnservice_fixture_drift`

Run:

```bash
go run ./cmd/kcheck androidvpnservice --quick
go run ./cmd/kcheck androidvpnservice --full --out testdata/audit/androidvpnservice.json
go run ./cmd/kcheck androidvpnservice generate --out testdata/androidvpnservice/androidvpnservice-report-golden.json --force
go run ./cmd/kcheck androidvpnservice verify
go run ./cmd/kcheck androidvpnservice compare --old testdata/androidvpnservice/androidvpnservice-report-golden.json --new testdata/androidvpnservice/androidvpnservice-report-golden.json
```

## Generated Backend

Generated modules include Android VpnService constants, fixture metadata, parity checks, trace hygiene checks, and the backend version `0.58.0-lab`.

## Limitations

M58 does not provide a mobile application, Android UI, foreground service implementation, notification implementation, carrier-connected Android traffic, packet capture, public carrier behavior, raw traffic diagnostics, automatic telemetry, app-store packaging, or field-test readiness.

## Next Milestone

M59 should connect the Android VpnService prototype to the reviewed carrier runtime while preserving fail-closed behavior, diagnostics hygiene, reconnect bounds, and generated/interpreted parity.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0063: Android Local Runtime Port

Milestone 57 prepares Kurdistan runtime execution for Android-shaped local operation without Android VpnService traffic capture. It validates that the runtime can be initialized from validated profile material, driven through Android lifecycle events, summarized through redacted diagnostics, bounded by storage and concurrency rules, shut down safely, and checked through generated/interpreted parity.

M57 is a local runtime port and audit milestone. It does not implement Android packet capture, TUN handling, app traffic interception, foreground service code, Android UI, automatic telemetry, public carrier behavior, app-store packaging, or field-test behavior.

## Runtime Contract

The Android local runtime contract models these lifecycle events:

- app start
- profile import
- profile validation
- connect intent
- disconnect intent
- background transition
- foreground transition
- network-change notification
- permission loss
- crash recovery
- shutdown

Profile material must be validated before it can initialize runtime state, carrier compatibility, path-health state, diagnostics, or generated backend parity checks. Invalid profile, stale session, permission loss, and unsafe compatibility paths fail closed into safe diagnostic buckets.

## Initialization And Profile Loading

Initialization uses the policy `validated_profile_android_local_runtime_startup`. The deterministic fixture checks:

- Android-shaped app startup sequence
- profile import and validation before runtime start
- safe defaults for disabled telemetry, bounded diagnostics, and no packet capture
- compatibility with relay auth, carrier selection, pathhealth, carrierreview, measurementreview, operational hardening, and trace hygiene

The runtime port is intentionally represented as a deterministic local model so repository checks do not require a physical Android device.

## Storage Boundaries

The storage model separates:

- validated profile bundle storage
- user-exported redacted diagnostic storage
- bounded cache storage
- generated runtime artifact metadata
- ephemeral runtime state

Fixtures and diagnostics do not include raw payloads, packet captures, visited domains, URLs, SNI, Host headers, DNS queries, resolver addresses, credentials, phone/SIM/device identifiers, precise location, private keys, session secrets, or telemetry upload markers.

## Diagnostics

Diagnostics are local and redacted. Allowed diagnostic fields are safe classes and counts such as:

- runtime state bucket
- profile validation result
- carrier compatibility bucket
- relay auth bucket
- pathhealth bucket
- lifecycle event count
- failure class
- recovery action
- shutdown status
- redaction status

Failure classes are mapped before export. Raw lower-level errors are not committed into fixtures or status output.

## Concurrency And Lifecycle

The M57 model checks bounded Android runtime tasks and queues:

- maximum runtime task count
- maximum lifecycle events
- maximum diagnostic events
- stale session rejection after lifecycle invalidation
- safe shutdown wait bounds
- no uncontrolled background work

Invalid lifecycle transitions are rejected, repeated close/shutdown is idempotent, and stale session reuse is represented as a misuse condition.

## Compatibility

M57 preserves the previous milestone contracts:

- M56 Android architecture review
- M55 operational hardening
- relay auth, profile expiry, rotation, and compatibility
- carrier selection gates
- measurementreview and carrierreview gates
- pathhealth gates
- generated backend version compatibility
- trace hygiene gates

The generated source backend includes Android runtime markers and tests:

```text
protocol/androidruntime_generated.go
protocol/androidruntime_test.go
protocol/androidruntime_parity_test.go
protocol/androidruntime_hygiene_test.go
```

Generated modules specialize Android runtime constants with profile ID, seed, lifecycle policy, carrier/backpressure policy, replay/compatibility policy, lifecycle event count, misuse-control count, and backend version `0.57.0-lab`.

## Fixtures And Gates

Committed fixtures under `testdata/androidruntime/` contain only deterministic safe metadata:

```text
testdata/androidruntime/androidruntime-report-golden.json
testdata/androidruntime/initialization.json
testdata/androidruntime/lifecycle.json
testdata/androidruntime/storage-boundaries.json
testdata/androidruntime/diagnostics.json
testdata/androidruntime/concurrency.json
testdata/androidruntime/compatibility.json
testdata/androidruntime/shutdown.json
testdata/androidruntime/checklist-report.json
testdata/androidruntime/misuse-report.json
testdata/androidruntime/trace-hygiene-report.json
testdata/androidruntime/public-claim-safety-report.json
testdata/androidruntime/androidruntime-parity-report.json
```

`kcheck androidruntime` reports:

- `androidruntime_report`
- `androidruntime_initialization`
- `androidruntime_lifecycle`
- `androidruntime_storage_boundaries`
- `androidruntime_diagnostics`
- `androidruntime_concurrency`
- `androidruntime_compatibility`
- `androidruntime_shutdown`
- `androidruntime_misuse_detection`
- `androidruntime_generated_backend_parity`
- `androidruntime_trace_hygiene`
- `androidruntime_public_claim_safety`
- `androidruntime_fixture_drift`

Run:

```bash
go run ./cmd/kcheck androidruntime --quick
go run ./cmd/kcheck androidruntime --full --out testdata/audit/androidruntime.json
go run ./cmd/kcheck androidruntime generate --out testdata/androidruntime/androidruntime-report-golden.json --force
go run ./cmd/kcheck androidruntime verify
go run ./cmd/kcheck androidruntime compare --old testdata/androidruntime/androidruntime-report-golden.json --new testdata/androidruntime/androidruntime-report-golden.json
```

## Limitations

M57 does not provide a mobile application, Android UI, Gradle project, JNI binding, Android VpnService integration, packet capture, traffic forwarding, foreground service implementation, notification implementation, automatic telemetry, live carrier behavior, public-network behavior, or field-test readiness. It proves the local runtime contract and fixtures that M58 must preserve when the VpnService prototype boundary is introduced.

## Follow-On

M58 adds the Android VpnService prototype boundary after this local runtime layer proves profile loading, lifecycle handling, diagnostics, storage boundaries, compatibility, safe shutdown, generated backend parity, and trace hygiene in Android-shaped local execution.

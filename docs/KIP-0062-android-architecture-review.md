<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0062: Android Architecture Review

Milestone 56 defines the Android client architecture contract before any Android runtime or VpnService implementation expands on device. It turns the relay/runtime operational boundary from M55 into a product-facing review for profile import, Android permissions, UI state, lifecycle, reconnect behavior, kill-switch semantics, diagnostics, privacy boundaries, and the M57/M58 implementation contracts.

M56 is a review and audit milestone. It does not implement an Android app, an Android runtime port, VpnService traffic handling, packet capture, public carrier behavior, automatic telemetry, or field-test behavior.

## User Flows

The Android contract covers these user-facing flows:

- onboarding and profile import
- profile signature, version, expiry, and rotation checks
- connect, disconnect, reconnect, and safe reset
- failure display for expired profiles, incompatible relays, carrier failure, network changes, revoked VPN permission, and crash recovery
- local diagnostic export with user-controlled notes

Profile import is fail-closed. A profile must be validated before it can influence runtime state, carrier selection, relay compatibility, path health, or diagnostics.

## Permission And Lifecycle Model

The architecture requires Android platform permission boundaries to be explicit:

- VPN permission must be requested through the platform flow before VpnService behavior can start in M58.
- Notification and foreground service behavior must be visible, bounded, and tied to active runtime state.
- Optional boot behavior is opt-in and must never bypass profile validation.
- Battery optimization guidance may be shown to the user, but it must not hide unsafe background execution assumptions.
- Background work must be bounded by lifecycle and resource limits inherited from operational hardening.

## UI State Model

The review freezes a UI state vocabulary for later Android implementation:

- disconnected
- validating profile
- connecting
- carrier selecting
- relay handshaking
- connected
- reconnecting
- blocked by kill switch
- profile expired
- relay incompatible
- carrier failed
- network changed
- VPN permission revoked
- diagnostic bundle ready
- crashed and recovered

The UI contract separates user-actionable failures from internal diagnostic classes. Raw lower-level errors are mapped to safe failure classes before display or export.

## Diagnostics And Privacy

Diagnostics are local and user-controlled by default. A diagnostic bundle may contain:

- app version, profile version class, profile expiry class, and compatibility class
- UI state transitions as safe state names
- relay compatibility result class
- carrier selection result class
- path-health result class
- operational health class
- Android permission state class
- resource-limit and reconnect counters
- user notes supplied during export

Diagnostics must not include payloads, packet captures, exact destinations, account identifiers, device identifiers, precise location, secrets, keys, nonces, auth tags, proof material, or automatic upload markers.

## Kill Switch And Fail-Closed Semantics

The architecture requires fail-closed behavior when:

- profile validation fails
- the profile is expired or revoked
- Android VPN permission is revoked
- runtime compatibility fails
- relay compatibility fails
- carrier review or measurement review blocks a selected path
- operational hardening reports unsafe resource or lifecycle state

M58 must map VpnService lifecycle transitions into these states without bypassing Android permission requirements. Repeated close/reset handling must remain idempotent and terminal where required by runtime and adapter contracts.

## Runtime Composition

Android state composes with existing Kurdistan review layers:

- carrier selection must preserve carrierreview, measurementreview, pathrace, and pathhealth decisions
- profile rotation must preserve relay-auth, compatibility, expiry, and revocation checks
- generated backend compatibility must preserve interpreted/generated safe summary parity
- diagnostics must preserve hardening and trace-hygiene constraints
- operational hardening remains the resource and lifecycle boundary for Android planning

## M57 Contract

M57 should implement an Android local runtime port against this review. It should:

- load validated local profiles through the reviewed profile-import contract
- run the Kurdistan local runtime in Android-shaped lifecycle states
- expose UI state summaries and diagnostic-safe counters
- preserve capability negotiation, profile compatibility, replay checks, carrier selection, and path-health composition
- remain local and deterministic for tests
- avoid full VpnService traffic handling until M58

The M57 contract is implemented in KIP-0063 and the `internal/contracts/android/androidruntime` audit package. Its fixtures validate Android-shaped local runtime initialization, lifecycle, storage boundaries, diagnostics, concurrency assumptions, compatibility, safe shutdown, trace hygiene, misuse controls, and generated backend parity.

## M58 Contract

M58 should implement the Android VpnService prototype boundary. It should:

- request and respect Android VPN permission
- bind VpnService lifecycle to the M56 UI and kill-switch state model
- preserve fail-closed behavior on revoked permission, invalid profile, runtime incompatibility, and carrier failure
- produce trace-safe summaries only
- keep packet and traffic handling bounded by reviewed local semantics

## Fixtures And Gates

Fixtures under `testdata/androidreview/` contain deterministic policy names, state names, counts, hashes, and hygiene flags:

```text
testdata/androidreview/androidreview-report-golden.json
testdata/androidreview/user-flows.json
testdata/androidreview/permission-model.json
testdata/androidreview/ui-states.json
testdata/androidreview/diagnostics-privacy.json
testdata/androidreview/privacy-boundaries.json
testdata/androidreview/kill-switch.json
testdata/androidreview/runtime-composition.json
testdata/androidreview/m57-m58-contracts.json
testdata/androidreview/misuse-report.json
testdata/androidreview/trace-hygiene-report.json
testdata/androidreview/public-claim-safety-report.json
testdata/androidreview/androidreview-parity-report.json
```

`kcheck androidreview` reports:

- `androidreview_report`
- `androidreview_user_flows`
- `androidreview_permission_model`
- `androidreview_ui_states`
- `androidreview_diagnostics_privacy`
- `androidreview_kill_switch`
- `androidreview_runtime_composition`
- `androidreview_m57_m58_contracts`
- `androidreview_misuse_detection`
- `androidreview_generated_backend_parity`
- `androidreview_trace_hygiene`
- `androidreview_public_claim_safety`
- `androidreview_fixture_drift`

Run:

```bash
go run ./cmd/kcheck androidreview --quick
go run ./cmd/kcheck androidreview --full --out testdata/audit/androidreview.json
go run ./cmd/kcheck androidreview generate --out testdata/androidreview/androidreview-report-golden.json --force
go run ./cmd/kcheck androidreview verify
go run ./cmd/kcheck androidreview compare --old testdata/androidreview/androidreview-report-golden.json --new testdata/androidreview/androidreview-report-golden.json
```

## Generated Backend

Generated modules include Android review markers and tests:

```text
protocol/androidreview_generated.go
protocol/androidreview_test.go
protocol/androidreview_parity_test.go
protocol/androidreview_hygiene_test.go
```

The generated source specializes profile ID, seed, runtime mapping policy, carrier family, replay policy, compatibility policy, UI state count, misuse-control count, and Android review backend version.

## Limitations

M56 is an architecture review. It does not provide Android UI code, Android dependency injection, profile picker UI, local Android runtime execution, VpnService traffic handling, platform notification code, packet capture, public carrier behavior, automatic telemetry, app-store packaging, or field readiness.

## Next Milestone

M58 should add the VpnService prototype after M57 proves profile loading, lifecycle, runtime composition, diagnostics, and generated parity in Android-shaped local execution.

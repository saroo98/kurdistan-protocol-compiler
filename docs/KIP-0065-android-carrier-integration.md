<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0065: Android Carrier Integration

Milestone 59 connects the deterministic Android VpnService prototype to the reviewed Kurdistan runtime and carrier path. It models the sequence from Android VPN flow state through profile validation, runtime initialization, carrier selection, relay compatibility, authenticated session setup, stream mapping, pathhealth, diagnostics, bounded reconnect/fallback, and safe shutdown.

This milestone is a reviewed prototype integration path. It does not add unrestricted field testing, public-network deployment, packet capture, telemetry upload, or ad hoc carrier behavior.

## Runtime Path

The Android carrier integration report records these safe stages:

- profile validation
- Android VpnService active
- runtime initialization
- carrier selection
- relay compatibility
- authenticated session
- stream mapping
- pathhealth
- safe shutdown

Traffic is considered connected only after profile validation, carrier gate checks, relay compatibility, and authenticated session setup have completed.

## UI States

The integration exposes safe Android-facing state vocabulary:

- `selecting_carrier`
- `connecting_relay`
- `connected_through_carrier`
- `carrier_failed`
- `relay_incompatible`
- `profile_expired`
- `reconnecting`
- `fallback_attempted`
- `diagnostic_bundle_ready`

The states are metadata classes. They do not include packet contents, raw destinations, identifiers, or lower-level carrier data.

## Carrier Selection Gates

Carrier selection must respect:

- profile policy
- carrier review
- measurement review
- pathhealth
- runtime compatibility
- operational safety
- generated-backend parity

The fixture rejects bypasses for carrier review, measurement review, pathhealth, runtime compatibility, public-network egress, unbounded fallback, and generated drift.

## Relay Compatibility

Relay compatibility checks cover relay identity, client profile identity, profile bundle version, transport/carrier compatibility, rotation window, expiry and revocation, downgrade rejection, and stale-profile handling.

These checks happen before Android state can report `connected_through_carrier`.

## Flow Integration

The integration maps Android VPN flow metadata through the existing runtime and carrier model using safe counters and classes:

- Android flow descriptors
- runtime streams
- carrier envelopes
- stream close/reset outcomes
- target error/reset outcomes
- pathhealth result classes

The report does not store raw packets, payload bodies, visited domains, URLs, SNI, Host headers, DNS queries, resolver identifiers, credentials, phone/SIM/device identifiers, precise locations, key material, session secrets, or telemetry endpoints.

## Failure Diagnostics

Diagnostics expose redacted failure classes:

- `profile_invalid`
- `profile_expired`
- `carrier_unavailable`
- `carrier_review_blocked`
- `measurement_review_blocked`
- `pathhealth_blocked`
- `relay_incompatible`
- `relay_auth_failed`
- `fallback_exhausted`
- `runtime_restart_required`

Diagnostic bundles are bounded and use counts, buckets, state names, policy classes, and hygiene flags.

## Reconnect and Fallback

Reconnect and fallback behavior is deterministic and bounded. The integration reports success path, carrier failure, relay failure, profile failure, network-change recovery, fallback exhaustion, kill-switch interaction, and diagnostic export scenarios.

Fallback is fail-closed when policy requires it. Exhaustion does not silently bypass profile, carrier, relay, pathhealth, or measurement-review constraints.

## Fixtures

Committed fixtures under `testdata/androidcarrier/` contain only deterministic safe metadata:

```text
testdata/androidcarrier/androidcarrier-report-golden.json
testdata/androidcarrier/runtime-path.json
testdata/androidcarrier/ui-states.json
testdata/androidcarrier/carrier-selection.json
testdata/androidcarrier/relay-compatibility.json
testdata/androidcarrier/flow-integration.json
testdata/androidcarrier/failure-diagnostics.json
testdata/androidcarrier/reconnect-fallback.json
testdata/androidcarrier/profile-validation.json
testdata/androidcarrier/shutdown-safety.json
testdata/androidcarrier/checklist-report.json
testdata/androidcarrier/misuse-report.json
testdata/androidcarrier/trace-hygiene-report.json
testdata/androidcarrier/public-claim-safety-report.json
testdata/androidcarrier/androidcarrier-parity-report.json
```

## Audit Gates

`kcheck androidcarrier` reports:

- `androidcarrier_report`
- `androidcarrier_runtime_path`
- `androidcarrier_ui_states`
- `androidcarrier_carrier_selection`
- `androidcarrier_relay_compatibility`
- `androidcarrier_flow_integration`
- `androidcarrier_failure_diagnostics`
- `androidcarrier_reconnect_fallback`
- `androidcarrier_profile_validation`
- `androidcarrier_shutdown_safety`
- `androidcarrier_misuse_detection`
- `androidcarrier_generated_backend_parity`
- `androidcarrier_trace_hygiene`
- `androidcarrier_public_claim_safety`
- `androidcarrier_fixture_drift`

Run:

```bash
go run ./cmd/kcheck androidcarrier --quick
go run ./cmd/kcheck androidcarrier --full --out testdata/audit/androidcarrier.json
go run ./cmd/kcheck androidcarrier generate --out testdata/androidcarrier/androidcarrier-report-golden.json --force
go run ./cmd/kcheck androidcarrier verify
go run ./cmd/kcheck androidcarrier compare --old testdata/androidcarrier/androidcarrier-report-golden.json --new testdata/androidcarrier/androidcarrier-report-golden.json
```

## Generated Backend

Generated modules include Android carrier integration constants, fixture metadata, parity checks, trace hygiene checks, and backend version `0.59.0-lab`.

Generated output includes:

```text
protocol/androidcarrier_generated.go
protocol/androidcarrier_test.go
protocol/androidcarrier_parity_test.go
protocol/androidcarrier_hygiene_test.go
```

## Limitations

M59 does not implement unrestricted public carrier behavior, Android app distribution, live carrier probing, public-network deployment, automatic telemetry, packet capture, raw traffic diagnostics, ad hoc carrier fallback, or field-test readiness.

## Next Milestone

M60 should adversarially test the Android carrier integration for unsafe fallback, leakage, bypasses, generated drift, and Android-specific safety failures.

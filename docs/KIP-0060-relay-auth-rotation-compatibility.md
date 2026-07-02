<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0060: Relay Auth, Rotation, and Compatibility

## Purpose

Milestone 54 defines the audited design layer for relay authentication, profile and version compatibility, controlled rotation, safe failure behavior, and M55 operational-hardening prerequisites.

This milestone does not provision relays, enable public discovery, add account systems, or implement deployment behavior. It freezes the relay-auth contract that later operational work must obey.

## Scope

The `internal/relayauthplan` package defines deterministic safe reports for:

- relay auth inventory
- identity binding policy
- relay, transport, carrier, and profile bundle compatibility matrix
- rotation window policy
- profile expiry and revocation policy
- safe failure policy
- downgrade rejection policy
- unknown-version and stale-profile handling
- M55 operational hardening prerequisites
- misuse controls
- trace hygiene
- public claim safety
- generated-backend parity

## Contract Summary

M54 requires relay identity and client profile identity before session open. It requires profile bundle version checks, relay/transport/carrier compatibility checks, bounded rotation windows, expiry and revocation checks, fail-closed behavior, downgrade rejection, unknown-version rejection by default, stale-profile rejection by default, and only bucketed diagnostics.

The contract is aligned with M53 key exchange design markers and relay process lifecycle constraints.

## Blocked Behavior

M54 blocks unauthenticated relay acceptance, silent downgrade, unknown-version fail-open behavior, stale-profile fail-open behavior, rotation without an overlap window, missing revocation policy, secret logging, key-material logging, account tracking, public relay discovery, production provisioning, cloud-provider dependency, and generated backend drift.

## Fixtures

Fixtures under `testdata/relayauthplan/` contain only policy names, safe buckets, counts, hashes, and hygiene flags:

```text
testdata/relayauthplan/relayauthplan-report-golden.json
```

Companion reports cover inventory, identity binding, compatibility, rotation, expiry/revocation, safe failure, downgrade rejection, unknown/stale profile handling, M55 prerequisites, misuse detection, trace hygiene, public claim safety, and generated parity.

## Audit Gates

`kcheck relayauthplan` reports:

- `relayauthplan_inventory`
- `relayauthplan_identity_binding`
- `relayauthplan_compatibility_matrix`
- `relayauthplan_rotation_policy`
- `relayauthplan_expiry_revocation`
- `relayauthplan_safe_failure`
- `relayauthplan_downgrade_rejection`
- `relayauthplan_unknown_stale_profile`
- `relayauthplan_m55_prerequisites`
- `relayauthplan_misuse_detection`
- `relayauthplan_generated_backend_parity`
- `relayauthplan_trace_hygiene`
- `relayauthplan_public_claim_safety`
- `relayauthplan_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck relayauthplan --quick
go run ./cmd/kcheck relayauthplan --full --out testdata/audit/relayauthplan.json
go run ./cmd/kcheck relayauthplan generate --out testdata/relayauthplan/relayauthplan-report-golden.json --force
go run ./cmd/kcheck relayauthplan verify
go run ./cmd/kcheck relayauthplan compare --old testdata/relayauthplan/relayauthplan-report-golden.json --new testdata/relayauthplan/relayauthplan-report-golden.json
```

Generated modules include relay auth design constants and tests:

```text
protocol/relayauthplan_generated.go
protocol/relayauthplan_test.go
protocol/relayauthplan_parity_test.go
protocol/relayauthplan_hygiene_test.go
```

## Limitations

M54 is a design and review layer. It does not implement production relay authentication, relay provisioning, public relay discovery, user accounts, cloud integration, Android behavior, or field-test tooling. M55 now covers the operational hardening contract around these relay-auth boundaries.

## Next Milestone

M55 operational hardening builds on this contract. After M55, M56 should perform the Android architecture review without bypassing relay-auth, compatibility, rotation, or operational-hardening gates.

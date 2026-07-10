<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0061: Operational Hardening

## Purpose

Milestone 55 hardens the relay/runtime operational surface before Android architecture work begins. It turns the M52 relay process architecture, M53 key-exchange design, and M54 relay-auth contract into deterministic operational checks for resource bounds, strict config validation, lifecycle behavior, safe diagnostics, rollback boundaries, compatibility preservation, misuse detection, fixture drift, and generated-backend parity.

M55 does not implement Android behavior, public deployment automation, public relay discovery, account systems, production provisioning, live carrier behavior, or field-test tooling.

## Scope

The `internal/contracts/readiness/operationalhardening` package defines deterministic safe reports for:

- relay/runtime resource limits
- operational config validation
- shutdown and restart lifecycle behavior
- safe logging and diagnostics
- rollback and update boundaries
- redacted operational health summaries
- carrier/runtime/pathhealth/measurementreview/carrierreview compatibility integration
- misuse controls for unsafe operational defaults
- trace hygiene
- public claim safety
- generated-backend parity

## Contract Summary

M55 requires bounded relay/runtime process, session, stream, queue, timer, generated-profile, and diagnostic-buffer classes. Operational configs must reject missing, ambiguous, stale, incompatible, unsafe-default, over-permissive, or disabled-gate states with safe error classes. Shutdown and restart behavior is deterministic and bounded, in-flight sessions use safe close behavior, and compatibility state must be revalidated before restart.

Operational diagnostics may expose state buckets, failure classes, version compatibility buckets, resource-limit classes, redaction status, rollback class, and health-summary buckets. They must not expose payloads, destinations, profile secrets, key material, exact user identifiers, sensitive network metadata, packet-capture artifacts, or telemetry-upload markers.

Rollback and update behavior is modeled as safe metadata: some operational components are rollbackable, compatibility floors remain forward-compatible, auth/profile/wire-policy changes require profile rotation, and unknown or ambiguous states fail closed.

## Misuse Controls

M55 represents and detects these unsafe controls:

- `operationalhardening_unsafe_defaults_allowed`
- `operationalhardening_fail_open_allowed`
- `operationalhardening_unbounded_retry_loop`
- `operationalhardening_unbounded_memory_growth`
- `operationalhardening_verbose_sensitive_logs`
- `operationalhardening_auth_disabled`
- `operationalhardening_compatibility_checks_disabled`
- `operationalhardening_measurementreview_disabled`
- `operationalhardening_carrierreview_disabled`
- `operationalhardening_hardening_gates_disabled`
- `operationalhardening_rollback_without_fail_closed`
- `operationalhardening_generated_backend_drift`

## Fixtures

Fixtures under `testdata/operationalhardening/` contain only policy names, safe buckets, counts, hashes, and hygiene flags:

```text
testdata/operationalhardening/operationalhardening-report-golden.json
```

Companion reports cover resource limits, config validation, lifecycle behavior, safe logging, rollback/update boundaries, health summaries, compatibility integration, checklist status, misuse detection, trace hygiene, public claim safety, and generated parity.

## Audit Gates

`kcheck operationalhardening` reports:

- `operationalhardening_report`
- `operationalhardening_resource_limits`
- `operationalhardening_config_validation`
- `operationalhardening_lifecycle`
- `operationalhardening_safe_logging`
- `operationalhardening_rollback_boundaries`
- `operationalhardening_health_summary`
- `operationalhardening_compatibility_integration`
- `operationalhardening_misuse_detection`
- `operationalhardening_generated_backend_parity`
- `operationalhardening_trace_hygiene`
- `operationalhardening_public_claim_safety`
- `operationalhardening_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck operationalhardening --quick
go run ./cmd/kcheck operationalhardening --full --out testdata/audit/operationalhardening.json
go run ./cmd/kcheck operationalhardening generate --out testdata/operationalhardening/operationalhardening-report-golden.json --force
go run ./cmd/kcheck operationalhardening verify
go run ./cmd/kcheck operationalhardening compare --old testdata/operationalhardening/operationalhardening-report-golden.json --new testdata/operationalhardening/operationalhardening-report-golden.json
```

Generated modules include operational hardening constants and tests:

```text
protocol/operationalhardening_generated.go
protocol/operationalhardening_test.go
protocol/operationalhardening_parity_test.go
protocol/operationalhardening_hygiene_test.go
```

## Limitations

M55 is an operational hardening and audit layer. It does not provide Android architecture, Android VpnService integration, production relay provisioning, public relay discovery, account tracking, deployment automation, live network testing, or a field-ready client.

## Next Milestone

M56 uses these hardened relay/runtime operational boundaries to define the Android architecture review. M57 should port the local runtime against that Android contract while preserving the M55 resource, lifecycle, diagnostics, compatibility, and trace-hygiene gates.

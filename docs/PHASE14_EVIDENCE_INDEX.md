<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 evidence index

Status: local assurance complete; candidate integration pending; release decision **NO_GO**

This index separates evidence that can be produced in the repository from
evidence that requires production systems, owned infrastructure, physical
devices, distribution accounts, or independent observation. Missing external
evidence is never replaced by a local simulation.

## Local evidence

| Evidence | Authority | Required result |
| --- | --- | --- |
| Prior-phase baseline | `go run ./cmd/gate -android`, Phase 13 acceptance record | Green, cache-independent |
| Phase 14 decision verifier | `go run ./cmd/phase14verify -root .` | Rejects incomplete or contradictory `GO` records |
| Android host assurance | `android/gradlew phase14Gate` | Build, lint, host tests, artifact scans, SBOM and evidence checks pass |
| Android device assurance | `android/gradlew phase14DeviceGate` | Exact manifest, non-zero tests, crash/ANR scan clean |
| Product coverage | `docs/PHASE14_FEATURE_COVERAGE.md` | Every inventory capability has an evidence-backed disposition |
| Field protocol | `docs/PHASE14_FIELD_VALIDATION_PROTOCOL.md` | Owned/authorized boundary, stop rules, privacy, scenarios and evidence defined |
| Release procedure | `docs/PHASE14_RELEASE_RUNBOOK.md` | Signing, staged rollout, rollback and abort gates defined without credentials |
| Recovery procedure | `docs/PHASE14_ROLLBACK_RUNBOOK.md` | App, profile, provider and relay rollback drills defined |
| Incident procedure | `docs/PHASE14_INCIDENT_RESPONSE.md` | Severity, containment, evidence and notification responsibilities defined |
| Same-host unsigned reproducibility | `testdata/evidence/phase14/reproducibility.json` | Two clean cache-disabled release APKs are byte-identical; cross-host and production signing remain unverified |
| Recovery drills | `testdata/evidence/phase14/recovery-drills.json` | Local fail-closed authority, backup, restore, reset, process-death and corruption exercises pass |
| Emulator longevity | `testdata/evidence/phase14/longevity.json` | Exact 28-test device manifest and 50-cycle navigation exercise pass without crash or ANR |

## External evidence

The following remain **[UNVERIFIED]** until observed in their declared
environment and recorded with an artifact digest, bounded timestamp, owner
alias, scope, result, limitations, expiry, and revalidation condition:

- production profile authority and protected key custody;
- owned production provider, control plane, and relay fleet;
- production monitoring, backup, recovery, and emergency deny;
- physical-device and OEM matrix;
- cellular/Wi-Fi handover, sleep, captive portal, constrained-device, and
  long-duration behavior;
- controlled hostile-network testing against owned or explicitly authorized
  systems;
- independent security, privacy, cryptography, accessibility, and operations
  assessments required by the release policy;
- production signing, store declaration, staged distribution, rollback, and
  post-release monitoring.

## Evidence handling

- Do not commit endpoints, credentials, keys, raw device identifiers, package
  inventories, payloads, destinations, user traffic, or reviewer personal data.
- Use random campaign/session aliases and coarse device classes.
- Hash immutable artifacts with SHA-256 and record the build provenance used.
- Treat expired, partial, contradictory, self-asserted, or environment-mismatched
  evidence as **[UNVERIFIED]**.
- `GO` requires every mandatory local and external item to be `PASS`; one
  missing item keeps the decision at `NO_GO`.

The external evidence classes are carried forward to Phases 16-22. Phase 15
may integrate and freeze this locally complete candidate, but cannot substitute
repository or emulator evidence for production, field, signing, distribution,
or independent observation.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 readiness matrix

Status: local assurance complete and integrated; release decision `NO_GO`

This matrix separates locally resolvable engineering work from evidence that
can exist only in an authorized production or field environment.

| Area | Local prerequisite | External completion evidence | Current status |
| --- | --- | --- | --- |
| Prior phases | Phase 13 host and API 26/34/36 device gates | Reviewed integration baseline | Integrated on `main` at `bd7fb851bdc5103fb77310839e1cdeebfe8ffda1` |
| Product coverage | Reconciled D0-D28 and inspiration inventory map | Physical-device workflow observation | Local reconciliation pass; external unverified |
| Android quality | API 26/34/36 emulator, accessibility, adaptive, recovery, performance | OEM, weak-device, foldable, tablet, cellular and sleep matrix | Emulator pass; external unverified |
| VPN correctness | Authority-bound TUN, fail-closed DNS, route and lifecycle tests | Owned non-loopback relay and leak tests | Local pass; external unverified |
| Relays | Deployment, health, capacity and rollback harnesses | Owned production relay fleet | Unverified |
| Provider/operator | Signed publication, rotation, revocation and emergency-deny tooling | Production identity, custody and operated service | Unverified |
| Key management | Provider interfaces, custody procedures and recovery drill format | Production HSM/KMS ceremonies and independent evidence | Unverified |
| Privacy | No telemetry, secret-safe diagnostics, data inventory and deletion | Privacy review and store disclosures | Local pass; external unverified |
| Supply chain | Locks, verification metadata, SBOM, licenses and pinned CI | Protected signing service and distribution provenance | Local pass; external unverified |
| Release | Unsigned artifact checks, rollout and rollback runbooks | Signed AAB/APK, Play declaration, staged rollout and rollback exercise | Same-host unsigned reproducibility pass; external unverified |
| Field validation | Controlled-test protocol and redacted evidence format | Authorized hostile-network observations | Unverified |
| Operations | Incident, backup, restore, emergency-disable and recovery procedures | On-call ownership, monitoring, SLO and disaster-recovery exercise | Unverified |

## Local closure evidence

- `go test -json -count=1 -timeout=10m ./...` passed with 4,914 streamed test
  events;
- the strict, cache-disabled Phase 14 Android host gate passed 1,079 executed
  tasks;
- the exact API 36 emulator manifest passed all 28 required tests in 122.873
  seconds with an empty crash buffer;
- two fully clean, cache-disabled unsigned release builds were byte-identical
  at 6,090,389 bytes and SHA-256
  `0ebb3a030a1ebe5955927c19c66bea9e4962191c74adfab7a2aa7616f864e8dd`;
- the release APK permission, exported-component, native-library, dependency,
  telemetry, claim, and secret boundaries passed local inspection;
- the coverage, field, incident, rollback, release, and evidence records are
  present and fail closed while external evidence is absent.

## Genuine external blockers

These cannot be truthfully closed by source changes or emulator tests:

- production signing and key custody;
- owned production relays and provider infrastructure;
- physical-device/OEM and mobile-network observations;
- controlled field validation in authorized environments;
- production monitoring, on-call ownership, incident response and disaster
  recovery exercises;
- store review, VpnService declaration, staged distribution and rollback.

The codebase must nevertheless provide every safe local prerequisite and the
exact evidence interface needed to close each item later.

Phases 16-22 in `ROADMAP.md` own those external implementation and observation
requirements. Phase 15 integrates this candidate and freezes their production
contract; it does not turn any external item into `PASS`.

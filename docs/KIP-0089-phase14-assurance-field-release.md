<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0089: Phase 14 assurance, field validation, and release readiness

Status: local assurance complete; candidate integration pending; release remains no-go

Last updated: 2026-08-02

## Decision

Phase 14 is the release-assurance phase. It may build release tooling, evidence
collection, controlled-test harnesses, operator runbooks, rollback exercises,
and locally testable product hardening. It may not convert source presence,
loopback behavior, emulator results, or self-authored reports into production
or field evidence.

The release decision is fail-closed. `GO` is valid only when every mandatory
local and external evidence item is present, current, integrity-bound, reviewed,
and observed in its declared environment. Missing, expired, contradictory, or
unverifiable evidence yields `NO_GO`.

## Prior-phase entry gate

Phase 14 work begins only after:

- `go run ./cmd/gate -android` passes;
- `go run ./cmd/phase13verify -root .` passes;
- the exact Phase 13 device manifest passes on the available API 36 emulator;
- `git diff --check` passes;
- Phase 13 evidence continues to distinguish local proof from external proof.

These entry checks passed on 2026-08-02. The Phase 13-14 candidate is ready for
integration review but is not yet integrated into `main`, so this KIP does not
claim an integrated baseline.

## Mandatory evidence classes

### Local assurance

- uncached Go build, vet, tests, and audit;
- cache-independent Android host gate;
- exact device-test manifests with crash and ANR rejection;
- release-manifest, dependency, native-symbol, SBOM, license, and secret-canary
  inspection;
- deterministic release-input and unsigned-artifact comparison;
- backup, restore, reset, key invalidation, process death, rollback, and
  emergency-recovery exercises;
- feature coverage reconciled with the product inventory.

### External assurance

- production profile authority and signing-custody evidence;
- production relay ownership, deployment, capacity, monitoring, and rollback;
- production provider publication, rotation, revocation, and emergency deny;
- physical-device and OEM matrix results;
- cellular, Wi-Fi, captive-portal, handover, sleep, battery, and constrained
  device results;
- controlled hostile-network and censorship-resilience observations on owned
  or explicitly authorized infrastructure;
- independent security, privacy, cryptography, accessibility, and operations
  review records where required by the release policy;
- production app signing, distribution-channel, Play VpnService declaration,
  prominent disclosure, store listing, staged rollout, rollback, and incident
  response evidence.

External evidence must identify its environment, observation time, scope,
artifact digest, owner, and expiry or revalidation condition. Credentials,
private keys, real endpoints, user data, and reviewer personal data must not be
stored in the repository.

Phases 16-22 own the implementation and collection needed to satisfy these
external evidence classes. Phase 14 closes the local prerequisites and the
fail-closed evidence interfaces only. It does not authorize deployment, a
pilot, signing, distribution, or a public release.

## Android and Play requirements

The release package must follow the current Android `VpnService` lifecycle,
foreground-service restrictions, system always-on and lockdown behavior, and
adaptive/core quality guidance. Google Play distribution additionally requires
an accurate VpnService declaration, encrypted traffic to the VPN endpoint, and
prominent in-app disclosure and affirmative consent if sensitive data is
accessed or collected.

Primary references:

- https://developer.android.com/reference/android/net/VpnService
- https://developer.android.com/develop/adaptive-apps/quality-guidelines/core-app-quality
- https://support.google.com/googleplay/android-developer/answer/12564964
- https://developer.android.com/studio/publish/app-signing
- https://csrc.nist.gov/pubs/sp/800/61/r3/final
- https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final

## Product boundary

The inspiration inventory is a coverage input, not a design or protocol
authority. Applicable capabilities must be implemented in original Kurdistan
VPN interaction and visual language. Capabilities that widen signed profile
authority, weaken certificate verification, expose an unauthenticated proxy,
leak DNS, collect hardware identifiers, log destinations or payloads, or claim
guaranteed bypass remain prohibited.

Every visible control must be one of:

1. implemented, validated, persisted when appropriate, runtime-backed, and
   tested;
2. unavailable with a precise reason and clearing condition; or
3. omitted because it is inapplicable or unsafe, with that disposition recorded
   in the Phase 14 coverage map.

## Release decision

`testdata/evidence/phase14/acceptance-status.json` is the machine-readable
decision input. `cmd/phase14verify` enforces its schema and fail-closed logic.
The repository currently records `NO_GO`. No local implementation can change
production or field items to `PASS` without real external evidence.

The machine-readable `complete` field remains `false` while the overall release
decision is `NO_GO`. That is compatible with local assurance being complete:
the remaining blockers are explicitly external and are assigned to the
production phases in `ROADMAP.md`.

## Prohibited claims

Until the decision is `GO` with complete evidence, the product and release
materials must not claim that Kurdistan VPN is production-ready, field-proven,
uncensorable, undetectable, anonymous, impossible to block, or guaranteed to
bypass censorship.

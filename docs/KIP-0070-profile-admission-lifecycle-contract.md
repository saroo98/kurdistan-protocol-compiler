<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0070: Offline Profile Admission and Lifecycle Contract

## Status

- status: implemented-contract
- scope: deterministic offline metadata validation and pure lifecycle state
- implementation authority: M3 contract foundation only

M3 opens only the verified-profile and revocation/update catalog entries. The
implementation validates explicit authority-evidence metadata, not a signature
or any cryptographic proof. It performs no I/O, persistence, networking,
runtime activation, fallback, relay, diagnostic, Android, VPN, or operator work.

## Admission and binding

An admitted candidate has bounded identifiers, the exact supported contract
version, mandatory safety floor, nonzero monotonic generation, current validity,
scoped revocation identifier, and complete authority metadata. Authority issuer,
subject, evidence reference, issue/expiry times, kind, and version are required.
The neutral envelope projection binds the same issuer, profile reference,
expiry, revocation identifier, and compatibility version without profile bytes.

Unknown, missing, expired, future, rollback, incompatible, weak, mismatched,
partial, replayed, stale, or over-scoped input is rejected before lifecycle
state changes. Metadata acceptance is not authentication evidence and cannot be
used as production trust.

## Lifecycle

The pure lifecycle statuses are absent, admitted, superseded, revoked, and
disabled. Generation never decreases. An equal-generation decision is
idempotent only when identical; conflicts fail closed. Revocation and disable
cannot be bypassed by a stale admission. Recovery requires a newer admission
with the same profile and revocation scope. Replacement is an explicit two-step
transition: a newer supersede decision moves an admitted profile to observable
superseded state, then only a still-newer admission in the same profile and
scope can activate its replacement. Superseding any other source state, direct
admitted-to-admitted replacement, and stale or partial activation fail closed.

## Compatibility and evolution

The v1 shape remains supported during any future additive overlap. Unknown
versions are rejected without reinterpretation and leave the prior safe state
unchanged. Deprecation must be explicit. Removal is permitted only in a later
incompatible contract version with its own authorization and migration proof.
The nested consumer fixture is compatibility evidence, not publication.

## Closed gates

Fallback execution, relay admission, diagnostic export, app runtime, routing,
storage, Android/Gradle, VpnService/TUN, deployment, signing, sealing, keys,
production cryptography, live networking, telemetry, and product-readiness or
bypass claims remain closed.

KIP-0075 supersedes only the blanket closure of offline signing, sealing, and
key-provider implementation for Phase 8. The metadata contract remains the
admission and lifecycle predecessor: authenticated candidate bytes must still
fail closed before activation, and rejection must preserve the last known-good
state. Production keys, production signers, Android storage, HSM/KMS operation,
live delivery, networking, deployment, pilot, release, telemetry, and
product-readiness claims remain closed.

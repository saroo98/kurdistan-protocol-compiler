<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0075: Phase 8 Offline Profile Cryptography

## Status

- status: authorized-plan
- last_verified: 2026-07-17
- scope: offline production-candidate profile artifacts only
- Work orders: WO-800 through WO-811

## Authority

The owner authorized Phase 8 to replace the metadata-only profile trust seam and
unavailable sealer with an offline production-candidate artifact system. This
authorization is staged. WO-800 reconciles policy and evidence first; later work
orders freeze the threat model, artifact classes, standards, suites, schema,
trust roles, lifecycle, issuance, conformance, and review before their dependent
implementation begins.

This KIP does not choose an algorithm suite. It does not itself authorize
cryptographic code beyond the later work order whose inputs and review gates
have passed.

## Required boundary

- Every authoritative profile artifact is authenticated.
- Confidentiality is optional and exists only for a specifically provisioned
  recipient class with defined enrollment and recovery.
- The authenticated payload is signed before any recipient seal wraps it.
- Encoding is deterministic, bounded, versioned, reject-unknown for critical
  fields, and free of compression in v1.
- Algorithm suites are identified by an authenticated registry. Runtime
  negotiation cannot lower the mandatory safety floor.
- Root, issuer, emergency, relay, app-release, operator, device-wrap, and backup
  roles are distinct.
- Generation, revocation, root epoch, compatibility, and artifact identity are
  authenticated. Equal generation is idempotent only for identical
  authenticated content.
- Verification and durable candidate staging complete before activation.
  Rejection or interruption preserves the last known-good state.
- Key-provider interfaces must permit later non-exportable Android and HSM/KMS
  implementations without changing trust semantics.
- Tests and fixtures use deterministic non-production key material only.

## Evidence and review gates

1. WO-801 freezes threats, artifact classes, recipient provisioning, metadata
   privacy, root evolution, recovery, and explicit non-goals.
2. WO-802 freezes the mandatory suite, dependencies, deterministic encoding,
   platform capability, randomness, interoperability, and licensing evidence.
3. WO-803 through WO-806 implement only those frozen contracts.
4. WO-807 supplies vectors, independent reproduction, negative corpora, fuzzing,
   mutation testing, migration, recovery, and resource evidence.
5. WO-810 reviews the exact design and candidate evidence.
6. WO-811 reviews the resulting implementation and is mandatory for merge
   eligibility.
7. WO-808 requires the complete uncached repository gate and reconciled
   capability claims. WO-809 closes only the private planning record.

Unsupported suites, unknown critical fields, wrong recipients, invalid
signatures, stale generations, revoked authority, root rollback, conflicting
equal generations, entropy failures, interrupted writes, and role confusion
must fail closed with bounded secret-safe reason codes.

## Privacy and safety

No payload, key, secret, endpoint, user identity, ciphertext excerpt, or stable
cross-session identifier enters logs or diagnostics. Recipient routing metadata
must be bounded and cannot be a stable device identifier. Confidentiality claims
do not imply protection against traffic analysis or ciphertext-size
correlation.

No custom primitive or unaudited composition may become the mandatory suite.
No claim of undetectability, guaranteed bypass, or production readiness follows
from Phase 8.

## Gates that remain closed

- production keys, production signing, or public profile issuance;
- Android Keystore, KeyMint, StrongBox, encrypted local storage, or biometrics;
- production HSM/KMS, operator ceremonies, fleet key rotation, or emergency
  operation;
- live profile delivery, subscription services, networking, VPN/TUN, relay
  sessions, or transport changes;
- deployment, controlled pilot, public release, signing infrastructure, or
  production-readiness claims.

Those boundaries require their later phases, explicit authorization, running
evidence, rollback controls, and required reviews.

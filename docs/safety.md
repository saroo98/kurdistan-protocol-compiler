<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Safety

Kurdistan has graduated from a lab-only research scope into a staged product-development program. Existing `[live]`, `[model]`, and `[plan]` labels still describe current evidence; they are not permanent prohibitions on later authorized implementation.

This repository contains deterministic models alongside explicitly authorized
local implementations. Current live behavior is limited to the Android
reserved-range TUN runtime and authenticated owned-loopback Kurd transport
defined by KIP-0084 through KIP-0086. Non-loopback targets, public relays, and
production operation remain closed until their own phase authority and evidence
exist. See the `[live]` / `[model]` / `[plan]` legend in `README.md` and
`STATUS.md`.

## Current authorization: staged product program

The completed M2-M7 contracts remain the foundation. Subsequent phases may implement real product behavior through phase-specific authorization, threat boundaries, tests, review, rollback, and deployment controls. “Lab-only” or “offline-only” must not be used by itself to reject an otherwise authorized phase.

KIP-0083 authorizes the Phase 9 native Android application foundation,
bounded JNI access to the Phase 8 verifier, encrypted local profile storage,
offline import, local diagnostics, and passphrase-encrypted backup/restore.
KIP-0084 authorizes the Phase 10 private-process `VpnService`, explicit consent,
foreground service, bounded per-app policy, and deterministic TUN/DNS behavior
over `198.18.0.0/15`. KIP-0085 and KIP-0086 authorize the Phase 11 canonical
Kurd wire, authenticated process-separated session, strict TLS 1.3/TCP carrier,
owned-loopback relay conformance, and bounded permitted fallback. These phases
do not authorize a public relay, unrestricted Internet egress, production
authority or signing custody, deployment, pilot operation, or public release.

## Controlled live-development boundary

The following are permitted only inside their explicitly authorized phase and may not be activated, deployed, or represented as complete before their phase gates pass:

- production deployment or operational deployment guidance
- external or non-loopback network targets
- real-world bypass deployment
- live VPN mode, TUN devices, or packet capture
- live SOCKS or HTTP proxy transport
- shipped mobile apps (Android/VPN real sources beyond contract models)
- public relay services or operator provisioning
- cloud scripts
- live DNS, CDN, TLS mimicry, or domain-fronting transport

Deterministic local models remain the default test substrate. Live implementations advance one reviewed phase at a time and use only owned or explicitly authorized systems.

The Android app may present the truthful local VPN test control authorized by
Phases 10 and 11. It must identify the owned-loopback scope and must not present
that state as public connectivity, production service, anonymity, or censorship
resilience.

## Data handling

Do not log payloads, secrets, credentials, real user data, raw frames, proofs,
keys, or external destinations — in live code, models, or fixtures.

## Cryptography

Do not invent cryptographic constructions or use production keys in this
repository. The v0 proof uses standard Go HMAC-SHA256 and test-only key
material. KIP-0075 through KIP-0082 authorize and implement Phase 8's local
production-candidate profile-artifact boundary using reviewed standards, bounded
parsing, deterministic non-production keys, and portable key-provider
interfaces. It does not authorize production signing, production key management,
Android Keystore integration, HSM/KMS operation, live profile delivery,
deployment, pilot, or release. The external merge-eligibility evidence is
**[UNVERIFIED]** and local tests are not a substitute for it. Fixtures are safe
to commit only when deterministic, non-production, secret-free, and explicitly
identified as test material.

## Claims

Do not claim undetectability, guaranteed bypass, or real-world censorship
resistance. The audit detects local regressions only; it cannot prove
undetectability or field robustness.

The security and runtime `*_mutant_detection` gates report bounded real lab
fault-injection detector sensitivity with paired controls. A pass shows only
that each named detector turns red for its deliberate lab fault while its
paired control stays green. It does not prove defect absence, production
security, product integration, release readiness, or authorization to merge or
deploy. Other mutant gates retain the meanings documented for their own model
or test harnesses.

## Review gate

Before any future milestone expands scope — especially any move from a
model/contract to live behaviour — reviewers must re-check network boundaries,
data handling, logging, auth/key management, tests, docs, and whether the change
creates operational deployment guidance.

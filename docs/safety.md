<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Safety

Kurdistan is a local-only research prototype.

This repository may contain **deterministic models and design contracts** for
behaviour that is **not implemented live** — including mobile/VPN, carrier,
relay, and proxy-shaped semantics. These are clearly labelled, loopback-only,
and payload-free (see the `[live]` / `[model]` / `[plan]` legend in `README.md`
and `STATUS.md`). Modelling such behaviour as a contract is in scope; wiring it
to real I/O is not.

## Hard boundary — do NOT implement live

Live implementation of any of the following remains out of scope pending a
separate, explicit review:

- production deployment or operational deployment guidance
- external or non-loopback network targets
- real-world bypass deployment
- live VPN mode, TUN devices, or packet capture
- live SOCKS or HTTP proxy transport
- shipped mobile apps (Android/VPN real sources beyond contract models)
- public relay services or operator provisioning
- cloud scripts
- live DNS, CDN, TLS mimicry, or domain-fronting transport

A deterministic, loopback-only, payload-free **model** of any item above (as the
KIPs carry) is permitted; a **live** version of it is not.

## Data handling

Do not log payloads, secrets, credentials, real user data, raw frames, proofs,
keys, or external destinations — in live code, models, or fixtures.

## Cryptography

Do not implement custom or production cryptography. The v0 proof uses standard
Go HMAC-SHA256 and test-only key material. Any future real crypto suite is gated
on external review (decision D-003). Generated profiles are safe to commit only
when they contain no real secrets and are clearly labelled as lab artifacts.

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

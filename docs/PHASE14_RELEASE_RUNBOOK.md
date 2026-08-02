<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 release runbook

Status: procedure ready; production execution **[UNVERIFIED]**

## Release inputs

- immutable source commit and clean tree;
- pinned Go, JDK, Gradle, AGP, SDK, NDK, CMake, and dependency manifests;
- green Phase 14 host/device gates and evidence record;
- independently reviewed production authority and signing-custody receipts;
- release notes, capability/limits statement, privacy disclosure, licenses,
  support path, and VpnService declaration;
- tested rollback artifact, profile/provider rollback path, relay drain plan,
  emergency deny, and staffed monitoring window.

No production key, credential, signing file, account token, or endpoint is
stored in this repository.

## Build and signing

1. Build unsigned APK/AAB artifacts on two clean builders from the same commit.
2. Compare normalized and byte-level outputs; investigate every difference.
3. Generate SBOM, licenses, provenance, checksums, native symbol allow-list, and
   manifest/permission report.
4. Sign only in the protected production signing environment with dual control.
5. Verify signer identity, artifact digest, package name, version monotonicity,
   supported ABIs, target SDK, permissions, and install/upgrade behavior.
6. Store only the public receipt and digest in release evidence.

## Staged rollout

- internal owner devices;
- authorized closed test cohort;
- small percentage rollout;
- progressive expansion only while crash-free, ANR, connection success,
  recovery, resource, privacy, and operator metrics remain inside approved
  thresholds.

Telemetry remains absent by default. Any release monitoring must use the
minimal, disclosed, opt-in, categorical design approved by the privacy gate.

## Abort and rollback

Abort for any critical/high privacy, authority, routing, DNS, kill-switch,
signing, update, crash-loop, or operator-control defect. Halt distribution,
activate emergency deny where appropriate, drain affected relays, revoke
affected profiles, publish a truthful advisory, and execute
`docs/PHASE14_ROLLBACK_RUNBOOK.md`.

## Decision

The release owner records `GO` only after every mandatory item in
`testdata/evidence/phase14/acceptance-status.json` is `PASS` and
`cmd/phase14verify` accepts the decision. Otherwise the decision is `NO_GO`.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0091: evidence-preserving CI and release acceleration

**Status:** active Phase 16 implementation authority
**Last verified:** 2026-08-02
**Work orders:** CI-001 through CI-012

## Decision

Kurdistan VPN will prove each exact subject once, record that proof in a strict
machine-readable receipt, and carry the immutable subject and receipt forward.
Signing, store upload, promotion, tagging, and publication may not rebuild the
candidate. Missing, stale, mismatched, replayed, malformed, or unauthorized
proof fails closed and triggers the complete applicable proof set.

This KIP authorizes local code, policy, CI, disposable test infrastructure, and
inactive release interfaces. It does not change the Phase 14 and Phase 15
`NO_GO` decision and does not authorize credentials, signing, Play mutation,
tags, GitHub releases, public infrastructure, pilots, or production traffic.

## Baseline

- Phase 15 main commit: `8fe2d59034deea215c45734f4bb8582bff004d9b`.
- Phase 15 branch CI: run `30747188157`, all four jobs passed.
- Phase 15 main CI: run `30748296232`, all four jobs passed.
- Historical Phase 15 input remains commit
  `1fcfeab111cf64f1295f10d788e4977ab4666a7a` and its recorded workflow bytes.
- Current release decision remains `NO_GO`.

## Proof model

The authoritative policy files are:

- `config/ci/proof-policy.json` for proof commands, platforms, cache policy,
  invalidation inputs, determinism, freshness, and phase authority;
- `config/ci/impact-policy.json` for deny-by-default pull-request selection;
- `config/ci/release-evidence-policy.json` for freshness and invalidation;
- `config/ci/tools.json` and `config/ci/android-sdk.json` for tool identities.

A receipt binds repository, commit, tree, ref, workflow path and digest, run and
job identity, trigger, proof policy, test inventory, toolchain, runner, exact
argv, timing, cache policy, result, artifacts, and limitations. A certificate
binds the exact required receipt digests. Unknown fields and duplicate JSON keys
are rejected. Receipt directories are ephemeral CI artifacts, not committed
historical evidence.

## Workflow topology

- Pull requests receive fast feedback selected by a deny-by-default impact
  policy. The stable `pr-policy` job verifies all selected proof receipts.
- Main and exact-SHA manual assurance remain full and cache independent.
- Android host jobs run Android-only proof; they do not repeat the Go gate.
- Device APK and test APK bytes are built once, hashed, uploaded once, and
  verified before each API lane installs them.
- Candidate builders are isolated and produce unsigned engineering candidates.
- Signing, Play, production promotion, and post-release workflows remain absent
  or inert until their named phases and external controls authorize activation.

## Security and privacy invariants

- Every external action is pinned to an immutable commit.
- Workflow permissions are explicit and least privilege.
- Pull requests and candidate builds receive no secrets.
- Signing and promotion jobs may never execute Gradle, Go builds, candidate
  binaries, or candidate-supplied scripts.
- Downloaded artifacts are independently hashed because transport-level digest
  warnings are not release authority.
- Receipts and logs exclude payloads, destinations, profiles, private endpoints,
  credentials, keys, tokens, device inventories, and stable user identifiers.
- CI sets `GOTELEMETRY=off`; assurance tools may not emit usage telemetry.
- External transactions are non-cancellable and must reconcile recorded remote
  state before retry.

## Rollback

The existing combined commands and `.github/workflows/ci.yml` remain available
until shadow equivalence and fault injection pass. Serial audit remains the
authoritative fallback. Receipt use remains non-authoritative until certificate
tests and policy checks pass. A failed workflow cutover is reverted without
changing protocol, crypto, Android routing, or historical evidence.

## Acceptance

This KIP is implemented only when proof inventories are equivalent, Android CI
does not repeat the Go gate, full main assurance remains cache independent,
receipts and certificates fail closed under mutation, device lanes consume the
same verified bytes, candidate comparison is repeatable, and ten measured runs
support any published speed claim. Production remains `NO_GO` until Phases
19-22 supply their separate evidence and authorization.

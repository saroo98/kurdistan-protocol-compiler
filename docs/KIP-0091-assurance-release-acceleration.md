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

- Phase 15 main commit: `83e262921d3ae8ecd8c04a2a440699b6cccace7b`.
- Phase 15 branch CI: run `30747188157`, all four jobs passed.
- Phase 15 main CI: run `30748296232`, all four jobs passed.
- Historical Phase 15 input remains commit
  `bd7fb851bdc5103fb77310839e1cdeebfe8ffda1` and its recorded workflow bytes.
- Current release decision remains `NO_GO`.

## Proof model

The authoritative policy files are:

- `config/ci/proof-policy.json` for proof commands, platforms, cache policy,
  invalidation inputs, determinism, freshness, and phase authority;
- `config/ci/impact-policy.json` for deny-by-default pull-request selection;
- `config/ci/release-evidence-policy.json` for freshness and invalidation;
- `config/ci/tools.json` and `config/ci/android-sdk.json` for tool identities.

A receipt binds repository, commit, tree, ref, workflow path, the exact commit
containing the workflow definition GitHub executed, that workflow blob's
digest, run and job identity, trigger, proof policy, test inventory, toolchain,
runner, exact argv, timing, cache policy, result, artifacts, and limitations. A certificate
binds the exact required receipt digests. Unknown fields and duplicate JSON keys
are rejected. A certificate also rejects receipts from a different workflow
source, run ID, run attempt, or trigger. Receipt directories are ephemeral CI artifacts, not committed
historical evidence.

The dependency-freshness proof scans Go call reachability with the pinned
`govulncheck` tool and scans the canonical Android release-runtime CycloneDX
SBOM with the pinned OSV Scanner. It deliberately does not misclassify Gradle
lint, unified-test-platform, source, or Javadoc configurations as shipped
Android dependencies. The Android host proof regenerates and byte-compares the
SBOM from the locked release runtime. Dependency proof invalidation binds every
Gradle lockfile, the version catalog, verification metadata, and the canonical
SBOM, so a dependency change cannot retain a stale runtime scan receipt.

## Workflow topology

- Pull requests receive fast feedback selected by a deny-by-default impact
  policy. Impact selection and the stable `pr-policy` receipt enforcement run
  from the protected base commit, not pull-request-owned tooling. Changes to
  proof policy or enforcement code therefore fail closed until trusted review
  integrates the new authority.
- Main and exact-SHA manual assurance remain full and cache independent. The
  authoritative `android-host` proof invokes `ciAssuranceHostGate` with build
  cache, configuration cache, and task-output reuse disabled.
- Pull requests substitute only the cache-enabled `android-pr-host` feedback
  proof for `android-host`. The typed impact policy requires both proofs to
  have identical invalidation coverage, so the substitution cannot narrow the
  paths that trigger Android feedback. Pull-request receipts never become
  candidate or release authority.
- Android host jobs run Android-only proof; they do not repeat the Go gate.
- The expensive nested executable-evidence matrix is a separate mandatory
  `go-executable-evidence` proof on Linux and Windows. Ordinary `go test ./...`
  verifies its immutable inventory without recursively executing it, while the
  default local gate executes the matrix exactly once.
- Device APK and test APK bytes are built once, hashed, uploaded once, and
  verified before each API lane installs them.
- Candidate builders are isolated and produce unsigned engineering candidates.
- Branch shadow receipts are feedback evidence only. An engineering candidate
  may be requested only from the default-branch workflow for the exact current
  `main` commit, and its certificate must authenticate one successful assurance
  run attempt, workflow source commit, policy, inventory, and complete receipt
  set before either clean builder starts.
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

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0090: Phase 15 production contract freeze

Status: active; production-infrastructure engineering authorized within the
boundaries below; deployment and release remain prohibited

Last updated: 2026-08-02

## Decision

Phase 13 and Phase 14 are integrated on `main` at
`1fcfeab111cf64f1295f10d788e4977ab4666a7a`. Candidate CI run
`30739580424` and merged-main CI run `30740549679` both passed the Linux and
Windows Go and Android assurance jobs. This digest is the only Phase 15 input
baseline.

The deterministic offline evidence binds the four successful baseline jobs and
the exact `.github/workflows/ci.yml` SHA-256
`e249f212339ca93429465db678ddd108190fd19f393b9cdc3e37976f8b280809`.
Live GitHub readback is a separate freshness check and is not simulated by the
offline contract verifier.

Phase 15 freezes the v1 production contract and authorizes bounded engineering
for Phase 16 production infrastructure. It does not assert that production
infrastructure exists, does not authorize live credentials or user traffic,
and does not change the Phase 14 `NO_GO` release decision.

The machine-readable authority is
`testdata/evidence/phase15/production-contract.json`. The human-readable
contract is `docs/PHASE15_PRODUCTION_CONTRACT.md`. Where these records disagree,
the narrower, fail-closed interpretation applies until both are corrected and
reviewed.

## Authorized work

The following work may begin on isolated Phase 16 branches:

- versioned operator, publication, relay-control, and emergency-deny API
  definitions;
- reproducible infrastructure-as-code modules and policy-as-code checks;
- provider adapters for identity, HSM/KMS, secrets, database, object storage,
  DNS, certificate, audit anchoring, backup, monitoring, and alerting systems;
- disposable test environments that contain no production identity, keys,
  endpoints, user data, or public traffic;
- local and CI conformance tests, failure injection, backup/restore exercises,
  cost models, capacity models, and rollback plans;
- secret-reference interfaces, key-ceremony procedures, role separation, and
  evidence schemas, provided no real secret value is stored in Git or logs.

This authorization permits engineering and validation. It does not silently
authorize purchasing services, creating production accounts, provisioning
public endpoints, issuing production keys, changing DNS, accepting user
traffic, deploying a pilot, signing a release, store submission, or public
release. Each external action requires its named owner, approved environment,
credentials supplied through the approved secret path, cost boundary, rollback
plan, and explicit execution authorization.

## Frozen boundaries

- The Android app is the only user-facing client.
- Signed and optionally sealed `kurd://` profiles are the sole source of
  connection authority.
- The app may narrow signed authority but may never widen it.
- Operator control, profile publication, relay data-plane operation, Android
  runtime, diagnostics, and release signing remain separate trust domains.
- No operator credential or control-plane privilege enters the Android app.
- Relays accept only authenticated, profile-authorized Kurd sessions and may
  not become open proxies.
- DNS must remain inside the authenticated path unless a signed policy and the
  user explicitly select a narrower, reviewed alternative.
- Telemetry remains off by default. Payloads, destinations, credentials,
  secrets, keys, raw frames, package inventories, and reusable device
  identifiers are never diagnostic fields.
- Emergency deny is root-bound, monotonic, auditable, and fail-closed.
- Production and release claims remain prohibited until Phases 16-22 provide
  their declared evidence.

## Change control

Any change to the frozen product scope, Android support matrix, native ABI,
profile or relay schema, cryptographic suite, production data inventory,
service trust boundary, SLO/RTO/RPO target, or release claim requires:

1. a new KIP or explicit amendment;
2. compatibility and migration analysis;
3. threat, privacy, rollback, and evidence impact analysis;
4. cache-independent validation; and
5. maintainer approval before implementation crosses the affected boundary.

## Exit condition

Phase 15 is complete only when the contract verifier passes, the contract is
reviewed and committed on a dedicated branch, `main` remains the certified
Phase 13-14 baseline, and Phase 16 starts from that unambiguous authority.
Completing Phase 15 does not change the release decision from `NO_GO`.

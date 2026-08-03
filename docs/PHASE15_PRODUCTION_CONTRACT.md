<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 15 production contract

This document freezes the target contract for production-infrastructure
engineering. Values marked **target** are requirements to prove in later
phases, not evidence that the deployed service already meets them.

## 1. Baseline and release truth

| Item | Frozen value |
|---|---|
| Source baseline | `bd7fb851bdc5103fb77310839e1cdeebfe8ffda1` |
| Candidate CI | GitHub Actions run `30739580424`, success |
| Integrated-main CI | GitHub Actions run `30740549679`, success |
| Baseline workflow | `.github/workflows/ci.yml`, SHA-256 `e249f212339ca93429465db678ddd108190fd19f393b9cdc3e37976f8b280809` |
| Required baseline jobs | Linux and Windows `gate`; Linux and Windows `Android Phase 14 local assurance` |
| Release decision | `NO_GO` |
| Production traffic | Prohibited until the later phase gates pass |
| Public claims | No production-ready, uncensorable, undetectable, anonymous, impossible-to-block, or guaranteed-bypass claim |

## 2. V1 product scope

V1 is an Android VPN client backed by the existing Kurd protocol engine,
signed and optionally sealed `kurd://` profiles, owned provider and relay
services, profile-authorized fallback, in-tunnel DNS, per-app routing,
diagnostics, backup/recovery, operator rotation/revocation, and fail-closed
emergency controls.

V1 excludes an unauthenticated or open proxy, arbitrary third-party relay
operation, silent trust-on-first-use, peer-controlled downgrade, destination or
payload logging, hardware-ID telemetry, covert operation claims, and any
guarantee that a network cannot detect or block the service.

## 3. Android support and compatibility

| Surface | Frozen contract |
|---|---|
| Minimum Android | API 26 |
| Target and compile API | API 36 |
| Production application ABI | `arm64-v8a` |
| Test-only emulator ABI | `x86_64` |
| Native bridge | `kurd-android-bridge-v1` |
| Profile admission | `product-profile-admission-v1` |
| Strategy registry | `permitted-fallback-v1` |
| Relay admission | `offline-relay-descriptor-admission-v1` until a reviewed production successor is introduced |
| Diagnostics | `offline-diagnostic-export-v1` until a compatible reviewed successor is introduced |
| Cryptographic suite | Suite 1, with changes requiring an explicit migration KIP |

Supporting additional production ABIs is a future compatibility decision, not
an implicit promise. Removing an API level or schema requires measured evidence,
a migration path, and a separately reviewed amendment.

## 4. Trust and service domains

### Android client

Verifies exact profile bytes and receipts, stores protected local state, obtains
VPN consent, narrows signed policy, establishes the authenticated Kurd session,
and renders redacted state. It has no operator authority and no production
signing capability.

### Production authority and control plane

Authenticates operators, enforces least privilege and dual control, issues and
revokes bounded intermediates, signs profiles and emergency state, maintains
monotonic generation, and writes immutable audit events. Root and recovery
roles remain offline or equivalently isolated.

### Provider publication plane

Publishes immutable signed artifacts, revocations, compatibility data, expiry,
and emergency deny. Publication cannot mint authority and cannot replace an
artifact without a newer valid generation.

### Relay data plane

Accepts authenticated Kurd sessions allowed by a current profile and relay
descriptor, applies resource and abuse controls, performs egress, and emits only
privacy-bounded health evidence. It cannot issue profiles or weaken client
policy.

### Diagnostics and support

Processes user-confirmed redacted bundles and short-lived support codes. It
receives no profile secrets, payloads, destination history, operator secrets,
or stable device identity.

### Release system

Builds from a digest-pinned source and toolchain, produces reproducible
artifacts, signs through protected custody, records provenance, stages rollout,
and can halt or roll back without changing profile authority.

## 5. Production data inventory

| Class | Examples | Storage and retention contract |
|---|---|---|
| Public signed artifacts | profiles, revocations, compatibility, emergency deny | Immutable, versioned, cacheable; retain through the maximum rollback and audit window |
| Operator identity and approvals | role, action, approval, ceremony receipt | Encrypted, access-controlled, immutable audit; retention set by the approved legal and incident policy |
| Key metadata | provider key identifier, generation, state, ceremony reference | No private key bytes in application databases or Git; retain lifecycle and destruction evidence |
| Relay health | coarse capacity, availability, error category, software generation | Bounded, aggregated, no payload or destination; short operational retention |
| Client support evidence | user-confirmed redacted bundle, expiring support code | Purpose-limited, encrypted, access logged, automatically expires |
| Prohibited data | payloads, destination histories, credentials, private keys, raw frames, package inventories, stable hardware IDs | Must not be collected or logged |

Every later provider selection must document residency, retention, deletion,
backup, restore, access review, breach response, and lawful ownership before it
may receive production data.

## 6. Availability and recovery targets

These are Phase 16-22 **targets**, not current claims.

| Capability | Target |
|---|---|
| Signed publication availability | 99.95% monthly |
| Relay fleet session establishment | 99.9% monthly across supported owned regions |
| Emergency-deny propagation | p95 within 5 minutes after dual-controlled approval |
| Routine revocation publication | p95 within 10 minutes after approval |
| Control-plane recovery time objective | 4 hours |
| Publication and emergency-control recovery time objective | 30 minutes |
| Relay regional recovery time objective | 60 minutes |
| Authority/audit recovery point objective | zero acknowledged authority transitions lost |
| Operational metrics recovery point objective | at most 15 minutes, with no authority impact |

Breaching an authority, privacy, or emergency-control invariant is never traded
against an availability target. The system fails closed and the incident owner
decides recovery or rollback.

## 7. Threat contract

The production design must address stolen operator sessions, phishing,
malicious insiders, key-provider compromise, publication rollback, stale or
split-brain time, database loss, forged profiles, relay impersonation, replay,
downgrade, open-proxy abuse, resource exhaustion, supply-chain compromise,
malicious updates, Android process death, DNS escape, traffic-analysis pressure,
regional loss, and emergency-control misuse.

Root compromise, device compromise while unlocked, global passive observation,
and a network capable of blocking all reachable infrastructure are not solved
by assertion. Later phases must state measured protections and residual risk.

## 8. Infrastructure implementation authorization

Phase 16 may implement and test the interfaces and infrastructure modules named
by this contract. Default execution uses disposable, isolated, non-production
homes/accounts, synthetic data, non-production keys, owned test endpoints, cost
limits, and automatic teardown.

The authorization does not by itself permit:

- creating or changing production cloud, identity, DNS, certificate, HSM/KMS,
  database, signing, monitoring, or distribution resources;
- placing a secret, credential, endpoint inventory, private key, or personal
  record in source control, logs, artifacts, or issue trackers;
- accepting public or user traffic;
- operating a public relay or proxy;
- issuing a production profile;
- running a pilot, store submission, staged release, or public release.

Those actions require the exact owner, environment, cost and data boundary,
credential path, rollback, evidence plan, and execution approval to be recorded
before the action occurs.

## 9. Phase 16 entry gate

- Start from the certified Phase 13-14 `main` baseline.
- Keep the Phase 14 release decision `NO_GO`.
- Use a dedicated branch and isolated test environments.
- Add no secret value or real endpoint to Git.
- Define provider-neutral interfaces before binding a provider.
- Require deterministic validation, negative tests, rollback, evidence schemas,
  and a cleanup path for every infrastructure module.
- Stop before any live production activation that lacks the explicit external
  authorization described above.

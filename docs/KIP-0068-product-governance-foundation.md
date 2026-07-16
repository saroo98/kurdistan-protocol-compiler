<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0068: Product Governance Foundation

## Status

- status: requirements-lock
- scope: M2 governance and design-contract documentation only
- implementation authority: none

This KIP freezes public-safe product governance requirements. It does not implement or authorize product behavior.

## Evidence, requirements, and future gates

- **[evidence]** The current repository is a standard-library Go research compiler, local runtime, audit system, and contracts-only product scaffold. Its validated execution remains local and lab-only.
- **[requirement]** The controls in this KIP constrain any future client, profile authority, protocol path, relay, operator system, diagnostic flow, or update system.
- **[future gate]** Android application code, device VPN integration, external transport, live relays, operator services, profile services, deployment, and release remain closed. A later milestone must explicitly authorize and validate each boundary before implementation begins.

A requirement is not implementation evidence. A passing local gate is not production-readiness evidence.

## Governed planes

The product boundary contains exactly five governed planes:

1. **Profile authority plane** for signed policy, compatibility, expiry, rotation, and revocation.
2. **Client and VPN plane** for import, protected local state, user intent, platform permission, routing, DNS, kill switch, and recovery.
3. **Protocol and path plane** for session security, framing, replay defense, policy negotiation, path choice, fallback, and bounded errors.
4. **Relay and egress plane** for relay identity, authorization, compatibility, isolation, forwarding policy, resource limits, and shutdown.
5. **Operations and update plane** for scoped operator actions, provisioning state, authentic updates, rollback, emergency disable, monitoring summaries, and incident response.

No plane may infer authority from another plane's diagnostics, availability, or possession of opaque data. Cross-plane actions require explicit, authenticated, policy-valid transitions.

## Governance invariants

**[requirement]** Every future executable change must identify:

- the plane and trust boundary it changes;
- the authority that permits the transition;
- accepted and rejected states;
- data classification and retention behavior;
- safe failure, recovery, and rollback behavior;
- tests and review evidence required to open the gate; and
- the conditions that immediately close the gate again.

**[requirement]** Safety and privacy controls are mandatory floors. A profile, peer, operator action, user override, fallback choice, or update cannot negotiate below them.

**[requirement]** Ambiguous, unknown, stale, incompatible, unauthenticated, expired, revoked, or partially applied state fails closed.

## Data and privacy governance

The default is data minimization.

- No automatic telemetry.
- No traffic content, secret material, precise destination history, personal identifiers, or stable cross-session identifiers in ordinary diagnostics.
- No diagnostic authority to change profiles, routing, relay state, operator state, or update state.
- Retention must be bounded, local by default, and explicitly justified by a later authorized milestone.
- Deletion and recovery behavior must be defined before persistent product data is introduced.

Diagnostic export is user initiated. Before an export is saved, the client must present a clear preview of the redacted categories and allow cancellation. Export must not happen silently, in the background, or as a condition of connection or recovery.

## Network and authorization boundary

**[evidence]** Current validated execution remains local and does not establish a product network boundary.

**[requirement]** Future network behavior must be limited to explicitly authorized product roles and policy-valid sessions. Client, relay, profile authority, and operator permissions are distinct. Possession of one role's artifact does not grant another role.

**[requirement]** Fallback and manual override may choose only among profile-permitted strategies that satisfy mandatory safety, privacy, compatibility, and authorization floors. Failure to find such a choice leaves the client disconnected or blocked.

## Required fail-closed outcomes

The appropriate safe outcome is disconnected, blocked, rejected, rolled back, or disabled when any required condition cannot be proven. This includes invalid profile authority, revoked permission, unsupported compatibility, failed authentication, replay, policy downgrade, unavailable protected storage, unsafe routing or DNS state, relay rejection, update validation failure, and incomplete operator action.

Safe failure reporting must be useful without exposing sensitive operational or user data. Recovery must be explicit and idempotent.

## Threat ownership

| Threat family | Primary owning plane | Required cross-plane check |
|---|---|---|
| Profile forgery, expiry, revocation, rollback | Profile authority | Client and protocol admission |
| Device permission, local-state, routing, DNS, or kill-switch failure | Client and VPN | Operations recovery policy |
| Replay, downgrade, context confusion, unsafe fallback | Protocol and path | Profile policy and relay compatibility |
| Relay impersonation, isolation failure, resource abuse | Relay and egress | Protocol authentication and operations response |
| Unauthorized provisioning, update substitution, rollback, operator misuse | Operations and update | All consuming planes reject invalid state |
| Diagnostic disclosure or correlation | All five planes | Local preview and privacy policy |

## Gate sequence

The following gates remain future work:

1. synchronize tracked repository instructions with the authorized product scope;
2. define executable schemas and state transitions for the plane being opened;
3. add biting negative tests and deterministic local integration evidence;
4. complete the required security, privacy, reliability, and maintainability reviews;
5. authorize a bounded environment and rollback plan;
6. validate end-to-end behavior within that boundary; and
7. separately approve any broader pilot, deployment, or release.

KIP-0070 opened deterministic offline profile admission and lifecycle contracts.
KIP-0071 opens only deterministic offline permitted-fallback selection over
bounded metadata. KIP-0072 opens only deterministic offline structural admission
of exact profile-authorized relay descriptors after M4 recomputation, client
binding, caller-supplied time, and complete revocation checks. Neither contract
executes or probes a path, authenticates a relay, or establishes a session. All
network, live-runtime, cryptographic, Android, live-relay, operator, deployment,
release, and remaining catalog gates stay closed. KIP-0073 opens only the
user-initiated, fixed-vocabulary, previewed diagnostic export as a deterministic
in-memory value. It performs no collection, file operation, sharing, upload,
retention, logging, telemetry, transmission, or control action.
KIP-0074 opens only deterministic offline app-runtime eligibility. It accepts
caller-supplied platform metadata and exact predecessor evidence, recomputes M4
and M5 results, and returns bounded categorical dispositions. It neither starts
nor stops a service, and every Android, VPN/TUN, storage, routing, DNS, network,
operator, deployment, and release boundary remains closed.

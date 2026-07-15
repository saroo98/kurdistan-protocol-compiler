<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0001: Threat Model

## Status and interpretation

Kurdistan remains a local, lab-only protocol compiler and audit system.

- **[evidence]** The repository exercises generated protocol variation, strict local runtime behavior, bounded adversarial tests, and contracts-only product models.
- **[requirement]** Any future product must preserve the threat and privacy boundaries in this KIP and KIP-0068.
- **[future gate]** No statement below authorizes an Android VPN, live relay, profile service, operator service, external transport, deployment, or release. Each requires a later, separately authorized milestone and its own evidence.

Requirements are constraints on future work, not proof that the corresponding product behavior exists.

## Current research boundary

The compiler studies whether profiles can vary first-contact grammars, state machines, frame grammars, scheduling, padding, invalid-input behavior, and trace shapes. A stable family fingerprint is a repeated observable shape across deployments, such as a fixed first message, frame layout, state path, failure class, or scheduler cadence.

**[evidence]** Profile generation can vary:

- first-contact sequence;
- state graph and state identifiers;
- semantic-to-wire mapping;
- frame length, type, header, padding, and fragmentation choices;
- scheduling and padding parameters;
- invalid-input behavior; and
- trace expectations.

**[evidence]** Global lab constraints include the Go runtime, versioned profile schema, local test harnesses, safe trace schema, standard-library cryptography, loopback-only carriers, and bounded resource limits.

## Five-plane product threat model

Future product work is divided into five planes. Compromise in one plane must not silently grant authority in another.

1. **Profile authority plane:** issuance, signing, expiry, rotation, revocation, policy, and compatibility metadata.
2. **Client and VPN plane:** profile import, local storage, user intent, platform permission, routing policy, DNS policy, kill switch, and recovery.
3. **Protocol and path plane:** authenticated session establishment, framing, replay protection, policy negotiation, path selection, fallback, and bounded failure handling.
4. **Relay and egress plane:** relay identity, authorization, compatibility, resource controls, traffic forwarding, isolation, and shutdown.
5. **Operations and update plane:** operator authorization, provisioning records, software and configuration updates, rollback, emergency disable, health summaries, and incident response.

Diagnostics are not a sixth authority plane. They are a constrained, read-only view across the five planes and must never become a control or secret-distribution channel.

## Trust and data boundaries

- **Profile import boundary:** untrusted imported material must be authenticated, version-compatible, unexpired, unrevoked, and policy-valid before it can affect client or runtime state.
- **Local device boundary:** protected local state must be separated from UI summaries and diagnostics. Loss of UI state must not weaken routing or kill-switch decisions.
- **Client-to-relay boundary:** peer identity, profile authority, negotiated policy, and session context must be authenticated before application traffic is accepted.
- **Relay egress boundary:** relay-side forwarding must be isolated from control, operator, and diagnostic authority and constrained by explicit policy.
- **Operator boundary:** issuance, rotation, revocation, update, and emergency actions require scoped authorization and auditable state transitions.
- **Diagnostic export boundary:** export is local and user initiated. The user must preview the redacted contents before saving or sharing them.
- **Update boundary:** software and configuration changes require authenticity, compatibility, rollback protection, and a safe recovery path before activation.

No automatic telemetry is permitted. The system must not retain or expose traffic content, secrets, precise destinations, personal identifiers, or linkable cross-session records in ordinary diagnostics.

## Named threats and required controls

| Threat | **[requirement]** Required disposition |
|---|---|
| Malicious or malformed profile | Reject before it changes runtime, routing, relay, or operator state. |
| Expired, revoked, replayed, or rolled-back authority | Reject before session establishment and surface only a safe failure class. |
| Version or policy downgrade | Enforce a mandatory safe floor and reject ambiguous or unsupported negotiation. |
| Peer or relay impersonation | Bind identity, profile authority, transcript, and session context before accepting traffic. |
| Cross-profile or cross-session confusion | Keep authorization, keys, replay state, and diagnostics scoped to the intended context. |
| Fail-open routing or DNS leakage | Enter a blocked state whenever required protection or routing policy cannot be maintained. |
| Unsafe fallback or manual override | Admit only profile-permitted choices; manual action must not weaken mandatory safety policy. |
| Secret or traffic disclosure | Keep sensitive material out of UI summaries, ordinary logs, diagnostics, and exported reports. |
| Diagnostic correlation | Use bounded local summaries and avoid stable identifiers or cross-session linkage. |
| Compromised update or rollback | Reject unauthenticated, incompatible, stale, or rollback-inducing changes. |
| Operator misuse or excessive authority | Separate roles, scope actions, record safe audit events, and support revocation and emergency disable. |
| Resource exhaustion | Apply bounded queues, retries, concurrency, storage, and shutdown behavior. |
| Supply-chain or build substitution | Require reproducible artifacts, protected signing authority, provenance, and rollback readiness before release. |

## Fail-closed states

**[requirement]** The future client must remain disconnected or blocked when profile validation, permission, compatibility, authentication, policy, routing, DNS, relay selection, key protection, update validation, or required local storage protection is unavailable or uncertain.

**[requirement]** The future relay and operator planes must reject unknown, stale, incompatible, unauthorized, or ambiguous state. Recovery must require an explicit safe transition, not silent fallback.

**[evidence]** Current local tests exercise bounded fail-closed behavior for the lab runtime and contracts. They do not prove device-wide routing, live relay behavior, production operations, or release readiness.

## Later gates

**[future gate]** Before any plane becomes executable beyond the lab, its milestone must define ownership, allowed network scope, security review, privacy review, test evidence, rollback, recovery, and operational approval. M3 and later behavior remains closed until those gates are explicitly opened.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0069: Product Contracts v1

## Status

- status: requirements-lock
- scope: M2 implementation-neutral catalog only
- implementation authority: none

This KIP freezes the minimum product-contract vocabulary needed for later
planning. It does not define executable schemas, storage, networking, Android,
relay, operator, update, or cryptographic behavior. Requirements below are not
evidence that a product exists, and M3 or later work remains closed.

## Contract rules

Every later representation of these contracts must preserve one accountable
owner, one explicit trust boundary, versioned admission rules, fail-closed
rejection, data minimization, and a separately authorized implementation gate.
Unknown, ambiguous, partially applied, stale, incompatible, unauthenticated,
expired, or revoked state is rejected unless a later contract expressly proves a
safe recovery transition.

The six catalog entries are:

| Contract | Owner | Trust boundary | Admitted state | Rejected state | Version rule | Failure behavior | Privacy class | Earliest later milestone |
|---|---|---|---|---|---|---|---|---|
| Verified profile | Profile authority plane | Imported profile material into client admission | Authenticated, compatible, unexpired, unrevoked, policy-valid profile with required authority | Malformed, unknown, stale, incompatible, unauthenticated, expired, revoked, rolled-back, or policy-invalid material | Explicit supported version and mandatory safety floor; no silent downgrade | Reject before changing routing, runtime, relay, or operator state; retain prior safe state | Sensitive configuration; protected local handling and no ordinary diagnostic disclosure | M3 profile-contract design gate |
| Permitted fallback | Protocol and path plane | Profile policy and mandatory safety floors into path selection | Profile-permitted strategy satisfying authorization, compatibility, safety, and privacy floors | Unlisted, risk-blocked, incompatible, unauthenticated, ambiguous, or floor-weakening choice | Selection semantics are version-bound to the admitted profile and client capability floor | Remain disconnected or blocked when no safe permitted choice exists | Restricted operational summary; no destination, traffic, or stable cross-session detail | M3 path-contract design gate |
| Relay descriptor | Relay and egress plane | Profile-authorized relay description into client-to-relay admission | Authenticated, compatible, authorized, current descriptor bound to the admitted profile context | Forged, unknown, stale, incompatible, unauthorized, expired, revoked, or context-mismatched descriptor | Descriptor version and compatibility range must be explicit and downgrade-safe | Reject before session establishment; do not substitute an unapproved relay | Sensitive infrastructure metadata; minimum local disclosure and redacted diagnostics | M3 relay-contract design gate |
| Revocation and update | Operations and update plane | Authorized control decision into consuming planes | Authentic, ordered, compatible, current decision with scoped authority and safe activation plan | Unauthenticated, stale, replayed, rollback-inducing, incompatible, partial, or over-scoped decision | Monotonic version or generation with explicit compatibility and rollback protection | Preserve or restore the last proven safe state; otherwise disable or block affected behavior | Restricted control metadata; bounded audit summary without secrets or personal data | M3 lifecycle-contract design gate |
| Diagnostic export | Client and VPN plane | Redacted local diagnostics into a user-selected file | User-initiated export after preview and confirmation of bounded redacted categories | Automatic, silent, background, mandatory, unpreviewed, secret-bearing, traffic-bearing, destination-bearing, or linkable export | Export schema is explicit, additive only when privacy-safe, and reject-unknown for sensitive fields | Cancel without side effects; connection and recovery cannot depend on export | User-controlled local diagnostic data; no automatic telemetry and bounded retention | M3 diagnostic-contract design gate |
| App runtime | Client and VPN plane | User intent and platform permission into protected local runtime state | Permission-valid, profile-valid, policy-valid, storage-protected state with explicit lifecycle transition | Missing permission, invalid profile, unsafe routing or DNS state, unavailable required protection, ambiguous lifecycle, or incompatible state | Runtime state model and imported contract versions must be explicitly compatible | Stay disconnected or blocked; shutdown and recovery are explicit, bounded, and idempotent | Protected device state; no traffic content, secrets, precise destinations, or stable identifiers in ordinary diagnostics | M3 app-runtime design gate |

## Cross-contract invariants

- A diagnostic view cannot grant control authority.
- Manual choice cannot weaken profile policy or mandatory safety and privacy floors.
- Possession of one plane's artifact does not grant another plane's role.
- No automatic telemetry is permitted.
- Diagnostic export is local, user initiated, previewed, cancellable, and redacted.
- Failure to prove required authority, compatibility, or protected state fails closed.
- Later executable work must define negative tests, recovery, rollback, retention,
  deletion, and gate-closing conditions before implementation is authorized.

## Future gate

The milestone labels in the catalog are sequencing markers, not authorization.
Opening any one of them requires a separate approved work order that names the
exact files, executable boundary, allowed environment, tests, reviews, rollback,
and stop conditions. KIP-0070 separately opened the verified-profile and
revocation/update entries as offline metadata and state-machine contracts.
KIP-0071 opens permitted fallback only as a deterministic offline selector. The
remaining three entries and all live product behavior remain closed.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0087: Phase 12 operator, provisioning, and relay-fleet authority

Status: authorized for local and disposable implementation

## Outcome

Phase 12 builds local production-candidate control-plane semantics for
authoritative profile and relay desired-state requests, split approval,
publication, signed emergency deny, reconciliation, and disposable journal
recovery.

The bounded local acceptance scenario exercises one disposable profile,
publication, relay desired-state, signed emergency-deny, reconciliation, and
journal-reopen workflow. It does not establish completion of production
adapters, authenticated operator identity, cross-platform operations, a public
service, production custody, a deployed relay fleet, or field reliability.

## Frozen architecture

- The Phase 8 authority matrix and cryptographic interfaces remain
  authoritative. Phase 12 orchestrates those capabilities and never acquires
  signing authority merely because an actor is an operator.
- The Phase 11 session plan, relay admission, Kurd wire, and relay process
  remain the data-plane authority. The control plane may publish desired state
  but cannot bypass data-plane admission.
- The initial implementation is a small Go control-plane core with explicit
  ports. Its deterministic durable reference store is suitable for local
  conformance and crash-recovery evidence only.
- Production PostgreSQL, transactional outbox workers, OIDC/WebAuthn, HSM/KMS,
  object storage, TUF distribution, infrastructure-as-code, and external
  monitoring remain adapter contracts until their providers and environments
  are explicitly selected and validated.
- Every local mutation uses a bounded idempotency key, expected aggregate
  revision, monotonic command sequence, and locally validated caller-supplied
  actor ID, authority role, and duties. Authentication and binding to a
  production identity remain unverified adapter responsibilities.
- Reconciliation validates the recoverer actor and `recover` duty before
  selecting state or invoking an external effect handler. The handler receives
  a value-only redacted command containing the exact outbox event ID as its
  idempotency key, digests, epochs, validity, and publication metadata, but no
  raw actor, approver, target, or operation IDs.
- Sensitive operations require two distinct approvers. The requester cannot
  approve the same operation and one identity cannot fill both approval slots.
- Audit entries use an internal SHA-256 chain over canonical, redacted event
  fields. The chain detects accidental corruption and non-rehashed edits when
  state is loaded. It cannot detect valid-prefix rollback, whole-file
  replacement across reopen, or attacker-recomputed hashes, and is not a
  substitute for an external immutable audit service.
- The outbox is written atomically with domain state. Reconciliation requires
  consumers to use the exact event ID as their provider-side idempotency key.
  Unrelated safety effects may bypass ordinary backlog, but an earlier pending
  effect for the same target remains ordered first. Failed invocations are
  durably counted and become a visible terminal local failure after three
  attempts; an acknowledgment revision conflict is retried without reinvoking
  the handler. External provider idempotency remains **[UNVERIFIED]**.
- Every effect, including a safety effect, remains lease-bounded. An operation
  at or past its expiry is rejected before handler dispatch and is recorded
  toward the same bounded terminal-failure path. No non-expiring safety bypass
  exists.
- Published update metadata is versioned, expiring, hash-bound, and monotonic.
  Checks reject rollback, freeze, mix-and-match, equivocation, a publication
  timestamp later than the verifier's supplied current time, a validity
  interval ending at or before publication, and indefinite staleness relative
  to the supplied last-trusted publication or current non-rolled-back state.
  The disposable journal has no durable external anti-rollback anchor.
- Relay desired state progresses `enrolled -> canary -> active -> draining ->
  retired`, with `quarantined` and `revoked` terminal safety paths. Revoked
  relay identity cannot be reactivated.
- The currently admitted emergency path first verifies a canonical,
  root-signed delegation for an exact emergency key and scope, then accepts
  canonically signed, monotonic, expiring deny actions under that opaque
  root-bound capability. Scope narrowing and reversal remain unavailable until
  authoritative parent-scope and recovery state can be represented.
- Profile issue, rotation, and revocation constructors derive creation and
  expiry times from their authoritative Phase 8 inputs and clamp expiry to all
  applicable verified authority bounds. Rotation and revocation also bind the
  exact digest of the current admitted artifact as an execution precondition;
  revocation proves that the fresh root-bound signed set revokes the current
  content.
- Complete journal copying accepts only individually valid records with exact
  revision continuity starting at revision one. Duplicate, reordered, or
  skipped revisions fail closed.
- Metrics, audit records, diagnostics, and support output contain no payload,
  destination, raw profile, credential, key, token, raw actor or target ID, or
  precise client network identity. Audit actor and target labels are
  deterministic SHA-256 pseudonyms and remain linkable; they are not anonymous
  identifiers.

## Required local work

1. Freeze the bounded domain model, actor capabilities, approval policy,
   idempotency rules, revisions, state machines, and redacted event schema.
2. Implement atomic state, audit-chain, and outbox transactions with a durable
   disposable reference store and deterministic crash points.
3. Implement profile issuance and publication ceremonies as adapters over the
   existing Phase 8 authority boundary.
4. Implement relay enrollment, canary, activation, drain, quarantine,
   retirement, and revocation desired state without granting network egress.
5. Implement signed deny-only emergency actions, monotonic expiry metadata,
   fail-closed narrowing, and split-authority tests.
6. Implement signed-update metadata semantics and a local verification helper
   for rollback, freeze, mix-and-match, and equivocation rejection.
7. Implement privacy-safe health summaries, reserved safety capacity,
   reconciliation, local journal copy/reopen, and partial-tail repair evidence.
   Authenticated backup/restore and disaster recovery remain external work.
8. Provide a bounded operator CLI for disposable local ceremonies. It must not
   contain production credentials, automatic deployment, or public endpoints.
9. Add misuse, property, fuzz, race, crash-recovery, tamper, privacy-canary,
   and end-to-end conformance tests.
10. Keep the Phase 12 evidence gate provisional until full local acceptance
    results are recorded on both Windows and Linux.

## External evidence boundary

The following remain **[UNVERIFIED]** until observed in explicitly authorized
environments:

- production OIDC/WebAuthn identity and break-glass operation;
- a production trusted-time source and clock-integrity controls;
- HSM/KMS custody, quorum ceremonies, backup, and recovery;
- PostgreSQL high availability and point-in-time recovery;
- external immutable object storage and update distribution;
- infrastructure provisioning and host hardening;
- owned non-loopback relay enrollment and replacement;
- capacity, availability, abuse response, incident response, and recovery SLOs;
- a controlled private pilot.

Local substitutes must never be reported as proof of these external results.

## Prohibited behavior and claims

- No public relay, cloud resource, external target, production key, production
  credential, or real user data is created or used by this milestone.
- No control-plane action may enable a profile, relay, strategy, or scope that
  the signed profile and local safety floor deny.
- No payload or destination logging is permitted.
- The implementation must not be described as uncensorable, undetectable,
  anonymous, publicly deployable, production-ready, or fully audited.

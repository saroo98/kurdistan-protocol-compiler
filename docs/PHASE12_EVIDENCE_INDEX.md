<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 12 evidence index

Phase 12 adds a production-candidate operator and relay-fleet control-plane
core. The evidence in this repository is local and disposable. It does not
establish a deployed service, production authority, public relay, or pilot.

## Reproducible local evidence

| Boundary | Command | Evidence |
|---|---|---|
| Repository gate | `go run ./cmd/gate` | Build, vet, uncached tests, audit, and the bounded disposable Phase 12 scenario |
| Control-plane core | `go test -count=1 ./internal/operator/controlplane` | Local actor-duty separation, two distinct approval IDs, authoritative-time and exact-profile-provenance binding, root-bound signed emergency-deny admission, redacted effect dispatch, safety-priority and per-target reconciliation order, bounded terminal attempts, expiry-before-dispatch, publication chronology, internal audit-chain validation, exact outbox ownership, journal-copy continuity, local recovery, forbidden-text canaries, and authoritative Phase 8/11 boundary integration |
| Race-sensitive state | `go test -race -count=1 ./internal/operator/controlplane ./cmd/koperator` | Store, journal, service, and reconciliation race coverage |
| Disposable workflow | `go run ./cmd/koperator verify` | Local profile desired state, publication, relay desired-state lifecycle, signed emergency deny, effect reconciliation, journal reopen, and overclaim rejection |
| Mutation and fuzz | `go test -count=1 ./internal/operator/controlplane -run 'Tamper|RoleIsolation|Monotonic|FailClosed|Idempotency|Forgery|Mismatch|Capacity|PublicationIntent|DeliveredOutbox|Reconcile|ProfileIssueAndRotationBind|ProfileOperationExpiryClamps|CopyCompleteJournal'` and `go test -fuzz=FuzzVerifyPublicationFailClosed -fuzztime=10s ./internal/operator/controlplane` | Selected security-negative behavior, review regressions, and bounded parser/state robustness |

The machine-readable status is
`testdata/evidence/phase12/acceptance-status.json`. Tests reject any external
result that is converted into a pass or any production/censorship-resilience
claim that is enabled.

## What local tests exercise

- Caller-supplied local actor structs are checked for duty separation,
  role-operation policy, distinct approval IDs, and requester/executor
  separation. The tests do not authenticate people or bind IDs to production
  identities.
- Exact Phase 8 profile artifacts are verified before the control plane retains
  only their digests. Rotation and revocation carry the exact current artifact
  digest as an execution precondition, and revocation requires a fresh
  root-bound signed set covering the current content.
- Protected constructors derive creation time from the authoritative Phase 8
  request or Phase 11 evaluation time and clamp expiry to the verified
  artifact, root, delegation, revocation, or relay-descriptor bounds that
  apply. This does not establish a production trusted-time source.
- Authoritative Phase 11 construction and admission bind relay desired state
  without retaining endpoint references; caller-built plans are rejected.
- Profile desired-state generation and relay desired-state epoch transitions
  are monotonic, preserve admitted identity/plan digests, and treat revocation
  as terminal.
- Canonical emergency authority delegation is bound to an independently
  authenticated root set before signed deny operations are admitted. Actions
  are monotonic by epoch and carry future `ValidUntil` metadata. Scope narrowing
  fails closed, expired effects are rejected before dispatch, and automatic
  reversal is not implemented by this local core.
- State, audit, and outbox commit in one journal record; partial tail writes do
  not become state and are truncated on reopen.
- Recoverer authorization occurs before effect dispatch. The handler receives
  a value-only redacted DTO without raw actor, approver, target, or operation
  IDs and must use the exact event ID for provider-side idempotency. Unrelated
  safety work may bypass ordinary backlog while same-target order remains
  intact. Handler errors are durably counted and become a visible terminal
  local failure after three attempts; acknowledgment conflicts retry without
  reinvoking the effect.
- Audit records are internally chained, redacted, and bounded. Internal checks
  reject malformed or non-rehashed mutation but do not provide authenticated
  storage, valid-prefix anti-rollback, or an immutable external audit trail.
- Publication metadata rejects rollback, expiry, future publication time,
  non-positive publication validity intervals, equal-version conflict, stale
  hash reuse, and non-monotonic publication relative to supplied trusted state.
  Complete journal copies additionally reject duplicate, reordered, or skipped
  revisions. The local journal does not provide a durable external
  anti-rollback anchor.

## Security review closure

The initial Phase 12 security review identified nine reportable findings. The
final local implementation remediates each within the disposable scope:

1. Full Phase 8 activation admission now precedes profile digest reduction.
2. Ordinary work cannot consume operation, idempotency, audit, outbox, or
   acknowledgment capacity reserved for safety actions.
3. Publication input is copied into service-owned immutable request state.
4. Every outbox event binds to and reconciles through its exact operation ID.
5. Security-sensitive requests require an unexported proof bound to immutable
   fields; generic request DTOs cannot bypass authoritative constructors.
6. Relay requests rerun authoritative Phase 11 construction and admission;
   caller-built plans are rejected.
7. Recovered state validates quorum, timestamps, audit evidence, receipts,
   outbox ownership, and delivery links before effects can run.
8. Emergency scope narrowing fails closed until a verifiable subset model
   exists; the admitted path is signed deny only.
9. Relay lifecycle transitions preserve the enrolled identity and admitted plan
   digests.

This closure is limited to local, single-process semantics. Production identity
binding, multiwriter database transactions, an immutable external audit and
anti-rollback anchor, audit-export pseudonymization, external provider
idempotency, authenticated backup/restore, capacity and recovery SLOs, deployed
relays, and pilot evidence remain **[UNVERIFIED]**.

## Second adversarial review closure

A second Phase 12 adversarial review identified nine additional reportable
findings. Each has a local regression and is remediated only within the
single-process disposable scope:

1. Recoverer identity shape and `recover` duty are checked before an effect
   handler can run; unauthorized paths make zero handler calls.
2. Emergency action verification requires an opaque emergency capability
   created from an exact root-set member's canonical signed delegation.
3. Protected request constructors bind authoritative creation time and clamp
   expiry to every applicable verified authority or descriptor bound.
4. Profile rotation and revocation bind the exact current artifact digest, and
   signed revocation must cover the current admitted content.
5. External effect adapters receive a redacted value DTO and exact event ID,
   not the full operation or raw actor and target identifiers.
6. An unrelated safety-priority lane preserves per-target ordering, while
   durable failure counters cap dispatch at three attempts and expose terminal
   failures in local health.
7. Expired operations, including safety operations, are rejected before effect
   dispatch and enter the bounded failure path rather than bypassing expiry.
8. Publication verification rejects future `PublishedAt` and
   `ValidUntil <= PublishedAt`.
9. Complete journal copy requires exact revision continuity and rejects
   duplicate, reordered, or missing revisions.

This review closure does not verify production authentication, trusted clock
operation, external adapter behavior, multiwriter ordering, immutable recovery
media, deployment, or field operation.

## What remains external

Production identity, trusted-time operation, HSM/KMS custody, external database
availability and recovery, immutable update hosting, infrastructure
provisioning, owned non-loopback relay operation, capacity, incident response,
disaster recovery, and a private pilot remain **[UNVERIFIED]**.

No evidence in this index supports the words uncensorable, undetectable,
anonymous, publicly deployed, production-ready, or fully audited.

# KIP-0080: Verified Profile Activation

Status: implemented offline contract

## Decision

Profile activation is a fixed-order, fail-closed transaction. The runtime bounds
and parses the opaque artifact, resolves and opens an authenticated recipient
when required, parses the signed object without decoding profile semantics,
verifies the root-authorized issuer delegation and signed revocation snapshot,
verifies the exact COSE signature bytes, compares authenticated dispatch fields,
and only then decodes and validates profile semantics.

Successful candidates are staged with their exact ingress and signed-object
bytes. The stored candidate is reopened and the complete verification path is
repeated before an activation marker is committed. Recovery retains either the
previous active record or the fully committed new record, never a partially
verified state. The previous active record becomes the last-known-good record.
Snapshot failures reject activation before verification. A failed recovery is
reported distinctly as `P8-ACT-RECOVERY-FAILED`; callers must quarantine the
provider and use neither candidate nor cached state until repair and a successful
snapshot establish a trustworthy state again.
If the provider cannot confirm quarantine, activation returns the distinct
terminal code `P8-ACT-QUARANTINE-FAILED`. Both recovery and quarantine terminal
codes require callers to stop using provider and cached state; the distinction
exists so operators know whether quarantine cleanup was confirmed.
Successful recovery must prove either byte-exact restoration of the captured
pre-transaction active and last-known-good records, or, only after the commit
boundary, an exact fully reverified newer candidate with the prior active record
as last-known-good. A nil recovery error without one of those states is quarantined.

## Security properties

- Equal-generation activation is idempotent only for the same authenticated
  content receipt. Conflicting authenticated content fails closed.
- A replacement is a complete snapshot: relay, strategy, and policy members
  omitted by the new authenticated snapshot are removed rather than merged.
- Root, revocation, recipient, generation, validity, contract, safety-floor,
  provider, lineage, and predecessor bindings are checked before state changes.
- Higher-generation and provider-migration activation cannot roll root or
  revocation epochs below the authenticated current receipt.
- Revocation snapshots are root-signed, scoped, expiring, and bounded by an
  explicit offline-staleness interval.
- Stable diagnostic failures expose only `P8-ACT-*` reason codes.
- Canonical dot namespaces such as `profiles.` authorize canonical profile IDs
  such as `profiles.one`; existing slash namespaces remain valid for legacy
  non-codec trust artifacts.

## Scope

This KIP defines and tests an offline activation contract. It adds no network
service, Android runtime, production key material, algorithm negotiation, or new
cryptographic dependency. Provider implementations remain responsible for
durable atomic storage and opaque key operations.

The sealed integration test uses the enabled Phase 8 construction through Go's
real `crypto/hpke` implementation: DHKEM(P-256), HKDF-SHA256, AES-256-GCM, and
the exact Phase 8 info/AAD builders. It uses test-only derived recipient material.

## Verification

The focused suites exercise verification-before-semantics ordering, thirty-six
categorical immutable-state failures, before/after partial writes at every
persistence boundary, snapshot and recovery failures, sealed recipient opening,
full-snapshot replacement/removal, canonical
namespace compatibility, authenticated receipts, and exact-byte reopen
verification. Activation and verified-lifecycle state machines also have fuzz
targets; the activation target checks byte-exact committed and transaction state.
Deterministic summaries are stored under
`internal/product/profile/testdata/phase8-activation/`.

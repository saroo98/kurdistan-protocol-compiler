<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0078: Phase 8 Trust and Portable Provider Boundaries

## Status and scope

- status: implementation candidate under Phase 8 review gates
- work order: WO-804
- scope: offline trust-role enforcement, opaque provider interfaces, recipient
  membership state, exact hint resolution, and deterministic test providers
- not included: Android Keystore, HSM/KMS, PKCS#11, KMIP, cloud services,
  attestation, production ceremonies, real keys, relay authentication, app
  signing, or live profile distribution

This KIP turns the structural trust vocabulary from KIP-0076 into executable
role and state boundaries. It does not claim that a production key backend or
ceremony exists.

## Non-interchangeable authority roles

| Role | Sole admitted operations | Explicitly denied examples |
|---|---|---|
| Root | Advance the root set; delegate Issuer, Provider, or Recipient Registrar scope | Ordinary profile issuance, recipient enrollment, emergency action |
| Issuer | Sign and authenticate profiles inside one delegated provider/lineage/profile namespace | Group membership, device/backup enrollment, root update |
| Provider | Authorize or revoke provider-group recipient membership | Profile issuance, device/backup enrollment |
| Recipient Registrar | Enroll, rotate, or revoke device and backup recipients in one expiring delegated scope | Profile issuance, provider-group authorization, root update |
| Emergency | Expiring monotonic deny or scope-narrowing action | Sign, enable, downgrade, erase, recover, or expand scope |
| Relay | Relay authentication only | Every profile, membership, root, and emergency operation |
| App-release | App-release signing only | Every profile, membership, root, and emergency operation |
| Device-wrap | Local device-key wrapping only | Every profile, membership, root, and emergency operation |
| Backup | Backup-key wrapping only | Every profile, membership, root, and emergency operation |
| Operator | Execute a separately authorized ceremony | Authority by job title or direct cryptographic bypass |

`AuthorizeRoleOperation` is fail closed. An unknown role or operation has no
capability. The role-confusion evidence includes every non-profile key role and
all Issuer/Provider/Recipient Registrar cross-role profile operations.

## Root and delegation artifacts

A root-set artifact carries a nonzero epoch, a view identifier, validity, and a
bounded set of unique opaque key references. A key reference contains only a key
ID and suite ID. It contains no private-key bytes.

Root replacement requires:

1. a valid current and next root set;
2. authorization by a key in the current root set;
3. exactly `current epoch + 1`;
4. unique key IDs;
5. rejection of rollback, skipped epochs, and equal-epoch conflict.

An observed root view at an already trusted epoch must have identical canonical
content: epoch, view ID, validity interval, ordered key IDs, and suite IDs. Reuse
of a view ID with different keys or validity fails as a split-view conflict.
Phase 8 records and detects views when they co-locate. Transparency or external
witnessing is deferred; no prevention claim is made.

An Issuer delegation binds root epoch and key ID, issuer key handle and suite,
provider, lineage, slash-terminated profile namespace, validity, delegation
epoch, and maximum profile validity. The root set itself must be structurally
valid and active at the decision time. Unknown, future, or expired roots;
expired/revoked delegations; key-ID collision; and scope escape fail closed.

Provider and Recipient Registrar authorizations use the same root, validity,
scope, and opaque-handle constraints, but carry distinct roles. They cannot be
substituted for one another.

## Portable provider interfaces

The Phase 8 package defines narrow operation interfaces:

- signer;
- verifier;
- recipient sealer;
- recipient opener;
- local wrapper;
- monotonic state provider;
- exact recipient resolver.

They accept opaque key references or recipient bindings. No method exports a
production private key, lists recipient keys for trial decryption, combines
trust roles, or embeds a vendor SDK.

The in-memory implementations exist only in tests. Their deterministic bytes
are non-production fixtures. Diagnostic events record operation names and safe
handles only. Tests scan those surfaces for test key bytes and profile bytes.

## Class-sensitive recipient epochs

`RecipientEpoch` remains authenticated and class-sensitive:

| Artifact class | Authority | Required epoch behavior |
|---|---|---|
| `signed-public` | none | exactly zero; no membership transition exists |
| `provider-group-recipient` | Provider | enrollment at one, then exact monotonic `+1` for rotation or revocation |
| `device-recipient` | Recipient Registrar | enrollment at one, then exact monotonic `+1` in the delegated scope |
| `encrypted-backup` | Recipient Registrar | enrollment at one, then exact monotonic `+1` in the delegated scope |

Stale, skipped, conflicting, post-revocation, wrong-role, wrong-class,
wrong-provider, wrong-lineage, and wrong-namespace transitions fail before state
mutation. Provider-group dispatch explicitly accepts only enroll, rotate, and
revoke; unknown transition values fail closed.

## Exact recipient-hint resolution

Lookup uses the authenticated artifact class plus the opaque hint. Candidate
input is bounded to `MaxRecipientBindingCandidates = 256`: the exact boundary is
accepted, while zero and one-over are rejected before scanning or provider work.
Resolution must return exactly one valid, non-revoked binding. Zero or multiple
matches are errors. A hint from another artifact class is not a fallback
candidate.

Resolver output is untrusted and revalidated for structure, revocation, exact
requested class, and exact requested hint before the opener receives one
binding. The opener never receives a key list. Unknown, colliding, oversized, or
maliciously substituted results therefore cause zero open attempts,
mechanically preventing try-all-recipient-key behavior in this boundary.

## Emergency authority

Emergency authority is scoped, expiring, revocable, and monotonic. It permits
only:

- deny inside its assigned scope;
- narrow to a strict child namespace.

Actions must advance exactly one epoch, carry a structurally valid
slash-terminated bounded scope, and remain inside both authority and action
validity. Sign, enable, downgrade, erase, recover, equal/stale epoch, malformed
scope, and scope expansion are rejected. Every named permit/reject row in the
emergency evidence report executes the corresponding authorization path.

## Phase 12 ceremony inputs

WO-804 records requirements only. A later Phase 12 ceremony design must define
and test:

1. offline root generation and a documented entropy source;
2. quorum or dual-control policy for root evolution;
3. issuer, Provider, and Recipient Registrar bootstrap as separate operations;
4. independent backup and recovery custody with no universal profile key;
5. signed, append-only ceremony and authorization receipts;
6. deterministic test-root inventory and witnessed destruction;
7. compromise detection, revocation, replacement, rollback prevention, and
   conflicting-view response;
8. least-privilege operator authentication, separation of duties, rehearsal,
   abort, and recovery procedures;
9. provider-specific exportability, availability, audit, and disaster-recovery
   evidence before deployment.

No production ceremony was performed by this work order.

## Later adapters

Phase 9 may implement an Android Keystore adapter behind the operation
interfaces. It must prove device/version support, non-exportability semantics,
authentication policy, invalidation, backup exclusion, error mapping, and
rollback behavior. This KIP does not require hardware attestation.

Phase 12 may implement HSM/KMS adapters after an explicit vendor and deployment
decision. Each adapter must prove handle scoping, role isolation, authorization,
audit receipts, failure behavior, rate limits, key lifecycle, backup/recovery,
and removal/rollback. Cloud SDKs and network services are intentionally absent
from Phase 8.

## Evidence

Executable reports live under `internal/product/profile/testdata/`:

- `role-confusion-report.json`;
- `delegation-negative-report.json`;
- `root-emergency-negative-report.json`;
- `emergency-authority-report.json`;
- `test-provider-hygiene-report.json`;
- `recipient-registrar-negative-report.json`.

They are bound to tests that rerun the named negative cases. Evidence is local
contract evidence, not a production adapter, ceremony, deployment, or external
security audit.

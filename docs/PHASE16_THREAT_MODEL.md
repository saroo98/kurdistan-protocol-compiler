# Phase 16 production trust threat model

> **Realignment notice:** KIP-0093 changes the deployment and trust model to
> independent self-hosted nodes. The threats below remain useful input, but
> Google-specific and centralized-control assumptions are superseded and must
> not be treated as current architecture.

## Protected assets

- root, recovery, issuer, emergency, publication, and audit signing authority;
- monotonic profile generations, authority epochs, revocations, and deny state;
- operator approvals and separation-of-duties evidence;
- acknowledged audit and publication heads;
- database, backup, infrastructure, and deployment integrity; and
- privacy-safe operator and operational metadata.

## Trust boundaries

1. Human operators enter through IAP with phishing-resistant authentication.
2. IAP and service identity tokens are verified for exact issuer, audience,
   authorized party, expiry, and subject before role mapping.
3. API, worker, signer, publisher, auditor, emergency, recovery, and deployer
   identities are separate.
4. Spanner is the authority state and time boundary.
5. KMS HSM is the private-key custody boundary.
6. Publication and audit storage are independent immutable effect boundaries.
7. GitHub receives short-lived Google credentials only through restricted OIDC
   Workload Identity Federation.

## Principal threats and required controls

| Threat | Required control |
|---|---|
| Stolen operator session | short-lived identity, role readback, dual approval, revocation, bounded break-glass |
| Confused deputy or wrong token | exact issuer/audience/authorized-party verification and production issuer allow-list |
| Self-approval or collusion by one identity | opaque actor equality checks, two distinct approvers, requester/executor exclusion |
| Local-clock rollback | Spanner commit time and database-side validity evaluation only |
| Transaction retry duplicates effects | pure deterministic callback plus post-commit outbox |
| Worker split brain | trusted-time lease, fencing token, exact event idempotency |
| Key export or substitution | HSM-only algorithm/protection readback, immutable version binding, immediate verification |
| Signature malleability or malformed DER | strict ASN.1 scalar validation and low-S canonicalization |
| Publication overwrite or rollback | digest address, create-only generation precondition, signed monotonic metadata |
| Audit deletion or fork | independent append-only bucket, previous-anchor hash, signed anchor, readback |
| Database loss or stale restore | restore to new database, compare external heads, reject rollback/fork |
| CI credential theft | no reusable cloud key, restricted OIDC claims, protected environments, pinned actions |
| Privacy leakage | opaque actors, categorical logs, secret canaries, no raw identities/endpoints/profile bytes |
| Emergency starvation | separate identity and reserved queue capacity |

## Fail-closed states

Missing identity, stale approval, unknown role, local-time dependence, wrong
epoch, missing audit/outbox record, ambiguous KMS result, failed readback,
missing anchor, stale restore, or absent external evidence blocks finalization.
The API may report `PENDING_ANCHOR` or a categorical failure but cannot report
final success.

## Explicit non-claims

Local tests do not prove HSM custody, cloud residency, operator identity,
physical recovery, field resilience, or production readiness. Phase 16 does not
prove live VPN connectivity. Those claims require later exact external evidence.

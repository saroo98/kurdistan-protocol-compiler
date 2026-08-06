# KIP-0092: Phase 16 production trust authority

**Status:** superseded by
[`KIP-0093`](KIP-0093-decentralized-self-hosted-kurd-network.md)

> Historical record only. The mandatory Google Cloud topology, centralized
> provider plane, and global-root assumptions below are not implementation
> authority. Do not deploy or complete Phase 16 from this KIP.

**Phase:** 16

**Baseline:** `62ceaf982bf557a437b5cc7c16878c2c820c80eb`

## Decision

Phase 16 uses a Google Cloud, EU-resident, separated-project production trust
plane. Cloud Spanner commit timestamps are the sole authority clock. Cloud KMS
HSM P-256 keys are the sole production signing custody. Cloud Run services use
IAP for human access and audience-bound service identities for machine access.
Cloud Storage publication and audit objects are immutable and generation
conditioned. Terraform is the infrastructure authority and GitHub may obtain
Google credentials only through OIDC and Workload Identity Federation.

The exact machine authority is in `config/production/`. Human documentation
cannot widen those policies. Any conflict fails closed in `phase16verify`.

## Separation of duties

The roles are `viewer`, `requester`, `approver`, `executor`, `publisher`,
`auditor`, `recovery`, `emergency`, and `deployer`. Root, issuer, publication,
revocation, recovery, emergency, retention-lock, and destruction operations
require two distinct approvers. A requester cannot approve its own operation,
and an executor cannot approve the operation it executes.

The API identity cannot sign, publish, anchor audit data, mutate backups, or
perform recovery. Signing, publication, audit anchoring, emergency action, and
recovery use distinct service identities and narrowly scoped key roles.

## Authority and acknowledgement

Each authority mutation is a deterministic transition inside one serializable
Spanner transaction. State, audit event, and outbox record commit atomically.
External signing, publication, and anchoring occur after commit with exact
idempotency keys and verified readback. Final success is withheld until every
required external postcondition is durable.

## Key custody

Production private keys are non-exportable Cloud KMS HSM keys using
`EC_SIGN_P256_SHA256`. KMS DER ECDSA signatures are strictly decoded,
canonicalized to low-S, converted to fixed-width raw ES256, and immediately
verified with the immutable KMS public key before use. This adapter requires a
targeted independent review before production activation.

## Evidence and activation

Git contains schemas, policies, redacted summaries, and digests. Private owner
inputs and external receipts remain under `.tools/phase16/private/` or in the
approved evidence store. Missing production evidence is represented as
`UNVERIFIED`; it is never inferred from local or emulator success.

Phase 16 does not authorize a public relay, Internet egress, Play publishing,
tagging, or a production-ready VPN claim. The full product release decision
remains `NO_GO`.

## Consequences

- The root Go module retains protocol and deterministic authority logic.
- Google Cloud client libraries live in the nested `production/` module.
- Production deployment cannot proceed without exact private owner inputs,
  protected environment approvals, and readback-bound receipts.
- Restore uses a new database and rejects any state older than the last
  externally acknowledged audit/publication head.

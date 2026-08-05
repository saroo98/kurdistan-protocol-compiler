# Phase 16 Evidence Index

## Local evidence

- Production API and identity boundary: `production/internal/authn`, `authz`,
  `server`. The HTTP boundary is tested, but no deployable API binary may be
  claimed until mutation inputs are converted into the existing unforgeable
  Phase 8/11 request proofs by a concrete verifier-backed backend.
- Serializable authority and trusted time: `production/internal/spannerstore`.
- Schema migration: `production/migrations`.
- HSM adapter and DER/raw-low-S boundary: `production/internal/kmsprovider`.
- Profile issuance and immediate reverification: `production/internal/lifecycle`.
- Immutable publication: `production/internal/publication`.
- Fenced effects: `production/internal/outbox`.
- Chained HSM audit anchors: `production/internal/auditanchor`.
- Restore rollback/fork verifier: `production/internal/backup`.
- Reproducible infrastructure: `infra/terraform`.

These artifacts establish implementation readiness only. They do not prove a
production Google Cloud deployment.

## Open local high-severity findings

The current digest-only HTTP mutation document is insufficient to create the
unforgeable `controlplane.RequestInput` required by profile, relay, and
emergency operations. Treating those digests as proof would create a forgeable
authority bypass. Therefore no production runtime image is authorized yet.
The API must accept or resolve complete bounded source material and rerun the
existing Phase 8/11 verifier before a request can enter the serializable store.
Profile issuance also needs a reviewed two-stage authorization/finalization
design because the final KMS-signed artifact digest does not exist before the
operation is approved. This blocks deployable runtime commands and images.

The Terraform graph creates separated runtime identities but does not yet grant
the exact per-resource IAM required for Spanner, KMS, publication, audit,
backup, Secret Manager, monitoring, or protected deployment. No broad project
role may substitute for this missing least-privilege graph.

The protected production-plan workflow creates a private, generation-locked
binary plan, but it does not yet run and bind the required policy-as-code report
to that plan. Production apply must remain unavailable until plan policy,
receipt, approval expiry, and drift reconciliation are enforced.

These are three high-severity local findings and must be closed before
production planning or Phase 16 completion.

## Required external evidence

The authoritative status remains `IMPLEMENTATION_ACTIVE` and `NO_GO` until all
of these exact-subject records pass:

- owner-input validation and protected production authorization;
- IAP, WIF, IAM, ingress, residency, budget, and ownership readbacks;
- HSM key/version, algorithm, state, protection, and public-key readbacks;
- independent targeted review of the KMS adapter;
- qualification create/test/destroy and production plan/apply/readback;
- three issue/publish/rotate/revoke/emergency-deny lifecycle runs;
- database-loss, recovery, compromise, trusted-time, and audit-continuity drills;
- CLI and Android verification against the exact production-authority artifacts.

Missing external evidence is a release blocker, not a local test failure, and
must never be replaced by a simulated or self-authored PASS receipt.

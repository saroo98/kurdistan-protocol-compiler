# Phase 16 Production Operations

## Deployment

Terraform is the infrastructure authority. Production plan and apply are
separate protected jobs. Apply must consume the exact reviewed binary-plan
digest, authenticate with GitHub OIDC/WIF, refuse drift, and never use a
reusable service-account key. Cloud Run images are digest pinned. Rollback
changes only service traffic to a previously verified image; it never rolls
authority state backward.

Binary Terraform plans are private infrastructure material. The planning job
stores them in the approved private plan bucket with a create-only generation
precondition and subject/digest metadata. GitHub receives only the plan digest,
object generation, run ID, and run attempt. The apply job reads the exact
generation through its separate identity and verifies generation, source
subject, metadata digest, and downloaded bytes before applying. Binary plans
must never be uploaded as GitHub artifacts.

The Terraform state bucket, private plan bucket, and initial WIF identities are
bootstrap dependencies. They must be created from reviewed Terraform through a
separately authorized short-lived bootstrap identity before the protected
GitHub workflows can operate. The bootstrap identity is not a runtime identity,
is disabled after readback, and is referenced only by its opaque owner-supplied
identifier. A workflow may not silently fall back to long-lived JSON keys when
bootstrap authority is unavailable.

## Effects and acknowledgement

Database transactions contain only deterministic state changes, audit events,
and outbox records. Network effects occur after commit. Workers use bounded
fenced leases and stable effect IDs. Delivery is at least once. Duplicate
delivery is safe only when exact postconditions match. Emergency work is
prioritized but cannot bypass authorization, anchoring, or publication checks.

## Monitoring

Alert on authentication rejection changes, denied authorization, transaction
conflicts, trusted-time mismatch, outbox backlog, terminal effects, audit gaps,
publication readback mismatch, KMS state changes, backup failures, and service
error rates. Metrics and logs are categorical and must not contain profile
bytes, destinations, keys, credentials, raw identities, or private endpoints.

## Stop conditions

Freeze ordinary mutations on an audit fork, rollback indication, unknown key,
failed HSM readback, unbounded backlog, publication ambiguity, identity
compromise, stale infrastructure plan, or missing approval. Emergency deny
remains available only through its separate bounded identity and evidence path.

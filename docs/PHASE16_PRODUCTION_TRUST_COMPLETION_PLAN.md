# Phase 16 Production Trust Completion Plan

**Status:** authoritative implementation plan; no Phase 16 production resources
are created by this document

**Intended executor:** Luna 5.6, Extra High

**Repository:** `saroo98/kurdistan-protocol-compiler`

**Implementation baseline:** `62ceaf982bf557a437b5cc7c16878c2c820c80eb`

**Implementation branch:** `product/phase16-production-trust`

## 1. Objective

Complete Phase 16 without weakening any earlier authority, privacy, recovery,
or evidence invariant. The final system must provide a real production trust
and operator control plane that can:

1. authenticate and authorize production operators;
2. enforce least privilege, separation of duties, two-person approval, and
   bounded break-glass access;
3. hold every private signing key in non-exportable HSM/KMS custody;
4. use externally consistent trusted time and monotonic authority state;
5. transact authority state, audit events, and an outbox durably;
6. issue, publish, verify, rotate, expire, revoke, and emergency-deny real
   profiles;
7. preserve acknowledged authority transitions through database loss and
   disaster recovery;
8. reproduce, review, deploy, reconcile, and roll back infrastructure safely;
9. prove the complete production-trust workflow with evidence bound to the
   exact source, infrastructure, identities, key versions, artifacts, and
   drill runs; and
10. leave zero unresolved critical or high Phase 16 finding.

This phase does **not** establish a working public VPN data plane. Phase 17 owns
the external provider, relay fleet, and live Kurd data plane. Phase 16 may issue
production-authority profiles only for a controlled trust-validation audience;
it must not claim that those profiles provide Internet connectivity.

## 2. Current verified baseline

The executor reproduced these facts before beginning implementation:

- `main` and `origin/main` resolve to
  `62ceaf982bf557a437b5cc7c16878c2c820c80eb` after the bounded reconciliation.
- The active implementation branch is `product/phase16-production-trust`.
- Four tracked files contained the validated roadmap reconciliation:
  - `ROADMAP.md`
  - `cmd/phase15verify/main.go`
  - `cmd/phase15verify/main_test.go`
  - `testdata/evidence/phase16/ci-release-acceleration-overlay.json`
- The four-file diff contained 27 insertions and 9 deletions and was committed
  as `62ceaf982bf557a437b5cc7c16878c2c820c80eb`.
- Exact-SHA shadow assurance run `31044898397` and post-fast-forward main
  validation run `31046063269` completed successfully.
- Phase 16 CI and exact-subject assurance foundations are integrated.
- No `infra/` tree or production cloud adapter exists.
- `gcloud` and `terraform` are not installed on the authoring workstation.
- `.tools/` is ignored and is the only permitted location for disposable local
  tools, private execution inputs, and generated receipts.
- Phase 14 remains `releaseDecision=NO_GO`.
- Phase 12 provides local/disposable operator semantics only. It does not
  provide authenticated production identities, HSM custody, trusted time,
  external durable state, or immutable external audit storage.

If any baseline fact differs, record the exact difference in
`.tools/phase16/preflight.json`, reconcile this plan's paths and digests, and
continue only if the difference does not widen authority. Do not reset, clean,
or discard existing work.

## 3. Non-negotiable completion rules

- Do not use Loom for this work.
- Do not use the Codex Security plugin or skill.
- Do not invent credentials, billing accounts, domains, identities, external
  reviews, drill results, or production evidence.
- Do not place secret values, private keys, tokens, raw operator identities,
  private endpoint inventories, or personal data in Git, logs, test reports,
  command lines, Terraform state outputs, or GitHub artifacts.
- Do not change Kurd wire behavior, profile cryptographic suites, Android
  routing, or Phase 14 historical evidence to make Phase 16 pass.
- Do not add a second profile authority implementation. Production adapters
  must call the existing Phase 8 and Phase 12 authority code.
- Do not use application or client clocks for authority ordering, issuance
  validity, revocation ordering, or rollback decisions.
- Do not call an external side effect from inside a retriable database
  transaction.
- Do not claim exactly-once network delivery. Use at-least-once delivery with
  exact idempotency keys and verified postconditions.
- Do not acknowledge an authority transition as final until its durable audit
  anchor and required publication postcondition are confirmed.
- Do not destroy a key, lock a retention policy, change production DNS, or
  expose a public endpoint without the exact irreversible-action receipt
  required below.
- Do not mark Phase 16 complete while any required evidence item is absent,
  stale, tied to a different subject, or marked `[UNVERIFIED]`.

## 4. Frozen production reference architecture

The executor must implement this architecture. It may make small mechanical
adjustments required by current provider APIs, but it must not substitute a
different cloud, database, identity model, or key-custody model without a new
reviewed KIP.

### 4.1 Cloud and residency

- Cloud provider: Google Cloud.
- Primary data plane: Europe.
- Spanner production instance configuration: `eur6`, or its documented
  successor only if `eur6` is unavailable at execution time. Any successor must
  be an EU multi-region configuration and must be recorded in the machine
  contract before resource creation.
- Default Cloud Run and supporting regional resource location:
  `europe-west2`.
- No authority data may leave the approved EU project set except an encrypted,
  documented disaster-recovery copy within the approved EU boundary.

### 4.2 Project separation

Create separate projects, with distinct service identities and IAM policies:

| Logical project | Purpose | Forbidden authority |
|---|---|---|
| `kvpn-prod-trust` | Cloud KMS HSM root, recovery, issuer, emergency, publication, and audit-signing keys | No public service, no Android traffic, no database |
| `kvpn-prod-control` | Cloud Run operator API/workers, Spanner, Secret Manager references, Artifact Registry | No public signing key export, no anonymous ingress |
| `kvpn-prod-publication` | Immutable signed profile and metadata publication, HTTPS load balancer, certificates | No signing permission, no operator database permission |
| `kvpn-prod-audit` | Independent append-only audit anchors, locked log storage, audit verification | No profile issuance or publication mutation |
| `kvpn-prod-ops` | Monitoring, alerts, budgets, deployment and DR coordination | No signing permission and no profile payload access |

Create the same logical separation under `kvpn-qual-*` for disposable
qualification. Qualification uses synthetic identities, nonproduction keys,
fake profile data, a delegated test domain, cost caps, and automatic teardown.
Irreversible retention-lock qualification must use a dedicated disposable
project that is never reused.

Actual project IDs are private execution inputs, not constants committed to
Git.

### 4.3 Runtime services

- `koperator-api`: Cloud Run service, `internal-and-cloud-load-balancing`
  ingress, direct `run.app` URL disabled, IAP enabled, IAM authentication
  required.
- `koperator-worker`: Cloud Run service or job with internal ingress only.
- `koperator-ceremony`: Cloud Run job that is disabled by default and can be
  invoked only through protected, time-bounded elevation.
- `koperator-drill`: Cloud Run job for qualification and scheduled recovery
  exercises. Production invocation requires protected approval.
- Human access terminates at IAP. Service-to-service calls use audience-bound
  Google-signed identity tokens and dedicated service accounts.
- The API and workers run as different identities. The API cannot sign, publish,
  anchor audit data, modify backups, or invoke recovery directly.

### 4.4 Authoritative database and trusted time

- Use Cloud Spanner with GoogleSQL dialect.
- Use serializable read-write transactions and strong reads.
- Use Spanner commit timestamps as the authoritative transition time and order.
- Use `CURRENT_TIMESTAMP()` only inside Spanner for expiry and not-before
  decisions.
- Local clocks may enforce transport timeouts and display durations only.
- Store authority data in normalized tables with explicit bounds and foreign
  keys or equivalent application-enforced constraints.
- Store audit events and outbox records in the same transaction as the
  corresponding state transition.
- Every mutation uses an expected revision, expected authority epoch, operation
  ID, and idempotency key.
- A retried transaction reruns only a pure deterministic state transition.
  Signing, object writes, notifications, and audit anchoring occur after commit
  through the outbox.

Spanner is chosen because its default serializable transactions provide
external consistency and TrueTime-backed commit ordering. This replaces local
wall-clock authority without inventing a new time protocol.

### 4.5 Key hierarchy and custody

Use Cloud KMS HSM keys with `EC_SIGN_P256_SHA256`, matching the existing Suite 1
P-256/SHA-256 profile authority.

| Key role | Location and state | Runtime access |
|---|---|---|
| Root authority | Isolated trust key ring, HSM, disabled except ceremony | None |
| Recovery root | Separate key ring and separate approver path, HSM, disabled | None |
| Issuer | HSM, bounded online signing service identity | `koperator-worker` only for approved issuance jobs |
| Emergency deny | Separate HSM key and separate service identity | Dedicated emergency worker only |
| Publication metadata | HSM key | Publication worker only |
| Audit anchor | HSM key | Audit-anchor worker only |

Private key material is never exported. Public keys and full lifecycle metadata
are retained permanently enough to verify historical artifacts and ceremonies.

Asymmetric key rotation is an application-controlled state machine:

```text
CREATED -> STAGED -> DUAL_APPROVED -> PRIMARY -> RETIRING
        -> DISABLED -> DESTROY_SCHEDULED -> DESTROYED
```

No key version may become `PRIMARY` until its public key is distributed in a
monotonic authority update and verified by both the production CLI and the
Android verifier. No key version may be destroyed until all dependent artifacts
have expired or been migrated, rollback evidence exists, and a separate
irreversible-action receipt has two distinct human approvals.

Cloud KMS returns ASN.1 DER ECDSA signatures while the existing profile format
requires fixed-width raw low-S ES256 signatures. The adapter must:

1. strictly decode exactly two positive ASN.1 integers;
2. reject trailing data, zero, negative, or out-of-range values;
3. canonicalize `S` to the low half of the P-256 order;
4. encode fixed-width `R || S` using the existing profile helper;
5. immediately verify the result using the exact KMS public key and suite; and
6. return only a categorical error on failure.

This boundary conversion requires targeted independent review before its merge
gate. The review is limited to adapter correctness and custody assumptions. It
does not change the existing suite.

### 4.6 Publication and emergency control

- Signed profile artifacts use digest-addressed immutable Cloud Storage objects.
- Mutable discovery metadata is a signed, monotonically versioned snapshot.
- Storage writes use generation preconditions. Overwrite is forbidden.
- The publication service account can write only immutable publication objects.
- The public delivery surface has read-only access to approved objects and no
  authority, database, audit, or secret permissions.
- Root metadata, profile metadata, revocation metadata, and emergency-deny
  metadata use independent object namespaces and cache policies.
- Emergency-deny publication has a separate narrow path, service identity,
  alert, and five-minute p95 target.
- Client acceptance remains controlled by existing signature, validity,
  revocation, emergency, compatibility, and monotonic-state verification.
- CDN or HTTP cache freshness is never treated as authority. Signed metadata
  expiry and monotonic client state remain authoritative.

### 4.7 Audit and final acknowledgement

Each authority transaction appends a canonical redacted audit event in Spanner.
The outbox then:

1. builds a bounded canonical audit batch;
2. hashes the batch and previous anchor;
3. signs the anchor digest with the audit HSM key;
4. writes the batch and signed anchor to an isolated append-only audit bucket
   with create-only preconditions;
5. confirms the stored digest and object generation;
6. records the external anchor receipt in Spanner; and
7. advances the operation to `FINALIZED`.

The API may return `PENDING_ANCHOR` after the database transaction, but it may
return final success only after the anchor receipt and any required publication
postcondition are durable. This is how the design meets zero lost acknowledged
authority transitions.

Retention locks and locked log buckets are irreversible. The executor must
qualify them in a disposable project first. Production lock activation requires
a dedicated receipt naming the bucket, retention period, legal owner, incident
owner, approvers, Terraform plan digest, rollback limitation, and exact API
readback.

### 4.8 Infrastructure and deployment

- Terraform is the infrastructure source of truth.
- Use a locally pinned Terraform CLI and pinned HashiCorp Google provider.
- Resolve the highest current stable versions at implementation time, record
  them in `config/production/tools.json`, and commit the provider lock file with
  official checksums. Pre-releases are forbidden.
- Terraform state lives in a dedicated encrypted remote bucket. It contains no
  secret values.
- GitHub Actions authenticates to Google Cloud only with OIDC and Workload
  Identity Federation. Reusable service-account JSON keys are forbidden.
- Production plan and apply are separate protected jobs. Apply consumes the
  exact reviewed binary plan digest and refuses drift.
- Production apply never uses `-auto-approve`.
- Container images are digest-pinned. Mutable tags are display aliases only.
- Deployment updates traffic only after health, schema, identity, and
  compatibility checks pass. Rollback restores the prior image digest and does
  not roll authority state backward.

## 5. Repository layout to create

The executor must use this layout unless an existing path already supplies the
same responsibility:

```text
api/operator/v1/operator.openapi.yaml
config/production/
  actions.json
  key-policy.json
  regions.json
  retention.json
  roles.json
  services.json
  tools.json
docs/
  KIP-0092-phase16-production-trust.md
  PHASE16_API.md
  PHASE16_CEREMONIES.md
  PHASE16_DISASTER_RECOVERY.md
  PHASE16_EVIDENCE_INDEX.md
  PHASE16_OPERATIONS.md
  PHASE16_PRODUCTION_TRUST_COMPLETION_PLAN.md
  PHASE16_THREAT_MODEL.md
infra/terraform/
  modules/
    audit/
    backup/
    certificate/
    control_plane/
    identity/
    kms_hsm/
    monitoring/
    network/
    projects/
    publication/
    secrets/
    spanner/
    workload_identity/
  environments/
    qualification/
    production/
  policies/
  tests/
internal/operator/controlplane/
  command.go
  production_interfaces.go
  transaction.go
  trusted_time.go
production/
  go.mod
  go.sum
  cmd/
    koperator-api/
    koperator-ceremony/
    koperator-drill/
    koperator-worker/
  internal/
    auditanchor/
    authn/
    authz/
    backup/
    config/
    kmsprovider/
    publication/
    server/
    spannerstore/
    trustedtime/
testdata/evidence/phase16/
  production-trust-status.json
  production-trust-status.schema.json
  fixtures/
cmd/phase16verify/
```

Keep Google Cloud client dependencies in the nested `production/` Go module so
the protocol/core module remains small and its existing gate remains fast. The
production module may import `kurdistan/internal/...`; its module path must be
`kurdistan/production`, and its local development requirement must bind the
root module by exact repository checkout. The CI gate must explicitly test both
modules.

## 6. Private execution input contract

The executor must not ask ad hoc architecture questions. It must consume one
predeclared private input document:

```text
.tools/phase16/private/owner-inputs.json
```

Create and commit only its schema and redacted example:

```text
testdata/schemas/phase16-owner-inputs-v1.schema.json
testdata/fixtures/phase16/owner-inputs.example.json
```

The private document must contain references, never secret values:

- Google Cloud organization and billing-account identifiers;
- approved qualification and production project IDs;
- EU region and Spanner configuration;
- delegated domain and DNS zone identifiers;
- Cloud Identity or Workspace tenant and opaque group identifiers;
- named operational roles and two distinct people for each required approval
  class;
- WIF pool/provider identifiers and allowed GitHub subject claims;
- Secret Manager resource names;
- alert channels and on-call owner references;
- budget and automatic qualification-teardown limits;
- retention periods and their legal/incident owners;
- backup target project and recovery owners;
- production mutation authorization ID;
- irreversible-action authorization IDs for retention locks, key destruction,
  and production DNS activation.

`cmd/phase16verify` must reject missing fields, placeholder values, secret-like
values, duplicate approvers, production/test project reuse, non-EU residency,
unbounded budgets, or authorization receipts that do not match the exact plan.

If private inputs or cloud access are absent, the agent must complete and test
all local and disposable work, then emit one precise missing-input report. It
must not fabricate completion or mutate an unintended account. Phase 16 remains
open until the real external evidence exists.

## 7. Ordered work packages

No later work package begins until the preceding package's commit gate is green.

### WP0. Commit, push, and integrate the roadmap reconciliation

**Purpose:** close the already validated four-file roadmap update before adding
Phase 16 implementation files.

1. Confirm the four tracked files are the only tracked changes.
2. Confirm this plan file is untracked or separately staged and is not included
   in the four-file commit.
3. Run:

   ```powershell
   go test ./cmd/phase9verify ./cmd/phase15verify -count=1
   go run ./cmd/phase15verify -root .
   go run ./cmd/gate
   go run ./cmd/gate -android
   git diff --check
   git status --short
   ```

4. Inspect the full four-file diff.
5. Stage exactly the four files listed in Section 2.
6. Commit with:

   ```text
   docs: reconcile Phase 16 CI foundation and remaining trust work

   Co-Authored-By: OpenAI Codex <codex@openai.com>
   ```

7. Push `engineering/ci-release-acceleration`.
8. Inspect every GitHub Actions job for the exact commit. Do not rely on the
   aggregate check alone.
9. Fast-forward `main` only if all required jobs are green and `origin/main`
   still equals the expected predecessor.
10. Push `main` with `force=false`.
11. Confirm the main assurance run is green.
12. Create `product/phase16-production-trust` from the exact new `main`.
13. Add and commit this plan document as a plan-only commit after confirming it
    does not alter runtime behavior.

**Acceptance:** both branch and main contain the reconciliation; the plan is on
the Phase 16 branch; no unrelated file is committed; Phase 14 remains `NO_GO`.

**Rollback:** revert the roadmap commit before Phase 16 work if its main CI run
fails. Never force-push main.

### WP1. Freeze Phase 16 authority and evidence schemas

**Files:**

- `docs/KIP-0092-phase16-production-trust.md`
- `docs/PHASE16_THREAT_MODEL.md`
- `config/production/*.json`
- `testdata/schemas/phase16-*.schema.json`
- `testdata/evidence/phase16/production-trust-status.json`
- `cmd/phase16verify/`

**Implementation:**

1. Convert Sections 3 and 4 into human and machine authority.
2. Define exact roles:
   - `viewer`
   - `requester`
   - `approver`
   - `executor`
   - `publisher`
   - `auditor`
   - `recovery`
   - `emergency`
   - `deployer`
3. Define the exact action-to-role matrix and forbidden role combinations.
4. Require two distinct approvers for root, issuer, publication, revocation,
   recovery, emergency, retention lock, and key-destruction operations.
5. Prohibit requester self-approval and approval by the executor for the same
   operation.
6. Define evidence subjects, expiry rules, authority targets, RTO/RPO targets,
   and `[UNVERIFIED]` handling.
7. Implement strict JSON parsers with duplicate-key rejection, unknown-field
   rejection, bounded strings/arrays, and canonical hashing.
8. Make `phase16verify` reject stale Phase 12/15 language that claims local
   evidence is production evidence.

**Tests:** valid fixture, every missing field, duplicate key, unknown field,
wrong phase, wrong commit, stale receipt, duplicate approver, forbidden role
combination, secret canary, non-EU region, unbounded budget, and unsupported
claim.

**Acceptance:** offline verification is deterministic and fails closed without
live cloud calls.

### WP2. Extract deterministic production transitions

**Files:** `internal/operator/controlplane/{command,transaction,
production_interfaces,trusted_time}.go` plus targeted tests.

**Implementation:**

1. Extract each Phase 12 mutation into a pure command transition.
2. Introduce a context-aware production transaction interface returning:
   revision, sequence, trusted commit time, audit hash, and outbox IDs.
3. Retain `Store`, `JournalStore`, and existing public APIs as compatibility
   adapters. Do not break local evidence.
4. Make transition functions deterministic under database retry.
5. Forbid randomness, network I/O, KMS calls, object writes, or wall-clock reads
   inside the transition callback.
6. Add explicit operation states:

   ```text
   PENDING -> APPROVED -> COMMITTED -> EFFECT_PENDING
           -> ANCHORED -> PUBLISHED -> FINALIZED
                         \-> FAILED_RETRYABLE
                         \-> FAILED_TERMINAL
   ```

7. Preserve exact event-ID idempotency and the existing three-attempt bound.
8. Add reserved capacity for revocation, emergency deny, audit anchoring, and
   recovery even when ordinary queues are saturated.

**Tests:** parity between old API and command engine; deterministic retry;
concurrent expected-revision conflict; replay; out-of-order epoch; skipped
epoch; queue saturation; emergency reserved capacity; mutation after callback;
and property/fuzz tests over command sequences.

**Acceptance:** local Phase 12 tests and new production transition tests pass
without changing emitted Phase 8 artifact bytes.

### WP3. Implement the versioned operator API and identity boundary

**Files:**

- `api/operator/v1/operator.openapi.yaml`
- `production/internal/{authn,authz,server}/`
- `production/cmd/koperator-api/`
- `docs/PHASE16_API.md`

**API surface:**

- `GET /v1/version`
- `GET /v1/health/live`
- `GET /v1/health/ready`
- `POST /v1/operations`
- `GET /v1/operations/{operation_id}`
- `POST /v1/operations/{operation_id}:approve`
- `POST /v1/operations/{operation_id}:reject`
- `POST /v1/operations/{operation_id}:execute`
- `GET /v1/profiles/{profile_id}`
- `GET /v1/publications/current`
- `GET /v1/revocations/current`
- `POST /v1/emergency:deny`
- `POST /v1/keys/{key_id}:rotate`
- `POST /v1/recovery:prepare`

All mutating endpoints require an idempotency key, expected revision, expected
epoch, bounded body, explicit content type, and exact API version.

**Identity rules:**

1. Validate IAP or service identity tokens for exact issuer, audience,
   authorized party, expiry, signature, and subject.
2. Map the external subject to a keyed, environment-specific opaque actor ID.
3. Never store email addresses or raw identity tokens in domain state or audit
   events.
4. Resolve roles from a versioned entitlement mapping and require a recent,
   phishing-resistant authentication context for privileged actions.
5. Apply application-level dual control even if cloud IAM or privileged-access
   tooling also approved the session.
6. Reject bearer tokens from query strings, cookies outside the IAP boundary,
   wrong audiences, or test issuers in production.
7. Rate-limit by opaque actor and action class without recording personal data.
8. Return stable categorical errors and correlation aliases, never stack traces
   or provider errors.

**Tests:** OpenAPI schema; request/response compatibility; token forgery,
confused deputy, wrong audience, expiry, replay, group removal, role change
during operation, requester self-approval, approver/executor collision,
break-glass expiry, body limit, content-type confusion, idempotency collision,
and error redaction.

### WP4. Implement Spanner authority storage and trusted time

**Files:** `production/internal/{spannerstore,trustedtime}/`, migration files,
and emulator/integration tests.

**Required tables:**

- `AuthorityHead`
- `Operations`
- `Approvals`
- `Profiles`
- `Relays`
- `Publications`
- `EmergencyAuthorities`
- `EmergencyRestrictions`
- `KeyVersions`
- `Ceremonies`
- `OutboxEvents`
- `AuditEvents`
- `AuditAnchors`
- `IdempotencyReceipts`
- `SchemaMigrations`

**Rules:**

1. Every authority mutation is one serializable read-write transaction.
2. `AuthorityHead` owns the monotonic revision and epoch.
3. Use pending commit timestamps for transition time.
4. Use database constraints plus domain validation for bounds and uniqueness.
5. Use interleaving only where deletion semantics cannot cascade authority
   history.
6. Authority and audit history are never hard-deleted by normal operations.
7. Outbox leases use trusted database time and fencing tokens.
8. A worker that loses its lease cannot acknowledge or finalize an effect.
9. Schema migration is forward-only, checksum-bound, idempotent, and runs under
   a dedicated identity.
10. Restore creates a new database and verifies it before any endpoint is
    redirected. It never overwrites the only known-good database.

**Tests:** Spanner emulator tests; transaction retry; conflict; lease theft;
worker death; delayed commit; local clock moved backward/forward; duplicate
idempotency; migration interruption; incompatible schema; restore into clean
database; rollback snapshot rejection; and strong-read parity.

**Acceptance:** no production authority decision reads local time, and every
committed transition has same-transaction audit and outbox records.

### WP5. Implement HSM/KMS key-provider adapters and ceremonies

**Files:**

- `production/internal/kmsprovider/`
- `production/cmd/koperator-ceremony/`
- `docs/PHASE16_CEREMONIES.md`
- KMS fixtures and adapter tests

**Implementation:**

1. Implement the existing opaque `profile.Signer` and verifier/provider
   interfaces against version-qualified Cloud KMS resource names.
2. Fetch and cache public keys by immutable key-version reference.
3. Verify key purpose, algorithm, protection level `HSM`, state, and project
   before use.
4. Implement the strict DER-to-raw low-S conversion described in Section 4.5.
5. Bind every signature request to role, operation, artifact digest, key
   version, trusted issuance reservation, and ceremony or approval ID.
6. Enforce separate service identities per key role.
7. Implement staged asymmetric rotation, public-key distribution, activation,
   retirement, disable, recovery, and destruction scheduling.
8. Root and recovery jobs refuse execution unless their key is currently
   enabled by a valid, time-bounded, dual-approved ceremony.
9. Persist no signature input containing secrets. Profile artifact bytes remain
   bounded transient data.
10. Zero transient buffers where practical and never log them.

**Tests:** official KMS emulator/stub contract tests plus qualification HSM
tests; malformed DER; high-S normalization; zero/negative/out-of-range scalar;
trailing ASN.1; wrong public key; wrong algorithm; software-key rejection;
disabled key; destroyed key; permission denied; timeout; replay; version
substitution; signature parity with the existing verifier; and no-secret scans.

**Review gate:** an independent reviewer must approve the KMS adapter's suite
mapping, DER parsing, low-S handling, key-version binding, and custody boundary.
Every finding must be fixed or explicitly rejected with evidence before merge.

### WP6. Implement real profile issuance and lifecycle

**Files:** production issuance/publication packages, Phase 8 boundary tests,
operator API operations, and CLI support.

**Implementation flow:**

1. Request an issuance or lifecycle operation with exact authority scope.
2. Obtain two valid approvals.
3. Reserve generation, epoch, and trusted issuance time in Spanner.
4. Create an outbox signing job.
5. Build the artifact through existing Phase 8 code only.
6. Sign through the exact HSM key version.
7. Verify the exact bytes with the independent existing verifier.
8. Persist digest and redacted receipt, not private payload fields.
9. Anchor the audit event.
10. Publish immutable artifact bytes and signed monotonic metadata.
11. Read back and hash the published object.
12. Verify through production CLI and Android verifier.
13. Finalize the operation.

Support:

- signed-public profile issuance;
- sealed-recipient profile issuance using existing recipient interfaces;
- controlled expiry;
- monotonic profile rotation;
- routine revocation;
- signed root-bound emergency deny;
- subscription metadata refresh;
- duplicate and idempotent replay;
- explicit cancellation before signing; and
- fail-closed terminal state after signing if publication cannot be confirmed.

The Phase 16 production profile uses a controlled trust-validation audience and
contains no claim of live relay availability. Phase 17 replaces or rotates its
relay descriptors when live provider infrastructure is authorized.

**Tests:** full lifecycle; expired approval; stale reservation; publication
collision; lost worker; duplicate delivery; object tamper; metadata rollback;
revocation before publication; rotation/revocation race; emergency deny during
outage; Android valid/expired/revoked/rollback verification; and exact-byte
golden parity where the HSM signature is substituted by a deterministic test
provider.

### WP7. Implement durable outbox, publication, and audit anchoring

**Files:** `production/internal/{publication,auditanchor}/`, worker command,
Terraform publication/audit modules, and tests.

**Implementation:**

1. Poll outbox with bounded batches, leases, fencing tokens, and jittered
   retries.
2. Use event ID as the sole idempotency key for effects.
3. For Cloud Storage, use create-only generation preconditions and digest-based
   object names.
4. Read back object metadata and digest before marking delivery.
5. Anchor audit batches in an independent project and sign each anchor.
6. Preserve canonical sequence and previous-anchor linkage.
7. Keep a dead-letter state after the existing maximum attempts. Safety events
   page immediately and retain reserved execution capacity.
8. Never include profile bytes, destinations, keys, tokens, operator identity,
   or private endpoints in logs or metrics.
9. Expose only bounded categorical health metrics.

**Tests:** double delivery; stale lease; worker split brain; bucket object
already exists with same/different digest; partial upload; readback mismatch;
anchor gap; chain fork; wrong previous hash; audit bucket unavailable; retry
exhaustion; emergency-priority scheduling; and forced recovery.

### WP8. Implement reproducible Terraform infrastructure

**Files:** `infra/terraform/**`, `config/production/tools.json`, validation
scripts, and policy tests.

**Implementation sequence:**

1. Bootstrap pinned Terraform and Google Cloud CLI under `.tools/phase16/bin`.
2. Verify every downloaded archive against a committed official digest or
   signature reference.
3. Build reusable modules listed in Section 5.
4. Enforce project separation, service-account separation, EU residency,
   customer-managed encryption where required, uniform bucket access, public
   access prevention except the exact publication reader, budget alerts,
   deletion protection, audit sinks, and VPC Service Controls where supported.
5. Keep Terraform state and variables free of secret values. Store only Secret
   Manager resource references.
6. Write policy tests that reject:
   - wildcard IAM;
   - owner/editor roles;
   - service-account keys;
   - public control-plane ingress;
   - direct `run.app` exposure;
   - non-HSM authority keys;
   - non-EU authority state;
   - unversioned images;
   - mutable publication objects;
   - missing deletion protection;
   - missing budgets or audit sinks;
   - missing WIF subject restrictions; and
   - production/test project reuse.
7. Run `terraform fmt -check`, `init -backend=false`, `validate`, provider lock
   verification, and plan-shape tests in CI.
8. Deploy qualification first, run all integration tests, then destroy it and
   prove cleanup.
9. Produce a production binary plan. Review and bind its digest to the external
   authorization receipt before apply.

**Acceptance:** two clean hosts generate semantically identical production
plans from the same inputs, excluding documented provider-generated volatile
fields. Drift detection is green after apply.

### WP9. Implement protected deployment workflows

**Files:**

- `.github/workflows/phase16-qualification.yml`
- `.github/workflows/phase16-production-plan.yml`
- `.github/workflows/phase16-production-apply.yml`
- `.github/workflows/phase16-drill.yml`
- local composite actions only after repeated setup is stable

**Rules:**

1. Pin every action to a full commit SHA.
2. Use minimum `permissions`; production jobs alone receive `id-token: write`.
3. Restrict WIF by repository, ref, workflow path, environment, and subject.
4. Forked PRs and ordinary PRs receive no cloud identity.
5. Qualification has a cost cap and automatic teardown.
6. Production plan is read-only and uploads an exact plan digest and policy
   report.
7. Production apply runs in a protected environment with required reviewers,
   consumes the exact plan, and never rebuilds application images.
8. External mutation workflows never use `cancel-in-progress: true`.
9. An interrupted apply reconciles actual state before retry.
10. Every workflow emits a strict receipt with source commit, tree, workflow
    digest, environment, cloud project digests, plan digest, resource inventory
    digest, identity, start/end time, result, and limitations.

**Tests:** workflow static verifier; OIDC claim mismatch; stale plan; changed
Terraform; changed image digest; expired approval; concurrent apply; cancelled
apply; partial state; drift; replayed receipt; and no-secret artifact scan.

### WP10. Implement backups and disaster recovery

**Files:** `production/internal/backup/`, Terraform backup module,
`docs/PHASE16_DISASTER_RECOVERY.md`, drill command, and evidence schemas.

**Backup policy:**

- Enable Spanner PITR for the maximum approved interval.
- Create scheduled transactionally consistent backups.
- Copy completed backups to a separate approved EU project.
- Protect backup operations with separate identities and deletion controls.
- Back up configuration, schema migrations, public key metadata, publication
  inventories, and audit-anchor inventories.
- Do not back up private key bytes because they never leave HSM custody.
- Test KMS key availability and recovery separately from database restore.

**Restore sequence:**

1. declare incident and freeze ordinary mutations;
2. capture current external publication and audit heads;
3. restore into a new database and new service revision;
4. apply and verify schema migrations;
5. verify every audit sequence and anchor;
6. compare restored authority head against public and HSM metadata;
7. reject any rollback, fork, missing acknowledged transition, or unknown key;
8. replay pending idempotent outbox events;
9. run read-only lifecycle verification;
10. switch traffic with an explicit approval;
11. retain the previous database for forensic review; and
12. record actual RTO and RPO.

**Drills:** total database loss; regional loss; control-plane image rollback;
outbox backlog; audit bucket unavailable; KMS issuer disabled; recovery-root
activation; trusted-time rollback attempt; identity-provider outage;
publication outage; and compromised operator session.

**Acceptance:** control plane RTO is at most four hours; publication and
emergency-control RTO is at most 30 minutes; zero acknowledged authority
transitions are lost; no restored state is older than the last externally
anchored head.

### WP11. Perform production ceremonies and compromise drills

**Required people:** two distinct authorized approvers plus a separate executor
for each root, recovery, issuer, emergency, and destruction ceremony. The same
person may not fill conflicting roles for one ceremony.

**Ceremonies:**

1. root creation and public-key capture;
2. recovery-root creation in a separate key ring and approval path;
3. issuer delegation;
4. emergency-key delegation;
5. publication and audit-key delegation;
6. issuer rotation;
7. issuer disable and recovery;
8. root-set update;
9. compromised intermediate revocation;
10. scheduled destruction dry run without destruction;
11. break-glass activation and expiry; and
12. audit of all ceremony receipts.

Each receipt binds exact key resource and version, public-key digest, algorithm,
HSM protection-level readback, participants' opaque actor IDs, approvals,
trusted start/end time, source and infrastructure digests, before/after state,
and verifier result. Receipts contain no personal details or secret material.

Actual key destruction is not required for Phase 16 completion. The plan,
approval, scheduling, cancellation, and recovery path must be tested using
disposable qualification keys. Production destruction remains a separate
irreversible action.

### WP12. Execute the Phase 16 end-to-end exit gate

Use a production-authority, controlled-distribution profile and perform this
exact sequence:

```text
issue -> anchor -> publish -> read back -> verify
      -> rotate -> anchor -> publish -> verify new and reject rollback
      -> revoke -> anchor -> publish -> reject profile
      -> emergency deny -> anchor -> publish -> reject affected scope
```

Evidence must prove:

- the API identities and approvals were valid and role-separated;
- each signature used the expected non-exportable HSM key version;
- each transition used Spanner trusted commit time;
- each database, outbox, audit, and publication digest agrees;
- CLI verification and Android verification agree;
- old metadata and artifacts cannot roll authority backward;
- emergency deny meets the five-minute p95 target;
- routine revocation meets the ten-minute p95 target;
- database loss and restore lose no acknowledged transition;
- recovery-root and compromised-intermediate drills pass;
- no secret or prohibited data appears in logs or artifacts; and
- all required production resources have ownership, monitoring, backup,
  retention, incident, and rollback records.

Run the complete sequence at least three times, including one forced failure at
each external boundary. A single lucky pass is insufficient.

### WP13. Final verification, commits, push, CI, and main integration

1. Regenerate only authoritative generated evidence through documented tools.
2. Run all checks in Section 9.
3. Inspect the complete branch diff, Git history, Terraform plan, IAM graph,
   API surface, KMS policy, data schema, logs, evidence, and documentation.
4. Search for secrets, private keys, service-account JSON, test authority in
   production, personal data, private endpoints, unsupported claims, TODOs,
   placeholders, skipped tests, broad IAM, and unpinned actions.
5. Fix every critical/high finding and rerun affected plus full gates.
6. Push `product/phase16-production-trust`.
7. Inspect every GitHub Actions and protected production-validation job.
8. Fast-forward main only if:
   - all required checks are green;
   - the exact Phase 16 exit-gate evidence is valid and fresh;
   - the independent KMS adapter review is approved;
   - no critical or high finding remains;
   - `origin/main` is still the expected predecessor; and
   - the full diff has final approval.
9. Push main with `force=false`.
10. Rerun main assurance and Phase 16 verifier.
11. Update ROADMAP only after the main evidence is green.
12. Do not tag, release, submit to Play, activate a public relay, or claim a
    production-ready VPN.

## 8. Commit sequence

Use small commits in this order. Each commit ends with
`Co-Authored-By: OpenAI Codex <codex@openai.com>`.

| Commit | Scope | Minimum gate before commit | Rollback |
|---|---|---|---|
| 0 | Four-file roadmap reconciliation | Phase 15 verifier, Go gate, Android gate | Revert before Phase 16 branch |
| 1 | This plan, KIP, threat model, schemas | `phase16verify` unit tests | Revert authority docs and schemas |
| 2 | Pure command/transaction extraction | control-plane parity, fuzz, full Go gate | Restore compatibility adapter path |
| 3 | Production module and API/identity | production module tests, OpenAPI, auth negative tests | Disable API deployment |
| 4 | Spanner store and trusted time | emulator, retry, rollback, migration tests | Keep JournalStore authoritative locally |
| 5 | HSM/KMS adapter | adapter corpus, live qualification HSM, review gate | Disable all production sign identities |
| 6 | Issuance and lifecycle | deterministic provider and qualification HSM lifecycle | Block production publication |
| 7 | Outbox, publication, and audit anchor | failure injection and exact readback | Stop workers; retain committed state |
| 8 | Terraform qualification modules | fmt, validate, policy tests, create/destroy | Destroy qualification only |
| 9 | Production IaC and workflows | plan equality, workflow verifier, OIDC negative tests | No apply; retain plan-only state |
| 10 | Backup/DR and ceremony tooling | restore and compromise drills | Keep old service/database isolated |
| 11 | Production external evidence | exact exit gate three times | Emergency deny; freeze mutations |
| 12 | Phase 16 closeout | every gate, full diff, CI | Revert code; do not roll authority state backward |

No commit may mix production logic with unrelated UI, protocol, Android,
planning-pack, or formatting changes.

## 9. Required validation commands

The executor must derive exact flags from the implemented commands, but these
top-level commands are mandatory:

```powershell
gofmt on changed Go files only
go mod verify
go test -count=1 ./...
go vet ./...
go run ./cmd/gate
go run ./cmd/gate -android
go test -count=1 ./cmd/phase15verify ./cmd/phase16verify
go run ./cmd/phase15verify -root .
go run ./cmd/phase16verify -root . -mode offline
go -C production mod verify
go -C production test -count=1 ./...
go -C production vet ./...
terraform -chdir=infra/terraform/environments/qualification fmt -check -recursive
terraform -chdir=infra/terraform/environments/qualification init -backend=false -lockfile=readonly
terraform -chdir=infra/terraform/environments/qualification validate
terraform -chdir=infra/terraform/environments/production init -backend=false -lockfile=readonly
terraform -chdir=infra/terraform/environments/production validate
go run ./cmd/assure workflow -root .
go run ./cmd/assure inventory -root .
git diff --check
git status --short
```

Protected external checks:

```text
phase16 qualification create -> test -> destroy
phase16 production plan -> policy -> approval -> apply -> readback
phase16 lifecycle exit gate x3
phase16 database-loss restore drill
phase16 root/recovery/intermediate compromise drills
phase16 trusted-time rollback drill
phase16 audit-continuity drill
```

Every Go test that proves authority behavior uses `-count=1`. Authoritative CI
runs are cache-independent. Repeated or fault-injection tests publish exact
test inventories so zero-test success is impossible.

## 10. Mandatory test matrix

### Identity and authorization

- valid IAP human token;
- valid service identity token;
- wrong issuer/audience/authorized party;
- expired/not-yet-valid token;
- removed group or role;
- requester self-approval;
- one human represented by two aliases;
- approver acting as executor;
- stale approval after operation mutation;
- break-glass without dual approval;
- break-glass after expiry;
- IdP unavailable;
- compromised operator session revocation.

### Database, time, and concurrency

- concurrent requests at one revision;
- transaction retry and callback replay;
- local clock moved backward by 24 hours;
- local clock moved forward by 24 hours;
- stale trusted timestamp;
- epoch rollback and equal-epoch fork;
- database regional failover;
- full database loss and restore;
- migration crash and resume;
- outbox lease theft and worker split brain.

### KMS and profile authority

- wrong project, key ring, key, or version;
- software key presented as HSM;
- wrong purpose/algorithm;
- disabled, pending-destruction, and destroyed version;
- DER edge corpus and low-S normalization;
- wrong public-key readback;
- signing timeout and ambiguous response;
- issuer rotation;
- root recovery;
- compromised intermediate revocation;
- signed-public and sealed profile verification;
- expired, forged, revoked, rollback, and emergency-denied profile.

### Publication, audit, and recovery

- immutable create collision;
- stale mutable pointer;
- partial object write;
- digest mismatch on readback;
- CDN stale data;
- publication outage;
- audit anchor outage;
- missing audit sequence;
- forked audit chain;
- dead-letter outbox;
- emergency event under ordinary queue saturation;
- restore with a valid database but stale public head;
- restore with current public head but missing audit anchor.

### Privacy and supply chain

- canary secrets in every input path;
- log, metric, trace, crash, receipt, artifact, Terraform state, and GitHub
  artifact scans;
- unpinned action/tool/image rejection;
- service-account JSON rejection;
- wildcard IAM rejection;
- unauthorized egress;
- dependency or module checksum tamper;
- qualification fixture in production artifact;
- private endpoint or operator identity disclosure.

## 11. Phase 16 evidence model

The authoritative `production-trust-status.json` must include:

- schema and phase;
- exact source commit and tree;
- exact Phase 15 contract digest;
- API schema digest;
- role/action policy digests;
- Terraform and provider lock digests;
- container image digests;
- cloud project opaque aliases and residency readbacks;
- WIF, IAP, ingress, and IAM policy digests;
- Spanner instance/database/schema/configuration readbacks;
- KMS key role, algorithm, HSM protection, state, version, and public-key
  digests;
- publication and audit bucket policy/readback digests;
- backup/PITR configuration and restore receipts;
- each lifecycle artifact and metadata digest;
- CLI and Android verification receipts;
- ceremony and drill receipt digests;
- measured RTO/RPO and propagation results;
- independent KMS adapter review disposition;
- unresolved findings by severity;
- release decision, which remains `NO_GO` for the full VPN; and
- limitations, including that live relays and Internet egress belong to Phase
  17.

Receipts must be strict, atomic, canonical, subject-bound, expiry-aware, and
safe to publish to the private evidence artifact store. Git stores schemas,
redacted summaries, and immutable digests, not cloud tokens, personal records,
private endpoints, or secret values.

## 12. Definition of Phase 16 complete

Phase 16 is complete only when all statements below are true:

- The roadmap reconciliation is committed, pushed, green, and fast-forwarded
  into main.
- The production API uses authenticated, phishing-resistant identities and
  exact role-based authorization.
- Dual control and separation of duties cannot be bypassed.
- Every authority private key is non-exportable and HSM-backed.
- Root, recovery, issuer, emergency, publication, and audit roles are separated.
- The KMS adapter review is approved with no unresolved critical/high finding.
- Spanner commit time and monotonic state are authoritative.
- Database, audit, and outbox transitions are atomic.
- Final acknowledgement waits for required audit and publication postconditions.
- Profile issue, publish, verify, rotate, revoke, and emergency deny work against
  the real production trust stack.
- Database-loss restore preserves the last acknowledged authority transition
  and rejects rollback.
- Root, recovery, compromise, trusted-time, publication, audit, and identity
  drills pass.
- Terraform reproduces the approved infrastructure and detects drift.
- GitHub uses OIDC/WIF and contains no reusable cloud credential.
- Monitoring, budgets, ownership, retention, incident, backup, and rollback
  controls exist for every production service.
- Full Go, Android, production module, Terraform, workflow, emulator, privacy,
  recovery, and cache-independent CI gates pass.
- The complete diff has no unresolved critical or high defect, TODO,
  placeholder, unsupported claim, secret, or unrelated change.
- Main is updated only by fast-forward after exact-subject CI is green.
- The full VPN release decision remains `NO_GO`, with Phase 17 named as the next
  frontier.

Anything less is progress, not Phase 16 completion.

## 13. Final report required from the implementing agent

Report:

1. every commit hash and branch;
2. exact files and services added or changed;
3. production project aliases and regions, without exposing private IDs;
4. identity, role, approval, and break-glass evidence;
5. KMS key-role and ceremony evidence;
6. database, trusted-time, outbox, audit, backup, and DR evidence;
7. complete profile lifecycle and emergency-deny results;
8. qualification and production Terraform plan/apply/readback results;
9. every local, CI, external, Android, and drill gate result;
10. independent review findings and disposition;
11. measured RTO, RPO, revocation, and emergency propagation;
12. the main fast-forward and final CI run;
13. confirmation that no tag, release, Play action, public relay, or VPN
    production-readiness claim occurred; and
14. any remaining limitation. If a required item remains, state that Phase 16
    is incomplete.

## 14. Primary technical references

- [Spanner TrueTime and external consistency](https://docs.cloud.google.com/spanner/docs/true-time-external-consistency)
- [Spanner backups](https://docs.cloud.google.com/spanner/docs/backup)
- [Spanner point-in-time recovery](https://cloud.google.com/spanner/docs/use-pitr)
- [Cloud KMS algorithms and HSM protection levels](https://docs.cloud.google.com/kms/docs/algorithms)
- [Cloud KMS asymmetric rotation considerations](https://docs.cloud.google.com/kms/docs/key-rotation)
- [Cloud Run ingress restrictions](https://docs.cloud.google.com/run/docs/securing/ingress)
- [Identity-Aware Proxy for Cloud Run](https://docs.cloud.google.com/run/docs/securing/identity-aware-proxy-cloud-run)
- [GitHub OIDC for Google Cloud](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-google-cloud-platform)

Provider documentation is an implementation reference. Repository contracts,
schemas, tests, and reviewed KIPs remain the product authority.

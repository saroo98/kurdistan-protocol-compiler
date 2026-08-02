<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan VPN roadmap

This roadmap ends only when Kurdistan VPN is a production-operated Android VPN,
not when source files merely exist. Detailed milestone authority remains in the
KIP documents and machine-readable evidence under `testdata/evidence/`. This
file defines the complete product sequence and the truth conditions for moving
between phases.

## Current truth

- Phases 1-15 are integrated on `main` at
  `8fe2d59034deea215c45734f4bb8582bff004d9b` with green Linux and Windows Go
  and Android assurance CI. The Phase 15 frozen input remains
  `1fcfeab111cf64f1295f10d788e4977ab4666a7a`.
- Phase 16 is active on `engineering/ci-release-acceleration`; this bounded
  workstream implements evidence-preserving CI and inactive release tooling.
- The current release decision is `NO_GO`.
- Production authority, non-loopback relays, a deployed provider service,
  production Android networking, signing, distribution, physical-device proof,
  controlled field validation, monitoring, support, and disaster recovery are
  not yet complete.
- Phases 15-22 are the required production program. Their implementation
  requires scoped KIP authority before work begins.

Local, emulator, loopback, or source-presence evidence cannot be promoted into
production, field, privacy, reliability, or censorship-resilience claims.

## Status legend

| Status | Meaning |
|---|---|
| Integrated | Reviewed, committed, merged to `main`, and green on the merged commit. |
| Local complete | Implemented and locally validated, but not yet integrated. |
| Active | The current governed work and evidence boundary. |
| Future | Required for the declared v1 product, but not yet authorized or complete. |
| `[UNVERIFIED]` | Evidence does not exist in the environment required to support the claim. |

## Complete phase sequence

| Phase | State | Outcome |
|---:|---|---|
| 1 | Integrated | Cryptographic/runtime remediation and cache-proof gates. |
| 2 | Integrated | Product governance and contract catalog. |
| 3 | Integrated | Offline profile admission, lifecycle, revocation, and updates. |
| 4 | Integrated | Deterministic permitted-fallback selection. |
| 5 | Integrated | Offline relay-descriptor admission. |
| 6 | Integrated | Offline diagnostic-export contract. |
| 7 | Integrated | Offline app-runtime contract. |
| 8 | Integrated | Profile signing, encryption, sealing, and local key-provider boundaries. |
| 9 | Integrated | Android foundation and protected local state. |
| 10 | Integrated | Bounded Android `VpnService`/TUN and deterministic local routing. |
| 11 | Integrated | Kurd wire-v1, authenticated records, fallback authority, and loopback relay conformance. |
| 12 | Integrated | Local operator, provisioning, publication, revocation, and emergency-control semantics. |
| 13 | Integrated | Android product surface, validated settings, routing, diagnostics, recovery, and operator projections. |
| 14 | Integrated | Candidate-local assurance, coverage reconciliation, reproducibility, and production-program readiness. |
| 15 | Integrated | Freeze the Phase 13-14 production contract and authorize bounded infrastructure engineering. |
| 16 | Active | Production trust, identity, key custody, control-plane foundations, and evidence-preserving CI/release tooling. |
| 17 | Future | Owned provider, relay fleet, and live Kurd data plane. |
| 18 | Future | Production Android integration and complete accepted product surface. |
| 19 | Future | Secure release engineering and operational platform. |
| 20 | Future | Independent assurance, remediation, and release-candidate freeze. |
| 21 | Future | Controlled field validation and closed production pilot. |
| 22 | Future | Public staged release and steady-state operational handover. |

## Foundation already built: Phases 1-12

Phases 1-8 establish the compiler, audits, deterministic product contracts, and
bounded profile cryptography. Phases 9-12 add the native Android foundation,
encrypted local state, bounded TUN runtime, Kurd wire and record protection,
loopback relay conformance, fallback authority, and local production-candidate
operator semantics.

These phases are a serious foundation. They do not provide a production relay,
public provider, production key custody, unrestricted Internet egress, signed
store release, or field evidence.

Two
nine-finding security reviews closed the local Phase 12 control-plane design.
Production trusted-time operation, external operator identity, and deployed
fleet evidence remain **[UNVERIFIED]**.

## Phase 13: Android product completion candidate

**State:** integrated.

The preserved candidate contains the three-area Android product structure,
verified runtime handoff, encrypted routing and diagnostics, validated settings,
profile/provider/operator views, recovery flows, localization parity, adaptive
layouts, and exact emulator manifests. Its local gates and merged CI establish
the integrated local product baseline. They are not physical-device,
production, field, or release evidence.

## Phase 14: candidate-local assurance and production-program readiness

**State:** integrated; local assurance complete. **Release decision:** `NO_GO`.

Phase 14 must close every locally resolvable problem before production work is
allowed to build on the candidate:

- freeze exact source, Android, Go, relay, operator, schema, documentation,
  SBOM, provenance, and evidence inputs;
- complete cache-independent host and emulator gates;
- complete local corruption, recovery, rollback, longevity, privacy-canary,
  accessibility, and reproducibility evidence;
- reconcile every D0-D28 and inspiration-inventory requirement;
- finalize field, incident, release, rollback, and evidence protocols;
- produce an objective local decision that remains `NO_GO` while production and
  field evidence is absent.

### Phase 14 exit gate

- Every locally observable requirement passes against one digest-bound
  candidate.
- No critical local blocker, stale evidence, false claim, contradictory status,
  accidental generated artifact, or unrelated change remains.
- Phase 13 and Phase 14 are ready for integration review.
- External production and field evidence stays explicitly **[UNVERIFIED]**.

## Phase 15: production contract freeze

**State:** integrated.

**Purpose:** establish a clean, reviewable baseline before any production
identity, network, key, deployment, pilot, or release work begins.

### Code and repository work

- Preserve the reviewed and integrated Phase 13-14 baseline.
- Reconcile Android/native ABI versions, schemas, evidence manifests, feature
  coverage, generated artifacts, and documentation.
- Remove stale evidence, contradictory claims, unsupported controls, accidental
  files, and unrelated churn.
- Freeze the declared v1 product scope, supported Android/API/ABI matrix,
  service boundaries, data inventory, SLOs, RTO/RPO, production threat model,
  and capabilities-and-limits statement.

### External decisions

- Maintainer approval of the complete diff and v1 scope.
- Scoped authorization for production identity, key custody, networking,
  deployment, controlled pilot, signing, and distribution.

### Exit gate

- Clean `main` contains the reviewed Phase 13-14 commit and green CI evidence.
- All evidence is bound to the merged commit.
- Phase 14 records local completion with `releaseDecision=NO_GO`.
- No production phase starts from an uncommitted or ambiguous baseline.

## Phase 16: production trust, identity, key custody, and control plane

### Required implementation

- Authenticated, versioned production operator APIs with least privilege,
  phishing-resistant identity, just-in-time elevation, dual control, and bounded
  break-glass recovery.
- Non-exportable HSM/KMS key-provider adapters, offline root and recovery roles,
  bounded online intermediates, rotation, revocation, recovery, destruction, and
  compromise procedures.
- Trusted-time and monotonic anti-rollback integration.
- External transactional database, durable outbox workers, idempotency,
  immutable audit anchoring, backup, restore, and disaster-recovery tooling.
- Production profile issuance, publication, expiry, rotation, revocation,
  subscription, and root-bound emergency-deny services.
- Reproducible infrastructure definitions and safe deployment automation.

### Required external evidence

- Owned identity, HSM/KMS, database, secret management, domain, certificate,
  backup, and audit-anchor services.
- Role-separated production key ceremonies.
- Named data-residency, retention, legal, incident, and on-call ownership.

### Exit gate

- A production profile can be issued, published, verified, rotated, revoked,
  and emergency-denied end to end.
- Database loss and restore preserve monotonic authority.
- Root/intermediate recovery, compromise, trusted-time rollback, and audit
  continuity drills pass.
- No unresolved critical or high trust/control-plane defect remains.

## Phase 17: owned provider, relay fleet, and live Kurd data plane

### Required implementation

- Replace loopback-only relay restrictions with an explicitly authorized,
  hardened non-loopback Kurd relay service.
- Authenticated relay enrollment and immutable desired-state reconciliation.
- IPv4 and IPv6 ingress, tunnel endpoints, egress, and fail-closed in-tunnel DNS.
- Live profile-authorized carrier and fallback execution.
- Relay drain, promotion, quarantine, revocation, rotation, load shedding,
  graceful restart, resource limits, and emergency disable.
- Privacy-bounded health, capacity, SLO, alerting, backup, restore, and rollback.
- Multi-region reproducible deployments and signed provider compatibility data.
- Abuse controls that do not create an open proxy or a payload/destination log.

### Exit gate

- A real client reaches an owned test destination through the exact Kurd path.
- No direct bypass or DNS escape occurs.
- Relay failure, fallback, rotation, revocation, drain, emergency deny, region
  loss, rollback, and restore succeed.
- Declared IPv4/IPv6, load, soak, resource, and SLO matrices pass.

## Phase 18: production Android integration and complete accepted product surface

This phase completes the declared v1 app. It owns every applicable outcome in
the inspiration inventory and D0-D28 feature contract.

### Required implementation

- Replace reserved loopback transport with the production-authorized Kurd path.
- Add only the Android network permissions genuinely required by the runtime.
- Live signed provider/profile updates with rollback protection.
- Real relay, path, strategy, speed, duration, health, fallback, failure, exit,
  expiry, quota, rotation, and revocation state.
- Production DNS, dual-stack, per-app routing, always-on/lockdown interaction,
  reconnect, handover, safe mode, and recovery.
- Authenticated local SOCKS5/HTTP and narrowly governed hotspot proxy only when
  they route exclusively through Kurd authority and pass abuse-control gates.
- Complete Home, Profiles/Providers, Settings, routing, DNS, probing,
  diagnostics, backup/restore, privacy dashboard, app lock, onboarding,
  permission/OEM guidance, troubleshooting, support, About, legal, release-note,
  automation, localization, accessibility, tablet, and foldable experiences.
- Every accepted expert option must be consumed by the runtime. Unsupported,
  unsafe, irrelevant, copied, or deceptive options receive a final documented
  replacement or rejection.
- Remove placeholders, inert controls, test authority, loopback terminology,
  debug fixtures, and unfinished flows from release variants.

### Product and design quality gate

- The UI is original, fluent, responsive, accessible, visually coherent, and
  measured for startup, interaction latency, jank, memory, battery, thermal,
  process death, and repeated navigation/connect cycles.
- Every screen, button, control, permission state, error, empty state, disabled
  reason, recovery path, and destructive action has automated and emulator
  evidence.
- Human linguistic, accessibility, privacy, and UX review closes all blocking
  findings.

### Exit gate

- A release build imports a production-candidate signed profile and routes real
  device traffic through an owned relay.
- The v1 feature map contains only `delivered-production`,
  `safely-replaced-final`, `rejected-final`, or `inapplicable-final`.
- No accepted feature remains partial, deferred, inert, placeholder, or TODO.

## Phase 19: secure release engineering and operational platform

### Required implementation

- Protected CI/CD with hermetic builds, dependency verification, SBOMs,
  licenses, provenance, signing requests, artifact promotion, and cross-host
  reproducibility analysis.
- Production versioning, migration, upgrade, downgrade rejection, rollback, and
  key-rotation tests.
- Signed AAB/APK pipeline with no production signing secret in Git, logs, or
  general developer machines.
- Privacy-bounded release dashboards, SLO alerts, rollback automation, backup,
  disaster recovery, incident tooling, and support operations.
- Accurate store listing, VpnService declaration, disclosures, affirmative
  consent, privacy policy, data inventory, terms, licenses, release notes,
  support material, and review demonstration scripts.

### Required external evidence

- Play Console and signing ownership.
- Protected upload/signing custody.
- Public privacy, terms, support, contact, and vulnerability-reporting routes.
- Staffed incident, privacy, communications, release, and support roles.

### Exit gate

- The protected pipeline produces signed, provenance-bound installable APK and
  AAB artifacts.
- The closed distribution track accepts the exact artifact.
- Monitoring, support, rollback, incident, backup, and disaster recovery are
  operational and exercised.
- An unsigned or manually substituted artifact cannot be promoted.

## Phase 20: independent assurance, remediation, and release-candidate freeze

### Required work

- Independent assessment of the exact Android app, Go engine, profile
  cryptography, control plane, relays, infrastructure, signing pipeline,
  privacy, accessibility, supply chain, operations, recovery, and incident
  procedures.
- Remediate every confirmed finding and add a regression test or gate.
- Regenerate all evidence after every change.
- Freeze the exact source commit, infrastructure revision, schemas, operator,
  relay, provider, signed artifact, SBOM, provenance, and rollback artifact.

### Exit gate

- No open critical or high finding remains.
- Every medium finding is fixed or accepted by a named accountable owner with
  scope, rationale, compensating controls, and expiry.
- No unresolved implementation finding remains.
- Any source or infrastructure change restarts the affected review and signing
  cycle.

## Phase 21: controlled field validation and closed production pilot

No new feature work is allowed. A defect fix returns the candidate through the
affected Phase 20 review and the relevant Phase 21 matrix.

### Required evidence

- Physical devices across every supported Android/API/ABI class, representative
  OEMs, low-end and flagship devices, tablets, foldables, shipped locales,
  200% text, TalkBack, Switch Access, keyboard, and D-pad.
- Wi-Fi, cellular, IPv4, IPv6, NAT64, captive portal, handover, roaming, sleep,
  Doze, battery saver, data saver, low memory, low storage, process death, and
  key invalidation.
- Multi-hour and multi-day app, relay, operator, CPU, memory, battery, thermal,
  descriptor, thread, connection, capacity, and recovery soak campaigns.
- Owned multi-region relay/provider failure, rotation, revocation, emergency
  deny, backup, restore, rollback, region loss, and disaster recovery.
- Narrow, authorized constrained-network observations with consent,
  minimization, stop conditions, and no unsupported generalization.
- Closed-cohort support, incident, rollback, and recovery drills.

### Exit gate

- The declared device, network, relay, provider, recovery, and operations matrix
  passes against the exact signed candidate.
- No traffic bypass, DNS escape, authority widening, rollback acceptance,
  secret leak, crash loop, unsupported claim, or unresolved critical/high defect
  remains.
- Reliability, connection success, recovery, latency, capacity, battery,
  privacy, accessibility, and support SLOs pass.

## Phase 22: public staged release and steady-state operational handover

This is the final roadmap phase. No implementation work is allowed at entry. A
source-code change invalidates the candidate and returns it through Phases 20
and 21.

### Required release work

- Submit the exact signed AAB and complete store and VpnService review.
- Roll out through internal, closed, small-percentage, regional, and progressive
  production stages with objective pause, abort, rollback, and emergency-disable
  thresholds.
- Operate production monitoring, support, incident response, profile/provider
  rotation, relay drain, backup, restore, rollback, and recovery throughout the
  stabilization window.
- Publish truthful capabilities, limitations, privacy, support, and incident
  communication routes.

### Final completion gate

- Every mandatory local, production, independent-review, physical-device,
  field, signing, store, distribution, operations, recovery, and rollback item
  is `PASS` against the exact release.
- The release owner records `GO` for the digest-pinned commit, infrastructure,
  profile authority, signed artifact, store metadata, and rollback artifact.
- Public users can complete the real end-to-end outcome:
  `import signed kurd:// profile -> connect -> authenticated Kurd path -> owned relay -> safe traffic routing -> fallback/recovery`.
- The supported public service is operational on owned infrastructure and meets
  the declared stable observation window.
- No required v1 feature, TODO, placeholder, inert control, unresolved release
  blocker, pending remediation, or unfinished implementation item remains.
- Operations ownership, vulnerability response, maintenance calendar, key and
  profile rotation, release cadence, support, and incident escalation are active.

At Phase 22 exit, normal maintenance and future optional enhancements may begin
on a separate post-launch roadmap. They are not unfinished v1 work.

## Final product capability contract

The declared v1 product preserves every useful and applicable capability from
the Android inspiration inventory, but it does not copy another product's
branding, layout, iconography, language, colors, or identity.

Permanently reject:

- certificate bypass, allow-insecure TLS, unsafe fingerprints, or user controls
  that lower a mandatory security floor;
- stable HWID transmission;
- unauthenticated or hidden public proxy behavior;
- payload, destination, DNS-question, credential, key, or raw-frame logging;
- silent external automation or arbitrary traffic sniffing;
- guaranteed claims of unblocking, undetectability, anonymity, or impossibility
  of blocking.

Replace safely:

- arbitrary protocol authority with signed Kurd profiles and explicitly
  quarantined non-executable imports;
- raw URL/JSON secret sharing with authenticated reveal, encrypted export,
  signed QR, preview, and expiry;
- direct DNS escape with authenticated in-tunnel DNS;
- stable identifiers with purpose-bound, rotating, revocable support or provider
  credentials;
- user-defined transport widening with operator-signed bounded strategy policy;
- unbounded debug retention with encrypted, redacted, bounded retention.

## Definition of complete

“Nothing left to code” means zero known release-blocking defect and zero
unfinished declared-v1 implementation. It does not mean software can never need
maintenance or that future optional features cannot exist.

The roadmap is complete only when:

- no accepted v1 feature, TODO, placeholder, inert control, deferred required
  capability, or known critical/high defect remains;
- production code and infrastructure are merged, deployed, signed, supported,
  monitored, recoverable, and evidence-bound;
- all mandatory independent, device, field, store, operational, privacy,
  accessibility, recovery, and rollback gates pass;
- the objective release decision is `GO` for the exact public artifact;
- the public service has completed its staged stabilization window.

The standing safety boundary is defined in `docs/safety.md`; validation and
review rules are defined in `docs/GOVERNANCE.md`.

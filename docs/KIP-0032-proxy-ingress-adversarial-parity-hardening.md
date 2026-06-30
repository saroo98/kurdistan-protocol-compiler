<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0032: Proxy Ingress Adversarial Parity Hardening

## Status

Implemented in Milestone 26.

## Purpose

Milestone 24 defined the concrete local proxy ingress contract. Milestone 25
implemented a deterministic in-memory local proxy ingress prototype. Milestone
26 hardens that prototype before local egress and relay bridge modeling begins.

The goal is to prove the local ingress model rejects malformed request event
sequences, unsafe descriptor shapes, lifecycle abuse, queue pressure failures,
reset/error leakage, mapping collapse, and generated-backend drift.

## Boundary

This KIP covers deterministic local ingress hardening only. It does not add
local proxy egress, target dialing, sockets, OS proxy configuration, DNS, TLS,
VPN, WebSocket, CDN behavior, deployment, or external network behavior.

Fixtures and reports store safe classes, counters, buckets, hashes, and
conclusions only.

## Adversarial Corpus

`internal/localproxyingressadversary` defines the adversarial corpus. Scenario
classes include malformed event ordering, missing or duplicate open events,
duplicate event IDs, data before open, data after close, reset-before-open,
target-error lifecycle abuse, queue overflow, descriptor abuse, fixed mapping
controls, cross-request leak controls, and generated-backend drift controls.

Every scenario defines expected accept/reject counts, lifecycle class, mapping
class, failure bucket, trace-hygiene expectation, and readiness impact.

## Descriptor Abuse Hardening

Descriptor abuse cases model endpoint-like, DNS-like, host-header-like,
cloud-metadata-like, credential-like, payload-like, oversized, Unicode, control
character, and path-like input classes. The validator rejects those classes with
redacted error text and keeps accepted descriptors synthetic and bounded.

## Lifecycle Hardening

Lifecycle stress checks reject invalid transitions such as direct close from
created, accepting after terminal state, reset then data, close then data,
target error before descriptor, duplicate reset, and terminal reopen attempts.

The lifecycle gate fails if any invalid transition is accepted.

## Queue And Pressure Hardening

Pressure checks exercise exact-limit queue usage, queue overflow, per-request
event overflow, many small requests, large request classes, reset under
pressure, target error under pressure, and collapsed unbounded controls.

The pressure gate requires bounded queues, safe rejection of overflow, mapped
backpressure, and no payload or secret logging.

## Reset/Error Isolation

Reset/error checks verify that reset and target-error events affect only the
intended synthetic request. Control scenarios intentionally leak reset or
descriptor details and must be detected.

## Mapping Collapse

The mapping collapse scanner detects fixed target binding, fixed stream mapping,
fixed lifecycle pattern, fixed error/reset buckets, ignored backpressure,
invalid targets mapped as valid, padding-only variation, and generated backend
mapping drift. Healthy fixture sets pass while collapsed controls fail.

## Generated/Interpreted Parity

Generated modules now emit `localproxyingressadv` constants and tests. The
parity report compares adversarial classification, accept/reject counts,
lifecycle/pressure/reset/error buckets, collapse conclusions, readiness, and
trace-hygiene flags across interpreted and generated paths.

## Readiness Report

The M27 readiness report checks:

- contract compliance
- descriptor abuse resistance
- lifecycle integrity
- queue pressure safety
- backpressure mapping
- reset/error isolation
- mapping diversity
- generated/interpreted parity
- trace hygiene
- fixture stability

The passing decision is `go_for_local_proxy_egress_model`.

## Mutants

M26 adds mutant identifiers for descriptor abuse acceptance, data-before-open,
data-after-close, terminal reopen, unbounded queue growth, ignored
backpressure, reset/error cross-request leakage, descriptor leakage, fixed
mapping, missed collapse, bad readiness decisions, payload/secret leaks, and
generated backend drift.

## Audit Gates

The default audit and `kcheck localproxyingressadv` include:

- `localproxyingressadv_corpus_validation`
- `localproxyingressadv_descriptor_abuse`
- `localproxyingressadv_lifecycle_hardening`
- `localproxyingressadv_pressure_hardening`
- `localproxyingressadv_reset_error_isolation`
- `localproxyingressadv_mapping_collapse`
- `localproxyingressadv_generated_backend_parity`
- `localproxyingressadv_m27_readiness`
- `localproxyingressadv_trace_hygiene`
- `localproxyingressadv_mutant_detection`
- `localproxyingressadv_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck localproxyingressadv --quick
go run ./cmd/kcheck localproxyingressadv --full --out testdata/audit/localproxyingressadv.json
go run ./cmd/kcheck localproxyingressadv generate --out testdata/localproxyingressadversary/adversarial-corpus-golden.json --force
go run ./cmd/kcheck localproxyingressadv verify
go run ./cmd/kcheck localproxyingressadv compare --old testdata/localproxyingressadversary/adversarial-corpus-golden.json --new testdata/localproxyingressadversary/adversarial-corpus-golden.json
go run ./cmd/kcheck --quick --status STATUS.md
```

## Fixtures

Committed fixtures live under `testdata/localproxyingressadversary/`.

They include the adversarial corpus, descriptor abuse report, lifecycle report,
pressure report, reset/error isolation report, mapping collapse report, parity
report, and M27 readiness report.

## Limitations

The milestone hardens deterministic local ingress behavior only. It does not
prove behavior for concrete proxy clients, operating system proxy APIs, target
networks, or deployed relay paths. M27 moves into adaptive path modeling so
future runtime work can reason about volatile candidate-path viability before
local egress and relay bridge modeling.

## Next Milestone

M27: adaptive path model and candidate taxonomy.

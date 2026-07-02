<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0050: DNS-Survival / Constrained-Carrier Design Lock

Milestone 44 converts the broad carrier readiness evidence into a narrow implementation contract for the next carrier family: constrained request/response carriers with DNS-survival-style shape constraints. This is a review and contract milestone. It does not implement DNS, resolver access, network probing, or a concrete carrier.

## Purpose

The M45 prototype needs a fixed contract before implementation starts. M44 freezes the safe vocabulary for constrained carriers:

- local deterministic resolver harness contract
- query-shape buckets
- response-shape buckets
- size, truncation, and retry classes
- poisoning/failure classes
- stream-to-shape mapping
- pathhealth and measurementreview binding
- trace-hygiene rules
- fixture schema and generated-backend parity requirements

The review keeps the work bounded to deterministic local fixtures so future implementation can be audited without ambiguity.

## Scope

Allowed behavior:

- symbolic DNS-survival / constrained request-response shape classes
- deterministic local resolver harness fixtures
- bucketed query and response metadata
- bounded truncation and retry summaries
- local failure and poisoning buckets
- stream mapping, reset/error mapping, and backpressure mapping contracts
- generated/interpreted parity checks

Blocked behavior:

- public resolver use
- real DNS queries by default
- resolver address logging
- exact query logging
- domain dependence
- wildcard resolver configuration
- public-network egress
- arbitrary target proxying
- payload logging
- packet capture
- measurement upload

## Resolver Harness Contract

The M45 harness must stay local and deterministic. It may model resolver classes as safe buckets such as `loopback_harness`, `fixture_resolver`, `failure_fixture`, and `poison_fixture`. It must not persist resolver addresses, exact query strings, account identifiers, device identifiers, or location data.

## Shape Taxonomy

Query-shape classes include small, chunked, repeated, delayed, truncated, retry, failure, and control-leak classes. Response-shape classes include small, truncated, delayed, failure, retry, poisoning-failure, reset, and control-leak classes.

The control classes are not implementation behavior. They are misuse controls that must fail if an implementation stores or exposes unsafe data.

## Size, Truncation, Retry, And Failure

The contract requires:

- bucketed size classes, not raw byte dumps
- bounded constrained-capacity classes
- explicit truncation buckets
- bounded retry-after-truncation classes
- timeout, reset, and poisoning/failure buckets
- pathhealth propagation
- measurementreview diagnostics using only safe fields

## M45 Acceptance Contract

M45 must provide:

- `internal/constrainedcarrier` or equivalent package
- deterministic local resolver/request-response harness
- `kcheck constrainedcarrier --quick|--full|verify|compare`
- generated backend constants and tests
- fixture drift detection
- trace hygiene checks
- mutant detection for public resolver, exact-query, resolver-address, domain-dependence, backpressure, retry, and generated-drift failures

## Commands

```bash
go run ./cmd/kcheck constrainedcarrierreview --quick
go run ./cmd/kcheck constrainedcarrierreview --full --out testdata/audit/constrainedcarrierreview.json
go run ./cmd/kcheck constrainedcarrierreview generate --out testdata/constrainedcarrierreview/constrainedcarrierreview-report-golden.json --force
go run ./cmd/kcheck constrainedcarrierreview verify
go run ./cmd/kcheck constrainedcarrierreview compare --old testdata/constrainedcarrierreview/constrainedcarrierreview-report-golden.json --new testdata/constrainedcarrierreview/constrainedcarrierreview-report-golden.json
```

`testdata/audit/constrainedcarrierreview.json` is an ignored audit artifact.

## Audit Gates

M44 adds gates for:

- `constrainedcarrierreview_scope_contract`
- `constrainedcarrierreview_resolver_harness_contract`
- `constrainedcarrierreview_query_shape_taxonomy`
- `constrainedcarrierreview_response_shape_taxonomy`
- `constrainedcarrierreview_size_truncation_contract`
- `constrainedcarrierreview_retry_failure_contract`
- `constrainedcarrierreview_stream_mapping`
- `constrainedcarrierreview_privacy_measurement`
- `constrainedcarrierreview_m45_contract`
- `constrainedcarrierreview_blocker_matrix`
- `constrainedcarrierreview_risk_model`
- `constrainedcarrierreview_checklist`
- `constrainedcarrierreview_misuse_detection`
- `constrainedcarrierreview_generated_backend_parity`
- `constrainedcarrierreview_trace_hygiene`
- `constrainedcarrierreview_public_claim_safety`
- `constrainedcarrierreview_mutant_detection`
- `constrainedcarrierreview_fixture_drift`

## Generated Backend Parity

Generated modules include:

```text
protocol/constrainedcarrierreview_generated.go
protocol/constrainedcarrierreview_test.go
protocol/constrainedcarrierreview_parity_test.go
protocol/constrainedcarrierreview_hygiene_test.go
```

Generated constants specialize the schema version, profile ID, profile seed, backend version, runtime policy, resolver buckets, query-shape classes, response-shape classes, M45 requirements, blocked behaviors, and misuse controls.

## Limitations

M44 is a design lock. It does not implement a DNS carrier, query real resolvers, depend on domains, perform public-network egress, or prove field behavior. It only defines the contract that M45 must satisfy in deterministic local conditions.

## Next Milestone

M45 should implement the constrained-carrier lab prototype against this contract.

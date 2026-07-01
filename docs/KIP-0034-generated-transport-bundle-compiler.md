<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0034: Generated Transport Bundle Compiler

## Purpose

Milestone 28 adds a deterministic transport bundle compiler. A bundle groups
multiple generated profile references, wire-shape policy references,
carrier-family candidates, synthetic relay metadata, eligibility roles, and
fallback hints into one auditable artifact.

The bundle compiler is the layer between adaptive path taxonomy and deterministic
path-racing work. It does not select a live winner. It produces candidate plans
for local scoring, revalidation, and later failover modeling.

## Why Bundles Are Needed

Adaptive path modeling can describe candidate families, freshness, uncertainty,
and viability, but a runtime also needs a concrete set of generated transport
options. A bundle freezes that set deterministically so audits can check:

- required carrier-family coverage
- profile seed diversity
- wire policy diversity
- primary, fallback, survival, experimental, high-risk, and control roles
- fallback hints without final winner selection
- synthetic relay and host binding metadata
- collapsed-bundle controls
- generated/interpreted parity
- payload-free and endpoint-free fixture hygiene

## Bundle Modes

The compiler supports these deterministic modes:

- `balanced_adaptive`
- `conservative_tcp`
- `survival_dns`
- `experimental_mix`
- `high_risk_review`
- `control_collapsed`

`control_collapsed` is a negative-control mode for tests and audits. Healthy
bundle modes must not collapse candidates to one family, one profile seed, or
one wire policy.

## Candidate Roles

Bundle candidates are assigned safe metadata roles:

- `primary_eligible`
- `fallback`
- `survival`
- `experimental`
- `high_risk_gated`
- `control`
- `rejected`

High-risk and experimental candidates remain gated. Burned or quarantined
synthetic relays cannot become primary-eligible candidates.

## Adaptive Path Mapping

Each bundle candidate can map to an adaptive-path candidate summary. The mapping
preserves candidate family, relay risk, metadata risk, freshness TTL class,
eligibility state, and decision inputs while avoiding real endpoints or live
network measurements.

## Relay Binding Metadata

Relay and host metadata are synthetic identifiers and risk buckets only. The
compiler never stores or emits real hosts, IP addresses, DNS queries, resolver
data, SNI, URLs, packet bytes, payloads, keys, nonces, auth tags, proof
material, or cloud metadata.

## Fallback Hints

Fallback hints describe ordered local decisions for later path-racing work.
They are hints, not an active selector. The bundle manifest explicitly records
that no final winner has been selected.

## Fixtures

The committed fixture set under `testdata/transportbundle/` includes safe JSON
summaries:

- `bundle-manifest-golden.json`
- `bundle-policy-golden.json`
- `bundle-seedplan-golden.json`
- `bundle-candidates-golden.json`
- `bundle-adaptivepath-mapping.json`
- `bundle-relay-binding-report.json`
- `bundle-fallback-hints.json`
- `bundle-collapse-report.json`
- `bundle-controls.json`

These fixtures are deterministic baselines for drift detection and review.

## Audit Gates

Milestone 28 adds these gates:

- `transportbundle_policy_validation`
- `transportbundle_seed_planning`
- `transportbundle_family_coverage`
- `transportbundle_adaptivepath_mapping`
- `transportbundle_relay_binding`
- `transportbundle_fallback_hints`
- `transportbundle_collapse_detection`
- `transportbundle_generated_backend_parity`
- `transportbundle_trace_hygiene`
- `transportbundle_mutant_detection`
- `transportbundle_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck transportbundle --quick
go run ./cmd/kcheck transportbundle --full --out testdata/audit/transportbundle.json
go run ./cmd/kcheck transportbundle generate --out testdata/transportbundle/bundle-manifest-golden.json --force
go run ./cmd/kcheck transportbundle verify
go run ./cmd/kcheck transportbundle compare --old testdata/transportbundle/bundle-manifest-golden.json --new testdata/transportbundle/bundle-manifest-golden.json
go run ./cmd/kdc bundle --seed 12345 --mode balanced_adaptive --out profiles/examples/bundle-12345.json
go run ./cmd/kdc validate-bundle --bundle profiles/examples/bundle-12345.json
go run ./cmd/kdc summarize-bundle --bundle profiles/examples/bundle-12345.json
```

## Generated Backend Parity

`kgen` emits transport-bundle generated constants and tests:

- `protocol/transportbundle_generated.go`
- `protocol/transportbundle_test.go`
- `protocol/transportbundle_parity_test.go`
- `protocol/transportbundle_hygiene_test.go`

The generated module validates fixture generation, self-parity, and hygiene
using the same deterministic metadata model.

## Limitations

The bundle compiler is not active probing, a health monitor, a
measurement client, or a real network selector. It does not open sockets,
perform DNS lookups, test TCP/UDP/QUIC/HTTPS paths, dial relays, manage real
hosts, or deploy infrastructure. It freezes safe candidate metadata for local
audit and deterministic scoring work.

## Next Milestone

Milestone 29 adds path racing and short-lived revalidation/scoring over
transport bundle candidates, still using synthetic observations and
deterministic local fixtures. Milestone 30 should focus on continuous health
monitoring and failover over already-selected synthetic paths.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0029: Relay Churn And Fleet Lifecycle

## Purpose

Milestone 23 adds deterministic relay-fleet lifecycle modeling above the host-based detection layer. Earlier milestones ask whether profile traces, byte paths, wire features, and synthetic host observations collapse into stable signatures. This milestone asks whether a fleet of synthetic relays can rotate profiles, churn safely, migrate sessions, and quarantine high-risk relays without creating a new stable fleet-level fingerprint.

The model is local, synthetic, and payload-free. It does not provision infrastructure, contact hosts, deploy services, model real cloud providers, or store endpoint data.

## Relationship To Host Detection

`internal/hostdetect` produces safe host-level observation summaries. `internal/relayfleet` consumes those summaries together with wire-evaluation records and builds a synthetic relay fleet:

```text
wire evaluation records
        |
        v
host-detection observations
        |
        v
synthetic relay fleet
        |
        v
lifecycle, churn, migration, risk, collapse reports
```

The relay layer uses synthetic relay IDs and synthetic host IDs only. It treats host risk as a safe input bucket, not as a real network measurement.

## Synthetic Relay Model

A relay entry records:

- synthetic relay ID
- relay class bucket
- synthetic host ID
- profile ID and seed
- wire-policy hash
- selected wire family
- lifecycle state
- risk bucket
- churn generation
- migration generation
- safe payload and secret hygiene flags

The model intentionally stores hashes, buckets, and aggregate counts instead of raw traffic, endpoints, packet captures, payloads, or secrets.

## Lifecycle States

Supported lifecycle states are:

- `provisioned`
- `active`
- `cooling`
- `rotating`
- `migrating`
- `quarantined`
- `retired`
- `burned`

Valid paths allow activation, cooling, rotation, migration, quarantine, retirement, and burn handling. Terminal states reject unsafe transitions except idempotent handling where explicitly allowed.

## Profile Assignment

Profile assignment checks enforce:

- maximum profile reuse
- maximum wire-policy reuse
- minimum unique profiles
- minimum unique wire policies
- no active relay with payload or secret leakage flags
- deterministic assignment reports

Synthetic controls intentionally reuse profiles or wire policies to prove collapse detection fails the right cases.

## Churn Schedule

The churn scheduler produces deterministic events such as:

- activate
- cool down
- rotate
- quarantine
- retire
- burn

Churn cadence is bounded by policy. The scheduler rejects empty fleets, unsafe churn limits, and schedules that exceed the synthetic policy envelope.

## Migration Model

Migration events model safe movement between synthetic relays:

- source relay
- target relay
- profile ID
- synthetic reason bucket
- migration result
- payload and secret hygiene flags

The validator rejects migration to retired or burned relays, self-migration, unknown relays, and leak-flagged events.

## Burn Risk

Burn-risk scoring aggregates safe evidence:

- high host-detection risk
- excessive profile reuse
- excessive wire-policy reuse
- collapsed-family evidence
- active relay hygiene failures

Risk is reported as buckets and counts. It is not a prediction about real infrastructure.

## Collapse Scanner

The collapse scanner flags suspicious fleet stability:

- too few unique profiles
- too few unique wire policies
- one selected wire family dominating the fleet
- active relays with high risk
- high-risk host-detection evidence
- payload or secret hygiene failures

The scanner also checks synthetic controls so padding-only or fixed-policy fleets are not mistaken for useful diversity.

## Controls And Mutants

Milestone 23 adds fleet-level mutant modes for:

- profile reuse collapse
- wire-policy reuse collapse
- no churn
- excessive churn
- ignored host risk
- burned relay kept active
- migration to retired relay
- ignored profile reuse limits
- ignored policy reuse limits
- collapsed control not detected
- endpoint, payload, or secret leak markers
- generated backend drift
- unstable schedule

The audit checks that these modes are represented and that fixed synthetic fleets fail collapse gates.

## Fixtures

Committed fixtures live in:

```text
testdata/relayfleet/
```

Key files:

- `relayfleet-golden.json`
- `relay-lifecycle-golden.json`
- `relay-churn-events.json`
- `relay-migration-events.json`
- `relay-burn-risk-report.json`
- `relay-collapse-report.json`
- `relay-controls.json`

Fixtures contain synthetic IDs, states, hashes, buckets, event summaries, and expected conclusions only.

## Audit Gates

Milestone 23 adds these gates:

- `relayfleet_lifecycle_integrity`
- `relayfleet_profile_assignment`
- `relayfleet_churn_schedule`
- `relayfleet_migration_model`
- `relayfleet_burn_risk`
- `relayfleet_collapse_detection`
- `relayfleet_control_detection`
- `relayfleet_generated_backend_parity`
- `relayfleet_trace_hygiene`
- `relayfleet_mutant_detection`
- `relayfleet_fixture_drift`

The default quick audit includes relay-fleet gates.

## Commands

Run the relay-fleet audit:

```bash
go run ./cmd/kcheck relayfleet --quick
go run ./cmd/kcheck relayfleet --full --out testdata/audit/relayfleet.json
```

Regenerate and verify fixtures:

```bash
go run ./cmd/kcheck relayfleet generate --out testdata/relayfleet/relayfleet-golden.json --force
go run ./cmd/kcheck relayfleet verify
go run ./cmd/kcheck relayfleet compare --old testdata/relayfleet/relayfleet-golden.json --new testdata/relayfleet/relayfleet-golden.json
```

## Generated Backend Parity

Generated modules include relay-fleet constants and tests:

```text
protocol/relayfleet_generated.go
protocol/relayfleet_test.go
protocol/relayfleet_parity_test.go
protocol/relayfleet_hygiene_test.go
```

Generated code specializes the relay-fleet schema version, profile seed anchor, assignment mode, churn mode, migration mode, selected wire family, wire-policy hash, and policy reuse limits.

## Limitations

This milestone does not implement host rotation, service orchestration, deployment automation, cloud-provider integration, endpoint discovery, external networking, production proxy ingress, or live measurement. It is a deterministic regression model for fleet-level behavior and collapse detection.

## Next Milestone

Milestone 24 should focus on concrete local proxy ingress design review: defining what a future local ingress prototype must prove before any real adapter implementation is considered.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0028: Host-Based Detection Resistance

## Purpose

Milestone 22 adds deterministic host-based detection modeling on top of the wire evaluation dataset. Earlier gates ask whether individual profiles and byte-path traces are diverse. This milestone asks a different question: if many observations are associated with the same synthetic host identity, does the generated family become easy to group by repeated behavior?

The model is still local and synthetic. It uses safe fixture metadata from generated profiles and byte-path scenarios. It does not use packet captures, live endpoints, raw payloads, raw bytes, destination addresses, or trained production classifiers.

## Model

`internal/hostdetect` builds a versioned `HostObservationSet` from `internal/wireeval` records. Each observation contains:

- synthetic host ID
- host class
- logical timestamp
- profile ID and seed
- scenario name
- selected abstract wire family
- feature hash
- first-N shape hash
- byte-shape hash
- metadata exposure bucket
- fragment rhythm bucket
- control-richness bucket
- train/test/OOD/holdout split
- payload and secret hygiene flags

The package then aggregates observations by synthetic host and computes detection and resistance reports.

## Assignment Modes

The model supports deterministic assignment modes:

- `single_long_lived_host`
- `many_hosts_uniform`
- `profile_pinned_hosts`
- `family_pinned_hosts`
- `scenario_pinned_hosts`
- `rotating_profile_hosts`
- `mixed_rotation_hosts`
- `control_collapsed_hosts`

Quick audits use representative modes. Full audits exercise the complete set.

## Timeline Windows

Observations are assigned deterministic logical times and evaluated across timeline windows:

- `short`
- `medium`
- `long`
- `burst`
- `steady`
- `mixed`

These windows make repeated-flow stability visible without relying on wall-clock sleeps or external traffic.

## Confidence Model

The confidence model is intentionally simple and deterministic. It scores each synthetic host using:

- observation count
- feature-hash consistency
- first-N shape consistency
- byte-shape consistency
- host-class risk
- entropy estimate
- collapsed-control evidence
- padding-only-control evidence

The output is a `HostDetectionReport` with flagged hosts, control detections, estimated false-positive and false-negative values, and safe evidence buckets.

## Resistance Metrics

`HostResistanceReport` summarizes whether generated observations remain varied at a host level:

- average observations per host
- average unique feature hashes
- average unique first-N shapes
- average consistency score
- rotation score
- high-risk generated hosts
- collapsed-control detection
- padding-only detection

The goal is not to prove resistance. The goal is to catch regressions where repeated observations collapse into stable host-level signatures.

## Synthetic Controls

Host-detection controls intentionally create suspicious families:

- collapsed fixed controls
- padding-only controls
- noise controls
- corpus baselines

The audit must detect fixed and padding-only controls. Random/noise controls are treated separately from useful polymorphism.

## Fixtures

Committed fixtures live in:

```text
testdata/hostdetect/
```

Key files:

- `host-observations-golden.json`
- `host-aggregates-golden.json`
- `host-detection-report.json`
- `host-resistance-report.json`
- `host-controls.json`
- `host-splits.json`

Fixtures contain synthetic IDs, buckets, hashes, counts, and report metadata only.

## Audit Gates

Milestone 22 adds these gates:

- `hostdetect_observation_build`
- `hostdetect_assignment_integrity`
- `hostdetect_timeline_integrity`
- `hostdetect_confidence_model`
- `hostdetect_resistance_metrics`
- `hostdetect_collapse_detection`
- `hostdetect_control_detection`
- `hostdetect_generated_backend_parity`
- `hostdetect_trace_hygiene`
- `hostdetect_mutant_detection`
- `hostdetect_fixture_drift`

The default quick audit includes the host-detection gates.

## Commands

Run the host-detection audit:

```bash
go run ./cmd/kcheck hostdetect --quick
go run ./cmd/kcheck hostdetect --full --out testdata/audit/hostdetect.json
```

Regenerate and verify fixtures:

```bash
go run ./cmd/kcheck hostdetect generate --out testdata/hostdetect/host-observations-golden.json --force
go run ./cmd/kcheck hostdetect verify
go run ./cmd/kcheck hostdetect compare --old testdata/hostdetect/host-observations-golden.json --new testdata/hostdetect/host-observations-golden.json
```

## Generated Backend Parity

Generated modules include:

```text
protocol/hostdetect_generated.go
protocol/hostdetect_test.go
protocol/hostdetect_parity_test.go
protocol/hostdetect_hygiene_test.go
```

Generated code specializes host-detect schema version, assignment mode, timeline window, host count, and generated profile ID.

## Limitations

This milestone does not train a detector, perform live traffic measurement, model real DNS or endpoint behavior, or evaluate against production DPI systems. It only creates deterministic local fixtures and gates that make host-level collapse visible inside the project.

## Next Milestone

KIP-0029 builds on this host-level model with synthetic relay churn and fleet lifecycle checks. The next design step after KIP-0029 is concrete local proxy ingress review.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0038: Safe Measurement-Client Design

Milestone 32 adds a safe measurement-client design review model. It defines what a future local diagnostic layer may summarize and what it must reject before any measurement-client architecture moves beyond design.

The model is local, synthetic, and payload-free. It does not upload telemetry, collect field data, run background measurement, contact resolvers, probe destinations, or record device, account, location, packet, payload, or secret material.

## Observation Taxonomy

`internal/measurementreview` defines bucketed observation classes such as:

- path availability bucket
- handshake outcome bucket
- first-useful-byte bucket
- stall pattern bucket
- reset-like and blackhole-like failure buckets
- poisoning-like, truncation-like, and rate-limit-like buckets
- relay burn-like bucket
- carrier family and bundle candidate buckets
- score, health-state, and failover outcome buckets
- coarse platform, network, and time buckets

## Privacy Model

The review model defines consent modes, retention classes, redaction classes, local diagnostic reports, and misuse controls. Direct identifiers and sensitive material are rejected by the scanner and must not appear in fixtures, reports, traces, generated outputs, or audit summaries.

## Audit Gates

`kcheck measurementreview --quick` and the default quick audit include gates for:

- observation schema
- redaction policy
- consent and retention
- local diagnostics
- privacy readiness
- misuse detection
- generated backend parity
- trace hygiene
- mutant detection
- fixture drift

## Fixtures

Committed fixtures under `testdata/measurementreview/` freeze the observation schema, redaction policy, local diagnostic summary, readiness report, misuse controls, and parity report.

## Commands

```bash
go run ./cmd/kcheck measurementreview --quick
go run ./cmd/kcheck measurementreview --full --out testdata/audit/measurementreview.json
go run ./cmd/kcheck measurementreview verify
```

## Limitations

This is a privacy and readiness review only. It is not a measurement client, telemetry system, public-network probe, DNS test, or field-data collection mechanism.

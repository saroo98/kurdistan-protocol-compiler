<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0008: Diversity Audit

The diversity audit asks whether generated profiles are structurally different protocols or merely renamed versions of the same protocol.

## Structural Difference

A structural difference changes the protocol shape a local lab observer or implementation would need to handle. The analyzer treats these as structural:

- first-contact sequence shape, including role order, proof steps, decoy steps, and payload sizes
- canonical state graph edge set
- transition count
- role-specific first-contact paths
- frame grammar strategy
- scheduler strategy
- padding strategy
- invalid-input policy
- semantic message mapping shape

State names, wire symbols, profile IDs, random message strings, generation hashes, and test-only keys are not enough to prove structural diversity.

## Cosmetic Difference

A cosmetic difference changes names or random identifiers while keeping the same protocol shape. Examples include a changed profile ID, changed state names, changed generated wire symbol strings, changed seed, changed generation hash, or changed test-only key material with no state, framing, scheduler, padding, or invalid-input strategy change.

Cosmetic differences matter for debugging, but they are not evidence of a different protocol family.

## Why Diversity Matters

The research question is whether a compiler can produce local relay profiles that avoid a stable family fingerprint. A corpus that varies only by symbol names would be easy to cluster. A stronger corpus varies first contact, state graph shape, framing, scheduling, padding, and invalid-input behavior.

## Analyzer Metrics

The profile analyzer reports:

- profile count
- pair classifications
- unique first-contact patterns and shapes
- unique frame grammar combinations
- unique scheduler combinations
- unique padding combinations
- unique invalid-input policy combinations
- state count distribution
- transition count distribution
- message symbol count distribution

The trace scanner reports suspicious stability in:

- first frame size
- first-contact message count
- canonical state path shape
- frame size histogram
- padding histogram
- invalid-input result when present
- close behavior when present

## Limitations

The analyzer is a lab tool. It cannot prove undetectability, censorship resistance, production safety, or that two generated protocols are indistinguishable from unrelated protocols. It also cannot model external network observers, active probing infrastructure, or real-world traffic classifiers.

The scanner can identify obvious stable signatures, but it is not a substitute for formal protocol analysis or adversarial measurement.

## Running The Audit

Generate an aggregate corpus summary:

```bash
go run ./cmd/kdc corpus --start-seed 1 --count 1000 --out testdata/corpus/summary.json
```

Scan existing traces:

```bash
go run ./cmd/ktrace scan --dir testdata/traces
```

Generate a small loopback trace corpus:

```bash
go run ./cmd/ktrace corpus --start-seed 1 --count 20 --out testdata/traces/corpus-summary.json
```

Run tests and fuzz targets:

```bash
go test ./...
go test -fuzz=Fuzz ./internal/framing
```

## Interpreting Results

For this milestone, a healthy corpus should show multiple first-contact patterns, frame grammar combinations, scheduler combinations, padding combinations, and invalid-input combinations. Pairwise comparisons between different seeds should usually be structurally different. Same-profile traces should remain equivalent, and timestamp-only changes should not be treated as structural evidence.

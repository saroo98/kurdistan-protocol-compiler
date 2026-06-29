<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0026: Wire-Shape Generator Prototype

Milestone 20 adds the first deterministic wire-shape generator prototype. It consumes the abstract protocol-feature corpus from KIP-0025 and turns corpus entries into profile-specific wire-shape policies.

The prototype does not implement real carrier mimicry, live network behavior, or third-party protocol cloning. It creates safe, deterministic policy metadata that can be applied to local byte-path summaries and audited for collapse.

## Purpose

The protocol-feature corpus and wire-feature baselines describe what observable shapes can be measured. The next requirement is a generator that can choose and apply those shapes per profile without collapsing every profile to one fingerprint.

Milestone 20 adds:

- deterministic wire-shape policy sampling
- validation and stable policy hashing
- `wire_shape` policy fields in generated profiles
- bytepath summary application
- expected feature matching
- collapse scanning
- committed wiregen fixtures
- audit gates and CLI commands
- generated-backend constants and tests

Milestone 21 builds on this by exporting generated wire-shape observations into deterministic classifier-ready datasets. See [KIP-0027](KIP-0027-wire-evaluation-classifier-datasets.md).

## Policy Model

`internal/wiregen` defines a versioned `WireShapePolicy` with:

- selected protocol-feature corpus family and entry
- phase plan
- field layout plan
- first-flight plan
- first-N packet plan
- frame-size plan
- fragment rhythm plan
- control richness plan
- metadata exposure plan
- length-alone plan

Every generated policy has a stable hash. The IR validator rejects unsupported values, unsafe strings, missing corpus entries, and hash drift.

## Profile Integration

Profiles now include:

```text
wire_shape
```

The compiler samples a policy deterministically from the profile seed and embeds it into the profile. The byte transport harness reads that policy to vary safe frame-count, frame-size, fragment, control, and metadata summary behavior.

## Expected Feature Matching

`internal/wiregencompare` derives expected wire-feature vectors from wiregen policies and compares them with applied bytepath feature vectors.

The comparison checks:

- first-N shape
- fragment rhythm
- metadata exposure
- selected corpus family
- trace hygiene flags
- safe feature hashes

Unexpected drift fails the wiregen audit.

## Collapse Scanner

The wiregen collapse scanner flags suspicious stability across profiles:

- identical policy hashes
- single selected corpus family
- identical first-N plan
- identical frame-size plan
- identical fragment rhythm
- identical metadata exposure
- trace hygiene failure

The scanner is deterministic and intended for regression gating, not proof of real-world indistinguishability.

## Fixtures

Committed wiregen fixtures live under:

```text
testdata/wiregen/
```

The fixture set contains:

- `wiregen-policy-golden.json`
- `wiregen-bytepath-golden.json`
- `wiregen-corpus-comparison.json`
- `wiregen-collapse-baseline.json`

These files contain safe policy summaries, feature vectors, hashes, and comparison reports only. They do not contain raw payloads, raw encoded bytes, keys, nonce bases, proof material, packet captures, or destination data.

## Audit Gates

New gates include:

- `wiregen_policy_generation`
- `wiregen_policy_validation`
- `wiregen_corpus_selection`
- `wiregen_profile_integration`
- `wiregen_bytepath_application`
- `wiregen_feature_expectation_match`
- `wiregen_firstn_diversity`
- `wiregen_metadata_exposure_diversity`
- `wiregen_collapse_resistance`
- `wiregen_mutant_detection`
- `wiregen_generated_backend_parity`
- `wiregen_trace_hygiene`
- `wiregen_baseline_fixtures`

The default quick audit includes the wiregen gates.

## Commands

Run the wiregen audit:

```bash
go run ./cmd/kcheck wiregen --quick
go run ./cmd/kcheck wiregen --full --out testdata/audit/wiregen.json
```

Regenerate and verify fixtures:

```bash
go run ./cmd/kcheck wiregen generate --out testdata/wiregen/wiregen-policy-golden.json --force
go run ./cmd/kcheck wiregen verify
go run ./cmd/kcheck wiregen compare --old testdata/wiregen/wiregen-policy-golden.json --new testdata/wiregen/wiregen-policy-golden.json
```

Run generated-backend checks:

```bash
go run ./cmd/kcheck codegen --quick
```

## Generated Backend Parity

Generated modules now include:

```text
protocol/wiregen_generated.go
protocol/wiregen_test.go
protocol/wiregen_parity_test.go
protocol/wiregenfeatures_test.go
```

The generated backend specializes the wiregen policy version, policy ID, policy hash, selected corpus family, selected corpus entry, frame-size buckets, fragment buckets, and phase sequence.

## Limitations

This milestone is a deterministic local generator prototype. It does not train classifiers, evaluate DPI systems, use real packet captures, implement carrier mimicry, add concrete network adapters, or claim real-world censorship resistance. Wire-shape policy diversity is measured against local fixtures and abstract corpus features.

## Next Milestone

Milestone 21 consumes these wiregen fixtures through the wire evaluation and classifier dataset harness. The next research step is host-based detection resistance over repeated synthetic destination observations.

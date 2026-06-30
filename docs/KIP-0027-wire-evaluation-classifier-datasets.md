<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0027: Wire Evaluation And Classifier Datasets

Milestone 21 turns deterministic wire-shape output into offline, classifier-ready datasets. The goal is evaluation infrastructure, not model training or live traffic collection.

The dataset harness consumes generated wire-shape policies and deterministic bytepath scenarios, then emits safe records that can be split into train, test, OOD, and holdout partitions. Records contain labels, scenario names, profile IDs, buckets, and stable hashes only.

## Purpose

Milestone 20 proved that profiles can generate wire-shape policies. Milestone 21 asks whether those generated shapes can be exported, compared, and regression-tested as observable datasets without logging raw traffic material.

The harness supports:

- deterministic wire evaluation records
- safe CSV and JSONL classifier exports
- train/test/OOD/holdout split manifests
- synthetic collapsed and padding-only controls
- observable diversity reports
- classifier-readiness reports
- dataset drift comparison
- generated/interpreted parity checks
- wireeval mutation gates

## Dataset Record Schema

`internal/wireeval` defines a versioned `WireEvalRecord` with stable fields:

- `record_id`
- `profile_id`
- `profile_seed`
- `scenario`
- `backend`
- `split`
- `label`
- `selected_family`
- `selected_corpus_entry`
- `phase_shape`
- `field_layout_class`
- `first_n_shape_hash`
- `direction_sequence`
- `packet_size_buckets`
- `frame_size_buckets`
- `fragment_rhythm`
- `control_richness`
- `metadata_exposure`
- `backpressure_class`
- `reset_close_class`
- `error_mapping_class`
- `feature_hash`
- `byte_shape_hash`

The schema is deterministic and versioned as `wireeval-v1`.

## Split Modes

The split generator supports:

- `profile_holdout`
- `scenario_holdout`
- `family_holdout`
- `mixed_holdout`
- `ood_generated_profiles`

The committed fixture set uses deterministic generated profile seeds and representative bytepath scenarios. Split manifests report train, test, OOD, and holdout counts.

## Safe Features

Classifier exports include feature buckets and hashes only. They do not include raw packet bytes, encoded frames, decoded frames, payloads, captures, endpoint addresses, domains, SNI, host headers, keys, nonces, auth tags, or proof material.

Forbidden columns are rejected by `internal/classifierdata`.

## Baselines And Controls

Synthetic controls are included to keep the evaluation honest:

- collapsed fixed-shape controls
- padding-only variation controls
- fixed first-N controls
- fixed metadata exposure controls
- fixed fragment rhythm controls
- random bucket-noise controls

These controls prove that collapse scanners detect bad datasets and that padding-only variation is not treated as healthy diversity.

## Fixtures

Committed fixtures live under:

```text
testdata/wireeval/
```

The fixture set includes:

- `wireeval-dataset-golden.json`
- `wireeval-dataset-golden.jsonl`
- `wireeval-dataset-golden.csv`
- `wireeval-manifest.json`
- `wireeval-splits.json`
- `wireeval-controls.json`
- `wireeval-baseline-report.json`

All fixture files are payload-free and endpoint-free.

## Audit Gates

Milestone 21 adds these gates:

- `wireeval_dataset_build`
- `wireeval_dataset_schema`
- `wireeval_split_integrity`
- `wireeval_export_consistency`
- `wireeval_observable_diversity`
- `wireeval_control_detection`
- `wireeval_classifier_readiness`
- `wireeval_dataset_drift`
- `wireeval_generated_backend_parity`
- `wireeval_trace_hygiene`
- `wireeval_mutant_detection`

The default quick audit includes the wireeval gates.

## Commands

Run wire evaluation:

```bash
go run ./cmd/kcheck wireeval --quick
go run ./cmd/kcheck wireeval --full --out testdata/audit/wireeval.json
```

Regenerate and verify fixtures:

```bash
go run ./cmd/kcheck wireeval generate --out testdata/wireeval/wireeval-dataset-golden.json --force
go run ./cmd/kcheck wireeval verify
go run ./cmd/kcheck wireeval compare --old testdata/wireeval/wireeval-dataset-golden.json --new testdata/wireeval/wireeval-dataset-golden.json
go run ./cmd/kcheck wireeval export --format jsonl --out testdata/wireeval/wireeval-dataset-golden.jsonl --force
go run ./cmd/kcheck wireeval export --format csv --out testdata/wireeval/wireeval-dataset-golden.csv --force
```

## Generated Backend Parity

Generated modules include:

```text
protocol/wireeval_generated.go
protocol/wireeval_test.go
protocol/wireeval_export_test.go
protocol/wireeval_parity_test.go
```

Generated code specializes dataset version, required columns, forbidden columns, split mode, profile ID, and backend version constants.

## Limitations

This milestone does not train classifiers, consume PCAPs, capture live traffic, connect to real networks, or optimize against a real censor. It creates deterministic local datasets that can be used as regression baselines for future offline evaluation work.

## Next Milestone

Milestone 22 is documented in [KIP-0028](KIP-0028-host-based-detection-resistance.md). It evaluates host-based detection risk: repeated synthetic observations against the same destination identity can reveal consistency that is not visible in single-flow records.

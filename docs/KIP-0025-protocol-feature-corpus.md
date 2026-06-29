<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0025: Protocol Feature Corpus And Wire-Shape Baselines

Milestone 19 adds a versioned protocol-feature corpus and a wire-feature baseline layer. It freezes the feature vocabulary that future wire-shape generation work will use.

This milestone does not generate new wire personalities. It defines abstract feature shapes, extracts safe feature vectors from deterministic byte-path fixtures, compares generated profiles against the corpus, and adds gates for feature collapse and fixture drift.

## Purpose

Byte-path fixtures prove that encoded frames can move through a deterministic local byte pipe and be reconstructed safely. The next question is whether those byte-path summaries can be described in a reusable feature vocabulary.

Milestone 19 answers that by adding:

- an abstract protocol-feature taxonomy
- a curated corpus of coarse protocol-shape entries
- a safe first-N packet-shape model
- wire-feature extraction from byte-path fixtures
- corpus-to-profile comparison
- wire-feature collapse scanning
- committed wire-feature baselines
- generated-backend parity checks

## Corpus Scope

The corpus is abstract. It does not copy protocol implementations, raw payloads, packet captures, keys, certificates, nonces, authentication tags, or destination data.

Entries describe coarse shape features such as:

- phase sequence
- handshake round-trip bucket
- field kinds
- field visibility classes
- field position buckets
- field size buckets
- first-flight size bucket
- first-N packet-shape bucket
- frame-size buckets
- fragment rhythm
- control-message richness
- metadata exposure class

The committed corpus lives under:

```text
testdata/protocorpus/
```

## Phase Taxonomy

The initial phase vocabulary includes:

```text
greeting
handshake
control
data
close
reset
```

These phases are descriptive labels for fixture analysis. They are not fixed external wire tags.

## Field Taxonomy

The initial field vocabulary includes:

```text
type
length
version
nonce_like
key_like
certificate_like
reserved
padding_length
padding
payload
auth_tag_like
unknown_encrypted
```

`payload` and `auth_tag_like` are abstract field-kind labels only. Fixtures and traces still must not contain raw payloads or raw authentication tag material.

## Visibility Classes

Fields use coarse visibility classes:

```text
cleartext
encrypted
derived
absent
```

These classes describe whether a field is modeled as visible metadata, encrypted/opaque content, derived metadata, or absent in the abstract shape.

## First-N Packet Model

`internal/wirefeatures` models first-N packet shapes using only:

- packet index
- direction bucket
- size bucket
- kind bucket
- final/reset/control flags
- deterministic hash

No raw encoded bytes or payloads are stored.

## Wire Feature Extraction

Wire-feature vectors are extracted from deterministic byte-path fixtures and summaries. A vector records:

- profile ID and seed
- scenario
- backend
- phase shape
- field layout class
- first-flight bucket
- first-N packet-shape hash
- frame-size buckets
- fragment rhythm
- control richness
- metadata exposure
- payload visibility
- sequence behavior
- backpressure pattern
- reset/close pattern
- error mapping pattern
- safe feature hash

Extraction supports committed byte-path fixtures and generated backend summaries. It does not require PCAPs or live traffic.

## Corpus Comparison

The corpus comparison maps generated feature vectors to abstract feature families. It reports:

- matched families
- unmatched profiles/scenarios
- feature coverage
- diversity score
- payload/secret hygiene
- conclusion

The comparison fails when feature vectors cannot be matched, when all generated features collapse to one family, or when hygiene flags indicate leakage.

## Collapse Scanner

The collapse scanner detects suspicious stability such as:

- identical feature hash across all profiles
- identical first-N packet shape
- identical frame-size bucket distribution
- identical phase shape
- identical field layout class
- identical metadata exposure class
- padding-only variation
- scenario-insensitive behavior
- generated/interpreted feature drift
- corpus mismatch

## Baseline Fixtures

Committed wire-feature baselines live under:

```text
testdata/wirefeatures/
```

The golden set uses the byte-path fixture seeds:

```text
12345
12346
12347
```

And representative scenarios:

```text
byte_single_flow_echo
byte_many_small_flows
byte_large_flow_fragmented
byte_mixed_flows
byte_reset_isolation
byte_corruption_rejection
byte_replay_rejection
```

## Mutants

Milestone 19 adds mutant modes for corpus and wire-feature collapse:

- `protocorpus_missing_phase_taxonomy`
- `protocorpus_invalid_field_visibility`
- `protocorpus_unsafe_payload_feature`
- `wirefeatures_identical_firstn_shape`
- `wirefeatures_padding_only_variation`
- `wirefeatures_missing_metadata_exposure`
- `wirefeatures_generated_interpreted_drift`
- `wirefeatures_secret_leak`

Audit gates require these mutants to be detected by the feature and hygiene checks.

## Audit Gates

New gates include:

- `protocorpus_schema_valid`
- `protocorpus_feature_taxonomy`
- `protocorpus_entry_coverage`
- `protocorpus_trace_hygiene`
- `wirefeatures_extraction`
- `wirefeatures_firstn_model`
- `wirefeatures_corpus_comparison`
- `wirefeatures_collapse_resistance`
- `wirefeatures_generated_backend_parity`
- `wirefeatures_mutant_detection`
- `wirefeatures_baseline`

The default quick audit includes these gates.

## Commands

Validate the protocol corpus:

```bash
go run ./cmd/kcheck protocorpus --quick
go run ./cmd/kcheck protocorpus --full --out testdata/audit/protocorpus.json
```

Run wire-feature checks:

```bash
go run ./cmd/kcheck wirefeatures --quick
go run ./cmd/kcheck wirefeatures --full --out testdata/audit/wirefeatures.json
```

Regenerate and verify wire-feature baselines:

```bash
go run ./cmd/kcheck wirefeatures generate --out testdata/wirefeatures/wirefeatures-golden.json --force
go run ./cmd/kcheck wirefeatures verify
go run ./cmd/kcheck wirefeatures compare --old testdata/wirefeatures/wirefeatures-golden.json --new testdata/wirefeatures/wirefeatures-golden.json
```

## Generated Backend Parity

Generated modules include:

```text
protocol/protocorpus_generated.go
protocol/protocorpus_test.go
protocol/wirefeatures_generated.go
protocol/wirefeatures_test.go
```

The generated backend specializes corpus schema constants, supported phase and field-kind lists, first-N model constants, profile feature extraction constants, and feature summary schema constants. `kcheck codegen --quick` includes generated corpus/wire-feature parity checks.

## Trace Hygiene

Corpus and wire-feature fixtures must not contain:

- raw payloads
- raw encoded or decoded bytes
- packet captures
- ciphertext or plaintext dumps
- authentication tag material
- nonce bases
- secrets or derived keys
- destination addresses or proxy/server IPs

The hygiene scanner accepts abstract taxonomy labels such as `payload` and `auth_tag_like` only as feature-kind labels.

## Limitations

This milestone defines feature vocabulary and baselines. It does not generate new wire shapes, train classifiers, evaluate DPI systems, ingest real packet captures, or prove real-world resistance. Corpus entries are manually curated abstract shapes, and feature extraction is based on deterministic local fixtures.

## Next Milestone

Milestone 20 implements the first wire-shape generation prototype in [KIP-0026](KIP-0026-wire-shape-generator-prototype.md). The next step is a wire evaluation and classifier dataset harness built on top of the M19 corpus and M20 generator fixtures.

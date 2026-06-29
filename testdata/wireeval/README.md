<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Wire Evaluation Fixtures

This directory contains deterministic, payload-free wire evaluation fixtures for the local classifier dataset harness.

The fixtures are generated from synthetic profile seeds and local bytepath/wire-shape scenarios. They store only safe metadata such as labels, split names, bucketed feature classes, and stable hashes. They do not contain raw packet bytes, payloads, endpoint addresses, domains, SNI, host headers, captures, keys, nonces, auth tags, or proof material.

Regenerate with:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck wireeval generate --out testdata/wireeval/wireeval-dataset-golden.json --force
.tools\go\bin\go.exe run ./cmd/kcheck wireeval export --format jsonl --out testdata/wireeval/wireeval-dataset-golden.jsonl --force
.tools\go\bin\go.exe run ./cmd/kcheck wireeval export --format csv --out testdata/wireeval/wireeval-dataset-golden.csv --force
```

Verify with:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck wireeval verify
.tools\go\bin\go.exe run ./cmd/kcheck wireeval compare --old testdata/wireeval/wireeval-dataset-golden.json --new testdata/wireeval/wireeval-dataset-golden.json
```
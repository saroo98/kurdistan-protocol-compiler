<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Byte-Path Fixtures

This directory contains deterministic byte-path regression metadata for the Kurdistan Protocol Compiler.

The fixtures store safe summaries, buckets, hashes, scenario names, expected results, malformed-input metadata, and broad performance buckets. They do not store raw payloads, raw encoded bytes, ciphertext, secrets, keys, auth tags, nonce bases, proof material, or destination data.

Regenerate the golden byte-path manifest:

```bash
go run ./cmd/kcheck fixtures generate --out testdata/fixtures/bytepath-golden.json --force
```

Verify the committed fixtures:

```bash
go run ./cmd/kcheck fixtures verify
```

Compare two manifests:

```bash
go run ./cmd/kcheck fixtures compare --old testdata/fixtures/bytepath-golden.json --new testdata/fixtures/bytepath-golden.json
```

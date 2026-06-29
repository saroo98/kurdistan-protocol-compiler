<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Wiregen Fixture Set

This directory contains deterministic, payload-free wire-shape generator
fixtures.

The committed JSON files store policy summaries, safe feature vectors,
comparison reports, and collapse summaries only. They do not contain raw
payload bytes, encoded frames, ciphertext, keys, nonce bases, proof material, or
external target data.

Regenerate with:

```bash
go run ./cmd/kcheck wiregen generate --out testdata/wiregen/wiregen-policy-golden.json --force
```

Verify with:

```bash
go run ./cmd/kcheck wiregen verify
go run ./cmd/kcheck wiregen --quick
```

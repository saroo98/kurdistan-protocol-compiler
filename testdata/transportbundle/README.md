<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Transport Bundle Fixtures

This directory contains deterministic, payload-free transport bundle fixtures.

The fixtures model bundle policies, candidate references, adaptive-path mappings,
synthetic relay binding metadata, fallback hints, collapse controls, and parity
summaries. They do not contain payloads, raw packet bytes, real endpoints, DNS
queries, resolver data, secrets, keys, nonce bases, auth tags, or proof material.

Regenerate after an intentional compiler change:

```bash
go run ./cmd/kcheck transportbundle generate --out testdata/transportbundle/bundle-manifest-golden.json --force
```

Verify drift:

```bash
go run ./cmd/kcheck transportbundle verify
```

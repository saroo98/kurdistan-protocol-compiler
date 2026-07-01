<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Local Pipeline Fixtures

This directory contains deterministic, payload-free fixtures for the end-to-end local proxy pipeline model.

The fixtures cover synthetic ingress events, proxy egress descriptors, relay bridge summaries, byte transport metadata, adaptive-path binding classes, generated/interpreted parity summaries, misuse controls, and fixture drift hashes.

The JSON files intentionally store only safe metadata: scenario names, counts, buckets, states, hashes, and boolean hygiene flags. They do not contain raw payloads, raw bytes, endpoint data, resolver data, DNS queries, secrets, keys, nonce bases, auth tags, proof material, or packet captures.

Regenerate and verify with:

```bash
go run ./cmd/kcheck localpipeline generate --out testdata/localpipeline/localpipeline-golden.json --force
go run ./cmd/kcheck localpipeline verify
```

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Production Readiness Review Fixtures

This directory contains deterministic, payload-free fixtures for the production integration readiness review model.

The fixtures store review inventory items, dependency edges, closed boundary reviews, future milestone contracts, blocker-register entries, misuse controls, generated/interpreted parity summaries, and a stable review hash.

The JSON files intentionally contain only safe review metadata. They do not contain raw payloads, raw bytes, endpoint data, resolver data, DNS queries, secrets, keys, nonce bases, auth tags, proof material, deployment tokens, or packet captures.

Regenerate and verify with:

```bash
go run ./cmd/kcheck productionreadiness generate --out testdata/productionreadiness/productionreadiness-golden.json --force
go run ./cmd/kcheck productionreadiness verify
```

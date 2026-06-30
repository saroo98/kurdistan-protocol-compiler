<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Host Detection Fixtures

This directory stores deterministic host-observation fixtures for the host-based detection resistance audit.

The fixtures contain synthetic host IDs, profile IDs, scenario names, bucketed features, hashes, aggregate reports, and expected detection outcomes. They do not contain payloads, raw bytes, real endpoint addresses, packet captures, keys, nonce material, auth tags, or proof material.

Regenerate intentionally with:

```bash
go run ./cmd/kcheck hostdetect generate --out testdata/hostdetect/host-observations-golden.json --force
```

Verify drift with:

```bash
go run ./cmd/kcheck hostdetect verify
go run ./cmd/kcheck hostdetect compare --old testdata/hostdetect/host-observations-golden.json --new testdata/hostdetect/host-observations-golden.json
```

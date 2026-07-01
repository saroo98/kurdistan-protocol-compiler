<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Pathrace Fixtures

This directory contains deterministic, local-only path racing fixtures for
Milestone 29. The JSON files store scenario metadata, bucketed observations,
score/ranking summaries, misuse-control reports, and fixture hashes.

The fixtures intentionally do not contain real endpoints, domains, resolver
data, DNS queries, packet captures, raw bytes, payload contents, keys, nonces,
auth tags, proof material, or secrets.

Regenerate after an intentional pathrace model change:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck pathrace generate --out testdata/pathrace/pathrace-report-golden.json --force
```

Verify committed drift:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck pathrace verify
```

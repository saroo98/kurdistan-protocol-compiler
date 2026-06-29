<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Wire Feature Baselines

This directory stores small, deterministic, payload-free wire-feature fixtures for
the byte-path regression set.

The fixtures contain abstract feature vectors, first-N packet-shape hashes,
corpus-comparison summaries, and collapse-scan summaries. They do not contain raw
payloads, raw encoded bytes, packet captures, keys, nonces, authentication tags,
or destination addresses.

Regenerate intentionally with:

```bash
go run ./cmd/kcheck wirefeatures generate --out testdata/wirefeatures/wirefeatures-golden.json --force
```

Verify drift with:

```bash
go run ./cmd/kcheck wirefeatures verify
```

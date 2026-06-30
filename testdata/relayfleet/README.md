<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Relay Fleet Fixtures

These fixtures are deterministic, synthetic relay-fleet lifecycle baselines for Milestone 23.

They contain synthetic relay IDs, profile seeds, wire-policy hashes, lifecycle states, churn events, migration events, burn-risk buckets, collapse reports, and parity summaries. They do not contain raw payloads, raw bytes, packet captures, endpoint addresses, host headers, cloud metadata, credentials, keys, nonces, proof material, or deployment data.

Regenerate intentionally with:

```bash
go run ./cmd/kcheck relayfleet generate --out testdata/relayfleet/relayfleet-golden.json --force
go run ./cmd/kcheck relayfleet verify
```

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Concrete Local Adapter Fixtures

This directory contains deterministic, loopback-only fixture summaries for the concrete local socket adapter milestone.

The fixtures store safe metadata only: scenario names, byte-count buckets, flow counts, loopback bind policy checks, reset/error counters, backpressure counters, and stable hashes. They do not contain raw payloads, raw socket bytes, endpoints beyond loopback policy metadata, secrets, keys, nonces, auth tags, or proof material.

Regenerate with:

```bash
go run ./cmd/kcheck concretelocaladapter generate --out testdata/concretelocaladapter/concretelocaladapter-golden.json --force
```

Verify drift with:

```bash
go run ./cmd/kcheck concretelocaladapter verify
```

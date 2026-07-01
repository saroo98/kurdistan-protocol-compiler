<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# HTTPS-Like Carrier Review Fixtures

These fixtures freeze the Milestone 41 design-lock contract for the first HTTPS-like carrier lab prototype.

The files contain safe contract metadata only: shape classes, bounded markers, stream/backpressure/reset mapping rules, blocker status, risk notes, and expected M42 acceptance criteria. They do not contain raw payloads, encoded bytes, packet captures, secrets, endpoint data, domains, resolver data, or live-network observations.

Regenerate the fixture set with:

```bash
go run ./cmd/kcheck httpscarrierreview generate --out testdata/httpscarrierreview/httpscarrierreview-report-golden.json --force
```

Verify drift with:

```bash
go run ./cmd/kcheck httpscarrierreview verify
```

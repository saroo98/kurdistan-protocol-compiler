<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Proxy Ingress Fixtures

This directory contains deterministic, synthetic-only fixtures for the concrete local proxy ingress design review.

The fixtures store contract metadata, synthetic request classes, target descriptor classes, lifecycle summaries, mapping summaries, and failure-mode review records. They intentionally omit raw traffic, raw payload bytes, endpoint addresses, DNS data, credentials, key material, and generated secrets.

Regenerate after an intentional contract change:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck proxyingress generate --out testdata/proxyingress/proxyingress-contract-golden.json --force
```

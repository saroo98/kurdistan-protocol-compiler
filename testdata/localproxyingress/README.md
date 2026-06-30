<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Local Proxy Ingress Fixtures

This directory contains deterministic fixture summaries for the in-memory local proxy ingress prototype.

The data covers synthetic request sources, request lifecycle outcomes, bounded queue pressure, reset/error isolation, and adversarial controls. Fixtures contain scenario names, counters, hashes, and safe metadata only. They do not contain raw traffic, raw payload bytes, destination data, DNS data, credentials, keys, nonces, auth tags, or secrets.

Regenerate after an intentional local ingress prototype change:

```bash
.tools\go\bin\go.exe run ./cmd/kcheck localproxyingress generate --out testdata/localproxyingress/localproxyingress-summary-golden.json --force
```

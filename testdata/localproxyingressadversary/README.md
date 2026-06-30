# Local Proxy Ingress Adversarial Fixtures

This directory contains deterministic, payload-free Milestone 26 fixtures for
local proxy ingress adversarial hardening.

The fixtures cover malformed ingress event order, descriptor abuse classes,
lifecycle misuse, queue pressure, reset/error isolation, mapping collapse
controls, generated/interpreted parity, and M27 readiness.

The files store safe classes, counters, buckets, hashes, and conclusions only.
They must not contain raw payloads, raw bytes, endpoint strings, DNS material,
host headers, SNI values, cloud metadata, keys, nonce material, proofs, or
secrets.

Regenerate with:

```bash
go run ./cmd/kcheck localproxyingressadv generate --out testdata/localproxyingressadversary/adversarial-corpus-golden.json --force
```

Verify with:

```bash
go run ./cmd/kcheck localproxyingressadv verify
```

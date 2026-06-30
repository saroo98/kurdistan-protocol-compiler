# Adaptive Path Fixtures

This directory contains deterministic, synthetic fixtures for the adaptive path
model.

The fixtures store candidate families, condition classes, observations,
viability summaries, decision-input summaries, collapse controls, and stable
hashes. They are intended for regression tests and audit gates.

The fixture set does not contain payloads, raw bytes, real endpoint addresses,
domains, SNI values, host headers, URLs, DNS queries, resolver addresses, cloud
metadata, keys, nonces, auth tags, or secrets.

Regenerate only when the adaptive path schema or deterministic model changes:

```bash
go run ./cmd/kcheck adaptivepath generate --out testdata/adaptivepath/path-candidates-golden.json --force
go run ./cmd/kcheck adaptivepath verify
go run ./cmd/kcheck adaptivepath compare --old testdata/adaptivepath/path-candidates-golden.json --new testdata/adaptivepath/path-candidates-golden.json
```

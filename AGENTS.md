# AGENTS.md

## Project

Kurdistan is a lab-only protocol compiler research prototype. It generates local, one-off relay protocol profiles with different state machines, frame grammars, scheduling policies, and invalid-input behavior.

## Hard scope limits

Do not implement production deployment, VPN mode, SOCKS mode, external web fetching, mobile apps, censorship bypass deployment, domain-fronting, TLS mimicry, CDN bypass, or real-world operational guidance.

All tests must be local. No tests may require external internet.

## Safety

Do not log payload contents, secrets, credentials, real user data, or external target data.

Do not implement custom cryptography. Use standard Go cryptographic libraries only.

## Build and test commands

Run:

- gofmt on changed Go files
- go test ./...
- go test -bench=. ./... when changing scheduler, framing, relay, or benchmark code
- go vet ./... when feasible
- go run ./cmd/kgen --profile <profile.json> --out .generated/<name> when verifying generated source output
- go run ./cmd/kcheck codegen --quick when changing the generated source backend
- from a generated output directory, go run ./cmd/generated-trace --trace generated.jsonl --summary generated-summary.json when verifying generated trace capture

## Style

Prefer clear, small packages.
Keep generated protocol semantics documented.
Add tests for every behavior change.
Do not hide failed tests.
If a milestone cannot be completed, explain exactly what is missing.

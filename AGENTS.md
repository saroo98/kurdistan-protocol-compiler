<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# AGENTS.md

## Project

Kurdistan is a lab-only censorship-resistance protocol research prototype building toward a production-grade polymorphic relay transport compiler. It generates local, profile-specific relay transport profiles with different state machines, frame grammars, scheduling policies, padding/probing behavior, multi-stream semantics, generated source modules, and adversarial audit gates.

## Hard scope limits

Do not implement production deployment, VPN mode, SOCKS mode, HTTP carriers, external web fetching, mobile apps, censorship bypass deployment, domain-fronting, TLS mimicry, CDN bypass, or real-world operational guidance.

Documentation may mention adversarial network environments and heavily filtered countries such as Iran as long-term motivation, but it must not claim that the current repository is usable, deployed, undetectable, production-ready, or proven to resist real-world censorship.

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
- go run ./cmd/kcheck --quick when changing audit gates or trace behavior
- go run ./cmd/kcheck streamadversary --quick when changing stream scheduling, flow control, stream traces, stream mutants, or multi-stream audit code
- go run ./cmd/kgen --profile <profile.json> --out .generated/<name> when verifying generated source output
- go run ./cmd/kcheck codegen --quick when changing the generated source backend
- from a generated output directory, go run ./cmd/generated-trace --trace generated.jsonl --summary generated-summary.json when verifying generated trace capture
- from a generated output directory, go run ./cmd/generated-client --multistream-demo --streams 3 when verifying generated multi-stream lab semantics
- from a generated output directory, go run ./cmd/generated-trace --multistream --streams 4 --trace generated-multistream.jsonl --summary generated-multistream-summary.json when verifying generated multi-stream traces

## Style

Prefer clear, small packages.
Keep generated protocol semantics documented.
Add tests for every behavior change.
Do not hide failed tests.
If a milestone cannot be completed, explain exactly what is missing.

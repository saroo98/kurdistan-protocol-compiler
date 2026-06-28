<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0012: Generated Source Backend

## Status

Accepted for Milestone 6.

## Summary

Kurdistan originally executed generated profiles through a shared interpreter. That is useful for research, but a common interpreter can also create common runtime structure. The generated source backend adds a lab-only path that emits a small Go module with profile-specific protocol constants, tables, commands, tests, and a manifest.

This is not deployment support. Generated modules remain loopback-only and use the same safety limits as the interpreted runtime.

## Research Question

Can Kurdistan generate not only different profile documents, but also profile-specific protocol implementations that compile and interoperate locally?

## Generated Output

`kgen` writes a module like:

```text
.generated/profile-12345/
  go.mod
  README.md
  manifest.json
  protocol/
    profile_static.go
    states_generated.go
    framing_generated.go
    stream_generated.go
    scheduler_generated.go
    invalid_input_generated.go
    auth_generated.go
    trace_capture_generated.go
    protocol.go
    protocol_test.go
    multistream_test.go
    protocol_bench_test.go
    probe_test.go
  cmd/
    generated-client/main.go
    generated-server/main.go
    generated-echo/main.go
    generated-trace/main.go
```

The generated module imports the local `kurdistan` repository through a `replace` directive. It is intended for local builds and tests only.

## What Is Specialized

Generated code inlines or specializes:

- profile ID, seed, generation hash, and backend metadata
- state constants
- transition table
- first-contact sequence
- semantic-to-wire symbol map
- frame grammar strategy constants
- scheduler constants
- stream ID encoding, max stream/window limits, priority, window-update, close, and reset constants
- padding and invalid-input policy constants
- safety limits
- static profile construction

The generated code does not load `profile.json` at runtime and does not shell out to `kclient` or `kserver`.

## What Remains Shared

The backend deliberately reuses small local helpers for:

- loopback-only relay IO
- frame encode/decode mechanics
- scheduler planning
- lab-only stream session and flow-control mechanics
- padding generation
- test-only HMAC transcript proof
- payload-free trace recording

Keeping those pieces shared avoids duplicating safety-sensitive code. This also means Milestone 6 does not prove that generated source removes all shared runtime signatures.

## Test-Only Auth Material

Compiler-generated profiles use deterministic test-only key material derived from the public profile ID and seed. `kgen` refuses profiles whose auth key cannot be derived this way, so arbitrary key material is not embedded into generated source or `manifest.json`.

The manifest does not contain keys, payloads, proofs, raw frames, or external targets.

## Commands

Generate a profile first:

```bash
go run ./cmd/kdc generate --seed 12345 --out profiles/examples/profile-12345.json
```

Generate source:

```bash
go run ./cmd/kgen --profile profiles/examples/profile-12345.json --out .generated/profile-12345
```

Overwrite an existing generated directory:

```bash
go run ./cmd/kgen --profile profiles/examples/profile-12345.json --out .generated/profile-12345 --force
```

Build and test generated output:

```bash
cd .generated/profile-12345
go test ./...
```

Run the generated loopback demo in separate terminals:

```bash
go run ./cmd/generated-echo --listen 127.0.0.1:9100
go run ./cmd/generated-server --listen 127.0.0.1:7100 --target 127.0.0.1:9100
go run ./cmd/generated-client --server 127.0.0.1:7100 --message "hello generated"
```

Optional payload-free client trace:

```bash
go run ./cmd/generated-client --server 127.0.0.1:7100 --message "hello generated" --trace client.jsonl
```

Run a self-contained generated loopback trace:

```bash
go run ./cmd/generated-trace --trace generated.jsonl --summary generated-summary.json
```

Run the generated multi-stream lab demo:

```bash
go run ./cmd/generated-client --multistream-demo --streams 3
go run ./cmd/generated-trace --multistream --streams 4 --trace generated-multistream.jsonl --summary generated-multistream-summary.json
```

Run the optional generated-backend audit:

```bash
go run ./cmd/kcheck codegen --quick
go run ./cmd/kcheck codegen --full --out testdata/audit/codegen.json
```

## Interpreted Vs Generated Comparison

The generated-backend audit generates profiles, emits static source modules, runs `go test ./...` inside generated modules, captures interpreted loopback traces, captures generated loopback traces through `cmd/generated-trace`, and compares same-profile semantic behavior. Generated module tests exercise local echo round trips and malformed/probe fixtures through the generated protocol package.

This is evidence of local interoperability, not proof that generated behavior is externally indistinguishable or superior.

## Limitations

- The generated backend still uses shared Go helper packages for safety-critical IO, framing, HMAC, scheduling, padding, and trace recording.
- Multi-stream support is loopback-only lab semantics, not proxy, VPN, SOCKS, or HTTP carrier behavior.
- Trace compatibility is a payload-free subset focused on existing `trace.Event` fields.
- There is no production key exchange.
- There is no SOCKS, VPN, HTTP carrier, TLS mimicry, CDN behavior, deployment script, mobile app, external target support, live-network testing, or real censorship testing.
- The backend cannot prove undetectability or real-world resistance.

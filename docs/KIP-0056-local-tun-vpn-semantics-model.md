<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0056: Local TUN/VPN Semantics Model

Milestone 50 defines the packet-flow semantics required before any future desktop packet-style adapter. It is a review and contract milestone, not an implementation of a TUN device, Android VpnService, packet capture, OS routing, or public-network behavior.

The model answers one narrow question: can packet-like local flow concepts be mapped to Kurdistan streams using safe classes, buckets, and fixture summaries without logging raw packets, payloads, exact endpoints, per-app identity, DNS queries, resolver addresses, secrets, or proof material?

## Scope

The `internal/vpnsemantics` package defines deterministic reports for:

- packet-flow taxonomy
- flow identity classes
- app-identity policy classes
- packet-flow to stream mapping
- stream result to flow summary mapping
- MTU, fragmentation, and reassembly buckets
- retry, reset, and backpressure buckets
- kill-switch policy classes
- DNS and routing boundary classes
- local diagnostics and privacy composition
- misuse controls
- generated/interpreted parity
- M51 implementation contract

## Blocked Behavior

The M50 contract blocks:

- real TUN device creation
- real packet capture
- OS route modification
- Android VpnService behavior
- app traffic interception
- real DNS interception
- public-network behavior
- payload logging
- packet dumps
- per-app identity logging
- precise endpoint logging

Only symbolic classes, buckets, counts, hashes, and hygiene flags are allowed in fixtures and traces.

## Fixture Set

Committed fixtures live in `testdata/vpnsemantics/`:

- `vpnsemantics-report-golden.json`
- `packet-flow-taxonomy.json`
- `flow-stream-mapping.json`
- `mtu-fragmentation-semantics.json`
- `boundary-policy-report.json`
- `m51-implementation-contract.json`
- `misuse-report.json`
- `vpnsemantics-parity-report.json`

The fixture set is deterministic and payload-free. It records safe summary fields and stable hashes only.

## Misuse Controls

The gate detects controls for packet capture, payload logging, OS route modification, Android VpnService behavior, real DNS interception, per-app identity logging, exact endpoint logging, bypasses of local proxy adapter or measurement review, public VPN claims, payload or secret leakage, and generated backend drift.

## M51 Contract

M51 may implement a controlled local desktop packet-style prototype only if it:

- uses deterministic local harnesses
- maps packet-flow classes to runtime streams through reviewed boundaries
- preserves local proxy adapter, measurement review, pathhealth, hardening, and codegen gates
- keeps payloads, raw packets, exact endpoints, DNS queries, app identity, and secrets out of traces
- rejects unsafe capture, routing, Android, and public-network behavior

## Commands

```bash
go run ./cmd/kcheck vpnsemantics --quick
go run ./cmd/kcheck vpnsemantics --full --out testdata/audit/vpnsemantics.json
go run ./cmd/kcheck vpnsemantics generate --out testdata/vpnsemantics/vpnsemantics-report-golden.json --force
go run ./cmd/kcheck vpnsemantics verify
go run ./cmd/kcheck vpnsemantics compare --old testdata/vpnsemantics/vpnsemantics-report-golden.json --new testdata/vpnsemantics/vpnsemantics-report-golden.json
```

`testdata/audit/vpnsemantics.json` is an ignored local audit artifact.

## Generated Backend

Generated modules include packet-semantics constants and tests through `protocol/vpnsemantics_generated.go`, `protocol/vpnsemantics_test.go`, `protocol/vpnsemantics_parity_test.go`, and `protocol/vpnsemantics_hygiene_test.go`. The generated source uses neutral packet-semantics markers so the source scanner can continue rejecting fixed universal protocol strings.

## Limitations

M50 does not create a real packet adapter. It does not prove field readiness, deployment readiness, censorship bypass, or safety for high-risk users. It only freezes deterministic semantics and review evidence for the next controlled local prototype.

## Next Milestone

M51 implements the controlled local desktop packet-style prototype against this contract while preserving packet-flow redaction, trace hygiene, boundary checks, generated parity, and audit gates.

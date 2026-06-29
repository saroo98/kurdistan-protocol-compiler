<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0018: Production Security Prerequisites

## Summary

Milestone 12 adds the internal security prerequisite layer for Kurdistan. The purpose is to define and test security invariants before any future real adapter or carrier integration work.

The layer binds profile identity, compiler output, stream policy, proxy semantics, carrier policy, capabilities, session transcript, key schedule, nonce schedule, replay policy, compatibility metadata, and trace hygiene into a verifiable context.

## Security Context Model

A `SecurityContext` contains:

- profile ID and profile hash
- session ID
- transcript hash
- capability hash
- stream, proxy, and carrier bindings
- selected security suite

The context is constructed from canonical transcript input. It is deterministic for tests and does not include raw secrets.

## Transcript Binding

The transcript binds:

- profile ID and hash
- compiler and generated semantic mapping identifiers
- state machine, framing, scheduler, padding, stream, proxy, and carrier policies
- selected capabilities
- session nonce
- selected security suite

Canonical serialization uses explicit fields, stable map ordering, canonicalized capabilities, and an explicit domain label.

## Key Schedule

The key schedule derives directional write keys, directional nonce bases, and an exporter secret from an input secret and transcript hash.

It uses standard HMAC-SHA256 HKDF-style extract/expand logic with domain-separation labels. Empty secrets, missing transcripts, and unknown suites are rejected.

## Nonce Schedule

Nonce managers provide per-direction counters and nonce construction modes. They reject counter overflow and support concurrency-safe generation. Client and server directions use separate nonce spaces.

## Replay Policy

Replay windows reject duplicates, stale sequences, and too-far future sequences. Supported policies include:

- `ordered_only`
- `bounded_reorder`
- `strict_no_reorder`
- `windowed_replay`

## Downgrade Resistance And Capabilities

Capabilities are canonicalized and hashed. Required capabilities and selected suites are transcript-bound. Downgrade checks reject removed capabilities, unsupported required features, and suite changes after transcript construction.

## Profile Compatibility

Profiles declare compatibility metadata:

- schema version
- compiler security version
- minimum runtime version
- supported security suites
- required capabilities
- supported carrier families
- supported stream and proxy features
- maximum envelope, stream, and replay limits

Compatibility checks reject unsupported suites, carrier families, capabilities, envelope sizes, stream counts, and replay windows.

## Config Hygiene And Redaction

Security config validation rejects:

- missing profile identity
- empty or all-zero secrets
- unsafe replay windows
- unsafe envelope and queue limits
- unknown suites or capabilities
- unsafe debug flags

Redaction preserves safe identifiers and hashes while replacing secret-bearing fields with `<redacted>`.

## Secure Envelope Model

The secure envelope model wraps semantic and carrier metadata with:

- sequence number
- stream ID
- semantic class
- carrier family
- transcript hash
- capability hash
- nonce
- ciphertext byte count
- auth tag byte count

The current implementation uses AES-GCM for synthetic test payloads and trace-safe metadata. It rejects transcript mismatch, capability mismatch, malformed envelopes, and replayed sequences.

## Trace Hygiene

Security traces may include safe buckets, counts, transcript hashes, and capability hashes.

Security traces must not include:

- raw secrets
- derived keys
- nonce bases
- plaintext payloads
- ciphertext payloads
- auth tags
- proof material

## Security Mutants

Milestone 12 adds test-only mutants for:

- missing transcript binding
- reused nonce behavior
- replay acceptance
- downgrade acceptance
- capability mismatch acceptance
- profile mismatch acceptance
- unsafe config acceptance
- secret trace leakage

The security audit must detect each mutant.

## Audit Gates

`kcheck security` runs gates for:

- transcript binding
- key schedule
- nonce uniqueness
- replay rejection
- downgrade resistance
- capability negotiation
- profile compatibility
- config hygiene
- secret trace hygiene
- security mutant detection
- generated backend parity

## Generated Backend Parity

`kgen` emits security-specific generated files:

- `protocol/security_generated.go`
- `protocol/security_test.go`
- `protocol/securityadversary_test.go`

Generated tests verify transcript and capability hash parity, replay rejection, mismatch rejection, config redaction, and trace hygiene.

## Commands

```bash
go run ./cmd/kcheck security --quick
go run ./cmd/kcheck security --full --out testdata/audit/security.json
go run ./cmd/kcheck codegen --quick
go test ./...
```

Generated module commands:

```bash
go run ./cmd/generated-client --security-demo --streams 4
go run ./cmd/generated-trace --security --carrier mixed --proxysem --streams 4 --trace out.jsonl --summary summary.json
```

## Limitations

This milestone defines prerequisite security architecture and regression checks. It is not a complete production transport security protocol, does not replace formal cryptographic review, and does not introduce real adapters, external targets, deployment behavior, SOCKS, VPN mode, HTTP carriers, TLS mimicry, CDN behavior, or live-network testing.

## Next Milestone

Milestone 13 builds on this layer with runtime session architecture: role validation, session lifecycle, capability negotiation, compatibility checks, secure channel setup, in-memory links, runtime adversary scenarios, and generated-backend runtime parity.

Milestone 14 adds implementation hardening, generated-backend parity fixtures, trace hygiene gates, and pre-adapter readiness review. See [KIP-0020](KIP-0020-implementation-hardening.md).

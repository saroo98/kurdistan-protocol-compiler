<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0072: Offline Relay-Descriptor Admission Contract

## Status

- status: implemented contract
- scope: M5 deterministic offline metadata admission only
- implementation: `internal/product/relaydescriptor`

M5 opens only the structural relay-descriptor entry from KIP-0069. It admits
bounded metadata after proving that the caller's Phase 4 selection belongs to
the complete supplied Phase 4 request. It does not authenticate, resolve, probe,
dial, operate, or deploy a relay.

## Admission proof

`Admit` accepts the complete original `strategy.Request` and a claimed
`strategy.Result`. It calls `strategy.Select` on that exact request, requires a
nil error, exact result equality, and `OutcomeSelected`. A detached, substituted,
blocked, zero, unknown, or selector-error result is rejected with a zero M5
result.

The relay policy and every descriptor bind exactly to the admitted lifecycle
profile ID, scope, evidence reference, generation, complete fallback policy,
selected family, and client capabilities. A separate bounded client identity
must appear in the profile-authorized client list. Authorized descriptors are
exact values, not patterns. Cross-profile, cross-generation, cross-family,
cross-capability, cross-client, stale, ambiguous, duplicate, or unauthorized
metadata rejects the whole request.

## Time, revocation, and compatibility

The caller supplies evaluation time and a complete revocation snapshot bound to
that same time, profile, scope, evidence reference, and generation. M5 reads no
clock and fetches no revocation data. Not-before is inclusive and expiry is
exclusive. Any invalid validity window or revoked descriptor fails closed.

Only `offline-relay-descriptor-admission-v1` is accepted. Zero, older, newer,
and unknown versions reject without negotiation or downgrade. Compatible v1
changes may only be additive when existing v1 callers and rejection semantics
remain exact. A semantic change requires a later major contract and migration
plan. Rollback is a scoped revert of the M5 commit; there is no persistent or
external state to migrate.

## Data and safety boundary

Endpoint material uses the exact `relayref:<opaque-token>` grammar. The token is
bounded ASCII alphanumeric, hyphen, or underscore only; slash, dot, extra colon,
at-sign, whitespace, query, fragment, and secret/key/token/password/payload
markers reject. This keeps it from being interpreted as a URL, hostname, IP
address, socket, destination, credential, key, or routing instruction. The
reference is grammar-validated, but never parsed or interpreted as a network
destination. Stable
categorical errors contain no caller-controlled text.
Lists, identifiers, references, and metadata are bounded before output is
constructed. Admission is all-or-nothing, preserves request order, returns
fresh minimal output, and never mutates caller input.

Structural admission is not evidence of signature validation, provenance,
authenticity, reachability, relay safety, cryptographic strength, or production
readiness. The package performs no file, environment, clock, randomness,
process, DNS, socket, HTTP, network, persistence, telemetry, goroutine, Android,
operator, deployment, runtime, cryptographic, relay-session, routing, probing,
dialing, or resolution work.

## Consumer and future gates

`testdata/consumer/m5-relay-descriptor-sdk` is a source-tree compatibility
fixture. It is not a published SDK. It proves exact-v1 admission and fail-closed
substitution, client-binding, mismatch, revocation, and prior-safe-state
behavior. Live relay authentication, session establishment, networking,
operator control, deployment, and publication remain separately closed.

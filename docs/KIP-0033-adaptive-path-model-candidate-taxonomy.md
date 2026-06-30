<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0033: Adaptive Path Model And Candidate Taxonomy

## Purpose

Milestone 27 introduces Kurdistan's first adaptive-runtime abstraction:
candidate paths. A generated transport is no longer represented only as a
profile. It can also be represented as one candidate among several possible
paths, each with a carrier family, relay-risk bucket, synthetic condition
observations, freshness metadata, uncertainty, and safe decision-input fields.

This KIP defines the deterministic taxonomy that later bundle compilation,
path racing, health monitoring, and failover work can consume.

## Why Stable Path Assumptions Are Insufficient

A generated profile can be structurally diverse and still be a poor active path
under volatile network conditions. Candidate viability may change by carrier
family, relay state, session phase, recent failures, and synthetic evidence
freshness. M27 models those factors as local, synthetic metadata rather than as
real connectivity measurements.

## Candidate Families

The taxonomy includes:

- `https_like_tcp`
- `dns_survival`
- `experimental_udp_quic`
- `domestic_media_risk`
- `relay_rotation`
- `baseline_control`
- `collapsed_control`

Each family has an intended role, safe carrier class, expected observation
signals, expected failure classes, metadata-risk bucket, default TTL class, and
flags for default eligibility, high-risk handling, gating, and experimental
status. High-risk and experimental families are gated and cannot silently become
default winners.

## Synthetic Condition Model

Synthetic conditions represent classes of volatile path behavior such as
poisoning-like signals, truncation-like signals, blackhole-like failures,
throttling, relay burn risk, route flapping, device variance, and recent-flow
history penalties.

The model is offline and deterministic. It does not perform DNS queries,
resolver tests, endpoint probing, transport handshakes, relay dialing, or public
network measurement.

## Freshness And Uncertainty

Observations use logical ticks instead of wall-clock time. Success evidence
decays quickly, volatile conditions receive shorter TTLs, repeated recent
failures increase uncertainty, and stale success cannot create strong viability.

Freshness classes include `fresh_seconds`, `fresh_short`, `stale_short`,
`stale_medium`, `expired`, and `unknown`. Uncertainty buckets include low,
medium, high, and unknown uncertainty.

## Viability Evaluation

Viability reports combine candidate descriptors, observations, relay risk,
metadata risk, freshness, uncertainty, and failure buckets. Examples:

- Poisoning-like signals degrade or reject `dns_survival` candidates.
- Truncation-like signals degrade `dns_survival` candidates without always
  blocking them.
- Blackhole-like signals degrade or block `https_like_tcp` candidates.
- UDP block or throttle signals degrade `experimental_udp_quic` candidates.
- Relay burn risk blocks or quarantines candidates.
- Unknown evidence remains conservative.

The evaluator produces state and decision metadata, not a final active path.

## Decision Inputs

The decision-input builder produces deterministic, ranked-for-inspection inputs
for future scoring. M27 does not implement path racing, winner selection, active
probing, or failover. Rejected candidates remain visible for audit.

## Relation To Relay Fleet And Host Detection

Relay fleet modeling contributes synthetic relay lifecycle and burn-risk
signals. Host detection work contributes host-level stability and confidence
concepts. Adaptive path modeling consumes those categories as safe classes and
hashes, without importing real hostnames, addresses, resolver data, or captures.

## Future Path Racing And Scoring

M29 is expected to consume M27 decision inputs for path racing and short-lived
scoring. M30 is expected to build a continuous health and failover model. Those
milestones must preserve the same payload-free, endpoint-free trace discipline.

## Non-Network Boundary

M27 is not a probing implementation. It does not add sockets, real DNS, real
resolver checks, real HTTPS/TCP/UDP/QUIC tests, relay dialing, bridge allocation,
host header handling, SNI handling, URLs, browser behavior, or public-network
testing.

## Payload-Free Trace Discipline

Adaptive path fixtures, audits, and generated outputs store only safe classes,
counts, buckets, hashes, flags, and conclusions. Forbidden material includes raw
payloads, raw bytes, endpoint data, domains, SNI, host headers, URLs, DNS
queries, resolver addresses, cloud metadata, keys, nonces, auth tags, proofs,
and secrets.

## Mutants

M27 adds mutants for collapsed candidate families, stale success treated as
fresh, ignored recent failure, ignored relay burn, ignored poisoning,
blackhole, or UDP-block signals, high-risk default eligibility, unknown
candidates marked usable, endpoint leaks, payload leaks, secret leaks, and
generated-backend drift.

## Audit Gates

The adaptive path audit gates cover:

- candidate taxonomy
- synthetic condition model
- freshness and uncertainty
- viability evaluation
- decision inputs
- misuse detection
- generated-backend parity
- trace hygiene
- mutant detection
- fixture drift
- public roadmap cleanup

## Commands

```bash
go run ./cmd/kcheck adaptivepath --quick
go run ./cmd/kcheck adaptivepath --full --out testdata/audit/adaptivepath.json
go run ./cmd/kcheck adaptivepath generate --out testdata/adaptivepath/path-candidates-golden.json --force
go run ./cmd/kcheck adaptivepath verify
go run ./cmd/kcheck adaptivepath compare --old testdata/adaptivepath/path-candidates-golden.json --new testdata/adaptivepath/path-candidates-golden.json
go run ./cmd/kcheck --quick --status STATUS.md
```

## Limitations

The model proves only deterministic local behavior. It cannot prove real-world
reachability, censorship resistance, stealth, safety in a specific country, or
field readiness. It also does not define a generated transport bundle, path
racing algorithm, health monitoring loop, measurement client, or egress bridge.

## Next Milestone

M28 should focus on the generated transport bundle compiler.

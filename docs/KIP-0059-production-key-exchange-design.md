<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0059: Production Key Exchange Design

## Purpose

Milestone 53 defines the production-oriented key exchange design contract for Kurdistan. It is a review package for later relay authentication, rotation, compatibility, Android, and independent cryptography review work.

This milestone does not implement a new production cryptographic protocol. It freezes what the future design must bind, reject, expose safely, and prove before later implementation milestones can rely on it.

## Design Scope

The `internal/keyexchangeplan` package defines safe, deterministic reports for:

- key exchange design inventory
- handshake transcript binding
- profile identity binding
- relay identity binding
- client ephemeral key policy
- relay static/rotating key policy
- nonce and replay policy
- downgrade resistance
- version negotiation boundary
- algorithm agility boundary
- forward secrecy and recovery goals
- key separation and exported-secret policy
- session resumption policy
- rotation readiness
- generated transport compatibility
- external cryptography review package requirements

## Contract Summary

The M53 contract requires profile identity, relay identity, client ephemeral policy, relay rotation epoch, version floor, algorithm suite bucket, generated transport compatibility, and capability policy to be bound into the handshake transcript.

The plan requires directional nonce spaces, bounded replay windows, downgrade rejection, named suite registries, context-labeled key separation, and explicit external review artifacts before stronger claims can be made.

## Blocked Behavior

M53 blocks custom primitive design, secret logging, nonce logging, auth tag logging, proof material logging, private key fixture persistence, silent downgrade, unauthenticated relay identity, profile/version confusion, replay acceptance, key reuse across contexts, independent review bypass, and deployment claims.

## Fixtures

Fixtures under `testdata/keyexchangeplan/` contain only policy names, bucket names, counts, hashes, and hygiene flags. They do not contain raw payloads, keys, nonce values, auth tags, proof material, private keys, session secrets, endpoint data, domains, SNI, Host headers, DNS queries, or provider metadata.

The golden fixture is:

```text
testdata/keyexchangeplan/keyexchangeplan-report-golden.json
```

Companion reports break out the design inventory, transcript binding, identity binding, nonce/replay, downgrade resistance, key separation, rotation readiness, generated transport compatibility, external review readiness, misuse detection, trace hygiene, public claim safety, and generated parity.

## Audit Gates

`kcheck keyexchangeplan` reports:

- `keyexchangeplan_design_inventory`
- `keyexchangeplan_transcript_binding`
- `keyexchangeplan_identity_binding`
- `keyexchangeplan_nonce_replay`
- `keyexchangeplan_downgrade_resistance`
- `keyexchangeplan_key_separation`
- `keyexchangeplan_rotation_readiness`
- `keyexchangeplan_generated_transport_compatibility`
- `keyexchangeplan_external_crypto_review_readiness`
- `keyexchangeplan_misuse_detection`
- `keyexchangeplan_generated_backend_parity`
- `keyexchangeplan_trace_hygiene`
- `keyexchangeplan_public_claim_safety`
- `keyexchangeplan_fixture_drift`

## Commands

```bash
go run ./cmd/kcheck keyexchangeplan --quick
go run ./cmd/kcheck keyexchangeplan --full --out testdata/audit/keyexchangeplan.json
go run ./cmd/kcheck keyexchangeplan generate --out testdata/keyexchangeplan/keyexchangeplan-report-golden.json --force
go run ./cmd/kcheck keyexchangeplan verify
go run ./cmd/kcheck keyexchangeplan compare --old testdata/keyexchangeplan/keyexchangeplan-report-golden.json --new testdata/keyexchangeplan/keyexchangeplan-report-golden.json
```

Generated modules include key exchange design constants and tests:

```text
protocol/keyexchangeplan_generated.go
protocol/keyexchangeplan_test.go
protocol/keyexchangeplan_parity_test.go
protocol/keyexchangeplan_hygiene_test.go
```

## Limitations

M53 is not an independent cryptography review, not a production cryptography implementation, and not a deployment gate. It does not provide final relay authentication, rotation execution, Android integration, or field-test approval.

## M54 Handoff

M54 uses this contract to define relay authentication, rotation, and compatibility behavior without weakening downgrade resistance, replay rejection, generated transport compatibility, or trace hygiene. M55 should harden the resulting relay operational semantics while keeping public relay provisioning, account tracking, payload logging, packet capture, and field-test behavior out of scope.

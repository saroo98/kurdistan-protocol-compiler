<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0058: Relay Process Architecture

Milestone 52 defines the long-running client and relay process architecture that will eventually host Kurdistan runtime sessions outside single-shot lab harnesses. It is an architecture and review milestone. It does not provision public relays, deploy services, change production key exchange, collect user traffic, or enable public-network operation.

## Scope

The `internal/relayprocess` package freezes deterministic contracts for:

- client process role
- relay process role
- supervisor process role
- config loading policy
- profile bundle loading policy
- service, session, carrier, listener, and egress lifecycle
- logging and observability policy
- graceful shutdown and crash recovery policy
- compatibility, upgrade, and rollback policy
- bounded resource policy
- abuse-control placeholder policy
- M53 production key exchange design preconditions

## Blocked Behavior

The architecture blocks:

- production relay provisioning
- public deployment defaults
- real user account systems
- payload logging
- packet capture
- secret logging
- cloud provider integration
- public observability upload
- unreviewed auto-update
- production key exchange changes
- Android behavior
- field-test tooling

## Fixture Set

Committed fixtures live in `testdata/relayprocess/`:

- `relayprocess-report-golden.json`
- `process-role-inventory.json`
- `config-contract.json`
- `lifecycle-contract.json`
- `logging-observability-contract.json`
- `shutdown-crash-recovery-contract.json`
- `compatibility-contract.json`
- `resource-contract.json`
- `abuse-control-placeholder-contract.json`
- `m53-preconditions.json`
- `misuse-report.json`
- `trace-hygiene-report.json`
- `public-claim-safety-report.json`
- `relayprocess-parity-report.json`

Fixtures contain only roles, states, classes, buckets, counts, hashes, and hygiene flags. They do not contain payloads, packet captures, endpoint values, account data, cloud metadata, secrets, keys, nonces, auth tags, or proof material.

## Audit Gates

Run:

```bash
go run ./cmd/kcheck relayprocess --quick
go run ./cmd/kcheck relayprocess --full --out testdata/audit/relayprocess.json
go run ./cmd/kcheck relayprocess generate --out testdata/relayprocess/relayprocess-report-golden.json --force
go run ./cmd/kcheck relayprocess verify
go run ./cmd/kcheck relayprocess compare --old testdata/relayprocess/relayprocess-report-golden.json --new testdata/relayprocess/relayprocess-report-golden.json
```

`testdata/audit/relayprocess.json` is an ignored local audit artifact.

## Generated Backend

Generated modules include relay process constants and tests through `protocol/relayprocess_generated.go`, `protocol/relayprocess_test.go`, `protocol/relayprocess_parity_test.go`, and `protocol/relayprocess_hygiene_test.go`. The generated markers bind the process architecture to the selected profile, carrier, adapter, and security policy classes without adding process deployment behavior.

## M53 Design Handoff

M53 now defines the production key exchange design contract. M52 leaves production keying changes blocked until later milestones implement relay authentication, rotation behavior, compatibility execution, and generated-backend parity under that contract.

## Limitations

M52 is not a daemon implementation, deployment system, public relay, or production operations layer. It defines safe process contracts and deterministic review fixtures so later work can add process prototypes without weakening logging, lifecycle, resource, or compatibility boundaries.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0067: Stage 6A Version Migration Boundary

## Status

Implemented as a local strict-candidate migration boundary. This KIP does not
authorize production cryptography, external networking, an Android VPN, or a
distributed relay deployment.

## Atomic cutover

The serialized profile tuple moved atomically:

| Operand | Old | Current |
|---|---|---|
| `Profile.Version` | `0.1.0-lab` | `0.2.0-lab` |
| `Compatibility.SchemaVersion` | `0.1.0-lab` | `0.2.0-lab` |
| `Security.SecurityVersion` | `0.12.0-lab` | `0.13.0-lab` |
| `Compatibility.CompilerSecurityVersion` | `0.12.0-lab` | `0.13.0-lab` |
| `Compatibility.MinimumRuntimeVersion` | `0.12.0-lab` | `0.13.0-lab` |

Strict generated evidence exposes exactly:

- `ProtocolSchemaVersion="0.2.0-lab"`
- `SecurityVersion="0.13.0-lab"`
- `RuntimeSecurityVersion="0.13.0-lab"`
- `HandshakeVersion="kurdistan-handshake-v1"`
- `PolicyEncodingVersion="policy-v1"`
- `RecordVersion="record-v1"`

## Offline-only migration

Normal decoding and live runtime admission are single-new-read. They do not
silently recognize, convert, or accept the old tuple. Exact old input returns
`ErrMigrationRequired`; malformed input returns `ErrProfileMalformed`; unknown
or future tuples return `ErrProfileVersionUnsupported`; mixed recognized tuples
return `ErrProfileVersionMismatch`; and current semantic/hash failures return
`ErrProfileInvalid`. Live loading rejects before handshake entropy or protected
records are created.

The only transformation is the explicit offline
`internal/crypto/profilemigration` leaf. Its authorization token is an opaque,
in-process anti-accident capability, not proof of human approval, ownership, or
production key management. With a valid token, exact legacy input is converted
by changing only the five tuple operands and recomputing `GenerationHash`.
Invalid categories remain distinct beneath the constant migration failure
surface. Runtime, commands, generated output, product models, and relays cannot
invoke this migration implicitly.

The public error ordering is fixed:

| Entry point or condition | Result |
|---|---|
| missing or invalid offline token | `ErrMigrationAuthorizationInvalid` before input classification |
| valid token with current-valid input | `ErrMigrationNotRequired` |
| malformed, mixed, future, or semantically invalid input | `ErrMigrationFailed` plus the exact IR category |
| valid legacy profile that does not match the authorized source | `ErrMigrationSourceMismatch` only |
| live load malformed/version/migration-required/invalid input | `ErrProfileLoad` plus the exact IR category |
| decoded current profile with unexpected ID or hash | `ErrProfileLoad` plus `ErrProfileMismatch` |
| decoded and matched profile failing runtime compatibility | `ErrCompatibility`, without a raw profile operand |

No error path performs live conversion. The legacy decoder is reachable only
from the offline migration leaf and its focused tests.

## Generated authorization evidence

Strict code generation is authorized by a reviewed role-separated catalog.
The independently frozen default audit fixture covers seeds 1 through 8; an
explicit range requires an exact `explicit_v1` catalog. Catalog entries and
their client/relay pins belong to codegen authorization and manifest metadata.
They are never emitted into `strictv1/runtime.go` and never become a default or
profile-derived runtime registry.

Only `strictv1/runtime.go` is strict generated evidence. It receives caller
supplied `ClientProfileAuthorizationRegistryV1` and
`RelayProfileAuthorizationRegistryV1` values through `NewStrictRuntimeV1`.
Sibling generated `protocol/**` and `cmd/**` files remain legacy parity-only and
non-evidentiary. They may retain existing lab imports and deterministic demo
material, but are unreachable from the strict surface and product/runtime
evidence.

## Hashes and goldens

The cutover deliberately regenerated the characterization rows whose five
version operands or derived hashes changed. Catalog canonical hashes and all
generated-source pre/post hashes are reviewed separately. Unrelated trace,
frame, behavior, or payload fields were not treated as migration drift.

WO-044 was authorized against sealed Git-visible repository state
`fe1f8b853cfd2ff790cefc1f7da7b70dfee0e4a6c67b8ed16140b51541e51610`;
the preserved prior lifecycle artifact has SHA-256
`117d07f338342048e0d5c48cf41021828b70abd7d68aaa7cafdfb1d7a3469ad5`.
Exact per-file hashes were not captured at the WO-044 execution boundary, so
the implementation does not relabel `HEAD` blobs as pre-WO evidence. Instead,
the guard records a deterministic six-path post-state manifest and binds it to
the named sealed repository state and lifecycle artifact. Any later comparison
must use that explicit post manifest or a newly sealed lifecycle.

## Rollback and replan

Rollback means restoring the complete pre-cutover code and its matching
goldens. Mixing old aliases with current profiles is not a rollback. A new
tuple, live dual-read, another migration caller, a changed catalog format, a
new generated evidence file, or production use requires a new explicit work
order, deliberate fixture review, and revalidation of the full gate.

## Safety boundary

This evidence is local and loopback-only. It contains no payloads, credentials,
destinations, or production secrets, makes no undetectability or censorship-
resistance guarantee, and does not instruct clients to contact an external
service.

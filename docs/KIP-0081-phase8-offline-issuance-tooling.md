# KIP-0081: Phase 8 Offline Issuance and Reference Tooling

Status: implemented offline contract

WO-806 provides a provider-neutral path to compile canonical profiles, sign
them, optionally seal them to an authorized recipient class, verify them, and
produce a bounded redacted inspection. Each request explicitly binds artifact
class, audience, suite, issuer role and scope, opaque issuer key handle,
generation floor, current time, expiry, and recipient binding when applicable.

Production packages contain no private key, deterministic randomness, embedded
provider, environment-selected key path, network client, listener, or service.
Signing and recipient operations use opaque host-provider interfaces. Sealed
providers receive the exact authenticated outer-protected bytes and use the
Phase 8 info and AAD builders. Deterministic provider material exists only under
`internal/testkit/phase8issuance`; AST and import tests keep it unreachable from
the product package and `cmd/kprofile` wiring.

`kprofile compile` writes a new canonical file with exclusive creation and never
overwrites. `kprofile inspect` is explicitly structural-only (`verified=false`)
and prints generation, expiry, and a digest only. Provider-backed sign, seal,
and verification remain package APIs for an authorized offline host. This
repository does not pretend to ship an HSM or KMS adapter.

Deterministic fixtures cover all four artifact classes. Their no-overwrite
generator, manifest, and six bound reports live under
`internal/product/profile/testdata/phase8-issuance/`.

The tooling starts no service, performs no networking, embeds no real endpoint
or key, and makes no production operational-security claim.

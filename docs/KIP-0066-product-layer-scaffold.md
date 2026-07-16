<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0066: Product Layer Scaffold (contracts-only)

- status: requirements-lock
- last_verified: 2026-07-15
- Work orders: Stage 8 (WO-801 design-lock, WO-802 envelope, WO-803 strategy, WO-804 android); gated by D-002 (build = yes) and D-003 (crypto path).

Milestone 60 lays honest, contract-only homes for a future product layer without
implementing any live VPN, relay, carrier, or cryptography. It adds
`internal/product/{envelope,strategy,android}` as `[plan]`/`[model]` design
contracts behind the `internal/testkit/importrules` boundary. Nothing in the live
runtime imports these packages, and no real sockets, packet capture, or
production cryptography are introduced.

This milestone is a scaffold and on-ramp. It does not claim undetectability,
guaranteed bypass, or censorship resistance, and it does not ship a product.

## M2 contract-catalog relationship

- **[evidence]** The Go packages described below remain contracts and models. They
  do not provide an Android application, device VPN integration, live transport,
  relay service, profile authority, operator service, or deployment system.
- **[requirement]** KIP-0069 freezes six implementation-neutral product contracts
  that any later executable design must satisfy: verified profile, fallback,
  relay descriptor, revocation and update, diagnostic export, and app runtime.
- **[future gate]** Each contract remains non-executable until a later milestone
  explicitly opens its trust boundary, supplies biting tests, and proves safe
  failure, privacy, compatibility, recovery, and rollback behavior.

KIP-0070 later opened the verified-profile and lifecycle contracts as offline,
deterministic Go contracts in `internal/product/{profile,lifecycle}`. KIP-0071
opens the permitted-fallback entry only as an offline metadata selector.
KIP-0072 opens relay-descriptor admission only as deterministic structural
validation in `internal/product/relaydescriptor`. These contracts do not
authenticate relay descriptors, probe paths, execute fallbacks, establish relay
sessions, or open runtime behavior. Diagnostic export and app runtime remain
closed.

The catalog does not define a wire schema, service API, storage format, network
endpoint, cryptographic construction, or application implementation. M3 and
later product behavior remains closed.

## Scope limits (hard)

- No live VpnService, TUN, packet capture, or non-loopback networking.
- No real profile encryption or production cryptography. Sealing is an interface
  only; real sealing is gated on external cryptographic review (D-003).
- No public relays, operator provisioning, or field-test tooling.
- No Kotlin/Java or Gradle build wired.
- The product runtime must not import the model/contract trees (enforced by
  `internal/testkit/importrules`).

## kurd:// envelope contract (`internal/product/envelope`)

A `kurd://` link is a profile-distribution envelope that carries metadata and an
opaque profile reference only — never payloads, secrets, keys, or raw profile
material. `Parse`/`Format`/`Validate` enforce the shape and the safety
invariants:

- issuer, opaque profile reference, positive expiry, revocation id, and
  compatibility version are required;
- the reference must be opaque (embedded key/secret/payload material is rejected);
- `payload_embedded` must be false;
- the only admitted seal mode is `unsealed_contract`; sealed modes await D-003.

The `Sealer` interface has no implementation. `UnavailableSealer` returns
`ErrSealingUnavailable` for both `Seal` and `Open`, because real sealing is
production cryptography gated on external review (D-003).

## Strategy selection surface (`internal/product/strategy`)

A profile-scoped, deterministic selector that **reuses** the existing carrier
design-review taxonomy (`carrierreview.DefaultDescriptors`) as a strict safety
ceiling: descriptors must validate and be default-eligible, synthetic-only,
not manual-review-required, and not blocked by risk. Permission always comes
from the admitted profile's ordered
policy. `Select` intersects that policy with client support, capabilities, and
mandatory safety/privacy floors, then returns one bounded selected result or an
explicit blocked result. Manual preference may promote only an already-eligible
family. It performs no probing, dialing, resolving, execution, or network I/O.

## Android source contract (`internal/product/android`)

A design contract for a future real `android/` Gradle tree, deliberately distinct
from the Go runtime models in `internal/contracts/android/**`. `Validate`
enforces the safety invariants: permission-first, fail-closed kill switch,
bounded fallback, redacted diagnostics, and no payload or destination logging. It
wires no Android build.

## Relay-descriptor admission (`internal/product/relaydescriptor`)

M5 recomputes an exact selected Phase 4 request/result before structurally
admitting exact profile-authorized relay metadata. It binds lifecycle, policy,
family, capabilities, bounded client identity, caller-supplied time, and a
complete revocation snapshot. Endpoint references remain opaque. The package
does not authenticate, resolve, dial, probe, operate, or deploy a relay.

## Verification

- `go build ./...` and `go run ./cmd/gate` are green.
- The `internal/testkit/importrules` boundary test confirms no live/real package
  imports `internal/product/**`.
- The package tests bite: each contract's `Validate` rejects unsafe or incomplete
  input (payload embedding, missing expiry, unbounded fallback, not fail-closed,
  secret-looking references), and sealing is proven unavailable.

## Out of scope / follow-ups

- `kcheck product` subcommand and a STATUS section (the safety checks currently
  run via `go test ./...`, which `go run ./cmd/gate` invokes).
- Real sealing, live Android sources, and live carrier transport. Each remains
  behind its own later authorization and validation gate.

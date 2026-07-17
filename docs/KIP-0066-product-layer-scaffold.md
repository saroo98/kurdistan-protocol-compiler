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
sessions, or open runtime behavior. KIP-0073 opens diagnostic export only as a
fixed-vocabulary, deterministic in-memory bundle after explicit preview and
confirmation. It writes, shares, uploads, logs, retains, and transmits nothing.
KIP-0074 opens only the offline app-runtime eligibility entry; live runtime
remains closed.
KIP-0075 opens the profile-artifact entry only as a staged Phase 8 offline
production-candidate program. It may replace the unavailable sealer and
metadata-only trust seam only after threat, suite, schema, key-role, state, and
review work orders freeze their contracts. It does not open Android key storage,
production keys or signers, HSM/KMS operation, live delivery, networking,
deployment, pilot, or release.

The catalog does not define a wire schema, service API, storage format, network
endpoint, cryptographic construction, or application implementation. M3 and
later product behavior remains closed.

## Scope limits (hard)

- No live VpnService, TUN, packet capture, or non-loopback networking.
- No production profile encryption, key material, or signing service. Phase 8
  may implement only the KIP-0075 offline production-candidate boundary with
  deterministic non-production keys and its mandatory review gates.
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

## Diagnostic export (`internal/product/diagnosticexport`)

M6 validates a fixed redacted vocabulary, bounds and canonicalizes its entries,
and enforces sealed prepare, preview, confirmation, build, and cancellation
states. It produces only an in-memory JSON value. It does not collect data,
write a file, invoke platform sharing, emit telemetry, or influence connection,
recovery, lifecycle, fallback, relay, or runtime decisions.

## App-runtime eligibility (`internal/product/appruntime`)

M7 opens the app-runtime catalog entry only as a pure offline eligibility state
machine. It recomputes exact fallback selection and relay admission, validates
caller-supplied platform-readiness booleans, and returns only categorical state
and disposition metadata. `ready_to_start` is not a live-start claim, and
`shutdown_required` is not a shutdown acknowledgment. The separate disconnect
API has no platform or predecessor prerequisites. The package performs no
Android, VpnService, TUN, storage, routing, DNS, network, process, telemetry, or
cryptographic action.

## Verification

- `go build ./...` and `go run ./cmd/gate` are green.
- The `internal/testkit/importrules` boundary test confirms no live/real package
  imports `internal/product/**`.
- The package tests bite: public validators and evaluators reject unsafe or
  incomplete input (payload embedding, missing expiry, unbounded fallback, not
  fail-closed, secret-looking references), and sealing is proven unavailable.

## Out of scope / follow-ups

- `kcheck product` subcommand and a STATUS section (the safety checks currently
  run via `go test ./...`, which `go run ./cmd/gate` invokes).
- Production sealing and key operation, live Android sources, and live carrier
  transport. Each remains behind its own later authorization and validation
  gate.

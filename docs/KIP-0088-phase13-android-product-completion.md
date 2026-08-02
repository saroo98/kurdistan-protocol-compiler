<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0088: Phase 13 Android product completion

Status: local implementation complete; release remains no-go pending the production program

Last updated: 2026-08-01

## Outcome

Phase 13 turns the existing Android foundation, protected profile store, bounded
VPN runtime, Kurd loopback transport, and Phase 12 operator contracts into one
coherent Android product. Every visible control must drive real persisted,
validated, or runtime behavior. Controls that require an unavailable public
relay, production authority, provider endpoint, or external operator service are
not represented as working controls.

The product remains profile-driven. A verified Kurd profile is the only source
of transport authority. Android preferences may narrow behavior but cannot add
an endpoint, strategy, route, or capability that the verified profile forbids.

## Product architecture

- `:core:model` owns immutable product, settings, routing, DNS, probe, provider,
  diagnostic, and connection models plus pure validation.
- `:data:settings` persists only nonsecret preferences in DataStore. Sensitive
  profile, provider, endpoint, credential, and authority material remains in the
  Phase 9 encrypted store and Go-owned verified artifacts.
- `:runtime:api` owns the versioned Android runtime command and status contract.
- `:runtime:android` applies validated Android routing, DNS, MTU, per-app, and
  lifecycle settings to `VpnService`. It cannot widen the signed session plan.
- Feature modules render state and emit typed user intent. They do not call JNI,
  Room, Keystore, file, camera, network, or service APIs directly.
- `:app` is the composition root and the sole owner of platform launchers,
  permission orchestration, navigation, and runtime coordination.

Manual dependency injection remains authoritative. Phase 13 does not add a
second dependency-injection or general MVI framework.

## Required product surfaces

1. Connection dashboard with one primary connect control, explicit lifecycle,
   active profile, Kurd protocol label, selection mode, path/strategy status,
   fallback status, packet counters, duration, protection state, failure reason,
   and diagnostics shortcut.
2. Profile and provider management with search, filter, sort, favorites,
   local probe, details, safe export, delete confirmation, expiry/rotation
   warnings, compatibility, and the complete bounded import surface.
3. Settings index covering connection, tunnel, routing, DNS, updates and probes,
   appearance and accessibility, privacy and recovery, diagnostics, about, and
   validated expert controls.
4. Per-app routing using launchable application discovery without
   `QUERY_ALL_PACKAGES`, include/exclude semantics, search, and explicit bypass
   warnings.
5. DNS policy with a private in-tunnel default, validated custom addresses, IP
   family selection, and leak-resistant fail-closed behavior. Public resolver
   presets are configuration choices, not privacy guarantees.
6. Recovery controls for permission denial, revoked VPN authority, key
   invalidation, storage degradation, repeated runtime failure, and explicit
   Internet recovery.
7. Operator integration that exposes verified profile generation, expiry,
   compatibility, relay-plan status, and signed-update readiness without
   embedding operator credentials or bypassing Phase 8/12 authority.

## Runtime configuration

The service accepts a bounded `VpnRuntimeConfig` containing:

- per-app routing mode and a validated package set;
- IPv4/IPv6 preference;
- DNS mode and validated addresses;
- allow-LAN policy;
- MTU in the supported range;
- metered declaration;
- reconnect policy and user-visible notification detail.

Phase 13 does not add direct egress, an unauthenticated local proxy, a hotspot
proxy, or a transport that bypasses Kurd. Proxy-only and hotspot modes remain
closed until they can use an authenticated Kurd relay path and pass successor
network, privacy, and abuse-surface validation.

## Privacy and accessibility

- Telemetry, remote crash reporting, remote configuration, advertising IDs,
  hardware identifiers, and automatic support upload remain absent.
- Logs and diagnostics remain categorical and redacted. Payloads, destinations,
  profile bytes, keys, credentials, tokens, and raw device identifiers are
  forbidden.
- The product supports English, Sorani Kurdish, Kurmanji, Persian, and Arabic,
  correct RTL, 200 percent text, TalkBack, Switch Access, keyboard and D-pad,
  high contrast, reduced motion, landscape, tablet, and foldable layouts.
- Every interactive element has a semantic role, meaningful label, enabled and
  disabled explanation, and at least the platform minimum touch target.

## Acceptance

Phase 13 requires:

- pure model and persistence tests for every setting, bound, migration, and
  invalid value;
- runtime tests proving each accepted routing and DNS setting changes the
  resulting VPN builder policy or fails before service establishment;
- Compose tests that invoke every screen and control, including destructive,
  permission-denied, empty, loading, error, and recovery states;
- automated accessibility checks and pseudo-locale coverage;
- emulator tests for import, profile selection, connect, stop, per-app policy,
  DNS policy, process death, revoke, failure recovery, diagnostics, backup,
  restore, and reset;
- the existing Go, Phase 9, Phase 10, Phase 11, and Phase 12 gates;
- a new cache-independent `phase13Gate` and a device gate that reject zero-test,
  crash, ANR, secret-canary, permission, manifest, or unsupported-claim passes;
- a feature-coverage map that classifies every product requirement as delivered,
  safely replaced, inapplicable, or successor-phase external evidence.

## External evidence boundary

Owned non-loopback relays, production profile authorities, provider services,
operator identity, production signing, store delivery, OEM diversity, hostile
networks, field censorship resilience, incident response, and public release
remain **[UNVERIFIED]** until the production and field phases observe them in
explicitly authorized environments.

Phase 13 must not be called uncensorable, undetectable, anonymous,
production-ready, publicly deployed, fully audited, or guaranteed to bypass
blocking.

## Local closure

The cache-independent Go and Android host gates pass. The exact Phase 13 device
manifest passes on API 26, API 34, and API 36 x86_64 emulators with clean
application-crash buffers. API 26 executes the 25 cases applicable below API
34; API 34 and API 36 execute all 26 cases, including the platform automated
accessibility assertion. These results close the locally demonstrable Phase 13
scope only. They do not replace the physical-device, provider, relay, field,
signing, distribution, or release evidence assigned to Phases 16-22.

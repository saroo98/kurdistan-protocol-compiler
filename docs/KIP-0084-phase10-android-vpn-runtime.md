<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0084: Phase 10 Android VPN runtime

## Status

Implemented as a bounded local runtime candidate. Emulator evidence is required
by `phase10DeviceGate`. Physical-device, OEM, network-handover, and live relay
evidence remain **[UNVERIFIED]** and are not implied by this status.

## Scope

Phase 10 introduces the first real Android `VpnService` and TUN data path. It is
deliberately constrained to the IANA benchmarking range `198.18.0.0/15` and a
deterministic virtual DNS address at `198.18.0.53`. It can answer only:

- UDP echo on port 5353; and
- an A query for `phase10.test`, returning `198.18.0.42`.

The runtime does not connect to a relay, proxy general traffic, provide Internet
access, or claim a kill switch. Live Kurd transport and relays remain Phase 11.
The application therefore does not request `android.permission.INTERNET`; the
separate instrumentation APK owns the socket permission needed to inject its
reserved-range device probes.

## Architecture

- The UI remains in the default application process.
- `KurdVpnService` runs in the private `:vpn` process.
- The service is non-exported and protected by
  `android.permission.BIND_VPN_SERVICE`.
- Startup requires Android VPN consent and an already verified local profile.
- The foreground service uses the Android `specialUse` VPN declaration.
- The default policy includes only the application package. All-app routing
  requires an explicit policy.
- Include-only and exclude-selected policies are mutually exclusive, bounded,
  normalized, and validated before the VPN is established.
- A package-scoped, non-exported status query restores truthful state after the
  UI controller is recreated.
- Packet handling emits only bounded categorical dispositions and counters.
  Payloads and destination data are not logged.

IPv6 is not advertised by this phase. It was intentionally withheld because the
bounded responder and its emulator evidence cover IPv4 only. Dual-stack support
must not be claimed until equivalent IPv6 behavior and tests exist.

## Failure behavior

- Missing, malformed, or unauthorized start commands fail closed.
- Invalid per-app policies prevent establishment.
- A null `VpnService.Builder.establish()` result is a failure.
- Repeated start does not establish a second TUN.
- Stop and revoke close the packet loop and descriptor before final status.
- UI recreation queries the running service rather than assuming it is idle.
- Unsupported packets, addresses, ports, fragments, DNS names, and DNS forms
  receive no reply.

## Automated evidence

`phase10Gate` requires:

- release and internal Android builds;
- release lint;
- Android unit tests, including runtime API, routing policy, packet engine, DNS,
  secure storage, metadata, and import paths;
- compilation of device tests;
- a CycloneDX dependency inventory;
- merged-manifest and APK inspection;
- exact native ABI and symbol checks inherited from Phase 9;
- rejection of exported VPN service, cleartext opt-in, network-state permission,
  `allowBypass`, analytics, crash telemetry, and unapproved HTTP stacks.

`phase10DeviceGate` installs the application and instrumentation APK, grants
emulator VPN consent for the test package, rejects crash/ANR evidence, and
requires at least seven real instrumentation tests. Its VPN scenarios prove:

- a separate UID included by policy can traverse the TUN;
- UDP echo and deterministic DNS receive exact local replies;
- a recreated UI controller recovers the active service state;
- the service stops cleanly; and
- an excluded UID cannot reach the reserved runtime.

## Evidence still required later

The following cannot be established by the current single emulator and are
therefore **[UNVERIFIED]**:

- physical-device behavior across supported Android and OEM versions;
- always-on and lockdown behavior under device policy;
- cellular/Wi-Fi handover, captive portals, sleep, reboot, and low-memory kills;
- IPv6, general DNS forwarding, full routing, per-app inventory UI, and kill
  switch semantics;
- live Kurd transport, relay compatibility, censorship-resilience measurements,
  and external network security;
- independent accessibility, privacy, and security review;
- signed production distribution and cross-host reproducibility.

These are not blockers to the bounded local Phase 10 implementation. They are
explicit acceptance gates for the later product phases that own those claims.

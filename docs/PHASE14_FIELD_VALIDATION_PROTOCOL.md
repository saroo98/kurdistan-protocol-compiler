<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 14 controlled field-validation protocol

Status: protocol ready; execution **[UNVERIFIED]**

## Authorization and privacy boundary

Field work is limited to devices, accounts, networks, providers, and relays
owned by the project or explicitly authorized in writing for the campaign. The
campaign record stores an authorization receipt digest, not the authorization
document or personal identity.

Collection is categorical and minimal: random session alias, Android API band,
coarse device class, coarse OEM family alias, network-transition category,
runtime state, latency/jitter/loss buckets, failure category, recovery result,
resource bounds, and artifact digest. Payloads, destinations, DNS questions,
profile bytes, keys, credentials, package inventories, phone numbers, precise
location, IP addresses, hardware identifiers, and user content are prohibited.

## Entry gate

Do not begin a field campaign until:

1. the exact candidate artifact is reproducible and digest-pinned;
2. production authority, provider, relay, monitoring, rollback, and emergency
   deny are operational on owned infrastructure;
3. the release candidate passes `phase14Gate` and the exact emulator matrix;
4. operator on-call, incident, rollback, and data-retention owners are named by
   role alias;
5. the campaign authorization and stop conditions are approved;
6. a clean rollback target is installed and tested.

## Device matrix

The minimum matrix covers:

- Android API 26, 29, 31, 34, and 36 or their supported production equivalents;
- low-memory/slow-storage, mainstream, flagship, tablet, and foldable classes;
- at least four materially different OEM Android implementations;
- 32-bit only where the release still claims support, ARM64, and every shipped
  native ABI;
- fresh install, upgrade, restore, key invalidation, low storage, battery saver,
  background restriction, reboot, and process death.

Unsupported hardware is removed from the compatibility claim rather than
silently omitted from the matrix.

## Network and resilience matrix

- Wi-Fi to cellular and cellular to Wi-Fi handover;
- loss, latency, jitter, reordering, constrained bandwidth, and intermittent
  reachability within the authorized environment;
- captive portal arrival and exit;
- device sleep, doze, battery saver, data saver, metered networks, and roaming;
- relay drain, rotation, revocation, profile expiry, provider rollback rejection,
  emergency deny, and controlled relay failure;
- DNS failure and leak detection using owned test domains;
- safe fallback only among strategies authorized by the signed profile;
- emergency Recover Internet, scoped reset, backup/restore, and rollback.

## Stop conditions

Stop the campaign immediately for any payload/secret exposure, traffic bypass,
DNS escape, authority widening, rollback acceptance, kill-switch failure,
unbounded resource growth, crash loop, unexplained data collection, operator
loss of control, or severity-critical issue. Preserve only redacted evidence,
revoke affected artifacts, and execute the incident and rollback runbooks.

## Exit criteria

Field evidence may become `PASS` only when the complete declared matrix has run
against the exact release candidate, all critical workflows succeed, no open
critical/high defect remains, privacy canaries remain absent, recovery drills
meet their declared objectives, and the result has an independent review
receipt. Anything less remains **[UNVERIFIED]** or `FAIL`.

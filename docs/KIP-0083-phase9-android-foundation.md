<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0083: Phase 9 Android Foundation and Protected Local State

Status: implemented locally; merge eligibility gated

Last verified: 2026-07-28

Work orders: WO-900 through WO-909

## Decision

Phase 9 creates a native Android application foundation around the existing Go
engine. The app imports bounded profile artifacts offline, asks the real Phase 8
Go implementation to normalize and verify them, presents a redacted preview,
requires explicit confirmation, persists exact bytes under application-layer
envelope encryption, reopens and reverifies them before activation, and recovers
transactionally after process or storage failure.

The Android build is a standalone `android/` Gradle root. The existing Go module
and its default gate remain independently usable. A versioned
`kurd-android-bridge-v1` C ABI and a thin JNI adapter are the only Android entry
points into Go. Kotlin must not reproduce Phase 8 profile cryptography, trust,
ingress normalization, lifecycle, diagnostic, or activation decisions.

Phase 9 also provides local-only settings, recovery, privacy, diagnostics,
passphrase-encrypted backup/restore, localization, accessibility, dependency
integrity, and reproducibility evidence. Production and release variants start
with an empty profile-authority trust store. Deterministic Phase 8 authorities
are restricted to tests and the internal demonstration variant.

## Scope and non-goals

Authorized:

- a native single-activity Android application using Compose;
- offline file, canonical `kurd://artifact/`, clipboard, share-intent, and QR
  profile ingress;
- a bounded Go C ABI and JNI adapter;
- Android Keystore-wrapped per-record data-encryption keys;
- encrypted artifacts under `noBackupFilesDir` and a minimal nonsecret Room
  transaction catalog;
- nonsecret DataStore preferences;
- local diagnostics, privacy controls, reset, and backup/restore;
- deterministic test authorities in non-release variants only.

Not authorized:

- `VpnService`, TUN, packet routing, DNS, kill switch, proxying, or live
  connection states;
- `INTERNET`, network-state, foreground-service, or VPN binding permissions;
- provider networking, remote configuration, analytics, telemetry, crash
  reporting, automatic support upload, or install identifiers;
- production authorities, production signing material, provider feeds, live
  relays, production deployment, store distribution, or public-release claims;
- translation of untrusted external formats into native trust.

The app must never claim to be uncensorable, undetectable, anonymous,
production-ready, fully audited, or guaranteed to bypass blocking. Phase 9
evidence is offline product-foundation evidence only.

## Frozen toolchain

The Android build pins:

- `minSdk 26`, `compileSdk 36`, `targetSdk 36`;
- Android Gradle Plugin 9.2.1 and Gradle 9.4.1;
- AGP built-in Kotlin 2.3.10 and JDK 17;
- Build Tools 36.0.0 and NDK 28.2.13676358;
- Go 1.26.5.

Kotlin DSL, a version catalog, dependency locks, strict checksum verification,
centralized repository content filters, and SHA-pinned CI actions are required.
Dynamic versions and production signing material are forbidden.

## Module and dependency boundaries

The module graph is:

```text
:app
:core:model
:core:ui
:domain
:core:native-api
:core:native-jni
:data:metadata
:data:secure
:data:settings
:platform:import
:runtime:api
:feature:home
:feature:profiles
:feature:settings-recovery
:feature:diagnostics-about
:benchmark
:test:fixtures
```

Features depend only on `:domain`, `:core:model`, and `:core:ui`. UI code cannot
call JNI, Room, Keystore, camera, files, or external intents directly.
`:core:native-jni` is the sole Android caller of the Go bridge.
`:runtime:api` exposes only `UnavailableRuntime(PHASE_9_NO_RUNTIME)`.

## Native boundary

The `kurd-android-bridge-v1` ABI exposes only:

- `kvpn_abi_info`;
- `kvpn_verify_preview`;
- `kvpn_activation_open`, `kvpn_activation_next`,
  `kvpn_activation_submit`;
- `kvpn_diagnostic_prepare`, `kvpn_diagnostic_preview`,
  `kvpn_diagnostic_confirm`, `kvpn_diagnostic_build`;
- `kvpn_backup_create`, `kvpn_backup_open_preview`,
  `kvpn_backup_restore`;
- `kvpn_cancel`;
- `kvpn_free`.

Only bounded byte buffers, fixed enums, bounded scalar accessors, categorical
errors, and typed generation-bound handles cross the ABI. JSON, Java objects,
filesystem paths, raw Go errors, and unbounded strings are forbidden. Every
exported function recovers nonfatal Go panics into a categorical failure where
possible. Fatal native faults remain process-fatal and are handled by the
Android transaction journal.

The compatibility handshake binds bridge, Go core, profile schema, crypto
suite, strategy registry, relay schema, diagnostic schema, and input bounds.

## Protected storage

Room stores only random local record IDs, transaction state, envelope version,
key generation, and coarse categorical health. It must not contain profile,
provider, relay, destination, content-hash, exact-expiry, secret, or artifact
data in plaintext.

Each persisted record uses a random 256-bit AES data-encryption key and 96-bit
GCM nonce. Authenticated data binds the envelope version, random record ID,
data class, key generation, and exact ciphertext length. An Android Keystore
AES-256-GCM key-encryption key wraps each record key. StrongBox is attempted
only when supported; fallback is functional and reported truthfully.

Keystore invalidation preserves ciphertext and enters `KeyInvalidated`.
It never silently deletes data or regenerates a same-named key. Secure deletion
on flash is not claimed; cryptographic erasure is the enforceable control.
An explicit reset first removes every protected blob and catalog row, then
writes a durable reset marker, destroys the availability KEK, recreates an
empty database and fresh KEK, and clears the marker. Startup completes any
marker-backed reset interrupted between those steps before opening storage.

Activation states are:

```text
PREPARED -> STAGED -> REOPENED -> MARKED -> COMMITTED -> FINALIZED
                         \-> RECOVERY_REQUIRED -> QUARANTINED
```

The UI must not label a profile usable before exact-byte reopen, Go
reverification, and durable finalization.

## Import, backup, and privacy

Every import source feeds one bounded pipeline:

```text
source adapter
-> platform size/type bounds
-> bounded private staging
-> Go ingress normalization
-> Go verification
-> redacted preview
-> explicit confirmation
-> encrypted staging
-> reopen and Go reverification
-> activation transaction
-> final UI state
```

Multipart `KURD1/` QR state is memory-only, expires after five minutes, clears
on cancellation or backgrounding, and is session-bound.

`kurd-backup-v1` is implemented in Go with Argon2id at 64 MiB, three
iterations, parallelism one, and AES-256-GCM. The clear header contains only
magic, version, bounded KDF parameters, cipher identifier, random 128-bit salt,
random 96-bit nonce, and ciphertext length; the entire header is AAD. Parameter
bounds are checked before allocation. There is no extra HMAC and no
compression. Passphrases are exact UTF-8, 12 code points minimum, 1024 bytes
maximum, and are never normalized or truncated. Restore reverifies current
trust and monotonic lifecycle state before commit.

No secret may enter logs, screenshots, clipboard without explicit reveal,
notifications, crash artifacts, test reports, Room plaintext, diagnostics, or
unencrypted backups.

## Work orders and evidence

- WO-900: authority, threat model, data inventory, and evidence manifest.
- WO-901: pinned toolchain, module skeleton, variants, locks, and verification.
- WO-902: Go facade, C ABI, JNI, compatibility handshake, and activation parity.
- WO-903: envelope storage, Room journal, key rotation, recovery, and quarantine.
- WO-904: application state, original UI, navigation, and runtime-unavailable UI.
- WO-905: bounded imports, previews, profile management, and safe export.
- WO-906: localization, RTL, accessibility, adaptive layouts, and asset provenance.
- WO-907: `kurd-backup-v1`, diagnostics, privacy dashboard, retention, and reset.
- WO-908: SBOM, licenses, provenance, reproducibility, and tamper gates.
- WO-909: full acceptance, physical-device evidence, diff audit, and merge gate.

Repository evidence must distinguish source inspection, host tests, emulator
tests, and physical-device observations. Unavailable external or device
evidence is marked **[UNVERIFIED]** and blocks claims dependent on it.

The implementation evidence index is `docs/PHASE9_EVIDENCE_INDEX.md`. Recovery
and operator-safe failure handling are documented in
`docs/PHASE9_RECOVERY_RUNBOOK.md`. Canonical machine-readable evidence lives
under `testdata/evidence/phase9/`.

## Acceptance

Phase 9 requires all of the following:

- `go run ./cmd/gate`;
- `android/gradlew phase9Gate`;
- `go run ./cmd/gate -android`;
- clean Windows and Linux builds;
- manifest and bytecode proof that the release has no network or VPN capability;
- real Go verification for signed-public and sealed test artifacts;
- transaction failure tests at every persistence boundary;
- corruption, key invalidation, rollback, duplicate, substitution, and resource
  bound rejection tests;
- explicit-reset tests that destroy and recreate protected state, preserve a
  durable recovery marker across interruption, and leave no old blob usable;
- backup vector, malformed corpus, wrong-passphrase, parameter-bound,
  reinstall/restore, and selective-restore tests;
- secret-canary scans across all persisted and exported surfaces;
- RTL, TalkBack, Switch Access, keyboard, 200 percent text, reduced-motion,
  tablet, foldable, landscape, and low-memory evidence;
- dependency, wrapper, verification-metadata, CI-action, and native-symbol
  tamper tests that demonstrably turn their gates red;
- a physical-device offline workflow proving import, real verification,
  encrypted persistence, process-death recovery, backup/reinstall/restore,
  deletion, accessibility, no network traffic, and absence of VPN runtime.

Physical-device or external evidence that is unavailable remains
**[UNVERIFIED]**. It is not replaced by source inspection, local tests, or an
emulator.

The branch implementation has no production signing material and emits an
unsigned nonproduction release APK. A locally byte-identical two-clean-build
comparison is useful build evidence, but cross-host Windows/Linux equality
remains **[UNVERIFIED]** until CI artifacts are compared.

## Completion and next boundary

Phase 9 is complete only when WO-900 through WO-909 are implemented, the full
acceptance matrix is green, and the physical-device evidence is recorded.
Phase 10 remains separately gated and is the first phase allowed to introduce
`VpnService`, TUN, routing, DNS, kill-switch, and per-app rules.

Until the physical-device workflow, no-network packet capture, measured
performance/accessibility matrix, reviewed translations, and cross-host CI
results are recorded, this implementation must not be called complete,
production-ready, or eligible to merge into `main`.

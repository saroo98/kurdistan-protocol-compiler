<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Protocol Compiler

[![Go](https://img.shields.io/badge/Go-1.26.6-00ADD8?logo=go)](go.mod)
[![Android](https://img.shields.io/badge/Android-API%2026%2B-3DDC84?logo=android)](android/)
[![License](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)](LICENSE)
[![Release status](https://img.shields.io/badge/release-pre--release-orange)](#current-boundary)

Kurdistan is a profile-driven, self-hosted relay transport system for
censorship-resilient networking. The repository contains the Kurd protocol
compiler, authenticated transport/runtime components, native profile tooling,
self-hosted node administration, an Android VPN application, and an unusually
strict audit and regression system.

The project is designed for independent deployments. Each operator controls
their own VPS, authority keys, profiles, backups, and data. The architecture
does not require a Kurdistan account, central relay directory, analytics
service, advertising system, product-wide shutdown authority, or mandatory
cloud vendor.

> [!IMPORTANT]
> This is pre-release software. The compiler, local authority, Android
> foundation, and controlled conformance paths are implemented, but the public
> non-loopback relay and unrestricted Internet-egress path are not yet part of
> a released production build. Source presence and local tests do not prove
> censorship bypass, undetectability, anonymity, or production readiness.

## Why Kurdistan is different

Traditional transports usually ship one fixed protocol implementation.
Kurdistan instead compiles bounded protocol behavior from a profile while
preserving common authenticated stream semantics. Profiles can vary framing,
state transitions, scheduling, padding, probing, carrier policy, permitted
fallback, and other observable behavior without granting the client authority
outside the signed profile.

The product model is deliberately decentralized:

- a deployment owner creates and controls their own authority;
- `kurdctl` issues, rotates, revokes, backs up, and recovers native profiles;
- `kurd-node` runs as a hardened, non-root service on an owner-controlled VPS;
- Android imports an explicit `kurd://` profile and confirms the deployment
  fingerprint before trust;
- profiles are signed and can be sealed for a recipient;
- no telemetry, advertising, remote crash reporting, or central traffic log is
  required;
- one deployment cannot revoke or disable another independent deployment.

The native profile and QR formats are Kurd-specific. They are interoperable by
design and therefore cannot honestly be made impossible for independent
developers to implement.

## Components

| Component | Purpose |
| --- | --- |
| `cmd/kdc` | Generate and validate deterministic compiler profiles and transport bundles. |
| `cmd/kgen` | Emit profile-specific Go source modules. |
| `cmd/kcheck` | Run adversarial, mutation, parity, runtime, and security audits. |
| `cmd/gate` | Execute the repository build, vet, test, audit, and product gates. |
| `cmd/kurdctl` | Initialize and administer a deployment-local authority, profiles, recovery, backup, and upgrades. |
| `cmd/kurd-node` | Run the hardened self-hosted node service. |
| `cmd/kurdpackage` | Build and verify deterministic native Linux engineering archives. |
| `internal/protocol` | Compiler IR, framing, state machine, scheduling, stream, and padding primitives. |
| `internal/crypto` | Authentication, transcript binding, nonce/replay, and profile-security implementation. |
| `internal/runtime` | Session lifecycle, compatibility, stream management, and policy enforcement. |
| `internal/selfhost` | Portable local authority, publication, backup, recovery, and node administration. |
| `android/` | Native Android application, protected local state, profile admission, and bounded `VpnService` runtime. |

## Implemented capabilities

### Protocol compiler and runtime

- deterministic profile generation from seeds;
- generated state machines, framing grammars, scheduler and padding policy;
- authenticated multi-stream semantics with flow control and backpressure;
- transcript binding, nonce management, replay rejection, downgrade checks,
  compatibility negotiation, and fail-closed policy enforcement;
- profile-specific generated Go source modules;
- payload-free trace capture and deterministic characterization fixtures.

### Profiles and self-hosting

- canonical signed and recipient-sealed profile artifacts;
- bounded file, URI, clipboard, share-intent, and QR admission;
- deployment-local root, online issuer, and relay identity;
- explicit first-trust deployment fingerprint;
- monotonic generations, expiry, rotation, revocation, and deployment-local
  emergency disable;
- encrypted recovery material and authenticated backups;
- host-loss recovery with rollback protection;
- deterministic amd64 and arm64 Linux engineering packages;
- hardened systemd service and optional isolated container adapter.

### Android application

- native Android application supporting API 26 and newer;
- encrypted profile storage backed by Android Keystore;
- real Go verification through a bounded native bridge;
- profile import preview, explicit confirmation, duplicate handling, and
  recovery states;
- bounded `VpnService` and TUN lifecycle implementation;
- routing, DNS, diagnostics, privacy, backup, accessibility, localization, and
  recovery foundations;
- English, Sorani Kurdish, Kurmanji, Persian, and Arabic resources, including
  right-to-left validation.

### Assurance

- cache-independent repository gate;
- adversarial and mutation testing;
- generated/interpreted parity checks;
- malformed-input corpora and fuzz targets;
- secret-safe diagnostic and trace enforcement;
- import-boundary and public-claim checks;
- deterministic package and artifact verification.

## Requirements

- Go 1.26.6 or newer in the Go 1.26 line;
- Git;
- for Android builds: JDK 17 and Android SDK 36;
- for native node installation: a supported 64-bit Linux system with systemd.

## Build and test

Run the complete Go gate from the repository root:

```bash
go run ./cmd/gate
```

Include the Android host gate:

```bash
go run ./cmd/gate -android
```

The broad gate intentionally runs module verification, compilation, vet,
uncached tests, executable evidence, the full audit inventory, and applicable
product verifiers. For focused development, individual Go packages and Gradle
tasks can be run directly, but a focused pass is not a substitute for the full
gate.

## Compiler quick start

Generate and validate a deterministic profile:

```bash
go run ./cmd/kdc generate --seed 12345 --out profile.json
go run ./cmd/kdc validate --profile profile.json
```

Generate a standalone Go implementation:

```bash
go run ./cmd/kgen -profile profile.json -out .generated/example
```

Run the audit suite:

```bash
go run ./cmd/kcheck --quick
go run ./cmd/kcheck --full
```

Generated output and locally issued profiles can contain sensitive deployment
material. Keep them outside source control unless they are explicit,
non-secret test fixtures.

## Self-hosted node

Build deterministic Linux engineering archives:

```bash
go run ./cmd/kurdpackage build \
  --root . \
  --out .tools/packages \
  --version 0.16.0-dev \
  --arches amd64,arm64
```

Verify an archive before extracting it:

```bash
go run ./cmd/kurdpackage verify --archive .tools/packages/<archive>.tar.gz
```

Installation, initialization, profile issuance, backup, restore, upgrade, and
rollback instructions are in
[the self-hosting guide](docs/self-hosting/QUICKSTART.md).

Current engineering archives are checksum-bound but not public release
artifacts. The current node package establishes authority and provisioning; it
must not be represented as providing public VPN egress.

## Android development

The Android project is rooted at [`android/`](android/). Open that directory in
Android Studio, or use the checked-in Gradle wrapper from a terminal.

Windows:

```powershell
cd android
.\gradlew.bat :app:assembleInternal --no-build-cache
```

Linux or macOS:

```bash
cd android
./gradlew :app:assembleInternal --no-build-cache
```

Internal builds may contain deterministic non-production trust fixtures for
testing. Release variants must not contain those fixtures.

## Security and privacy

- Do not log payloads, destinations, DNS questions, profile bytes, keys,
  credentials, tokens, or private device identifiers.
- Treat `kurd://` profiles, QR codes, recovery artifacts, and backups as
  sensitive.
- Keep root recovery material off the VPS and maintain tested encrypted
  backups.
- Do not weaken certificate, signature, expiry, revocation, replay, downgrade,
  or rollback checks to restore connectivity.
- Report security issues privately to the repository owner rather than opening
  a public issue containing exploit details or secrets.

See [self-hosting security](docs/self-hosting/SECURITY.md),
[project safety boundaries](docs/sb-evidence-ref-068), and
[governance](docs/GZ-evidence-ref-001).

## Current boundary

The repository demonstrates substantial compiler, authority, Android, and
controlled transport behavior. It does not currently claim:

- a released public relay/data plane;
- unrestricted production Internet egress;
- completed public artifact signing and distribution;
- broad physical-device and hosting-provider field validation;
- independent release-candidate assurance;
- guaranteed censorship bypass, undetectability, anonymity, or immunity from
  blocking.

These limits are intentional and enforced by tests so documentation cannot
silently overstate the software.

## Project structure

```text
android/                 Native Android application and runtime
cmd/                     Command-line tools and validation gates
deploy/selfhost/         Native and container deployment adapters
docs/self-hosting/       Operator installation and recovery guides
internal/crypto/         Authentication and security primitives
internal/operator/       Provisioning and relay-control implementation
internal/protocol/       Compiler and protocol runtime
internal/runtime/        Session and policy enforcement
internal/selfhost/       Portable deployment-local authority
internal/transport/      Carrier, path, relay, and fallback implementation
testdata/                Deterministic fixtures and evidence inputs
```

## Contributing

Changes should be narrowly scoped, behavior-preserving unless explicitly
intended, and accompanied by tests. Run the relevant focused checks during
development and the complete gate before proposing integration.

Please preserve the project’s fail-closed authority boundaries, payload-free
diagnostics, deterministic evidence, and truthful capability descriptions.

## License

The project is licensed under the
[GNU Affero General Public License v3.0 or later](LICENSE). Additional notices
and third-party licensing information are available in [NOTICE](NOTICE) and
[`LICENSES/`](LICENSES/).

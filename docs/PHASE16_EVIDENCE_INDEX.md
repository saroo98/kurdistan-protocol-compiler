<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 16 Evidence Index

**Authority:** KIP-0093 decentralized self-hosting

**Phase state:** complete for the portable authority, provisioning, recovery,
and owner-VPS scope

**Product release decision:** `NO_GO`

## Self-hosted qualification

The machine-readable record is
`testdata/evidence/phase16/self-hosted-vps-qualification.json`, validated by
`cmd/phase16verify` against the strict
`phase16-self-hosted-vps-qualification-v1` schema and portable implementation
boundary. It contains only redacted or one-way values. The owner VPS address,
provider UUID, passphrases, private keys, exact local paths, and SSH material
are not tracked.

The recorded owner-VPS exercise proved:

- two independent deterministic x86_64 and arm64 engineering-package builds
  produced matching bytes;
- the x86_64 archive was checksum-verified, installed on a fresh supported
  owner-controlled VPS, upgraded, rolled back, and re-upgraded;
- `kurdctl init` created deployment-local authority and a separately encrypted
  recovery artifact;
- recovery confirmation, profile issue, profile rotation, profile revocation,
  deployment disable/enable, issuer rotation, and relay-identity rotation
  advanced the authenticated monotonic state;
- encrypted backup verification rejected wrong passphrases, modified bytes,
  and an older authority snapshot;
- a destructive total-host-state-loss drill restored the encrypted backup into
  quarantine and then reactivated it without authority rollback;
- the native systemd service runs as the dedicated `kurd-node` user with an
  empty capability bounding set, `NoNewPrivileges`, strict filesystem
  protection, and `AF_UNIX` as its only permitted address family;
- the host firewall defaults to deny and exposes only rate-limited key-only
  SSH during Phase 16;
- the optional container adapter ran non-root, read-only, without a network or
  Linux capabilities, using the same verified binaries;
- the Android KVP2 bridge independently verified the exact owner-issued outer
  profile bytes, exposed the deployment fingerprint for explicit first trust,
  and completed the activation state machine without replacing those bytes;
- 100 issue, Android-verify, and revoke cycles completed without generation,
  profile-count, or revocation-epoch drift;
- temporary VPS packages, recovery copies, backup copies, and container test
  images were removed after their digests matched the offline owner copies.

No known critical or high Phase 16 finding remains in the KIP-0093 portable
self-hosted scope.

## Local implementation evidence

- Deployment authority, state, recovery, profile issuance, QR, publication,
  audit chain, and backup: `internal/selfhost`.
- Owner administration: `cmd/kurdctl`.
- Authority publication supervisor: `cmd/kurd-node`.
- Deterministic native packages and strict verifier: `cmd/kurdpackage`.
- Native and container deployment: `deploy/selfhost`.
- Android exact-profile verifier and first-trust preview:
  `cmd/phase16androidverify`, `internal/androidbridge`, and
  `android/core/native-jni`.
- Privacy and architecture verifier: `cmd/phase16verify`.
- Operator documentation: `docs/self-hosting`.

The portable dependency gate rejects `net/http`, RPC, Google/cloud SDKs,
OpenTelemetry, and the superseded centralized `production` tree from the
`kurd-node`, `kurdctl`, and `internal/selfhost` dependency closure. Static gates
also reject Internet address families or network capabilities in the Phase 16
service and reject privileged, host-networked, or Docker-socket container
configuration.

## Honest capability boundary

- Engineering archives are checksum-bound and reproducible but are not public
  signed release artifacts.
- `kurd-node` reports `READY_AUTHORITY_ONLY` and
  `UNAVAILABLE_PHASE_16` for the relay data plane. A real non-loopback Kurd
  listener, DNS, egress, and Android traffic proof are not established by this
  evidence set.
- Emulator and physical-device traffic evidence cannot be inferred from an
  offline profile activation. Device/OEM breadth and distributed VPS field
  validation require separate evidence.

The full VPN remains `NO_GO` until these separate product and release claims
are supported by their own evidence.

## Historical KIP-0092 experiment

The Google-specific operator API, Spanner, KMS, Terraform, multi-role, and
workflow artifacts were developed under KIP-0092. KIP-0093 supersedes them as
mandatory product authority. Their historical status remains in
`testdata/evidence/phase16/production-trust-status.json` and must not be
rewritten into a PASS.

Those artifacts are excluded from the portable completion gate and from the
runtime dependency closure. They may be retained only as isolated optional
adapter research. Missing Google Cloud evidence is not a blocker for the
decentralized Phase 16 architecture.

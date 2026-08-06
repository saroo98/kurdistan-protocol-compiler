<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0093: decentralized self-hosted Kurd network

**Status:** accepted for implementation

**Phase:** 16-22 architecture amendment

**Supersedes:** the mandatory Google Cloud production topology in KIP-0092 and
the centralized-provider assumptions in later roadmap phases

## Decision

Kurdistan VPN is a decentralized, self-hosted VPN product. The project ships
software, protocol specifications, signed release artifacts, and operator
documentation. It does not operate a mandatory account system, global profile
authority, relay directory, provider control plane, traffic platform, analytics
platform, advertising system, or universal shutdown mechanism.

Every deployment owner controls an independent Kurd node on infrastructure they
own or are explicitly authorized to administer. An ordinary supported VPS is
the primary deployment target. The node creates its own authority, relay
identity, client credentials, signed profile, update state, revocation state,
backup, and diagnostics locally. The Android app connects only to nodes the
user explicitly imports and trusts.

Google Cloud, AWS, Azure, or any other cloud vendor may host a VPS or satisfy an
optional adapter seam, but no vendor account, vendor-specific database, managed
key product, hosted identity product, billing account, or Kurdistan-operated
infrastructure is required by the protocol, Android app, node, tests, release,
or normal operation.

## End-to-end ownership model

```text
deployment owner
  -> installs signed Kurd node software on an authorized VPS
  -> initializes a deployment-local authority
  -> creates a client profile and displays a QR or kurd:// artifact

Android user
  -> obtains the artifact directly from the deployment owner
  -> reviews and explicitly trusts its authority fingerprint
  -> stores the exact verified profile locally
  -> connects directly to that deployment owner's Kurd node

Kurd node
  -> authenticates the profile-authorized client
  -> carries traffic through Kurd wire records
  -> resolves DNS inside the tunnel according to the imported policy
  -> forwards traffic to the user's intended destinations
```

No Kurdistan-controlled system participates in that flow.

## Trust model

1. Each deployment has an independent root public key and fingerprint.
2. The first QR, file, or `kurd://` import is an explicit trust decision. The
   app shows the deployment fingerprint, source warning, scope, expiry, and
   capabilities before activation.
3. A deployment root may authorize bounded online issuer and relay keys for
   that deployment only.
4. The app persists the highest accepted generation, authority epoch, and
   revocation state for each independent deployment and rejects rollback.
5. Rotation and revocation are scoped to the signing root that authorized the
   affected profile. They cannot affect another deployment.
6. Deleting a deployment trust record is a local user action.
7. There is no global root, universal revocation list, centralized profile
   directory, or Kurdistan-operated emergency authority.

The node owner may stop or revoke their own node and profiles. The Android user
may disconnect, delete a profile, enable the device kill switch, or recover
Internet access locally. Neither action grants authority over anyone else's
deployment.

## Profile and protocol identity

- `kurd://` remains the native signed profile format.
- Kurd wire remains a distinct protocol and does not translate profiles into
  VMess, VLESS, Trojan, Shadowsocks, or another protocol's authority.
- Official provisioning tools emit artifacts intended for Kurdistan VPN.
- The project will not add DRM, secret protocol identifiers, or remote license
  checks to prevent independent implementations.
- Because the protocol and source are reviewable, it is not technically honest
  to promise that no third party can ever implement a compatible client. The
  enforceable claim is that Kurdistan VPN defines and supports the native
  format and that other protocol clients cannot consume it without separately
  implementing Kurd semantics and verification.

## Self-hosted node interface

Phase 16 must deliver one coherent self-hosting interface with substantial
depth behind it:

- `kurd-node`: the relay and local profile-publication runtime;
- `kurdctl`: initialization, profile issuance, QR display, rotation,
  revocation, backup, restore, upgrade, diagnostics, and repair;
- an optional local administration UI bound to loopback or a Unix socket and
  reachable remotely only through an operator-created SSH tunnel;
- native systemd packaging as the primary low-overhead deployment;
- an OCI image and Compose-compatible manifest as an optional deployment
  adapter;
- offline, deterministic and checksum-verifiable Phase 16 engineering
  artifacts, with protected public signatures added in Phase 19;
- no mandatory web panel, remote account, hosted dashboard, or central callback.

The default mode is one owner and one VPS. Team roles, external databases,
TPM/PKCS#11/HSM key adapters, multiple nodes, and automation are optional
extensions. They may strengthen a deployment but may not become prerequisites
for ordinary self-hosting.

## Key custody

- Initialization creates an offline deployment root and a separate bounded
  online issuer.
- The offline root is exported once as an encrypted recovery artifact and is
  not required for ordinary connections.
- The online issuer and relay identity are stored with strict filesystem and
  process isolation. The documentation must state that software-only VPS key
  storage cannot provide hardware-backed non-exportability.
- Optional PKCS#11, TPM, and cloud KMS adapters may exist behind a key-provider
  seam, but the portable software adapter remains supported.
- No private key, recovery secret, profile credential, or backup passphrase is
  sent to the Kurdistan project.
- No custom cryptographic primitive may be introduced.

## State, time, and recovery

- A single-node deployment uses a durable embedded store with transactional
  migrations, a monotonic authority epoch, append-only redacted events, and an
  outbox for profile publication.
- A supported external database adapter may be added for larger deployments,
  but it cannot change protocol authority.
- Authority ordering uses persisted monotonic generations. Wall time is used
  for bounded validity and display, with clock-health checks and explicit
  failure states. There is no centralized Kurdistan time source.
- Restores must preserve or advance the last acknowledged authority epoch.
  Older backups fail closed unless the owner performs an explicit recovery
  transition that clients can verify.
- Backups are encrypted, versioned, integrity checked, owner-controlled, and
  exportable without contacting the project.

## Privacy contract

The Android app and self-hosted node must contain:

- no advertising SDK;
- no analytics or telemetry SDK;
- no remote crash reporter;
- no stable installation identifier sent to the project;
- no centralized traffic, destination, DNS-question, profile, or connection
  logging;
- no automatic support upload;
- no mandatory remote configuration, account login, or product-operated API;
- no payload, credential, key, token, raw-frame, or destination logging on the
  node.

The app exchanges control metadata only with the explicitly imported node.
Tunneled traffic necessarily leaves that node for the destinations the user
chooses, and optional third-party DNS or update sources must be disclosed and
explicitly selected. The default DNS path is deployment-local or otherwise
carried inside the authenticated tunnel.

Software installation and optional update retrieval may contact the release
source chosen by the owner. Offline installation and manual updates must remain
supported. Distribution-provider metadata is not app telemetry and must not be
misrepresented as such.

## No central shutdown

The following are permanently prohibited:

- a global Kurdistan root capable of disabling independent deployments;
- a universal deny list or mandatory remote configuration;
- a central relay registry required for connection;
- a product-operated account gate or license check;
- a release key that also grants profile or relay authority;
- an Android back channel capable of stopping independent nodes;
- a provider action whose scope is wider than that provider's own root.

Existing `emergency-deny` semantics are retained only as deployment-scoped
revocation or local device recovery. All documentation, interfaces, tests, and
UI text must make that scope explicit.

## Consequences for existing Phase 16 work

- Provider-neutral profile lifecycle, audit-chain, outbox, idempotency,
  recovery, and key-provider interfaces may be retained after review.
- Google-specific Spanner, Cloud KMS, Cloud Run, IAP, Workload Identity,
  multi-project, billing, and Terraform assumptions are no longer production
  authority.
- Unfinished Google-specific adapters must not be merged as the default path.
  They may be removed or retained later as optional adapters only if they add
  no dependency, authority widening, telemetry, or test burden to the portable
  self-hosted path.
- Mandatory two-person approval and centralized operational roles are removed
  from the ordinary single-owner deployment. Optional team mode may support
  scoped roles and approval policies without affecting single-owner use.
- The release decision remains `NO_GO` until the revised Phase 16-22 gates pass.

## Downstream amendment

Phases 17-22 must validate and release software that lets an independent owner
deploy and operate their own node. The final completion proof is:

```text
download signed node package
  -> install on an authorized VPS
  -> initialize deployment-local authority
  -> display QR or export kurd:// profile
  -> import into Kurdistan VPN
  -> connect through Kurd wire
  -> route traffic through that VPS
  -> rotate, revoke, back up, restore, upgrade, and recover without a central system
```

The project may publish software and documentation, but it is not required to
operate a public relay, provider account system, or hosted control plane.

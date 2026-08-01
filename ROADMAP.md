<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Roadmap

Detailed stage and milestone tracking lives in the per-milestone KIP documents
(`docs/KIP-*.md`) and the generated gate status in `STATUS.md`. This file records
only the current phase and the standing review gates.

## Current phase: Phase 12 operator, provisioning, and relay-fleet authority

The project has graduated from its lab-only phase. The compiler, audit system, and M2-M7 offline contracts remain the validated starting point, while Phases 8-13 progressively open profile cryptography, Android, VPN/TUN, live Kurd transport and relays, operator infrastructure, and controlled release. Current labels remain factual capability markers, not permanent scope blockers.

M3 implements deterministic offline authority-metadata admission and a pure
monotonic profile lifecycle. M4 adds only deterministic offline selection among
profile-ordered, permitted carrier-family metadata after mandatory client,
safety, privacy, compatibility, and lifecycle checks. M5 adds only deterministic
offline structural admission of exact profile-authorized relay descriptors. It
recomputes the M4 result, binds profile, family, capabilities, client identity,
time, and complete revocation metadata, and treats relay references as opaque.
It authenticates no descriptor, probes or executes no path, and opens no product
runtime or network capability. M6 adds only deterministic construction of a
redacted in-memory diagnostic bundle after explicit prepare, preview, and
confirmation. It collects nothing, writes nothing, transmits nothing, and
grants no control authority. M7 adds only a pure offline eligibility state
machine. It recomputes exact M4 selection and M5 relay admission, validates
caller-supplied platform-readiness metadata, and returns bounded dispositions.
`ready_to_start` does not start anything, and `shutdown_required` does not prove
shutdown. No Android, VPN, service, storage, routing, DNS, or network capability
is opened. See KIP-0070 through KIP-0074.

Every further implementation milestone requires its scoped authorization and evidence before work begins; no blanket lab-only prohibition applies.

Phase 8 implements the bounded local production-candidate profile-artifact
boundary. WO-800 through WO-807 reconcile policy and implement authenticated
profile artifacts, optional recipient confidentiality, portable key-provider
interfaces, deterministic fixtures, local issuance, verification, recovery, and
assurance evidence. Only deterministic non-production keys and local evidence
are permitted. Android key storage, production signers, HSM/KMS operation, live
update delivery, networking, deployment, pilot, and release remain closed.
The external merge-eligibility evidence is **[UNVERIFIED]**; it must not be
substituted by local tests. See KIP-0075 through KIP-0082.

Phase 9 is authorized by KIP-0083. It builds a native Android application
foundation, calls the real Phase 8 verifier through a bounded native bridge,
stores exact artifacts under application-layer envelope encryption, and proves
offline import, recovery, diagnostics, and backup/restore workflows. Phase 9
does not add `VpnService`, TUN, packet routing, network permissions, provider
networking, live relays, production authorities, production signing, or public
release. Those capabilities remain closed until their later named phases.

Phase 10 is defined by KIP-0084. It adds a real, private-process Android
`VpnService`, explicit consent, a foreground service, bounded per-app policy,
and a deterministic TUN/DNS test runtime over `198.18.0.0/15`. It does not
provide Internet access, connect to a public relay, implement live Kurd
transport, or claim a kill switch. The current emulator gate proves included
and excluded application behavior, deterministic local replies, lifecycle
state recovery, and clean shutdown. Physical-device/OEM, dual-stack, handover,
live-network, and production-distribution evidence remains **[UNVERIFIED]**.
Those claims belong to later phases and must not be inferred from this slice.

Phase 11 is defined by KIP-0085 and KIP-0086. It adds the canonical Kurd
wire-v1 framing, independent client/relay handshake and protected-record state,
TLS 1.3/TCP carrier binding, a process-separated loopback relay conformance
path, immutable session-plan authority, and bounded ordered fallback among
already permitted and admitted relay descriptors. The internal Android variant
routes the reserved Phase 10 TUN/DNS test flow through this authority. The
release variant has no deterministic test authority and fails closed until
production authority provisioning exists. Owned-LAN, owned-relay,
physical-device matrix, handover, capacity, and field censorship-resilience
evidence remains **[UNVERIFIED]**. See `docs/PHASE11_EVIDENCE_INDEX.md`.

Phase 12 is authorized by KIP-0087. It adds local production-candidate
control-plane semantics for split-authority approvals, authoritative Phase 8
profile admission with exact lifecycle provenance, publication chronology,
authoritative Phase 11 relay desired state, single-process atomic journal/outbox
processing, root-bound signed deny-only emergency action, redacted audit and
effect boundaries, pre-dispatch recoverer authorization, lease-bounded
safety-priority reconciliation with per-target order and terminal attempts,
partial-tail repair, exact-continuity journal copy, and journal reopen. Two
nine-finding security reviews are recorded as remediated within this local
disposable scope. The implementation and its tests use only local or disposable
state. Production identity and trusted-time operation, HSM/KMS custody,
authenticated backup and restore, an external anti-rollback anchor, external
databases and distribution, infrastructure deployment, public relays,
owned-network pilots, capacity and SLO evidence, and release remain
**[UNVERIFIED]** until their exact environments are authorized and observed.

## Future phase gates

Live implementation — as opposed to a loopback-only, payload-free model — of any
of the following requires a dedicated review before work begins:

- multiplexing over real transports
- production key management, production cryptography, and any mandatory
  post-quantum suite
- non-loopback carriers (HTTP/TLS/DNS/QUIC) as live transport
- UI, mobile, and VPN as shipped products (beyond contract models)
- SOCKS / HTTP proxy as live transport
- cloud deployment, public relays, and live-network testing

The standing safety boundary is defined in `docs/safety.md`; the validation bar
and enforced boundaries are in `docs/GOVERNANCE.md`.

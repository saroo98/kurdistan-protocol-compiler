<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Roadmap

Detailed stage and milestone tracking lives in the per-milestone KIP documents
(`docs/KIP-*.md`) and the generated gate status in `STATUS.md`. This file records
only the current phase and the standing review gates.

## Current phase: Phase 8 profile cryptography preparation

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

## Future phase gates

Live implementation — as opposed to a loopback-only, payload-free model — of any
of the following requires a dedicated review before work begins:

- multiplexing over real transports
- production key management and any real or post-quantum cryptography (external review)
- non-loopback carriers (HTTP/TLS/DNS/QUIC) as live transport
- UI, mobile, and VPN as shipped products (beyond contract models)
- SOCKS / HTTP proxy as live transport
- cloud deployment, public relays, and live-network testing

The standing safety boundary is defined in `docs/safety.md`; the validation bar
and enforced boundaries are in `docs/GOVERNANCE.md`.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Kurdistan Roadmap

Detailed stage and milestone tracking lives in the per-milestone KIP documents
(`docs/KIP-*.md`) and the generated gate status in `STATUS.md`. This file records
only the current phase and the standing review gates.

## Current phase: M5 offline relay-descriptor admission contract

The runtime remains a lab-only research prototype. The compiler generates
deterministic protocol profiles and validates them through an in-repo audit;
carrier, relay, proxy, and Android/VPN surfaces exist as **models and design
contracts only**, never as live transport. M2 permits documentation and
design-contract work only. It does not authorize source/runtime product
behavior, an Android application, VPN/TUN or proxy operation, relay or operator
services, non-loopback networking, telemetry, deployment, or production
cryptography. See the `[live]` / `[model]` / `[plan]` legend in `README.md` and
`STATUS.md` for what is real versus modelled.

M3 implements deterministic offline authority-metadata admission and a pure
monotonic profile lifecycle. M4 adds only deterministic offline selection among
profile-ordered, permitted carrier-family metadata after mandatory client,
safety, privacy, compatibility, and lifecycle checks. M5 adds only deterministic
offline structural admission of exact profile-authorized relay descriptors. It
recomputes the M4 result, binds profile, family, capabilities, client identity,
time, and complete revocation metadata, and treats relay references as opaque.
It authenticates no descriptor, probes or executes no path, and opens no product
runtime or network capability. See KIP-0070, KIP-0071, and KIP-0072.

Every further implementation milestone requires a separate scoped review
and fresh authorization before work begins.

## Future review gates (still out of scope until separately reviewed)

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

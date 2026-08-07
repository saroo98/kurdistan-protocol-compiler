# Live data-plane self-hosting contract

<!-- KURD-LIVE-CONTRACT: PRIVACY_PAYLOAD_LOGGING=PROHIBITED -->
<!-- KURD-LIVE-CONTRACT: PRIVACY_FIVE_TUPLE_LOGGING_AND_PERSISTENCE=PROHIBITED -->
<!-- KURD-LIVE-CONTRACT: READINESS=NOT_CLAIMED -->
<!-- KURD-LIVE-CONTRACT: PREDECESSOR_UNIT_STATE=SUPERSEDED -->
<!-- KURD-LIVE-CONTRACT: REQUIRED_LIVE_UNIT_STATE=APPLIED_LOCAL_UNVERIFIED_EXTERNAL -->

Native Linux deployment only. This document specifies the implemented local
privileges, limits, and network boundary. It does not assert that a public
deployment or external data path has passed the Phase 17 exit gate.

The authority-only predecessor unit is superseded. The current native unit uses
`PrivateDevices=no`, `DevicePolicy=closed`, `/dev/net/tun rw`, and
`AF_UNIX AF_INET AF_INET6`. Repository and Linux syntax checks establish local
configuration compliance; owner-VPS and Android egress remain separate gates.

## Required host components and privileges

The host requires systemd, systemd-networkd, iproute2, nftables, unbound, and
the standard TUN device. systemd owns the TCP listener and passes exactly one
listening socket as file descriptor 3. systemd-networkd creates persistent
`kurd0` for `kurd-node`, with `PacketInfo=no` and `KeepCarrier=yes`.

`kurd-node` runs unprivileged and opens only its owned TUN and the inherited
listener. It has no ambient capabilities and an empty capability bounding set.
The service uses `PrivateDevices=no`, `DevicePolicy=closed`, and
`/dev/net/tun rw`; the remaining sandbox remains in force. Its address-family
allowlist is `AF_UNIX AF_INET AF_INET6`.

Root owns nftables and sysctl. The service cannot edit firewall or routing
policy. Unbound binds only to the TUN server addresses, accepts only TUN client
prefixes, validates DNSSEC, minimises query names, hides identity and version,
and keeps query logging disabled. Health, drain, resume, and reload use a
root-local Unix control socket under `/run/kurd-node/`. The TCP listener
exposes authenticated Kurd TLS only.

## Capacity limits

For the 1 vCPU and 2 GiB reference host, the hard ceilings are 128 accepted
TCP connections, 32 simultaneous handshakes, and 64 authenticated sessions.
The TCP/TLS/Kurd handshake has a 10-second TCP/TLS/Kurd handshake deadline.
Each directional session queue holds at most 256 packets per directional
session queue. A session holds at most 64 incomplete inner operations with a
5-second reconstruction deadline. The issued MTU is 1280, and an operation
uses at most 16 inner fragments in addition to the signed live-program limit.
The existing legacy protected-record layer permits 8 legacy protected-record
incomplete operations. That is a separate framing layer and does not replace
the 64 incomplete inner operations bound above.

The process has a 64 MiB total live packet-buffer budget. The service ceiling
is `MemoryMax=512M`, `TasksMax=128`, and `LimitNOFILE=4096`; observed use must
remain materially below those ceilings. A connection request allows 5
reconnect attempts with jittered 1, 2, 4, 8, and 16 second delays, capped at
30 seconds. The authenticated idle-session maximum is a 300-second
authenticated idle-session maximum unless traffic or an authenticated
keepalive is present. Pre-authentication rate limiting is memory-only, keyed
by a per-process secret hash, expires within 600 seconds, and is neither
logged nor persistent.

## Addressing and forwarding

The IPv4 client pool is `10.77.0.0/24`; the TUN server and DNS address is
`10.77.0.1`, and clients receive unique `/32` assignments. The IPv6 client
pool is `fd4b:7572:6400::/64`; the TUN server and DNS address is
`fd4b:7572:6400::1`, and clients receive unique `/128` assignments. An active
address is never reused. Following revocation, an address remains quarantined
for the maximum profile validity plus 24 hours.

Full-tunnel profiles contain only `0.0.0.0/0 and ::/0`. Private-network access
is denied except for the TUN DNS addresses. nftables blocks spoofed sources and
forwarded loopback, link-local, RFC1918, CGNAT, ULA, multicast, documentation,
benchmark, and provider-metadata destination classes, with exceptions only for
the TUN DNS addresses. IPv6 assignment requires a global address, default
route, forwarding, nftables IPv6 NAT or a routed prefix, and a successful
external IPv6 test; otherwise assignment is IPv4-only.

## Privacy and limitations

The service does not log payload contents or a packet 5-tuple, and it does not
persist either; telemetry is off by default, and public resolvers are not
permitted. The live program excludes model-only authentication keys, lab
carrier labels, compiler seeds, and owner-only metadata.

Android `RuntimeStatus` and `NativeBridge` are loopback-only predecessor
surfaces. Their plan-digest field and 1280 through 1500 MTU checks are
compatibility constraints, not an authorization to create a live tunnel.

These constraints do not provide an availability guarantee, a universal host
compatibility claim, an anonymity guarantee, or a claim of resistance to every
network control.

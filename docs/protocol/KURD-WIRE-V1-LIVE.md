# Kurd wire v1 live data-plane contract

This document describes the bounded `kurd-wire-v1` data plane. It specifies a
wire contract, not a statement of service availability, censorship resistance,
or operational readiness.

## Carrier and outer record

The carrier is TLS 1.3 over TCP with ALPN `kurd/1`. Both the TLS minimum and
maximum are 1.3; session tickets, client session caching, and resumption are
disabled. Certificate validation is strict, and the TLS exporter binds the
authenticated Kurd session to the exact session-plan digest. TCP keepalive is
only secondary transport liveness; it is not Kurd authentication.

Each carrier message contains exactly one Kurd outer record. The outer record
uses the `KURD` magic, major version 1, minor version 0, and a 48-byte header.
The header binds the record to the plan digest. The profile bind record is
`TypeProfileBind` and is type 3,
`TypeEngineReady` is type 4, `TypeReliableData` is type 5, and `TypeClose` is
type 7. The existing authenticated envelope remains the only outer envelope.
Carrier framing uses a 4-byte length prefix. The outer record permits the
critical flag only, limits control records to 65536 bytes and payload records
to 1048576 bytes, and rejects inconsistent lengths.

The 72-byte profile bind body is exactly: `KRDBND01`, followed by the
32-byte TLS exporter at bytes 8 through 39 and the 32-byte session-plan digest
at bytes 40 through 71. Engine-ready and close remain their existing protected
control record types.

## Packet path

One raw IP packet becomes one profile-shaped inner framing operation with data
semantic, a bounded stream slot, a per-direction monotonically increasing
sequence, and the raw packet as its payload. The inner frames use the exact
signed live program and are sealed in authenticated `TypeReliableData`
records. The receiver authenticates the record, decodes and reconstructs the
complete operation, validates the raw IP packet, writes it to TUN, and only
then commits replay state. A parse, queue, or TUN write failure discards the
pending replay capability and closes the session.

Application slots are `1..64`. A session-keyed HMAC-SHA-256 over the parsed
5-tuple maps packets to those slots. The tuple is neither logged nor persisted.
Slot `65534` carries authenticated profile-shaped padding or keepalive. Slot
`65535` remains the protected control slot. When otherwise idle, a peer sends
authenticated padding on slot `65534` every 30 seconds. A session terminates
after 90 seconds without authenticated peer activity.

TCP already provides ordered, reliable delivery, so there are no per-packet acknowledgements in this data path. The legacy `EncodeOperation`,
`DecodeFrames`, and one-shot v1 record APIs remain legacy adapters; live
handling does not recreate a compiler profile or introduce test-only
authentication material.

## Compatibility and limits

The signed runtime policy is deterministic `kurd-runtime-policy-v2`. It names
the wire protocol and carrier, supplies the canonical live program and its
SHA-256 digest, authenticates the client and relay public keys, binds the TLS
identity and ordered IP-literal endpoints, limits routes and DNS, sets MTU and
payload permissions, bounds resources and fallback, and binds relay admission.
Users may narrow this policy but cannot widen its routes, endpoints, DNS,
protocols, MTU, carrier, strategy, or resource limits.

The TLS server name is a DNS name or canonical IP literal no longer than 253
bytes. The pinned self-signed leaf is 1 through 4096 bytes, parseable,
currently valid, valid for server authentication, and contains that name as a
SAN. Live programs are 1 byte through 48 KiB after canonical processing. Canonical
policy decoding rejects duplicate map keys, tags, indefinite-length values,
unknown or missing labels, noncanonical CBOR, invalid UTF-8, excessive
nesting, unsorted or duplicate lists, and re-encoding mismatches.

Endpoints are ordered IP literals only, with one through four entries. IPv4
and IPv6 addresses are present only when authorized. DNS entries may name only
the TUN server addresses. TCP and UDP are required payload protocols; ICMP and
ICMPv6 are limited to PMTU, error handling, and explicit probes. Unknown
payload protocols are rejected. The issued MTU is 1280; policy values outside
1280 through 1500 are rejected.

The contract does not add a second packet-fragment grammar, custom
cryptography, unbounded queues, a public resolver, or packet-level delivery
acknowledgements.

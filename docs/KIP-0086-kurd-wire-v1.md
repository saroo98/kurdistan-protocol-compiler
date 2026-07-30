# KIP-0086: Kurd wire-v1 outer envelope

Status: local conformance frozen; release compatibility not frozen

## Purpose

Wire-v1 provides one canonical, transport-neutral envelope for authenticated
Kurd runtime records. It does not replace the existing handshake, key schedule,
protected record, replay, stream, or policy logic.

## Canonical header

All integers use network byte order.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | ASCII `KURD` |
| 4 | 1 | major version, `1` |
| 5 | 1 | minor version, `0` |
| 6 | 1 | frame type |
| 7 | 1 | flags |
| 8 | 4 | stream ID |
| 12 | 4 | payload length |
| 16 | 32 | `session-plan-v1` digest |
| 48 | variable | exact payload |

The total encoded length must equal `48 + payload_length`; trailing data is
invalid. Payloads are limited to 1 MiB. Control payloads are limited to 64 KiB.

## Frame registry

1. `ClientHello`
2. `ServerHello`
3. `ProfileBind`
4. `EngineReady`
5. `ReliableData`
6. `Heartbeat`
7. `Close`
8. `ClientFinish`
9. `ServerFinish`

`ReliableData` requires a nonzero stream ID and nonempty payload. `Heartbeat`
requires stream zero and an empty payload. Other v1 frames require stream zero
and a nonempty bounded control payload.

Bit zero is the critical flag. All other v1 flag bits are invalid. Unknown frame
types, unknown flags, unknown major/minor versions, zero plan digests, malformed
lengths, and noncanonical encodings fail closed.

`ClientHello`, `ServerHello`, `ClientFinish`, and `ServerFinish` carry the
corresponding complete length-prefixed authenticated-handshake message. Their
outer payload is never parsed as a second source of handshake fields.

## Release-freeze boundary

The local Phase 11 conformance envelope and control sequencing are frozen and
covered by canonical, malformed, partial-I/O, replay, cancellation, and
process-separation tests. A later release freeze still requires:

- exact control payload layouts and critical-extension registry;
- authenticated close reason registry and truncation behavior;
- transcript placement for the plan digest and TLS carrier binding;
- independent decoder vectors;
- generated/interpreted cross-version conformance;
- partial-I/O reader and writer behavior;
- release version and compatibility policy.

## TLS/TCP loopback conformance binding

The first carrier uses TLS 1.3 only, ALPN `kurd/1`, certificate validation,
disabled session tickets, and no 0-RTT. Reads and writes require explicit
deadlines.

Before `ReliableData`, the client sends a `ProfileBind` frame whose payload is
an inner-authenticated Kurd record containing:

```text
"KRDBND01" (8 bytes)
+ TLS exporter binding (32 bytes)
+ session-plan digest (32 bytes)
```

The exporter label is `EXPORTER-Kurdistan-VPN-wire-v1` and its context is the
session-plan digest. The relay compares the recovered statement with its own
exporter and plan values before returning an inner-authenticated `EngineReady`
acknowledgement. Any mismatch or malformed frame terminally aborts the session.

This binding is locally proven both with a pair-owned runtime and with distinct
client and relay process state. An operating-system subprocess test proves the
relay can own its handshake, replay, record, and delivery authority outside the
client process. That evidence remains loopback-only and does not establish
public-relay or Internet-forwarding readiness.

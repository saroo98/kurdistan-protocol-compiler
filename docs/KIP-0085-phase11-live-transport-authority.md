# KIP-0085: Phase 11 live transport authority and wire-completion sequence

Status: local implementation complete; owned-network evidence pending

## Outcome

Phase 11 connects the admitted profile, deterministic permitted-strategy
decision, admitted relay descriptor, existing authenticated Kurd session, and
Android VPN runtime without replacing the Go protocol engine.

Phase 11 is not complete merely because a socket connects. Completion requires
real owned client-to-relay forwarding, bounded fallback, relay isolation,
privacy-safe evidence, and failure behavior that cannot bypass profile or local
safety authority.

## Frozen first decisions

- The existing Go engine remains authoritative.
- Every dial begins from an immutable `session-plan-v1` value.
- `session-plan-v1` recomputes both strategy selection and relay admission. It
  does not trust caller-supplied result objects.
- Relay endpoint references remain opaque at this boundary.
- The first live carrier is Kurd over TLS 1.3 over TCP with strict certificate
  validation and an honest Kurd ALPN.
- The historical `https_like_tcp` strategy family remains a synthetic shape
  contract. `live-carrier-authority-v1` maps that selected shape to the distinct
  `kurd_tls13_tcp_v1` implementation family; no synthetic readiness flag grants
  socket authority.
- The first live-carrier authority remains loopback-conformance-only. Its
  endpoint resolver accepts exact opaque references from a closed local
  registry and literal loopback IP endpoints only.
- The Android application still does not request `android.permission.INTERNET`.
  Its packaged Phase 11 conformance carrier is in-process and release transport
  authority fails closed.
- TLS session resumption and 0-RTT remain disabled for the first wire version.
- Carrier failure creates a fresh authenticated Kurd session. Phase 11 does not
  migrate an established Kurd session across carriers.
- WebSocket over TLS is the second native candidate only after the TLS/TCP
  conformance harness passes.
- QUIC, HTTP/2, split HTTP, branded impersonation, cover traffic, and public
  third-party relays are not promoted by this KIP.
- The first non-loopback relay design separates ingress/session handling from
  destination-policy enforcement and egress.

## Required order

1. Freeze `session-plan-v1` and its digest.
2. Freeze a normative Kurd wire-v1 document and independent conformance corpus.
3. Implement a bounded TLS/TCP loopback client and two-boundary relay harness
   using owned test certificates and deterministic public test bytes.
4. Prove that invalid certificate, profile, relay, plan, generation, and
   authorization inputs fail before any egress connection.
5. Add partial-read/write, half-close, reset, cancellation, replay, resource,
   and generated/interpreted differential tests.
6. Connect the accepted flow boundary to the Android Phase 10 runtime.
7. Add bounded fallback only among profile-permitted, admitted candidates.
8. Run owned LAN and explicitly authorized owned-relay demonstrations.

No later item may weaken an earlier gate.

Items 1 through 7 have executable local conformance coverage. The authenticated
Kurd record layer has distinct client-process and relay-process handshakes,
record state, replay state, and delivery authority. An operating-system
subprocess test proves that the relay can own its state outside the client
process. Android instrumentation proves the reserved Phase 10 TUN flow crosses
the packaged Phase 11 Kurd authority in the internal conformance variant.

Item 8 remains **[UNVERIFIED]**. Local loopback and emulator results are not
evidence of a deployable public relay or real Internet forwarding. The release
variant therefore retains an empty production trust bootstrap and fails closed
when Phase 11 transport authority is requested.

## Wire-v1 prerequisites

Before application traffic is allowed, the specification and implementation
must bind:

- wire major and minor version;
- admitted profile identity, generation, and content evidence;
- strategy decision and session-plan digest;
- admitted relay descriptor and relay identity;
- client and relay nonces;
- negotiated capability set and mandatory floor;
- outer TLS carrier context;
- direction, epoch, stream slot, record type, sequence, and length bounds.

Unknown critical extensions, unsupported major versions, stale generations,
mixed authority, transcript mismatch, and safety-floor mismatch fail closed.
Canonical encodings use explicit network byte order and bounded lengths.

Before application records, both peers exchange an inner-authenticated
`KRDBND01 || tls_exporter(32) || session_plan_digest(32)` statement. A mismatch
terminally aborts the Kurd session. Application delivery failure also
terminally aborts the session and emits no success acknowledgement; v1 does
not retry an already-opened record on another carrier.

The network record seam enforces that ordering with a pair-bound, one-shot
delivery authorization. Authenticating a record returns plaintext but cannot
create a success acknowledgement. The relay produces that acknowledgement
only after its downstream delivery step explicitly commits the authorization.
Rejecting delivery closes both endpoints, concurrent delivery authorizations
are forbidden, and a used or copied authorization cannot be replayed.

## Security and privacy boundaries

- No application bytes flow before TLS validation and Kurd authentication.
- No raw payload, destination, token, key, nonce, authentication tag, stable
  client identifier, or packet buffer is logged or exported.
- Probe results may rank only candidates that have already passed signed policy,
  local floor, lifecycle, compatibility, and revocation gates.
- Relay egress denies loopback, link-local, private, metadata-service, multicast,
  and otherwise special-use destinations unless an exact disposable test
  exception is present.
- Release builds contain no deterministic test authority or test certificate.
- No telemetry or automatic upload is introduced.

## Evidence ladder

- **Local conformance:** deterministic loopback and process-boundary tests.
- **Emulator:** Android lifecycle, TUN flow, cancellation, and leak tests.
- **Owned LAN:** two-host forwarding and failure injection.
- **Owned relay:** explicitly authorized endpoint and target with scrubbed
  packet captures and relay-issued random receipts.

Results from one level do not prove a later level. Physical-device, diverse OEM,
mobile-network handover, owned WAN, capacity, and field censorship-resilience
claims remain **[UNVERIFIED]** until directly observed.

## Prohibited claims

This phase must not be described as uncensorable, undetectable, anonymous,
guaranteed to bypass blocking, production-ready, publicly deployable, or fully
audited. It establishes measurable transport and relay behavior only.

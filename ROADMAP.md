# Kurdistan Stage Roadmap

## Stage 1: Scaffold

- Create the Go module, repository layout, CLI skeletons, safety docs, and local-only agent instructions.
- Keep the repo standard-library only and avoid any production deployment surface.

## Stage 2: IR And Validation

- Define the profile schema for state machines, first contact, framing, auth, scheduler, padding, invalid input, and safety limits.
- Validate generated profiles before use.

## Stage 3: Compiler

- Generate deterministic profiles from a seed.
- Vary first-contact patterns, state graphs, frame grammars, scheduler policies, padding policies, and invalid-input behavior.

## Stage 4: FSM

- Interpret generated client and server state machines.
- Reject wrong role, wrong message, missing proof, and malformed transition graphs.

## Stage 5: Framing

- Encode stable semantic operations through generated frame grammars.
- Decode under the correct profile, reject mismatched profiles, enforce max sizes, and reconstruct fragments.

## Stage 6: Authentication

- Use HMAC-SHA256 over the first-contact transcript with test-only profile key material.
- Reject wrong proofs, tampered transcripts, and replayed nonces in the lab model.

## Stage 7: Local Relay

- Implement a single-stream local client, local server, and local echo target.
- Restrict all runtime network addresses to loopback.

## Stage 8: Trace

- Emit JSONL metadata traces without payloads, keys, proofs, raw frames, or destinations.
- Compare traces and profiles for structural differences.

## Stage 9: Benchmarks

- Measure generation, frame encode/decode, scheduler, padding, and local round-trip overhead.
- Report lab numbers only.

## Stage 10: Polish

- Keep docs aligned with implemented behavior.
- Run formatting, tests, vet, and benchmarks before publishing.

## Future Review Gates

- Multiplexing, production key management, non-loopback carriers, UI, mobile, VPN, SOCKS, HTTP proxy, cloud deployment, and live-network testing are out of scope until separately reviewed.

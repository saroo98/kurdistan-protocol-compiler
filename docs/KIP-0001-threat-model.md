# KIP-0001: Threat Model

Kurdistan is a local research prototype. It studies whether a compiler can generate relay protocol profiles with different first-contact grammars, state machines, frame grammars, scheduling behavior, padding behavior, invalid-input behavior, and trace shapes.

The prototype does not solve production deployment, real-world censorship resistance, production key management, mobile distribution, VPN operation, proxy operation, endpoint discovery, or safe operation on live networks.

A stable family fingerprint is a repeated observable shape across deployments, such as a fixed first packet, fixed frame layout, fixed state path, fixed failure mode, or fixed scheduler cadence. Fixed protocol families are easier to cluster because deployments share durable features.

Generated per profile:

- first-contact sequence
- state graph and state IDs
- semantic-to-wire mapping
- frame length/type/header/padding/fragmentation choices
- scheduler and padding parameters
- invalid-input behavior
- trace expectations

Fixed globally:

- Go runtime
- JSON profile schema
- test and benchmark harnesses
- trace format
- standard-library cryptography
- local-only TCP carrier
- safety limits

Production use is not allowed because this milestone has test-only key material, no reviewed deployment model, no user safety analysis, and no live-network validation. Data handling rules are strict: do not log payloads, keys, proofs, raw frames, credentials, real user data, external targets, or personal identifiers.

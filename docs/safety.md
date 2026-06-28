<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Safety

Kurdistan is local-only research.

Do not add:

- production deployment
- external targets
- real-world bypass deployment
- VPN mode
- SOCKS or HTTP proxy mode
- mobile apps
- public relay services
- cloud scripts
- DNS, CDN, TLS mimicry, or domain-fronting features

Do not log payloads, secrets, credentials, real user data, raw frames, proofs, keys, or external destinations.

Do not implement custom cryptography. The v0 proof uses standard Go HMAC-SHA256 and test-only key material. Generated profiles are safe to commit only when they contain no real secrets and are clearly labeled as lab artifacts.

Before any future milestone expands scope, reviewers must re-check network boundaries, data handling, logging, auth/key management, tests, docs, and whether the change creates operational deployment guidance.

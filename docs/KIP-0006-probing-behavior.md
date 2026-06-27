# KIP-0006: Probing Behavior

Invalid-input behavior means local lab handling of malformed or unexpected traffic. It is not deployment guidance.

One universal error behavior can become a signature because every profile fails the same way. Generated profiles therefore vary unknown first-message behavior, malformed-frame behavior, failed-auth behavior, replay behavior, and delay bounds.

Allowed local outcomes include silent close, delayed close, generated decoy-shaped response, ordinary error-shaped response, ignore, local-only rejection, and nonce rejection.

Safety constraints:

- no external targets
- no live probing tools
- no public relay service
- no stealth deployment instructions
- no payload logging
- no raw frame logging

Tests only verify that malformed input is handled safely and does not panic.

<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# KIP-0011: Mutation And Longitudinal Testing

Passing the current audit gates is not enough. A compiler can drift into cosmetic polymorphism while still producing valid profiles. Mutation testing proves the inverse: when known bad generator shapes are introduced in the lab, the audit system catches them.

This is a local regression method. It is not evidence of real-world performance, censorship resistance, or undetectability.

## Mutant Generators

Mutant generators are test-only profile families in `internal/mutant`. They are not used by production CLI commands. Each mutant simulates a specific design regression:

- `fixed_first_contact`: IDs and symbols vary, but first-contact message count, direction sequence, frame sizes, and state path shape are fixed.
- `fixed_frame_grammar`: state names and symbols vary, but frame length mode, type mode, header order, fragmentation, checksum, and padding placement are fixed.
- `cosmetic_symbols_only`: profiles differ only in IDs, wire symbols, and metadata. The state graph, first contact, framing, scheduler, padding, and invalid-input behavior stay identical.
- `fixed_scheduler`: handshakes and framing vary, but scheduler mode, flush interval, batch size, in-flight limit, and priority policy are fixed.
- `fixed_invalid_input`: valid-session behavior varies, but unknown first message, malformed frame, failed auth, replay, and close/probe behavior are fixed.
- `padding_noise_only`: padding changes, but first contact, frame grammar, scheduler, and invalid-input behavior are fixed.

## Expected Gate Coverage

The mutation suite checks that:

- `fixed_first_contact` fails black-box trace diversity, fixed-signature, and adversarial clustering gates.
- `fixed_frame_grammar` fails profile corpus diversity.
- `cosmetic_symbols_only` is classified as cosmetic and fails structural diversity.
- `fixed_scheduler` fails scheduler diversity.
- `fixed_invalid_input` fails invalid-input/probe behavior diversity.
- `padding_noise_only` fails adversarial clustering, demonstrating that padding noise alone is not enough.
- The normal generator still passes the same reduced test thresholds.

## Longitudinal Audit Comparison

`kcheck compare` compares two audit JSON reports:

```bash
go run ./cmd/kcheck compare \
  --old testdata/audit/baseline-small.json \
  --new testdata/audit/latest.json
```

It reports:

- profile and trace count deltas
- gate pass/fail changes
- first-contact pattern count delta
- frame grammar combination delta
- scheduler combination delta
- padding combination delta
- invalid-input combination delta
- adversarial cluster count delta
- largest cluster ratio delta
- different-profile separation ratio delta
- benchmark timing deltas when present

The command exits nonzero when required gates regress, diversity metrics drop beyond thresholds, cluster count collapses, largest cluster ratio rises too much, or different-profile separation drops too far.

## Baseline Fixtures

Committed fixtures under `testdata/audit/` are small and safe. They contain aggregate metrics and gate results only. They do not contain payloads, raw frames, proofs, keys, secrets, raw messages, or external target data.

- `baseline-small.json`: small passing report for comparison tests.
- `failing-fixed-small.json`: synthetic failing report used to prove regressions are detected.

To update a baseline safely, generate a fresh local audit, inspect that it contains only aggregate metrics, and replace only the committed baseline fixture. Do not commit generated `latest.json` files or trace JSONL.

## STATUS.md

Status generation can include longitudinal comparison:

```bash
go run ./cmd/kcheck --quick --status STATUS.md --baseline testdata/audit/baseline-small.json
```

Without `--baseline`, `STATUS.md` explicitly warns that no baseline comparison was run.

## Limitations

Mutation testing catches known local failure modes. It cannot prove that all future regressions will be caught, that generated protocols are safe to deploy, or that any behavior has real-world robustness. The harness remains loopback-only and lab-only. It does not add VPN mode, SOCKS, HTTP carriers, TLS mimicry, CDN behavior, external targets, deployment scripts, production key exchange, mobile apps, or live-network testing.

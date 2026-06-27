# KIP-0013: Generated Backend Audit

## Status

Accepted for Milestone 7.

## Summary

Milestone 6 proved that Kurdistan can emit profile-specific Go source that compiles and completes a local loopback round trip. Milestone 7 adds a separate generated-backend audit because generated source can introduce its own regressions: fixed code skeletons, fixed trace shapes, wrapper-style output, direct interpreter calls, or profile diversity collapse.

This audit remains lab-only. It does not add deployment, external targets, VPN mode, SOCKS mode, HTTP carriers, TLS mimicry, CDN behavior, mobile apps, or live-network testing.

## Why Generated Source Needs Its Own Audit

Profile diversity and interpreted-runtime diversity do not automatically prove generated-source diversity. A source generator can accidentally:

- emit the same constants for every profile
- emit profile-specific data but route everything through a shared wrapper
- call the interpreted FSM directly instead of using generated tables
- preserve semantic correctness while collapsing black-box traces
- log payload material while adding debug code

The generated-backend audit checks those failure modes directly.

## Semantic Equivalence Vs Trace Divergence

For the same profile, generated and interpreted backends should complete the same semantic operation:

- same echo byte count
- matching first-contact count
- data events present in both traces
- no payload strings in trace events

The traces do not have to be byte-for-byte identical. Event ordering and timing can differ between the generated command path and the interpreted helper path, so trace divergence is reported separately instead of treated as a failure by itself.

## Generated Trace Corpus

`kcheck codegen` now builds a small generated-backend trace corpus:

1. Generate deterministic profiles.
2. Generate Go modules with `kgen`.
3. Run interpreted loopback traces for each profile.
4. Run generated loopback traces through `cmd/generated-trace`.
5. Compare same-profile interpreted/generated behavior.
6. Compare generated traces across different profiles.

Quick mode keeps the corpus small. Full mode runs more profiles but remains local-only.

## Gates

`generated_semantic_equivalence` fails if generated and interpreted backends do not complete the same local semantic operation for the same profile.

`generated_profile_diversity` fails if generated traces across different profiles are not separated by black-box trace comparison.

`generated_fixed_signature` fails if generated traces or generated source introduce suspicious universal artifacts.

`generated_vs_interpreted_divergence` is informational. It reports same-profile similarity and whether generated traces appear more, less, or equally diverse compared with interpreted traces.

`generated_mutant_detection` uses small mutant fixture corpora to confirm collapsed profile families are detected. It is a regression check, not a proof of real-world behavior.

`generated_source_scanner` fails if generated source looks like a trivial wrapper, directly imports `internal/fsm`, loads `profile.json` at runtime, logs payloads, or lacks profile-specific constants.

## Code Skeleton Artifact Scanner

The source scanner checks generated modules for:

- profile-specific constants and tables
- specialized files differing across profiles
- absence of direct `internal/fsm` imports
- absence of runtime `profile.json` loading
- absence of wrapper-only markers
- absence of payload logging patterns
- absence of forbidden hardcoded universal magic strings

The scanner does not prove that no shared behavior exists. It only catches simple source-level regressions.

## Generated Probe Fixtures

Generated modules include `protocol/probe_test.go`, which exercises local-only malformed/probe behavior:

- invalid first contact
- malformed frame
- failed auth proof
- replay policy representation
- oversized frame rejection

These tests do not contact external targets and do not log payloads.

## Commands

```bash
go run ./cmd/kcheck codegen --quick
go run ./cmd/kcheck codegen --full --out testdata/audit/codegen-full.json
go run ./cmd/kcheck codegen --quick --status STATUS.md
```

Generated modules can also run a local trace directly:

```bash
cd .generated/profile-12345
go run ./cmd/generated-trace --trace generated.jsonl --summary generated-summary.json
```

## Limitations

- The generated backend still reuses shared lab helpers for IO, framing, padding, scheduling, HMAC, and trace recording.
- The source scanner is heuristic and text-based.
- Generated mutant detection uses small synthetic fixture corpora.
- The audit is single-stream and loopback-only.
- Passing these gates does not prove undetectability, production safety, censorship resistance, or real-world robustness.

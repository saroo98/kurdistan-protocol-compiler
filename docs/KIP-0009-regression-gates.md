# KIP-0009: Regression Gates

Kurdistan generates many profile structures, but profile diversity is not enough. A future change could preserve structural variation in JSON while making the observable trace behavior look stable. Regression gates exist to catch that failure mode.

The core question is:

> If generated protocols start looking alike from the outside, will local tests fail?

## Profile Diversity vs Trace Diversity

Profile diversity compares generated IR: first-contact patterns, state graph shape, frame grammar, scheduler policy, padding policy, invalid-input policy, and semantic mapping shape.

Trace diversity compares observable local metadata emitted by loopback runs: first frame sizes, first-contact counts, canonical state path shape, frame-size histograms, padding histograms, invalid-input outcomes, and close behavior.

Both are needed. Profile diversity can miss converged runtime behavior. Trace diversity can miss structural issues that do not appear in one short local run.

## Gates

`kcheck` runs required gates:

- `profile_corpus_diversity`: generated profile corpus must exceed diversity thresholds.
- `black_box_trace_diversity`: generated traces must not share suspiciously stable observable metadata.
- `adversarial_black_box_clustering`: generated traces and synthetic controls are clustered using payload-free black-box features; fixed and noisy-fixed controls must be detected as suspicious.
- `fixed_signature`: near-universal first bytes, first frame lengths, semantic sequences, wire-symbol sequences, malformed-frame behavior, or fixed state paths fail the audit.
- `cosmetic_difference`: cosmetic-only profile changes and timestamp-only trace changes must not be classified as structural differences.
- `same_profile_consistency`: two traces from the same profile and same message must remain equivalent.
- `different_profile_separation`: traces from different profiles should usually be separated.
- `malformed_probe_behavior`: invalid-auth and malformed-frame policies must not collapse to one universal behavior.
- `fuzz_presence`: fuzz targets for framing, IR validation, FSM transitions, and trace parsing must exist.

## Threshold Philosophy

Thresholds are regression tripwires, not scientific proof. They are intentionally conservative enough for quick local use, but strict enough to catch obvious collapse into one stable family shape.

Quick mode defaults to 100 profiles and 20 loopback traces. Full mode defaults to 1000 profiles and 100 loopback traces.

## Failure Examples

The audit should fail if:

- every generated profile begins with the same first byte
- most traces have the same first frame size
- first-contact counts collapse to one value
- malformed-frame behavior becomes universal
- generated traces collapse into one tight black-box cluster
- noisy-fixed controls stop being detected as fixed-family
- cosmetic-only profile changes are treated as structural
- timestamp-only trace changes are treated as meaningful

## Commands

Run quick audit:

```bash
go run ./cmd/kcheck --quick
```

Run full audit and write JSON:

```bash
go run ./cmd/kcheck --full --out testdata/audit/latest.json
```

Update status:

```bash
go run ./cmd/kcheck --quick --status STATUS.md
```

Run standalone adversary clustering:

```bash
go run ./cmd/kcheck adversary --quick
go run ./cmd/kcheck adversary --quick --out testdata/audit/adversary.json
```

## Limitations

These gates are local-only. They do not prove undetectability, production readiness, or real-world censorship resistance. They do not model real classifiers, active probing infrastructure, deployment risk, or user safety. They only guard against accidental regression in the lab prototype.

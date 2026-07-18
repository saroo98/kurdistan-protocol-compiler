# Phase 8 Evidence Index

| Evidence | Demonstrates | Does not demonstrate |
|---|---|---|
| `testdata/evidence/phase8-release-corpus-manifest.json` | Hash-bound provenance, generators, expected bytes, and decisions for the release corpus | Runtime behavior by itself |
| `testdata/evidence/phase8-independent-interop-report.json` | Independent Python canonical/sign/open fixtures, with at least five per artifact class | Production provider or platform-keystore behavior |
| `internal/product/profile/testdata/phase8-issuance/` | Reproducible local issue/verify and deliberate rejection fixtures | Production HSM/KMS integration |
| `testdata/evidence/phase8-fuzz-command-manifest.json` | Exact targets, seed-source hashes, commands, duration, passed status, and binding to the campaign report | Execution evidence by itself |
| `testdata/evidence/phase8-fuzz-campaign-report.json` | Seven exact final-source ten-minute campaigns, 1,186,161,346 executions, interesting-input growth, sampled process-tree working set, source/output hashes, and resulting cache-corpus hashes | Percentage code coverage, Go allocation profiling, Android/device, field, or production evidence |
| `testdata/evidence/phase8-wo807-recovery-report.json` | Observed offline recovery drill state and test bindings | Android process death or filesystem durability |
| Phase 8 final guard overlay in `testdata/evidence/phase1-m0-committed-sha256.json` | Exact post-WO-807 correction hashes and no-silent-drift enforcement | An independent security review or authorization to merge |
| `testdata/evidence/phase8-suite-decision-matrix.json` | Mandatory suite and prohibited-composition decisions | Certification or universal algorithm agility |
| `testdata/evidence/phase8-toolchain-randomness-report.json` | Toolchain randomness design and observed local checks | Device entropy quality in the field |
| `docs/PHASE8_RECOVERY_RUNBOOK.md` | Exact fail-closed recovery procedure | Automated production operations |

All Phase 8 evidence is local and test-only. It contains no live endpoint,
owner data, real key, credential, or external-service result. Phase 8 does not
claim a finished Android VPN, relay fleet, operator service, production key
custody, field reliability, or production readiness.

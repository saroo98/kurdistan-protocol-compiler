<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
<!-- Copyright 2026 Saro -->

# Phase 9 Evidence Index

Phase 9 is an offline Android product foundation. It is not a VPN runtime and
does not prove censorship resistance, anonymity, production readiness, or
release readiness.

## Machine-enforced evidence

- `go run ./cmd/gate` runs cache-independent Go build, vet, tests, and audit.
- `android/gradlew phase9Gate` builds release/internal variants, compiles the
  instrumentation suite, runs JVM tests and release lint, verifies release
  permissions/bytecode/native symbols/trust separation, and checks canonical
  supply-chain evidence.
- `go run ./cmd/gate -android` composes both boundaries.
- `cmd/phase9verify` rejects forbidden network/VPN APIs, unsupported ABIs,
  release trust fixtures, unexpected C/JNI exports, unpinned CI actions,
  wrapper drift, missing dependency checksums, and dynamic dependency versions.
- `cmd/phase9evidence` removes volatile CycloneDX identity, rejects unlicensed
  release dependencies, and verifies the committed CycloneDX, SPDX, and pinned
  toolchain records.

## Canonical artifacts

- `testdata/evidence/phase9/android-sbom.cdx.json`
- `testdata/evidence/phase9/android-licenses.spdx.json`
- `testdata/evidence/phase9/toolchain-manifest.json`
- `testdata/evidence/phase9/asset-provenance.json`
- `testdata/evidence/phase9/reproducibility-report.json`
- `testdata/evidence/phase9/acceptance-status.json`

The unsigned release APK is a nonproduction verification artifact. Production
signing material is intentionally absent.

## Evidence classes

| Evidence | State |
| --- | --- |
| Go unit, integration, audit, and mutation gates | Recorded by the final gate |
| Android JVM tests, release lint, manifest/DEX/native inspection | Recorded by `phase9Gate` |
| Two clean local unsigned-APK builds | Recorded by the reproducibility report |
| Windows and Linux clean CI | **[UNVERIFIED]** until pushed CI completes |
| Physical-device import, storage, process-death, backup/reinstall/restore | **[UNVERIFIED]** |
| Physical-device no-network packet capture | **[UNVERIFIED]** |
| Floor/modern-device performance budgets and jank | **[UNVERIFIED]** |
| TalkBack, Switch Access, keyboard/D-pad, 200% text, reduced motion, foldable, tablet | **[UNVERIFIED]** |
| Human review of `ckb`, `ku-Latn`, `fa`, and `ar` translations | **[UNVERIFIED]** |

Unavailable evidence is not inferred from source inspection or host tests and
remains merge-blocking where KIP-0083 requires it.

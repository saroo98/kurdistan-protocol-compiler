# KIP-0082: Phase 8 Integrated Assurance

Status: implemented bounded local assurance; external merge-eligibility evidence **[UNVERIFIED]**

WO-807 binds the Phase 8 release corpus into one reproducible manifest and
tests it from independent and local directions. The corpus includes canonical
CBOR, COSE Sign1, ES256, HPKE, all four artifact classes, deliberate rejection
fixtures, standards decisions, randomness evidence, generator identity,
provenance, and dependency-license references. The authoritative index is
`testdata/evidence/phase8-release-corpus-manifest.json`.

The independent Python generator uses pinned `cbor2`, `cryptography`, and
`pyhpke` packages and shares no Go production encoder, decoder, signer, or
opener. It now supplies at least five fixtures for each mandatory artifact
class. Go consumers reconstruct protected bytes, verify signatures, open HPKE
ciphertexts, validate metadata binding, reconstruct sealed frames, and require
exact bytes. This is interoperability evidence for the mandatory classical
suite, not a claim that the complete product or every platform crypto provider
has been validated.

Bounded tests attack canonical framing, CBOR, COSE, sealed framing, corruption,
resource ceilings, concurrency, authority, recipient dispatch, revocation,
lifecycle monotonicity, storage interruption, and recovery. Rejections must not
change committed state. All seven release fuzz targets completed their exact
ten-minute final-source campaigns with exit code zero. Together they executed
1,186,161,346 inputs. The command manifest records the required commands and
links to `testdata/evidence/phase8-fuzz-campaign-report.json`, which binds wall
duration, executions, interesting-input growth, sampled peak process-tree
working set, timeout, resulting cache-corpus hash, source hashes, and output
hashes for each target. Working set is an operational memory proxy, not a Go
allocation profile, and Go fuzz emitted no percentage coverage metric.

An earlier activation campaign exposed a nested-CBOR-tag ambiguity. The parser
was corrected, the triggering input was retained as a repository regression
corpus entry, and the activation campaign plus all affected envelope and ingress
campaigns were rerun against the final source before the PASS report was written.

Final assurance convergence also made profile CLI file access root-anchored,
refused symlink, reparse, and overwrite paths, and made the fixture and
independent-report writers exclusive-create only. These are local integrity
controls, not a claim of filesystem durability across all platforms. The
release corpus, activation/recovery reports, and interoperation report were
then regenerated and bound to the corrected sources.

The evidence intentionally excludes Android devices, production keystores,
HSM/KMS integrations, live relays, real profiles or keys, network field tests,
side-channel certification, and production readiness. Those claims require
later phases and cannot be inferred from this local assurance slice. Local
evidence also does not substitute for the external merge-eligibility evidence,
which remains **[UNVERIFIED]**.

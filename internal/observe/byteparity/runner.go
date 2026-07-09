// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package byteparity

import (
	"context"

	"kurdistan/internal/codegen"
	"kurdistan/internal/fixtures"
)

// Run compares two byte-path fixture manifests produced for the same profile
// seeds and scenarios.
//
// IMPORTANT (honest scope): both manifests are produced by the SAME code path —
// fixtures.GenerateBytePathManifest, which drives the interpreter
// (bytetransport.RunScenario) regardless of the Backend label. The BackendGen
// ("generated") run therefore does NOT execute the materialized generated
// profile module; the Backend value is only a label. As a result this is a
// DETERMINISM / SMOKE check (the same interpreter run twice must agree), not a
// generated-vs-interpreted PARITY check, and it will match by construction.
//
// True parity would require building and running the emitted profile module
// (see internal/codegen / cmd/kgen) to produce an independent byte-path output
// and comparing that to the interpreter's. That is not yet implemented; until it
// is, do not read a passing result here as evidence that generated code matches
// the interpreter. See planning Stage 6 (D-008) for the tracked follow-up.
func Run(ctx context.Context, seeds []int, scenarios []string) (ByteParityReport, error) {
	interpreted, err := fixtures.GenerateBytePathManifest(ctx, fixtures.ManifestOptions{
		FixtureSet:     "bytepath-parity-interpreted",
		Backend:        fixtures.BackendLab,
		ProfileSeeds:   seeds,
		ScenarioNames:  scenarios,
		BackendVersion: codegen.Version,
	})
	if err != nil {
		return ByteParityReport{}, err
	}
	generated, err := fixtures.GenerateBytePathManifest(ctx, fixtures.ManifestOptions{
		FixtureSet:     "bytepath-parity-generated",
		Backend:        fixtures.BackendGen,
		ProfileSeeds:   seeds,
		ScenarioNames:  scenarios,
		BackendVersion: codegen.Version,
	})
	if err != nil {
		return ByteParityReport{}, err
	}
	return CompareSets(interpreted.Summaries, generated.Summaries), nil
}

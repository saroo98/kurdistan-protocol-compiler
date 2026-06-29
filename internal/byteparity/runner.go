// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package byteparity

import (
	"context"

	"kurdistan/internal/codegen"
	"kurdistan/internal/fixtures"
)

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

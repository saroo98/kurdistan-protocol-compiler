// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"context"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

type Config struct {
	Mode         string `json:"mode"`
	StartSeed    int64  `json:"start_seed"`
	ProfileCount int    `json:"profile_count"`
}

func DefaultConfig(mode string) Config {
	if mode == "" {
		mode = "quick"
	}
	cfg := Config{Mode: mode, StartSeed: 1, ProfileCount: 3}
	if mode == "full" {
		cfg.ProfileCount = 20
	}
	return cfg
}

func GenerateProfiles(startSeed int64, count int) ([]*ir.Profile, error) {
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		p, err := compiler.Generate(startSeed + int64(i))
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func RunLocalAnalysis(ctx context.Context, cfg Config) (Report, error) {
	if cfg.Mode == "" {
		cfg = DefaultConfig("quick")
	}
	if cfg.ProfileCount == 0 {
		cfg.ProfileCount = DefaultConfig(cfg.Mode).ProfileCount
	}
	if cfg.StartSeed == 0 {
		cfg.StartSeed = 1
	}
	profiles, err := GenerateProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return Report{}, err
	}
	scenarios := QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = FullScenarios()
	}
	runs, err := RunScenarioCorpus(ctx, profiles, scenarios)
	if err != nil {
		return Report{}, err
	}
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	report.Mode = cfg.Mode
	return report, nil
}

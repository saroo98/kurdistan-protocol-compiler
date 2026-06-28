// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package diversity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

type CorpusSummary struct {
	StartSeed int64 `json:"start_seed"`
	Count     int   `json:"count"`
	ProfileDiversityReport
}

func GenerateProfiles(startSeed int64, count int) ([]*ir.Profile, error) {
	if count < 0 {
		return nil, fmt.Errorf("count must be non-negative")
	}
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		seed := startSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return nil, fmt.Errorf("generate seed %d: %w", seed, err)
		}
		if err := ir.Validate(p); err != nil {
			return nil, fmt.Errorf("validate seed %d: %w", seed, err)
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

func SummarizeCorpus(startSeed int64, profiles []*ir.Profile) CorpusSummary {
	return CorpusSummary{
		StartSeed:              startSeed,
		Count:                  len(profiles),
		ProfileDiversityReport: AnalyzeProfiles(profiles),
	}
}

func WriteCorpusSummary(path string, summary CorpusSummary) error {
	if path == "" {
		return fmt.Errorf("summary output path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func WriteProfiles(dir string, profiles []*ir.Profile) error {
	if dir == "" {
		return fmt.Errorf("profile output directory is required")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, p := range profiles {
		if p == nil {
			continue
		}
		path := filepath.Join(dir, fmt.Sprintf("profile-%d.json", p.Seed))
		if err := ir.SaveProfile(path, p); err != nil {
			return err
		}
	}
	return nil
}

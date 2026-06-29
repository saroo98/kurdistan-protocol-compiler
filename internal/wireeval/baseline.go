// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"kurdistan/internal/protocorpus"
)

func LoadDataset(path string) (Dataset, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Dataset{}, err
	}
	var dataset Dataset
	if err := json.Unmarshal(raw, &dataset); err != nil {
		return Dataset{}, err
	}
	return dataset, nil
}

func WriteDataset(path string, dataset Dataset, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ValidateDataset(dataset); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(dataset)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func GenerateGoldenDataset(ctx context.Context) (Dataset, error) {
	return BuildDataset(ctx, protocorpus.DefaultCorpus(), BuildOptions{Seeds: DefaultSeeds(), Scenarios: DefaultScenarios(), SplitMode: DefaultSplitMode(), Controls: true})
}

func VerifyDataset(ctx context.Context, path string) (WireEvalComparisonReport, error) {
	expected, err := LoadDataset(path)
	if err != nil {
		return WireEvalComparisonReport{}, err
	}
	current, err := BuildDataset(ctx, protocorpus.DefaultCorpus(), BuildOptions{Seeds: DefaultSeeds(), Scenarios: DefaultScenarios(), SplitMode: DefaultSplitMode(), Controls: true})
	if err != nil {
		return WireEvalComparisonReport{}, err
	}
	report := CompareDatasets(expected, current)
	if report.Conclusion != "passed" {
		return report, ErrBaselineDrift
	}
	return report, nil
}

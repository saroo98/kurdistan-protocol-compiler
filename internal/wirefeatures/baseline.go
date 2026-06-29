// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/fixtures"
	"kurdistan/internal/protocorpus"
)

type BaselineManifest struct {
	Version        string                    `json:"version"`
	GeneratedAt    string                    `json:"generated_at"`
	CorpusVersion  string                    `json:"corpus_version"`
	ProfileSeeds   []int                     `json:"profile_seeds"`
	ScenarioNames  []string                  `json:"scenario_names"`
	FeatureCount   int                       `json:"feature_count"`
	FeatureVectors []WireFeatureVector       `json:"feature_vectors"`
	Comparison     CorpusComparisonReport    `json:"comparison"`
	Collapse       WireFeatureCollapseReport `json:"collapse"`
	PayloadLogged  bool                      `json:"payload_logged"`
	SecretLogged   bool                      `json:"secret_logged"`
}

type BaselineCompareReport struct {
	Compared   int      `json:"compared"`
	Added      []string `json:"added,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	Changed    []string `json:"changed,omitempty"`
	Passed     bool     `json:"passed"`
	Conclusion string   `json:"conclusion"`
}

func GenerateBaseline(_ context.Context, fixtureManifest fixtures.FixtureManifest, corpus protocorpus.CorpusManifest) (BaselineManifest, error) {
	vectors, report := ExtractFromFixtureManifest(fixtureManifest)
	if report.Conclusion != "passed" {
		return BaselineManifest{}, fmt.Errorf("%w: %v", ErrInvalidFeature, report.InvalidFeatures)
	}
	baseline := BaselineManifest{
		Version:        SchemaVersion,
		GeneratedAt:    "2026-06-29T00:00:00Z",
		CorpusVersion:  string(corpus.Version),
		ProfileSeeds:   append([]int(nil), fixtureManifest.ProfileSeeds...),
		ScenarioNames:  append([]string(nil), fixtureManifest.ScenarioNames...),
		FeatureVectors: vectors,
		Comparison:     CompareToCorpus(vectors, corpus),
		Collapse:       ScanCollapse(vectors),
	}
	baseline.FeatureCount = len(vectors)
	for _, vector := range vectors {
		baseline.PayloadLogged = baseline.PayloadLogged || vector.PayloadLogged
		baseline.SecretLogged = baseline.SecretLogged || vector.SecretLogged
	}
	if err := ValidateBaseline(baseline); err != nil {
		return BaselineManifest{}, err
	}
	return baseline, nil
}

func ValidateBaseline(baseline BaselineManifest) error {
	if baseline.Version != SchemaVersion {
		return fmt.Errorf("%w: baseline schema %s", ErrInvalidFeature, baseline.Version)
	}
	if baseline.FeatureCount != len(baseline.FeatureVectors) {
		return fmt.Errorf("%w: feature count mismatch", ErrInvalidFeature)
	}
	for _, vector := range baseline.FeatureVectors {
		if err := ValidateVector(vector); err != nil {
			return err
		}
	}
	if baseline.PayloadLogged || baseline.SecretLogged {
		return ErrTraceLeak
	}
	return nil
}

func LoadBaseline(path string) (BaselineManifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return BaselineManifest{}, err
	}
	var baseline BaselineManifest
	if err := json.Unmarshal(raw, &baseline); err != nil {
		return BaselineManifest{}, err
	}
	return baseline, nil
}

func WriteBaseline(path string, baseline BaselineManifest, force bool) error {
	if path == "" {
		return ErrMissingPath
	}
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ValidateBaseline(baseline); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(baseline)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func VerifyBaseline(ctx context.Context, baselinePath, fixturePath, corpusPath string) (BaselineCompareReport, error) {
	expected, err := LoadBaseline(baselinePath)
	if err != nil {
		return BaselineCompareReport{}, err
	}
	fixtureManifest, err := fixtures.LoadManifest(fixturePath)
	if err != nil {
		return BaselineCompareReport{}, err
	}
	corpus, err := protocorpus.LoadManifest(corpusPath)
	if err != nil {
		return BaselineCompareReport{}, err
	}
	current, err := GenerateBaseline(ctx, fixtureManifest, corpus)
	if err != nil {
		return BaselineCompareReport{}, err
	}
	report := CompareBaselines(expected, current)
	if !report.Passed {
		return report, ErrBaselineDrift
	}
	return report, nil
}

func CompareBaselines(oldBaseline, newBaseline BaselineManifest) BaselineCompareReport {
	oldMap := vectorMap(oldBaseline.FeatureVectors)
	newMap := vectorMap(newBaseline.FeatureVectors)
	report := BaselineCompareReport{Compared: len(oldMap), Passed: true, Conclusion: "passed"}
	for key, oldVector := range oldMap {
		newVector, ok := newMap[key]
		if !ok {
			report.Removed = append(report.Removed, key)
			continue
		}
		if oldVector.FeatureHash != newVector.FeatureHash {
			report.Changed = append(report.Changed, key)
		}
	}
	for key := range newMap {
		if _, ok := oldMap[key]; !ok {
			report.Added = append(report.Added, key)
		}
	}
	if len(report.Added)+len(report.Removed)+len(report.Changed) > 0 {
		report.Passed = false
		report.Conclusion = "failed"
	}
	return report
}

func vectorMap(vectors []WireFeatureVector) map[string]WireFeatureVector {
	out := map[string]WireFeatureVector{}
	for _, vector := range vectors {
		out[fmt.Sprintf("%s/%s/%s", vector.Backend, vector.ProfileID, vector.Scenario)] = vector
	}
	return out
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

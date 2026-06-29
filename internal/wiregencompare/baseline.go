// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
)

const SchemaVersion = "wiregen-baseline-v1"

type BaselineManifest struct {
	Version         string                           `json:"version"`
	GeneratedAt     string                           `json:"generated_at"`
	CorpusVersion   string                           `json:"corpus_version"`
	ProfileSeeds    []int                            `json:"profile_seeds"`
	ScenarioNames   []string                         `json:"scenario_names"`
	PolicyCount     int                              `json:"policy_count"`
	FeatureCount    int                              `json:"feature_count"`
	PolicySummaries []wiregen.PolicySummary          `json:"policy_summaries"`
	FeatureVectors  []wirefeatures.WireFeatureVector `json:"feature_vectors"`
	Comparison      PolicyFeatureComparisonReport    `json:"comparison"`
	Collapse        WireGenCollapseReport            `json:"collapse"`
	PayloadLogged   bool                             `json:"payload_logged"`
	SecretLogged    bool                             `json:"secret_logged"`
}

type BaselineCompareReport struct {
	Compared   int      `json:"compared"`
	Added      []string `json:"added,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	Changed    []string `json:"changed,omitempty"`
	Passed     bool     `json:"passed"`
	Conclusion string   `json:"conclusion"`
}

func DefaultSeeds() []int {
	return []int{12345, 12346, 12347, 12348, 12349}
}

func DefaultScenarios() []string {
	return []string{
		bytetransport.ScenarioSingleFlow,
		bytetransport.ScenarioManySmall,
		bytetransport.ScenarioLargeFragmented,
		bytetransport.ScenarioMixed,
		bytetransport.ScenarioResetIsolation,
		bytetransport.ScenarioCorruption,
		bytetransport.ScenarioReplay,
	}
}

func GenerateBaseline(_ context.Context, corpus protocorpus.CorpusManifest, seeds []int, scenarios []string) (BaselineManifest, error) {
	if len(seeds) == 0 {
		seeds = DefaultSeeds()
	}
	if len(scenarios) == 0 {
		scenarios = DefaultScenarios()
	}
	policies := make([]wiregen.WireShapePolicy, 0, len(seeds))
	summaries := make([]wiregen.PolicySummary, 0, len(seeds))
	vectors := make([]wirefeatures.WireFeatureVector, 0, len(seeds)*len(scenarios))
	for _, seed := range seeds {
		policy, err := wiregen.SamplePolicy(int64(seed), corpus)
		if err != nil {
			return BaselineManifest{}, err
		}
		if err := wiregen.ValidatePolicy(policy, corpus); err != nil {
			return BaselineManifest{}, err
		}
		policies = append(policies, policy)
		summaries = append(summaries, wiregen.SummarizePolicy(policy))
		for _, scenario := range scenarios {
			vectors = append(vectors, ExpectedVector(policy, scenario, "interpreted", fmt.Sprintf("profile-%d", seed)))
		}
	}
	comparison := ComparePoliciesToFeatures(policies, vectors)
	collapse := ScanCollapse(policies, vectors)
	baseline := BaselineManifest{
		Version:         SchemaVersion,
		GeneratedAt:     wiregen.FixedGeneratedAt,
		CorpusVersion:   string(corpus.Version),
		ProfileSeeds:    append([]int(nil), seeds...),
		ScenarioNames:   append([]string(nil), scenarios...),
		PolicyCount:     len(policies),
		FeatureCount:    len(vectors),
		PolicySummaries: summaries,
		FeatureVectors:  vectors,
		Comparison:      comparison,
		Collapse:        collapse,
		PayloadLogged:   comparison.PayloadLogged || collapse.PayloadLogged,
		SecretLogged:    comparison.SecretLogged || collapse.SecretLogged,
	}
	if err := ValidateBaseline(baseline); err != nil {
		return BaselineManifest{}, err
	}
	return baseline, nil
}

func ValidateBaseline(baseline BaselineManifest) error {
	if baseline.Version != SchemaVersion {
		return fmt.Errorf("%w: schema %s", ErrInvalidBaseline, baseline.Version)
	}
	if baseline.PolicyCount != len(baseline.PolicySummaries) {
		return fmt.Errorf("%w: policy count mismatch", ErrInvalidBaseline)
	}
	if baseline.FeatureCount != len(baseline.FeatureVectors) {
		return fmt.Errorf("%w: feature count mismatch", ErrInvalidBaseline)
	}
	for _, vector := range baseline.FeatureVectors {
		if err := wirefeatures.ValidateVector(vector); err != nil {
			return err
		}
	}
	if baseline.PayloadLogged || baseline.SecretLogged {
		return fmt.Errorf("%w: trace hygiene failure", ErrInvalidBaseline)
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
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil && dir != "." {
		return err
	}
	raw, err := StableJSON(baseline)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func VerifyBaseline(ctx context.Context, baselinePath string, corpus protocorpus.CorpusManifest) (BaselineCompareReport, error) {
	expected, err := LoadBaseline(baselinePath)
	if err != nil {
		return BaselineCompareReport{}, err
	}
	current, err := GenerateBaseline(ctx, corpus, expected.ProfileSeeds, expected.ScenarioNames)
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
		if oldVector.FeatureHash != newVector.FeatureHash || oldVector.WirePolicyHash != newVector.WirePolicyHash {
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

func vectorMap(vectors []wirefeatures.WireFeatureVector) map[string]wirefeatures.WireFeatureVector {
	out := map[string]wirefeatures.WireFeatureVector{}
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

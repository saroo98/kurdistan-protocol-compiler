// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"kurdistan/internal/byteparity"
	"kurdistan/internal/fixtures"
)

type BytePathAuditSummary struct {
	FixtureCount          int                    `json:"fixture_count"`
	ProfileCount          int                    `json:"profile_count"`
	ScenarioCount         int                    `json:"scenario_count"`
	MalformedCases        int                    `json:"malformed_cases"`
	ParityPairs           int                    `json:"parity_pairs"`
	SemanticMatches       int                    `json:"semantic_matches"`
	ByteShapeMatches      int                    `json:"byte_shape_matches"`
	UnexpectedDifferences []string               `json:"unexpected_differences,omitempty"`
	FixtureDrift          fixtures.CompareReport `json:"fixture_drift"`
	Conclusion            string                 `json:"conclusion"`
}

func RunBytePathAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	if cfg.ProfileCount < 3 {
		cfg.ProfileCount = 3
	}
	if cfg.Mode == "full" && cfg.ProfileCount < 20 {
		cfg.ProfileCount = 20
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	fixturePath := filepath.Join(root, "testdata", "fixtures", "bytepath-golden.json")
	malformedPath := filepath.Join(root, "testdata", "fixtures", "malformed-byte-corpus.json")
	perfPath := filepath.Join(root, "testdata", "fixtures", "performance-baseline.json")
	seeds := fixtures.DefaultSeeds()
	scenarios := fixtures.DefaultScenarios()
	parity, err := byteparity.Run(ctx, seeds, scenarios)
	if err != nil {
		return AuditReport{}, err
	}
	drift, _ := fixtures.VerifyManifest(ctx, fixturePath)
	malformedCases := fixtures.DefaultMalformedCorpus()
	gates := []GateResult{
		BytePathFixtureDriftGate(ctx, fixturePath),
		BytePathFixtureStabilityGate(ctx, fixturePath),
		BytePathGeneratedInterpretedParityGate(parity),
		BytePathMalformedCorpusGate(malformedPath, malformedCases),
		BytePathRegressionBaselinesGate(fixturePath),
		BytePathFixtureTraceHygieneGate(fixturePath),
		BytePathPerformanceBaselineGate(perfPath),
	}
	summary := BytePathAuditSummary{
		FixtureCount:          len(seeds) * len(scenarios),
		ProfileCount:          len(seeds),
		ScenarioCount:         len(scenarios),
		MalformedCases:        len(malformedCases),
		ParityPairs:           parity.ComparedPairs,
		SemanticMatches:       parity.SemanticMatches,
		ByteShapeMatches:      parity.ByteShapeMatches,
		UnexpectedDifferences: parity.UnexpectedDifferences,
		FixtureDrift:          drift,
		Conclusion:            "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "bytepath-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(seeds),
		TraceCount:       summary.FixtureCount,
		Gates:            gates,
		TraceScanSummary: summary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		summary.Conclusion = "failed"
		report.TraceScanSummary = summary
	}
	return report, nil
}

func BytePathFixtureDriftGate(ctx context.Context, path string) GateResult {
	report, err := fixtures.VerifyManifest(ctx, path)
	if err != nil {
		return gate("fixture_bytepath_drift", false, "required", "committed bytepath fixtures drifted from deterministic regeneration", map[string]any{"compare": report}, []string{err.Error()})
	}
	return gate("fixture_bytepath_drift", report.Passed, "required", fmt.Sprintf("%d bytepath fixtures checked for drift", report.Compared), map[string]any{"compare": report}, nil)
}

func BytePathFixtureStabilityGate(ctx context.Context, path string) GateResult {
	report, err := fixtures.VerifyManifest(ctx, path)
	if err != nil {
		return gate("bytepath_fixture_stability", false, "required", "committed bytepath fixture drift detected", map[string]any{"compare": report}, []string{err.Error()})
	}
	return gate("bytepath_fixture_stability", report.Passed, "required", fmt.Sprintf("%d bytepath fixtures match committed golden set", report.Compared), map[string]any{"compare": report}, nil)
}

func BytePathGeneratedInterpretedParityGate(report byteparity.ByteParityReport) GateResult {
	failures := append([]string{}, report.UnexpectedDifferences...)
	if report.PayloadLogged {
		failures = append(failures, "payload logged")
	}
	if report.SecretLogged {
		failures = append(failures, "secret logged")
	}
	if report.ComparedPairs == 0 || report.SemanticMatches != report.ComparedPairs {
		failures = append(failures, "semantic parity mismatch")
	}
	return gate("bytepath_generated_interpreted_parity", len(failures) == 0, "required", fmt.Sprintf("%d/%d generated/interpreted bytepath summaries match semantically", report.SemanticMatches, report.ComparedPairs), map[string]any{"parity": report}, failures)
}

func BytePathMalformedCorpusGate(path string, cases []fixtures.MalformedByteCase) GateResult {
	failures := []string{}
	if path != "" {
		if loaded, err := loadMalformedCases(path); err == nil {
			cases = loaded
		} else {
			failures = append(failures, err.Error())
		}
	}
	if err := fixtures.ValidateMalformedCorpus(cases); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range cases {
		result := fixtures.RunMalformedCase(tc)
		if tc.ExpectedReject && !result.Rejected {
			failures = append(failures, tc.Name+": accepted")
		}
		if !result.SafeError {
			failures = append(failures, tc.Name+": unsafe error")
		}
	}
	return gate("bytepath_malformed_corpus", len(failures) == 0, "required", fmt.Sprintf("%d malformed byte corpus cases checked", len(cases)), map[string]any{"path": path, "cases": len(cases)}, failures)
}

func BytePathRegressionBaselinesGate(path string) GateResult {
	manifest, err := fixtures.LoadManifest(path)
	if err != nil {
		return gate("bytepath_regression_baselines", false, "required", "could not load bytepath fixture baseline", nil, []string{err.Error()})
	}
	failures := []string{}
	if len(manifest.ProfileSeeds) < 3 {
		failures = append(failures, "expected at least 3 fixture seeds")
	}
	if len(manifest.ScenarioNames) < 7 {
		failures = append(failures, "expected representative bytepath scenarios")
	}
	if len(manifest.Entries) != len(manifest.ProfileSeeds)*len(manifest.ScenarioNames) {
		failures = append(failures, "fixture entry count does not match seed/scenario matrix")
	}
	return gate("bytepath_regression_baselines", len(failures) == 0, "required", fmt.Sprintf("%d entries across %d seeds and %d scenarios", len(manifest.Entries), len(manifest.ProfileSeeds), len(manifest.ScenarioNames)), nil, failures)
}

func BytePathFixtureTraceHygieneGate(path string) GateResult {
	manifest, err := fixtures.LoadManifest(path)
	if err != nil {
		return gate("bytepath_fixture_trace_hygiene", false, "required", "could not load bytepath fixture baseline", nil, []string{err.Error()})
	}
	report := fixtures.ValidateRedaction(manifest)
	failures := []string{}
	if !report.Passed {
		failures = append(failures, report.Findings...)
	}
	return gate("bytepath_fixture_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d bytepath fixture entries scanned for payload/secret leakage", len(manifest.Entries)), map[string]any{"findings": report.Findings}, failures)
}

func BytePathPerformanceBaselineGate(path string) GateResult {
	baseline := fixtures.DefaultPerformanceBaseline()
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &baseline); err != nil {
			return gate("bytepath_performance_baseline", false, "warning", "performance baseline JSON invalid", nil, []string{err.Error()})
		}
	}
	if err := fixtures.ValidatePerformanceBaseline(baseline); err != nil {
		return gate("bytepath_performance_baseline", false, "warning", "performance baseline buckets invalid", nil, []string{err.Error()})
	}
	return gate("bytepath_performance_baseline", true, "warning", "bytepath performance baseline buckets loaded as warning-only thresholds", map[string]any{"path": path, "baseline": baseline}, nil)
}

func loadMalformedCases(path string) ([]fixtures.MalformedByteCase, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Version string                       `json:"version"`
		Cases   []fixtures.MalformedByteCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if doc.Version != fixtures.SchemaVersion {
		return nil, fmt.Errorf("malformed corpus version %s != %s", doc.Version, fixtures.SchemaVersion)
	}
	return doc.Cases, nil
}

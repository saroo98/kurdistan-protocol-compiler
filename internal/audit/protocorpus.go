// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/fixtures"
	"kurdistan/internal/mutant"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
)

type ProtocolCorpusAuditSummary struct {
	CorpusVersion string `json:"corpus_version"`
	FeatureSchema string `json:"feature_schema_version"`
	CorpusEntries int    `json:"corpus_entries"`
	PhaseKinds    int    `json:"phase_kinds"`
	FieldKinds    int    `json:"field_kinds"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
	Conclusion    string `json:"conclusion"`
}

type WireFeaturesAuditSummary struct {
	CorpusVersion   string                                 `json:"corpus_version"`
	FeatureSchema   string                                 `json:"feature_schema_version"`
	CorpusEntries   int                                    `json:"corpus_entries"`
	FeatureVectors  int                                    `json:"feature_vectors"`
	ProfileCount    int                                    `json:"profile_count"`
	ScenarioCount   int                                    `json:"scenario_count"`
	Comparison      wirefeatures.CorpusComparisonReport    `json:"comparison"`
	Collapse        wirefeatures.WireFeatureCollapseReport `json:"collapse"`
	BaselineCompare wirefeatures.BaselineCompareReport     `json:"baseline_compare"`
	Conclusion      string                                 `json:"conclusion"`
}

func RunProtocolCorpusAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	corpusPath := filepath.Join(root, "testdata", "protocorpus", "corpus-v1.json")
	bucketsPath := filepath.Join(root, "testdata", "protocorpus", "feature-buckets-v1.json")
	corpus, err := protocorpus.LoadManifest(corpusPath)
	if err != nil {
		return AuditReport{}, err
	}
	summary := protocorpus.Summarize(corpus)
	gates := []GateResult{
		ProtocolCorpusSchemaValidGate(corpusPath),
		ProtocolCorpusFeatureTaxonomyGate(corpus, bucketsPath),
		ProtocolCorpusEntryCoverageGate(corpus),
		ProtocolCorpusTraceHygieneGate(corpus),
	}
	reportSummary := ProtocolCorpusAuditSummary{
		CorpusVersion: string(summary.Version),
		FeatureSchema: summary.FeatureSchema,
		CorpusEntries: summary.EntryCount,
		PhaseKinds:    summary.PhaseKindCount,
		FieldKinds:    summary.FieldKindCount,
		PayloadLogged: summary.PayloadLogged,
		SecretLogged:  summary.SecretLogged,
		Conclusion:    "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "protocorpus-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       len(corpus.Entries),
		Gates:            gates,
		CorpusSummary:    reportSummary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		reportSummary.Conclusion = "failed"
		report.CorpusSummary = reportSummary
	}
	return report, nil
}

func RunWireFeaturesAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	corpusPath := filepath.Join(root, "testdata", "protocorpus", "corpus-v1.json")
	fixturePath := filepath.Join(root, "testdata", "fixtures", "bytepath-golden.json")
	baselinePath := filepath.Join(root, "testdata", "wirefeatures", "wirefeatures-golden.json")
	corpus, err := protocorpus.LoadManifest(corpusPath)
	if err != nil {
		return AuditReport{}, err
	}
	fixtureManifest, err := fixtures.LoadManifest(fixturePath)
	if err != nil {
		return AuditReport{}, err
	}
	vectors, extraction := wirefeatures.ExtractFromFixtureManifest(fixtureManifest)
	comparison := wirefeatures.CompareToCorpus(vectors, corpus)
	collapse := wirefeatures.ScanCollapse(vectors)
	baselineCompare, _ := wirefeatures.VerifyBaseline(ctx, baselinePath, fixturePath, corpusPath)
	gates := []GateResult{
		WireFeaturesExtractionGate(extraction),
		WireFeaturesFirstNModelGate(vectors),
		WireFeaturesCorpusComparisonGate(comparison),
		WireFeaturesCollapseResistanceGate(collapse),
		WireFeaturesGeneratedBackendParityGate(),
		WireFeaturesMutantDetectionGate(),
		WireFeaturesBaselineGate(ctx, baselinePath, fixturePath, corpusPath),
	}
	summary := WireFeaturesAuditSummary{
		CorpusVersion:   string(corpus.Version),
		FeatureSchema:   wirefeatures.SchemaVersion,
		CorpusEntries:   len(corpus.Entries),
		FeatureVectors:  len(vectors),
		ProfileCount:    extraction.ProfileCount,
		ScenarioCount:   extraction.ScenarioCount,
		Comparison:      comparison,
		Collapse:        collapse,
		BaselineCompare: baselineCompare,
		Conclusion:      "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "wirefeatures-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     extraction.ProfileCount,
		TraceCount:       len(vectors),
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

func ProtocolCorpusSchemaValidGate(path string) GateResult {
	corpus, err := protocorpus.LoadManifest(path)
	if err != nil {
		return gate("protocorpus_schema_valid", false, "required", "could not load protocol corpus", map[string]any{"path": path}, []string{err.Error()})
	}
	if err := protocorpus.ValidateManifest(corpus); err != nil {
		return gate("protocorpus_schema_valid", false, "required", "protocol corpus schema invalid", map[string]any{"path": path}, []string{err.Error()})
	}
	return gate("protocorpus_schema_valid", true, "required", fmt.Sprintf("%d protocol corpus entries validated", len(corpus.Entries)), map[string]any{"path": path, "version": corpus.Version}, nil)
}

func ProtocolCorpusFeatureTaxonomyGate(corpus protocorpus.CorpusManifest, bucketsPath string) GateResult {
	failures := []string{}
	if len(protocorpus.SupportedPhases()) < 6 {
		failures = append(failures, "phase taxonomy incomplete")
	}
	if len(protocorpus.SupportedFieldKinds()) < 12 {
		failures = append(failures, "field taxonomy incomplete")
	}
	if len(corpus.Buckets.Size) < 11 {
		failures = append(failures, "size buckets incomplete")
	}
	return gate("protocorpus_feature_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d field kinds and %d phase kinds checked", len(protocorpus.SupportedFieldKinds()), len(protocorpus.SupportedPhases())), map[string]any{"buckets": bucketsPath}, failures)
}

func ProtocolCorpusEntryCoverageGate(corpus protocorpus.CorpusManifest) GateResult {
	summary := protocorpus.Summarize(corpus)
	failures := []string{}
	if summary.EntryCount < 12 {
		failures = append(failures, "expected at least 12 abstract corpus entries")
	}
	if summary.FamilyCount < 8 {
		failures = append(failures, "expected broad protocol family coverage")
	}
	if summary.PhaseKindCount < 5 {
		failures = append(failures, "expected phase coverage")
	}
	return gate("protocorpus_entry_coverage", len(failures) == 0, "required", fmt.Sprintf("%d entries across %d families", summary.EntryCount, summary.FamilyCount), map[string]any{"summary": summary}, failures)
}

func ProtocolCorpusTraceHygieneGate(corpus protocorpus.CorpusManifest) GateResult {
	report := protocorpus.ValidateRedaction(corpus)
	return gate("protocorpus_trace_hygiene", report.Passed, "required", "protocol corpus scanned for unsafe feature material", map[string]any{"findings": report.Findings}, report.Findings)
}

func WireFeaturesExtractionGate(report wirefeatures.FeatureExtractionReport) GateResult {
	failures := append([]string{}, report.InvalidFeatures...)
	if report.PayloadLogged {
		failures = append(failures, "payload logged")
	}
	if report.SecretLogged {
		failures = append(failures, "secret logged")
	}
	if report.FeatureCount == 0 {
		failures = append(failures, "no wire features extracted")
	}
	return gate("wirefeatures_extraction", len(failures) == 0, "required", fmt.Sprintf("%d wire feature vectors extracted from %d fixtures", report.FeatureCount, report.FixtureCount), map[string]any{"report": report}, failures)
}

func WireFeaturesFirstNModelGate(vectors []wirefeatures.WireFeatureVector) GateResult {
	unique := map[string]bool{}
	failures := []string{}
	for _, vector := range vectors {
		if vector.FirstNPacketShape == "" {
			failures = append(failures, vector.ProfileID+"/"+vector.Scenario+": missing first-n shape")
		}
		unique[vector.FirstNPacketShape] = true
	}
	if len(unique) < 2 {
		failures = append(failures, "expected multiple first-n shapes")
	}
	return gate("wirefeatures_firstn_model", len(failures) == 0, "required", fmt.Sprintf("%d unique first-n packet shapes found", len(unique)), map[string]any{"unique_firstn_shapes": len(unique)}, failures)
}

func WireFeaturesCorpusComparisonGate(report wirefeatures.CorpusComparisonReport) GateResult {
	failures := append([]string{}, report.UnmatchedProfiles...)
	if report.PayloadLogged {
		failures = append(failures, "payload logged")
	}
	if report.SecretLogged {
		failures = append(failures, "secret logged")
	}
	if len(report.MatchedFamilies) < 2 {
		failures = append(failures, "generated features mapped to too few corpus families")
	}
	return gate("wirefeatures_corpus_comparison", len(failures) == 0, "required", fmt.Sprintf("%d corpus families matched by generated features", len(report.MatchedFamilies)), map[string]any{"comparison": report}, failures)
}

func WireFeaturesCollapseResistanceGate(report wirefeatures.WireFeatureCollapseReport) GateResult {
	failures := append([]string{}, report.SuspiciousMetrics...)
	return gate("wirefeatures_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d feature hashes and %d first-n shapes checked", report.UniqueFeatureHashes, report.UniqueFirstNShapes), map[string]any{"collapse": report}, failures)
}

func WireFeaturesGeneratedBackendParityGate() GateResult {
	failures := []string{}
	markers := []string{"protocorpus_generated.go", "wirefeatures_generated.go", "protocorpus_test.go", "wirefeatures_test.go", "ProtocolCorpusSchemaVersion", "WireFeatureSchemaVersion"}
	root, err := repoRoot()
	if err != nil {
		return gate("wirefeatures_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("wirefeatures_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source := string(raw)
	for _, marker := range markers {
		if !strings.Contains(source, marker) {
			failures = append(failures, "missing generated marker "+marker)
		}
	}
	return gate("wirefeatures_generated_backend_parity", len(failures) == 0, "required", "generated backend protocol corpus and wirefeature markers checked", nil, failures)
}

func WireFeaturesMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeProtocolCorpusMissingPhaseTaxonomy,
		mutant.ModeProtocolCorpusInvalidFieldVisibility,
		mutant.ModeProtocolCorpusUnsafePayloadFeature,
		mutant.ModeWireFeaturesIdenticalFirstNShape,
		mutant.ModeWireFeaturesPaddingOnlyVariation,
		mutant.ModeWireFeaturesMissingMetadataExposure,
		mutant.ModeWireFeaturesGeneratedInterpretedDrift,
		mutant.ModeWireFeaturesSecretLeak,
	}
	modes := map[string]bool{}
	for _, mode := range mutant.Modes() {
		modes[mode] = true
	}
	failures := []string{}
	for _, mode := range required {
		if !modes[mode] {
			failures = append(failures, "missing mutant mode "+mode)
		}
	}
	return gate("wirefeatures_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d wirefeature mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func WireFeaturesBaselineGate(ctx context.Context, baselinePath, fixturePath, corpusPath string) GateResult {
	report, err := wirefeatures.VerifyBaseline(ctx, baselinePath, fixturePath, corpusPath)
	if err != nil {
		return gate("wirefeatures_baseline_fixtures", false, "required", "wirefeature baseline drift detected", map[string]any{"compare": report}, []string{err.Error()})
	}
	return gate("wirefeatures_baseline_fixtures", report.Passed, "required", fmt.Sprintf("%d wirefeature baseline entries checked", report.Compared), map[string]any{"compare": report}, nil)
}

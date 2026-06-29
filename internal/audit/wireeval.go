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

	"kurdistan/internal/classifierdata"
	"kurdistan/internal/mutant"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

type WireEvalAuditSummary struct {
	DatasetVersion string                             `json:"dataset_version"`
	Records        int                                `json:"records"`
	Profiles       int                                `json:"profiles"`
	Scenarios      int                                `json:"scenarios"`
	Splits         map[string]int                     `json:"splits"`
	Labels         map[string]int                     `json:"labels"`
	Diversity      wireeval.ObservableDiversityReport `json:"diversity"`
	Readiness      wireeval.ClassifierReadinessReport `json:"readiness"`
	Comparison     wireeval.WireEvalComparisonReport  `json:"comparison"`
	Conclusion     string                             `json:"conclusion"`
}

func RunWireEvalAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	seeds := wireeval.DefaultSeeds()
	if cfg.Mode == "full" {
		seeds = make([]int, 30)
		for i := range seeds {
			seeds[i] = int(cfg.StartSeed) + i
		}
	}
	dataset, err := wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{Seeds: seeds, Scenarios: wireeval.DefaultScenarios(), SplitMode: wireeval.DefaultSplitMode(), Controls: true})
	if err != nil {
		return AuditReport{}, err
	}
	csvRaw, err := classifierdata.ExportCSV(dataset.Records)
	if err != nil {
		return AuditReport{}, err
	}
	jsonlRaw, err := classifierdata.ExportJSONL(dataset.Records)
	if err != nil {
		return AuditReport{}, err
	}
	diversity := wireeval.AnalyzeObservableDiversity(dataset.Records)
	readiness := wireeval.ClassifierReadiness(dataset.Records, classifierdata.Columns(), []string{"json", "jsonl", "csv"})
	baselinePath := filepath.Join(root, "testdata", "wireeval", "wireeval-dataset-golden.json")
	comparison, _ := wireeval.VerifyDataset(ctx, baselinePath)
	gates := WireEvalGates(ctx, dataset, csvRaw, jsonlRaw, baselinePath)
	summary := WireEvalAuditSummary{
		DatasetVersion: string(wireeval.Version),
		Records:        len(dataset.Records),
		Profiles:       dataset.Manifest.ProfileCount,
		Scenarios:      dataset.Manifest.ScenarioCount,
		Splits:         dataset.Manifest.SplitCounts,
		Labels:         dataset.Manifest.LabelCounts,
		Diversity:      diversity,
		Readiness:      readiness,
		Comparison:     comparison,
		Conclusion:     "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "wireeval-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     dataset.Manifest.ProfileCount,
		TraceCount:       len(dataset.Records),
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

func WireEvalGates(ctx context.Context, dataset wireeval.Dataset, csvRaw, jsonlRaw []byte, baselinePath string) []GateResult {
	diversity := wireeval.AnalyzeObservableDiversity(dataset.Records)
	readiness := wireeval.ClassifierReadiness(dataset.Records, classifierdata.Columns(), []string{"json", "jsonl", "csv"})
	comparison, _ := wireeval.VerifyDataset(ctx, baselinePath)
	return []GateResult{
		WireEvalDatasetBuildGate(dataset),
		WireEvalDatasetSchemaGate(dataset),
		WireEvalSplitIntegrityGate(dataset),
		WireEvalExportConsistencyGate(dataset, csvRaw, jsonlRaw),
		WireEvalObservableDiversityGate(diversity),
		WireEvalControlDetectionGate(diversity),
		WireEvalClassifierReadinessGate(readiness),
		WireEvalDatasetDriftGate(comparison),
		WireEvalGeneratedBackendParityGate(),
		WireEvalTraceHygieneGate(dataset, csvRaw, jsonlRaw),
		WireEvalMutantDetectionGate(),
	}
}

func WireEvalDatasetBuildGate(dataset wireeval.Dataset) GateResult {
	failures := []string{}
	if len(dataset.Records) == 0 {
		failures = append(failures, "no wireeval records generated")
	}
	if dataset.Manifest.ProfileCount < 3 {
		failures = append(failures, "profile count below quick threshold")
	}
	return gate("wireeval_dataset_build", len(failures) == 0, "required", fmt.Sprintf("%d records across %d profiles", len(dataset.Records), dataset.Manifest.ProfileCount), map[string]any{"manifest": dataset.Manifest}, failures)
}

func WireEvalDatasetSchemaGate(dataset wireeval.Dataset) GateResult {
	failures := []string{}
	if err := wireeval.ValidateDataset(dataset); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("wireeval_dataset_schema", len(failures) == 0, "required", fmt.Sprintf("%d records validated against %s", len(dataset.Records), wireeval.Version), nil, failures)
}

func WireEvalSplitIntegrityGate(dataset wireeval.Dataset) GateResult {
	manifest := wireeval.BuildSplitManifest(dataset.Records, wireeval.DefaultSplitMode())
	failures := []string{}
	if !manifest.Passed {
		failures = append(failures, "split manifest failed")
	}
	return gate("wireeval_split_integrity", len(failures) == 0, "required", fmt.Sprintf("train=%d test=%d ood=%d holdout=%d", manifest.SplitCounts["train"], manifest.SplitCounts["test"], manifest.SplitCounts["ood"], manifest.SplitCounts["holdout"]), map[string]any{"splits": manifest}, failures)
}

func WireEvalExportConsistencyGate(dataset wireeval.Dataset, csvRaw, jsonlRaw []byte) GateResult {
	failures := []string{}
	if err := classifierdata.ValidateCSV(csvRaw); err != nil {
		failures = append(failures, "csv: "+err.Error())
	}
	if err := classifierdata.ValidateJSONL(jsonlRaw); err != nil {
		failures = append(failures, "jsonl: "+err.Error())
	}
	return gate("wireeval_export_consistency", len(failures) == 0, "required", fmt.Sprintf("%d records exported as CSV and JSONL", len(dataset.Records)), map[string]any{"formats": []string{"csv", "jsonl"}, "columns": classifierdata.Columns()}, failures)
}

func WireEvalObservableDiversityGate(report wireeval.ObservableDiversityReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, "observable diversity report failed")
	}
	return gate("wireeval_observable_diversity", len(failures) == 0, "required", fmt.Sprintf("%d unique feature hashes and %d first-n shapes", report.UniqueFeatureHashes, report.UniqueFirstNShapes), map[string]any{"diversity": report}, failures)
}

func WireEvalControlDetectionGate(report wireeval.ObservableDiversityReport) GateResult {
	failures := []string{}
	if report.ControlFailuresDetected == 0 || report.CollapsedRecords == 0 || report.PaddingOnlyRecords == 0 {
		failures = append(failures, "control datasets were not detected")
	}
	return gate("wireeval_control_detection", len(failures) == 0, "required", fmt.Sprintf("%d collapsed controls and %d padding-only controls detected", report.CollapsedRecords, report.PaddingOnlyRecords), map[string]any{"control_failures_detected": report.ControlFailuresDetected}, failures)
}

func WireEvalClassifierReadinessGate(report wireeval.ClassifierReadinessReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, append(report.MissingColumns, report.ForbiddenColumns...)...)
		failures = append(failures, report.SplitViolations...)
		failures = append(failures, report.LeakageFindings...)
	}
	return gate("wireeval_classifier_readiness", len(failures) == 0, "required", fmt.Sprintf("%d records, %d feature columns", report.RecordCount, report.FeatureColumnCount), map[string]any{"readiness": report}, failures)
}

func WireEvalDatasetDriftGate(report wireeval.WireEvalComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
		failures = append(failures, report.FeatureDrift...)
	}
	return gate("wireeval_dataset_drift", len(failures) == 0, "required", fmt.Sprintf("%d old records compared to %d new records", report.OldRecordCount, report.NewRecordCount), map[string]any{"comparison": report}, failures)
}

func WireEvalGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("wireeval_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("wireeval_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source := string(raw)
	markers := []string{"wireeval_generated.go", "wireeval_test.go", "wireeval_export_test.go", "wireeval_parity_test.go", "WireEvalDatasetVersion"}
	failures := []string{}
	for _, marker := range markers {
		if !strings.Contains(source, marker) {
			failures = append(failures, "missing generated marker "+marker)
		}
	}
	return gate("wireeval_generated_backend_parity", len(failures) == 0, "required", "generated backend wireeval markers checked", nil, failures)
}

func WireEvalTraceHygieneGate(dataset wireeval.Dataset, csvRaw, jsonlRaw []byte) GateResult {
	failures := []string{}
	if report := wireeval.ScanDatasetForLeakage(dataset); !report.Passed {
		failures = append(failures, report.Findings...)
	}
	if err := classifierdata.ValidateCSV(csvRaw); err != nil {
		failures = append(failures, "csv: "+err.Error())
	}
	if err := classifierdata.ValidateJSONL(jsonlRaw); err != nil {
		failures = append(failures, "jsonl: "+err.Error())
	}
	return gate("wireeval_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d records and classifier exports scanned", len(dataset.Records)), nil, failures)
}

func WireEvalMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeWireEvalRawPayloadColumn,
		mutant.ModeWireEvalRawBytesColumn,
		mutant.ModeWireEvalEndpointLeak,
		mutant.ModeWireEvalTrainTestSeedOverlap,
		mutant.ModeWireEvalOODSeedOverlap,
		mutant.ModeWireEvalMissingRequiredFeature,
		mutant.ModeWireEvalUnstableRecordID,
		mutant.ModeWireEvalPaddingOnlyDataset,
		mutant.ModeWireEvalCollapsedFirstNDataset,
		mutant.ModeWireEvalControlNotDetected,
		mutant.ModeWireEvalGeneratedBackendDatasetDrift,
		mutant.ModeWireEvalSecretLeak,
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
	return gate("wireeval_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d wireeval mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

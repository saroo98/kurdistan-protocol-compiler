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

	"kurdistan/internal/ir"
	"kurdistan/internal/localadapteradversary"
	"kurdistan/internal/mutant"
)

func RunLocalAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := localadapteradversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = localadapteradversary.FullScenarios()
	}
	runs := localadapteradversary.RunScenarioCorpus(ctx, profiles, scenarios)
	analysis := localadapteradversary.AnalyzeRuns(runs, localAdapterCollapseThresholds(cfg.Thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		LocalAdapterCorrectnessGate(ctx, profiles, scenarios, cfg.Thresholds),
		LocalAdapterFlowLifecycleGate(ctx, profiles),
		LocalAdapterRuntimeIntegrationGate(ctx, profiles, scenarios, cfg.Thresholds),
		LocalAdapterBackpressureGate(ctx, profiles),
		LocalAdapterErrorResetIsolationGate(ctx, profiles),
		LocalAdapterSequenceIntegrityGate(ctx, profiles),
		LocalAdapterTraceHygieneGate(ctx, profiles),
		LocalAdapterCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		LocalAdapterMutantDetectionGate(ctx, cfg.Thresholds),
		LocalAdapterGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "localadapter-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       len(runs),
		Gates:            gates,
		TraceScanSummary: analysis,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func LocalAdapterCorrectnessGate(ctx context.Context, profiles []*ir.Profile, scenarios []localadapteradversary.Scenario, thresholds AuditThresholds) GateResult {
	report := localadapteradversary.AnalyzeRuns(localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios), localAdapterCollapseThresholds(thresholds))
	failures := localAdapterCorrectnessFailures(report)
	return gate("local_adapter_correctness", len(failures) == 0, "required", fmt.Sprintf("%d local adapter scenario runs checked", report.Correctness.ScenarioRuns), map[string]any{"correctness": report.Correctness, "source_models": report.SourceModels}, failures)
}

func LocalAdapterFlowLifecycleGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioManySmall)})
	failures := []string{}
	for _, run := range runs {
		if run.Summary.FlowsOpened == 0 || run.Summary.FlowsClosed == 0 {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("local_adapter_flow_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d local adapter lifecycle runs checked", len(runs)), nil, failures)
}

func LocalAdapterRuntimeIntegrationGate(ctx context.Context, profiles []*ir.Profile, scenarios []localadapteradversary.Scenario, thresholds AuditThresholds) GateResult {
	report := localadapteradversary.AnalyzeRuns(localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios), localAdapterCollapseThresholds(thresholds))
	failures := []string{}
	if report.Correctness.RuntimeFailures > 0 {
		failures = append(failures, "runtime mapping failures")
	}
	return gate("local_adapter_runtime_integration", len(failures) == 0, "required", fmt.Sprintf("%d runtime/local adapter mappings checked", report.Correctness.ScenarioRuns), map[string]any{"correctness": report.Correctness}, failures)
}

func LocalAdapterBackpressureGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioLargeBackpressure)})
	events := 0
	failures := []string{}
	for _, run := range runs {
		events += run.Summary.BackpressureEvents
		if !run.Checks.BackpressureCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("local_adapter_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d local adapter backpressure events observed", events), nil, failures)
}

func LocalAdapterErrorResetIsolationGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []localadapteradversary.Scenario{
		localadapteradversary.DefaultScenario(localadapteradversary.ScenarioTargetError),
		localadapteradversary.DefaultScenario(localadapteradversary.ScenarioTargetReset),
	})
	errors, resets := 0, 0
	failures := []string{}
	for _, run := range runs {
		errors += run.Summary.TargetErrors
		resets += run.Summary.TargetResets
		if !run.Checks.ErrorResetCorrect {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	return gate("local_adapter_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d target errors and %d target resets mapped locally", errors, resets), nil, failures)
}

func LocalAdapterSequenceIntegrityGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioMalformedChunk)})
	failures := []string{}
	for _, run := range runs {
		if run.Failure == "" {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("local_adapter_sequence_integrity", len(failures) == 0, "required", fmt.Sprintf("%d malformed local chunks rejected", len(runs)), nil, failures)
}

func LocalAdapterTraceHygieneGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioHappyPath)})
	failures := []string{}
	for _, run := range runs {
		if !run.Checks.TraceHygiene {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("local_adapter_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d local adapter traces checked", len(runs)), nil, failures)
}

func LocalAdapterCollapseResistanceGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	runs := localadapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 8), []localadapteradversary.Scenario{
		localadapteradversary.DefaultScenario(localadapteradversary.ScenarioManySmall),
		localadapteradversary.DefaultScenario(localadapteradversary.ScenarioLargeBackpressure),
	})
	report := localadapteradversary.AnalyzeRuns(runs, localAdapterCollapseThresholds(thresholds))
	failures := localAdapterCollapseFailures(report)
	return gate("local_adapter_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d local adapter collapse reports evaluated", len(report.CollapseReports)), map[string]any{"collapse_reports": report.CollapseReports}, failures)
}

func LocalAdapterMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeLocalAdapterIgnoresSourceBackpressure,
		mutant.ModeLocalAdapterAcceptsPostCloseWrite,
		mutant.ModeLocalAdapterDropsFinalChunk,
		mutant.ModeLocalAdapterDuplicatesChunk,
		mutant.ModeLocalAdapterWrongFlowStreamMapping,
		mutant.ModeLocalAdapterPayloadTraceLeak,
		mutant.ModeLocalAdapterSecretTraceLeak,
		mutant.ModeLocalAdapterPaddingOnlyDiversity,
	}
	detected := []string{}
	missed := []string{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 7100, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		report := localadapteradversary.AnalyzeRuns(localadapteradversary.RunMutantScenarioCorpus(ctx, mode, profiles, localAdapterMutantScenarios(mode)), localAdapterCollapseThresholds(thresholds))
		if localAdapterMutantDetected(mode, report) {
			detected = append(detected, mode)
		} else {
			missed = append(missed, mode)
		}
	}
	return gate("local_adapter_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d local adapter mutant modes detected", len(detected), len(modes)), map[string]any{"detected_modes": detected, "missed_modes": missed}, missed)
}

func LocalAdapterGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("local_adapter_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("local_adapter_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(raw)
	failures := []string{}
	for _, marker := range []string{"localadapter_generated.go", "LocalAdapterDemo", "CaptureLocalAdapterTrace", "localadapter-demo", "localadapter"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("local_adapter_generated_backend_parity", len(failures) == 0, "required", "generated backend local adapter support markers checked", nil, failures)
}

func localAdapterCollapseThresholds(thresholds AuditThresholds) localadapteradversary.CollapseThresholds {
	defaults := localadapteradversary.DefaultCollapseThresholds()
	if thresholds.MaxLocalAdapterAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxLocalAdapterAdversaryDominantRatio
	}
	if thresholds.MinLocalAdapterAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinLocalAdapterAdversaryDiversityScore
	}
	if thresholds.MinLocalAdapterScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinLocalAdapterScenarioSuccess
	}
	return defaults
}

func localAdapterCorrectnessFailures(report localadapteradversary.Report) []string {
	failures := []string{}
	if report.Correctness.RuntimeFailures > 0 {
		failures = append(failures, "runtime mapping failures")
	}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "backpressure failures")
	}
	if report.Correctness.ResetFailures > 0 {
		failures = append(failures, "reset failures")
	}
	if report.Correctness.ErrorResetFailures > 0 {
		failures = append(failures, "error/reset failures")
	}
	if report.Correctness.SequenceFailures > 0 {
		failures = append(failures, "sequence failures")
	}
	if report.Correctness.TraceHygieneFailures > 0 {
		failures = append(failures, "trace hygiene failures")
	}
	return failures
}

func localAdapterCollapseFailures(report localadapteradversary.Report) []string {
	failures := []string{}
	for _, collapse := range report.CollapseReports {
		if collapse.Conclusion == "passed" {
			continue
		}
		for _, metric := range collapse.SuspiciousMetrics {
			failures = append(failures, collapse.Scenario+": "+metric)
		}
	}
	return failures
}

func localAdapterMutantScenarios(mode string) []localadapteradversary.Scenario {
	switch mode {
	case mutant.ModeLocalAdapterIgnoresSourceBackpressure:
		return []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioLargeBackpressure)}
	case mutant.ModeLocalAdapterWrongFlowStreamMapping:
		return []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioManySmall)}
	case mutant.ModeLocalAdapterPayloadTraceLeak, mutant.ModeLocalAdapterSecretTraceLeak:
		return []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioHappyPath)}
	default:
		return []localadapteradversary.Scenario{localadapteradversary.DefaultScenario(localadapteradversary.ScenarioManySmall)}
	}
}

func localAdapterMutantDetected(mode string, report localadapteradversary.Report) bool {
	switch mode {
	case mutant.ModeLocalAdapterIgnoresSourceBackpressure:
		return report.Correctness.BackpressureFailures > 0
	case mutant.ModeLocalAdapterAcceptsPostCloseWrite, mutant.ModeLocalAdapterDuplicatesChunk:
		return report.Correctness.SequenceFailures > 0 || report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns
	case mutant.ModeLocalAdapterDropsFinalChunk, mutant.ModeLocalAdapterWrongFlowStreamMapping:
		return report.Correctness.RuntimeFailures > 0 || report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns
	case mutant.ModeLocalAdapterPayloadTraceLeak, mutant.ModeLocalAdapterSecretTraceLeak:
		return report.Correctness.TraceHygieneFailures > 0
	case mutant.ModeLocalAdapterPaddingOnlyDiversity:
		for _, collapse := range report.CollapseReports {
			if collapse.Conclusion != "passed" {
				return true
			}
		}
	}
	return false
}

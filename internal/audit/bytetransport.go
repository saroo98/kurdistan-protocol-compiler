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

	"kurdistan/internal/bytetransportadversary"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func RunByteTransportAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := bytetransportadversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = bytetransportadversary.FullScenarios()
	}
	runs := bytetransportadversary.RunScenarioCorpus(ctx, profiles, scenarios)
	analysis := bytetransportadversary.AnalyzeRuns(runs, byteTransportCollapseThresholds(cfg.Thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		ByteTransportEncodingCorrectnessGate(ctx, profiles, scenarios, cfg.Thresholds),
		ByteTransportFragmentationReassemblyGate(ctx, profiles),
		ByteTransportPipeBackpressureGate(ctx, profiles),
		ByteTransportSequenceIntegrityGate(ctx, profiles),
		ByteTransportCorruptionRejectionGate(ctx, profiles),
		ByteTransportRuntimeIntegrationGate(ctx, profiles, scenarios, cfg.Thresholds),
		ByteTransportErrorResetIsolationGate(ctx, profiles),
		ByteTransportTraceHygieneGate(ctx, profiles),
		ByteTransportCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		ByteTransportMutantDetectionGate(ctx, cfg.Thresholds),
		ByteTransportGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "bytetransport-" + cfg.Mode,
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

func ByteTransportEncodingCorrectnessGate(ctx context.Context, profiles []*ir.Profile, scenarios []bytetransportadversary.Scenario, thresholds AuditThresholds) GateResult {
	report := bytetransportadversary.AnalyzeRuns(bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios), byteTransportCollapseThresholds(thresholds))
	failures := byteTransportCorrectnessFailures(report)
	return gate("byte_transport_encoding_correctness", len(failures) == 0, "required", fmt.Sprintf("%d byte transport scenario runs checked", report.Correctness.ScenarioRuns), map[string]any{"correctness": report.Correctness}, failures)
}

func ByteTransportFragmentationReassemblyGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioLargeFragmented)})
	failures := []string{}
	created, reassembled := 0, 0
	for _, run := range runs {
		created += run.Summary.FragmentsCreated
		reassembled += run.Summary.FragmentsReassembled
		if !run.Checks.ReassemblyCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_fragmentation_reassembly", len(failures) == 0, "required", fmt.Sprintf("%d fragments created; %d reassemblies observed", created, reassembled), nil, failures)
}

func ByteTransportPipeBackpressureGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioBackpressureChain)})
	events := 0
	failures := []string{}
	for _, run := range runs {
		events += run.Summary.BackpressureEvents
		if !run.Checks.BackpressureCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_pipe_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d byte pipe backpressure events observed", events), nil, failures)
}

func ByteTransportSequenceIntegrityGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioReplay)})
	rejected := 0
	failures := []string{}
	for _, run := range runs {
		rejected += run.Summary.SequenceRejected
		if !run.Checks.SequenceCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_sequence_integrity", len(failures) == 0, "required", fmt.Sprintf("%d replay/sequence frames rejected", rejected), nil, failures)
}

func ByteTransportCorruptionRejectionGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioCorruption)})
	rejected := 0
	failures := []string{}
	for _, run := range runs {
		rejected += run.Summary.CorruptionRejected
		if !run.Checks.CorruptionCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_corruption_rejection", len(failures) == 0, "required", fmt.Sprintf("%d corrupted frames rejected", rejected), nil, failures)
}

func ByteTransportRuntimeIntegrationGate(ctx context.Context, profiles []*ir.Profile, scenarios []bytetransportadversary.Scenario, thresholds AuditThresholds) GateResult {
	report := bytetransportadversary.AnalyzeRuns(bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios), byteTransportCollapseThresholds(thresholds))
	failures := []string{}
	if report.Correctness.RuntimeIntegrationFailures > 0 {
		failures = append(failures, "runtime integration failures")
	}
	return gate("byte_transport_runtime_integration", len(failures) == 0, "required", fmt.Sprintf("%d byte runtime mappings checked", report.Correctness.ScenarioRuns), map[string]any{"correctness": report.Correctness}, failures)
}

func ByteTransportErrorResetIsolationGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioMixed)})
	failures := []string{}
	resets := 0
	for _, run := range runs {
		resets += run.Summary.TargetResets
		if !run.Checks.ErrorResetCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d byte reset/error paths observed", resets), nil, failures)
}

func ByteTransportTraceHygieneGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioHappyPath)})
	failures := []string{}
	for _, run := range runs {
		if !run.Checks.TraceHygiene {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("byte_transport_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d byte transport traces checked", len(runs)), nil, failures)
}

func ByteTransportCollapseResistanceGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	runs := bytetransportadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 8), []bytetransportadversary.Scenario{
		bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioManySmall),
		bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioLargeFragmented),
	})
	report := bytetransportadversary.AnalyzeRuns(runs, byteTransportCollapseThresholds(thresholds))
	failures := byteTransportCollapseFailures(report)
	return gate("byte_transport_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d byte collapse reports evaluated", len(report.CollapseReports)), map[string]any{"collapse_reports": report.CollapseReports}, failures)
}

func ByteTransportMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeByteTransportAcceptsMalformedFrame,
		mutant.ModeByteTransportIgnoresMaxFrameSize,
		mutant.ModeByteTransportIgnoresBackpressure,
		mutant.ModeByteTransportReusesSequence,
		mutant.ModeByteTransportAcceptsCorruption,
		mutant.ModeByteTransportDropsFragmentSilently,
		mutant.ModeByteTransportPayloadTraceLeak,
		mutant.ModeByteTransportPaddingOnlyDiversity,
	}
	detected := []string{}
	missed := []string{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 8100, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		report := bytetransportadversary.AnalyzeRuns(bytetransportadversary.RunMutantScenarioCorpus(ctx, mode, profiles, byteTransportMutantScenarios(mode)), byteTransportCollapseThresholds(thresholds))
		if byteTransportMutantDetected(mode, report) {
			detected = append(detected, mode)
		} else {
			missed = append(missed, mode)
		}
	}
	return gate("byte_transport_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d byte transport mutant modes detected", len(detected), len(modes)), map[string]any{"detected_modes": detected, "missed_modes": missed}, missed)
}

func ByteTransportGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("byte_transport_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("byte_transport_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(raw)
	failures := []string{}
	for _, marker := range []string{"bytetransport_generated.go", "ByteTransportDemo", "CaptureByteTransportTrace", "bytetransport-demo", "bytetransport"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("byte_transport_generated_backend_parity", len(failures) == 0, "required", "generated backend byte transport support markers checked", nil, failures)
}

func byteTransportCollapseThresholds(thresholds AuditThresholds) bytetransportadversary.CollapseThresholds {
	defaults := bytetransportadversary.DefaultCollapseThresholds()
	if thresholds.MaxByteTransportAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxByteTransportAdversaryDominantRatio
	}
	if thresholds.MinByteTransportAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinByteTransportAdversaryDiversityScore
	}
	if thresholds.MinByteTransportScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinByteTransportScenarioSuccess
	}
	return defaults
}

func byteTransportCorrectnessFailures(report bytetransportadversary.Report) []string {
	failures := []string{}
	if report.Correctness.RuntimeIntegrationFailures > 0 {
		failures = append(failures, "runtime integration failures")
	}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "backpressure failures")
	}
	if report.Correctness.SequenceFailures > 0 {
		failures = append(failures, "sequence failures")
	}
	if report.Correctness.CorruptionFailures > 0 {
		failures = append(failures, "corruption failures")
	}
	if report.Correctness.ReassemblyFailures > 0 {
		failures = append(failures, "reassembly failures")
	}
	if report.Correctness.TraceHygieneFailures > 0 {
		failures = append(failures, "trace hygiene failures")
	}
	return failures
}

func byteTransportCollapseFailures(report bytetransportadversary.Report) []string {
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

func byteTransportMutantScenarios(mode string) []bytetransportadversary.Scenario {
	switch mode {
	case mutant.ModeByteTransportIgnoresBackpressure:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioBackpressureChain)}
	case mutant.ModeByteTransportReusesSequence:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioReplay)}
	case mutant.ModeByteTransportAcceptsCorruption:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioCorruption)}
	case mutant.ModeByteTransportDropsFragmentSilently:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioLargeFragmented)}
	case mutant.ModeByteTransportPayloadTraceLeak:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioHappyPath)}
	default:
		return []bytetransportadversary.Scenario{bytetransportadversary.DefaultScenario(bytetransportadversary.ScenarioManySmall)}
	}
}

func byteTransportMutantDetected(mode string, report bytetransportadversary.Report) bool {
	switch mode {
	case mutant.ModeByteTransportIgnoresBackpressure:
		return report.Correctness.BackpressureFailures > 0
	case mutant.ModeByteTransportReusesSequence:
		return report.Correctness.SequenceFailures > 0
	case mutant.ModeByteTransportAcceptsCorruption:
		return report.Correctness.CorruptionFailures > 0
	case mutant.ModeByteTransportAcceptsMalformedFrame, mutant.ModeByteTransportIgnoresMaxFrameSize, mutant.ModeByteTransportDropsFragmentSilently:
		return report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns || report.Correctness.ReassemblyFailures > 0
	case mutant.ModeByteTransportPayloadTraceLeak:
		return report.Correctness.TraceHygieneFailures > 0
	case mutant.ModeByteTransportPaddingOnlyDiversity:
		for _, collapse := range report.CollapseReports {
			if collapse.Conclusion != "passed" {
				return true
			}
		}
	}
	return false
}

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

	"kurdistan/internal/carrieradversary"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func RunCarrierAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := carrieradversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = carrieradversary.FullScenarios()
	}
	thresholds := cfg.Thresholds
	if cfg.ProfileCount < 10 {
		thresholds.MinCarrierPolicyCombinations = min(thresholds.MinCarrierPolicyCombinations, 2)
		thresholds.MinCarrierFamilies = min(thresholds.MinCarrierFamilies, 3)
		thresholds.MinCarrierEnvelopeEncodings = min(thresholds.MinCarrierEnvelopeEncodings, 2)
	}
	runs, err := carrieradversary.RunScenarioCorpus(ctx, profiles, scenarios)
	if err != nil {
		return AuditReport{}, err
	}
	analysis := carrieradversary.AnalyzeRuns(runs, carrierCollapseThresholds(thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		CarrierSemanticsCorrectnessGate(ctx, profiles, scenarios, thresholds),
		CarrierDiversityGate(profiles, thresholds),
		CarrierBackpressurePreservationGate(ctx, profiles, thresholds),
		CarrierLossReorderRecoveryGate(ctx, profiles, thresholds),
		CarrierProxySemParityGate(ctx, profiles, thresholds),
		CarrierMutantDetectionGate(ctx, thresholds),
		CarrierGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "carrier-" + cfg.Mode,
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

func CarrierSemanticsCorrectnessGate(ctx context.Context, profiles []*ir.Profile, scenarios []carrieradversary.Scenario, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 3)
	runs, err := carrieradversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("carrier_semantics_correctness", false, "required", err.Error(), nil, []string{err.Error()})
	}
	report := carrieradversary.AnalyzeRuns(runs, carrierCollapseThresholds(thresholds))
	failures := carrierCorrectnessFailures(report)
	return gate("carrier_semantics_correctness", len(failures) == 0, "required", fmt.Sprintf("%d carrier scenario runs checked; %d failures", report.Correctness.ScenarioRuns, len(failures)), map[string]any{
		"profile_count":    report.ProfileCount,
		"scenario_count":   report.ScenarioCount,
		"carrier_families": report.CarrierFamilies,
		"correct_runs":     report.Correctness.CorrectRuns,
		"scenario_runs":    report.Correctness.ScenarioRuns,
		"correctness":      report.Correctness,
	}, failures)
}

func CarrierDiversityGate(profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	combinations := profileValues(profiles, func(p *ir.Profile) string {
		return strings.Join([]string{
			p.CarrierPolicy.CarrierFamily,
			p.CarrierPolicy.EnvelopeEncoding,
			p.CarrierPolicy.FlushPolicy,
			p.CarrierPolicy.BatchPolicy,
			p.CarrierPolicy.ChunkingPolicy,
			p.CarrierPolicy.ReliabilityPolicy,
			p.CarrierPolicy.BackpressurePolicy,
			p.CarrierPolicy.EnvelopePaddingPolicy,
		}, "|")
	})
	families := profileValues(profiles, func(p *ir.Profile) string { return p.CarrierPolicy.CarrierFamily })
	encodings := profileValues(profiles, func(p *ir.Profile) string { return p.CarrierPolicy.EnvelopeEncoding })
	failures := []string{}
	if uniqueStrings(combinations) < thresholds.MinCarrierPolicyCombinations {
		failures = append(failures, "carrier policy combinations below threshold")
	}
	if uniqueStrings(families) < thresholds.MinCarrierFamilies {
		failures = append(failures, "carrier families below threshold")
	}
	if uniqueStrings(encodings) < thresholds.MinCarrierEnvelopeEncodings {
		failures = append(failures, "carrier envelope encodings below threshold")
	}
	return gate("carrier_diversity", len(failures) == 0, "required", fmt.Sprintf("%d carrier policy combinations across %d profiles", uniqueStrings(combinations), len(profiles)), map[string]any{
		"unique_carrier_policy_combinations": uniqueStrings(combinations),
		"unique_carrier_families":            uniqueStrings(families),
		"unique_carrier_envelope_encodings":  uniqueStrings(encodings),
		"min_carrier_families":               thresholds.MinCarrierFamilies,
	}, failures)
}

func CarrierBackpressurePreservationGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 2)
	scenarios := []carrieradversary.Scenario{carrieradversary.DefaultScenario(carrieradversary.ScenarioCarrierBackpressureChain)}
	runs, err := carrieradversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("carrier_backpressure_preservation", false, "required", err.Error(), nil, []string{err.Error()})
	}
	events := 0
	failures := []string{}
	for _, run := range runs {
		events += run.Checks.BackpressureEvents + run.Checks.TargetBackpressure
		if !run.Checks.BackpressureCorrect {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	return gate("carrier_backpressure_preservation", len(failures) == 0, "required", fmt.Sprintf("%d carrier/target backpressure events observed", events), map[string]any{
		"profile_count":       len(selected),
		"backpressure_events": events,
	}, failures)
}

func CarrierLossReorderRecoveryGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 2)
	scenarios := []carrieradversary.Scenario{
		carrieradversary.DefaultScenario(carrieradversary.ScenarioDatagramReorderRecovery),
		carrieradversary.DefaultScenario(carrieradversary.ScenarioLossyRetryRecovery),
	}
	runs, err := carrieradversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("carrier_loss_reorder_recovery", false, "required", err.Error(), nil, []string{err.Error()})
	}
	reorders, retries := 0, 0
	failures := []string{}
	for _, run := range runs {
		reorders += run.Checks.ReorderEvents
		retries += run.Checks.RetryEvents
		if !run.Checks.RecoveryCorrect {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	if reorders+retries == 0 {
		failures = append(failures, "no reorder or retry events observed")
	}
	return gate("carrier_loss_reorder_recovery", len(failures) == 0, "required", fmt.Sprintf("%d reorder and %d retry events observed", reorders, retries), map[string]any{
		"reorder_events": reorders,
		"retry_events":   retries,
	}, failures)
}

func CarrierProxySemParityGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 2)
	scenarios := []carrieradversary.Scenario{carrieradversary.DefaultScenario(carrieradversary.ScenarioMixedCarrierMatrix)}
	runs, err := carrieradversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("carrier_proxysem_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	failures := []string{}
	for _, run := range runs {
		if !run.Checks.ProxySemParity || !run.Checks.ErrorResetPreserved {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("carrier_proxysem_parity", len(failures) == 0, "required", fmt.Sprintf("%d proxysem carrier parity runs checked", len(runs)), map[string]any{
		"runs": len(runs),
	}, failures)
}

func CarrierMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeFixedCarrierFamily,
		mutant.ModeFixedEnvelopeEncoding,
		mutant.ModeFixedFlushPolicy,
		mutant.ModeFixedBatchPolicy,
		mutant.ModeFixedChunkingPolicy,
		mutant.ModeNoCarrierBackpressure,
		mutant.ModeNoReorderRecovery,
		mutant.ModePaddingOnlyCarrierDiversity,
	}
	detected := []string{}
	missed := []string{}
	modeDetails := map[string]any{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 3100, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		runs, err := carrieradversary.RunMutantScenarioCorpus(ctx, mode, profiles, carrierMutantScenarios(mode))
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		report := carrieradversary.AnalyzeRuns(runs, carrierCollapseThresholds(thresholds))
		reasons := carrierMutantDetectionReasons(mode, report)
		modeDetails[mode] = map[string]any{"reasons": reasons, "correctness": report.Correctness, "collapse_reports": report.CollapseReports}
		if len(reasons) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("carrier_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d carrier mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
		"mode_details":   modeDetails,
	}, missed)
}

func CarrierGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("carrier_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("carrier_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"carrier_generated.go", "CarrierDemo", "CaptureCarrierTrace", "carrier-demo", "carrier"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("carrier_generated_backend_parity", len(failures) == 0, "required", "generated backend carrier support markers checked", map[string]any{
		"scanner": "source-marker",
	}, failures)
}

func carrierCollapseThresholds(thresholds AuditThresholds) carrieradversary.CollapseThresholds {
	defaults := carrieradversary.DefaultCollapseThresholds()
	if thresholds.MaxCarrierAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxCarrierAdversaryDominantRatio
	}
	if thresholds.MinCarrierAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinCarrierAdversaryDiversityScore
	}
	if thresholds.MinCarrierScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinCarrierScenarioSuccess
	}
	return defaults
}

func carrierCorrectnessFailures(report carrieradversary.Report) []string {
	failures := []string{}
	if report.Correctness.ReconstructionFailure > 0 {
		failures = append(failures, "semantic reconstruction failures")
	}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "carrier backpressure failures")
	}
	if report.Correctness.RecoveryFailures > 0 {
		failures = append(failures, "carrier recovery failures")
	}
	if report.Correctness.ProxyParityFailures > 0 {
		failures = append(failures, "proxysem parity failures")
	}
	if report.Correctness.MalformedFailures > 0 {
		failures = append(failures, "malformed envelope rejection failures")
	}
	return failures
}

func carrierMutantScenarios(mode string) []carrieradversary.Scenario {
	switch mode {
	case mutant.ModeNoCarrierBackpressure:
		return []carrieradversary.Scenario{carrieradversary.DefaultScenario(carrieradversary.ScenarioCarrierBackpressureChain)}
	case mutant.ModeNoReorderRecovery:
		return []carrieradversary.Scenario{carrieradversary.DefaultScenario(carrieradversary.ScenarioLossyRetryRecovery)}
	default:
		return []carrieradversary.Scenario{carrieradversary.DefaultScenario(carrieradversary.ScenarioMixedCarrierMatrix)}
	}
}

func carrierMutantDetectionReasons(mode string, report carrieradversary.Report) []string {
	reasons := []string{}
	if mode == mutant.ModeNoCarrierBackpressure && report.Correctness.BackpressureFailures > 0 {
		reasons = append(reasons, "carrier backpressure correctness failed")
	}
	if mode == mutant.ModeNoReorderRecovery && report.Correctness.RecoveryFailures > 0 {
		reasons = append(reasons, "carrier reorder recovery failed")
	}
	expected := map[string]string{
		mutant.ModeFixedCarrierFamily:          "carrier_family",
		mutant.ModeFixedEnvelopeEncoding:       "envelope_encoding_pattern",
		mutant.ModeFixedFlushPolicy:            "flush_pattern",
		mutant.ModeFixedBatchPolicy:            "batch_policy",
		mutant.ModeFixedChunkingPolicy:         "chunking_policy",
		mutant.ModePaddingOnlyCarrierDiversity: "carrier_behavior_fixed",
	}
	if metric := expected[mode]; metric != "" && carrierReportHasSuspiciousMetric(report, metric) {
		reasons = append(reasons, metric)
	}
	return reasons
}

func carrierReportHasSuspiciousMetric(report carrieradversary.Report, metric string) bool {
	for _, collapse := range report.CollapseReports {
		for _, found := range collapse.SuspiciousMetrics {
			if found == metric {
				return true
			}
		}
	}
	return false
}

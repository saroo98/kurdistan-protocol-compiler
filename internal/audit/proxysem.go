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
	"kurdistan/internal/mutant"
	"kurdistan/internal/proxyadversary"
)

func RunProxySemanticsAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := proxyadversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = proxyadversary.FullScenarios()
	}
	thresholds := cfg.Thresholds
	if cfg.ProfileCount < 10 {
		thresholds.MinProxyPolicyCombinations = min(thresholds.MinProxyPolicyCombinations, 2)
		thresholds.MinProxyTargetDescriptorEncodings = min(thresholds.MinProxyTargetDescriptorEncodings, 1)
		thresholds.MinProxyErrorPolicies = min(thresholds.MinProxyErrorPolicies, 2)
	}
	runs, err := proxyadversary.RunScenarioCorpus(ctx, profiles, scenarios)
	if err != nil {
		return AuditReport{}, err
	}
	analysis := proxyadversary.AnalyzeRuns(runs, proxyCollapseThresholds(thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		ProxySemanticsCorrectnessGate(ctx, profiles, scenarios, thresholds),
		ProxySemanticsDiversityGate(profiles, thresholds),
		ProxyTargetBackpressureGate(ctx, profiles, thresholds),
		ProxyErrorResetIsolationGate(ctx, profiles, thresholds),
		ProxyMutantDetectionGate(ctx, thresholds),
		ProxyGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "proxysem-" + cfg.Mode,
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

func ProxySemanticsCorrectnessGate(ctx context.Context, profiles []*ir.Profile, scenarios []proxyadversary.Scenario, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 3)
	runs, err := proxyadversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("proxy_semantics_correctness", false, "required", err.Error(), map[string]any{
			"profile_count": len(selected), "scenario_count": len(scenarios),
		}, []string{err.Error()})
	}
	report := proxyadversary.AnalyzeRuns(runs, proxyCollapseThresholds(thresholds))
	failures := proxyCorrectnessFailures(report)
	return gate("proxy_semantics_correctness", len(failures) == 0, "required", fmt.Sprintf("%d proxy scenario runs checked; %d failures", report.Correctness.ScenarioRuns, len(failures)), map[string]any{
		"profile_count":  report.ProfileCount,
		"scenario_count": report.ScenarioCount,
		"correct_runs":   report.Correctness.CorrectRuns,
		"scenario_runs":  report.Correctness.ScenarioRuns,
		"target_classes": report.TargetClasses,
		"correctness":    report.Correctness,
	}, failures)
}

func ProxySemanticsDiversityGate(profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	combinations := profileValues(profiles, func(p *ir.Profile) string {
		return strings.Join([]string{
			p.ProxySemantics.RelayIntentEncoding,
			p.ProxySemantics.TargetDescriptorEncoding,
			p.ProxySemantics.RequestClassEncoding,
			p.ProxySemantics.ResponseModeEncoding,
			p.ProxySemantics.TargetErrorPolicy,
			p.ProxySemantics.TargetClosePolicy,
			p.ProxySemantics.TargetResetPolicy,
			p.ProxySemantics.TargetMetadataPolicy,
			p.ProxySemantics.TargetClassMapping,
		}, "|")
	})
	descriptors := profileValues(profiles, func(p *ir.Profile) string { return p.ProxySemantics.TargetDescriptorEncoding })
	errors := profileValues(profiles, func(p *ir.Profile) string { return p.ProxySemantics.TargetErrorPolicy })
	failures := []string{}
	if uniqueStrings(combinations) < thresholds.MinProxyPolicyCombinations {
		failures = append(failures, "proxy policy combinations below threshold")
	}
	if uniqueStrings(descriptors) < thresholds.MinProxyTargetDescriptorEncodings {
		failures = append(failures, "target descriptor encodings below threshold")
	}
	if uniqueStrings(errors) < thresholds.MinProxyErrorPolicies {
		failures = append(failures, "target error policies below threshold")
	}
	return gate("proxy_semantics_diversity", len(failures) == 0, "required", fmt.Sprintf("%d proxy policy combinations across %d profiles", uniqueStrings(combinations), len(profiles)), map[string]any{
		"unique_proxy_policy_combinations": uniqueStrings(combinations),
		"unique_descriptor_encodings":      uniqueStrings(descriptors),
		"unique_target_error_policies":     uniqueStrings(errors),
		"min_proxy_policy_combinations":    thresholds.MinProxyPolicyCombinations,
	}, failures)
}

func ProxyTargetBackpressureGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 2)
	scenarios := []proxyadversary.Scenario{
		proxyadversary.DefaultScenario(proxyadversary.ScenarioSlowTargetBackpressure),
		proxyadversary.DefaultScenario(proxyadversary.ScenarioLargeResponseBackpressure),
	}
	runs, err := proxyadversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("proxy_target_backpressure", false, "required", err.Error(), nil, []string{err.Error()})
	}
	failures := []string{}
	events := 0
	for _, run := range runs {
		events += run.Checks.BackpressureEvents
		if !run.Checks.TargetBackpressureCorrect {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
		if run.Scenario == proxyadversary.ScenarioLargeResponseBackpressure && run.Checks.WindowUpdateEvents == 0 {
			failures = append(failures, run.ProfileID+":large response did not recover with window update")
		}
	}
	return gate("proxy_target_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d target-induced backpressure events observed", events), map[string]any{
		"profile_count":          len(selected),
		"scenario_count":         len(scenarios),
		"backpressure_events":    events,
		"window_update_required": true,
	}, failures)
}

func ProxyErrorResetIsolationGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 2)
	scenarios := []proxyadversary.Scenario{
		proxyadversary.DefaultScenario(proxyadversary.ScenarioErrorTargetIsolation),
		proxyadversary.DefaultScenario(proxyadversary.ScenarioTargetResetMidstream),
	}
	runs, err := proxyadversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("proxy_error_reset_isolation", false, "required", err.Error(), nil, []string{err.Error()})
	}
	errorsSeen, resetsSeen := 0, 0
	failures := []string{}
	for _, run := range runs {
		errorsSeen += run.Checks.TargetErrorCount
		resetsSeen += run.Checks.TargetResetCount
		if !run.Checks.ErrorResetIsolation {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	if errorsSeen == 0 {
		failures = append(failures, "no synthetic target errors observed")
	}
	if resetsSeen == 0 {
		failures = append(failures, "no synthetic target resets observed")
	}
	return gate("proxy_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d target errors and %d target resets observed", errorsSeen, resetsSeen), map[string]any{
		"target_errors": errorsSeen,
		"target_resets": resetsSeen,
	}, failures)
}

func ProxyMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeFixedTargetDescriptorEncoding,
		mutant.ModeFixedTargetOpenSequence,
		mutant.ModeFixedTargetErrorPolicy,
		mutant.ModeFixedTargetClosePolicy,
		mutant.ModeFixedResponseChunking,
		mutant.ModeNoTargetBackpressure,
		mutant.ModePaddingOnlyProxyDiversity,
	}
	detected := []string{}
	missed := []string{}
	modeDetails := map[string]any{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 2100, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		scenarios := proxyMutantScenarios(mode)
		runs, err := proxyadversary.RunMutantScenarioCorpus(ctx, mode, profiles, scenarios)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		report := proxyadversary.AnalyzeRuns(runs, proxyCollapseThresholds(thresholds))
		reasons := proxyMutantDetectionReasons(mode, report)
		modeDetails[mode] = map[string]any{"reasons": reasons, "correctness": report.Correctness, "collapse_reports": report.CollapseReports}
		if len(reasons) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("proxy_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d proxy mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
		"mode_details":   modeDetails,
	}, missed)
}

func ProxyGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("proxy_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("proxy_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"proxysem_generated.go", "ProxySemDemo", "CaptureProxySemTrace", "proxysem-demo", "proxysem"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("proxy_generated_backend_parity", len(failures) == 0, "required", "generated backend proxysem support markers checked", map[string]any{
		"scanner": "source-marker",
	}, failures)
}

func proxyCollapseThresholds(thresholds AuditThresholds) proxyadversary.CollapseThresholds {
	defaults := proxyadversary.DefaultCollapseThresholds()
	if thresholds.MaxProxyAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxProxyAdversaryDominantRatio
	}
	if thresholds.MinProxyAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinProxyAdversaryDiversityScore
	}
	if thresholds.MinProxyAdversaryScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinProxyAdversaryScenarioSuccess
	}
	return defaults
}

func proxyCorrectnessFailures(report proxyadversary.Report) []string {
	failures := []string{}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "target backpressure correctness failures")
	}
	if report.Correctness.ErrorResetFailures > 0 {
		failures = append(failures, "target error/reset isolation failures")
	}
	if report.Correctness.FairnessFailures > 0 {
		failures = append(failures, "target fairness failures")
	}
	if report.Correctness.MetadataFailures > 0 {
		failures = append(failures, "missing safe proxy trace metadata")
	}
	if report.Correctness.DescriptorProbeFailures > 0 {
		failures = append(failures, "descriptor probe rejection failures")
	}
	return failures
}

func proxyMutantScenarios(mode string) []proxyadversary.Scenario {
	switch mode {
	case mutant.ModeNoTargetBackpressure:
		return []proxyadversary.Scenario{proxyadversary.DefaultScenario(proxyadversary.ScenarioSlowTargetBackpressure)}
	case mutant.ModeFixedTargetErrorPolicy:
		return []proxyadversary.Scenario{proxyadversary.DefaultScenario(proxyadversary.ScenarioErrorTargetIsolation)}
	case mutant.ModeFixedTargetClosePolicy:
		return []proxyadversary.Scenario{proxyadversary.DefaultScenario(proxyadversary.ScenarioManySmallRequests)}
	case mutant.ModeFixedResponseChunking:
		return []proxyadversary.Scenario{proxyadversary.DefaultScenario(proxyadversary.ScenarioChunkedResponseMix)}
	default:
		return []proxyadversary.Scenario{proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)}
	}
}

func proxyMutantDetectionReasons(mode string, report proxyadversary.Report) []string {
	reasons := []string{}
	if mode == mutant.ModeNoTargetBackpressure && report.Correctness.BackpressureFailures > 0 {
		reasons = append(reasons, "target backpressure correctness failed")
	}
	expected := map[string]string{
		mutant.ModeFixedTargetDescriptorEncoding: "descriptor_encoding_pattern",
		mutant.ModeFixedTargetOpenSequence:       "target_open_sequence",
		mutant.ModeFixedTargetErrorPolicy:        "target_error_behavior",
		mutant.ModeFixedTargetClosePolicy:        "close_behavior",
		mutant.ModeFixedResponseChunking:         "response_mode_encoding",
		mutant.ModePaddingOnlyProxyDiversity:     "proxy_behavior_fixed",
	}
	if metric := expected[mode]; metric != "" && proxyReportHasSuspiciousMetric(report, metric) {
		reasons = append(reasons, metric)
	}
	return reasons
}

func proxyReportHasSuspiciousMetric(report proxyadversary.Report, metric string) bool {
	for _, collapse := range report.CollapseReports {
		for _, found := range collapse.SuspiciousMetrics {
			if found == metric {
				return true
			}
		}
	}
	return false
}

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

	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/mutant"
)

type LocalProxyIngressAdversarialAuditSummary struct {
	Version             string                                                  `json:"version"`
	ScenarioCount       int                                                     `json:"scenario_count"`
	DescriptorCases     int                                                     `json:"descriptor_cases"`
	LifecycleViolations int                                                     `json:"lifecycle_violations"`
	PressureCases       int                                                     `json:"pressure_cases"`
	ResetErrorScenarios int                                                     `json:"reset_error_scenarios"`
	ReadinessDecision   string                                                  `json:"readiness_decision"`
	Fixture             localproxyingressadversary.AdversarialFixtureComparison `json:"fixture"`
	Conclusion          string                                                  `json:"conclusion"`
}

func RunLocalProxyIngressAdversarialAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localProxyIngressAdversarialFixtureComparison(ctx, filepath.Join(root, "testdata", "localproxyingressadversary", "adversarial-corpus-golden.json"), set)
	gates := LocalProxyIngressAdversarialGates(set, comparison)
	summary := LocalProxyIngressAdversarialAuditSummary{
		Version:             localproxyingressadversary.Version,
		ScenarioCount:       set.Corpus.ScenarioCount,
		DescriptorCases:     set.DescriptorAbuse.CaseCount,
		LifecycleViolations: set.Lifecycle.ViolationsAttempted,
		PressureCases:       set.Pressure.ScenarioCount,
		ResetErrorScenarios: set.ResetError.ScenarioCount,
		ReadinessDecision:   set.Readiness.GoNoGoDecision,
		Fixture:             comparison,
		Conclusion:          "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "localproxyingressadv-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
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

func LocalProxyIngressAdversarialGates(set localproxyingressadversary.AdversarialFixtureSet, comparison localproxyingressadversary.AdversarialFixtureComparison) []GateResult {
	return []GateResult{
		LocalProxyIngressAdvCorpusValidationGate(set.Corpus),
		LocalProxyIngressAdvDescriptorAbuseGate(set.DescriptorAbuse),
		LocalProxyIngressAdvLifecycleHardeningGate(set.Lifecycle),
		LocalProxyIngressAdvPressureHardeningGate(set.Pressure),
		LocalProxyIngressAdvResetErrorIsolationGate(set.ResetError),
		LocalProxyIngressAdvMappingCollapseGate(set.MappingCollapse, set.CollapsedControl),
		LocalProxyIngressAdvGeneratedBackendParityGate(set.Parity),
		LocalProxyIngressAdvM27ReadinessGate(set.Readiness),
		LocalProxyIngressAdvTraceHygieneGate(set),
		LocalProxyIngressAdvMutantDetectionGate(),
		LocalProxyIngressAdvFixtureDriftGate(comparison),
	}
}

func LocalProxyIngressAdvCorpusValidationGate(corpus localproxyingressadversary.AdversarialIngressCorpus) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateCorpus(corpus); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_corpus_validation", len(failures) == 0, "required", fmt.Sprintf("%s: %d scenarios", corpus.Version, corpus.ScenarioCount), nil, failures)
}

func LocalProxyIngressAdvDescriptorAbuseGate(report localproxyingressadversary.DescriptorAbuseReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateDescriptorAbuseReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_descriptor_abuse", len(failures) == 0, "required", fmt.Sprintf("%d descriptor cases rejected", report.Rejected), map[string]any{"descriptor_abuse": report}, failures)
}

func LocalProxyIngressAdvLifecycleHardeningGate(report localproxyingressadversary.LifecycleHardeningReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateLifecycleHardeningReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_lifecycle_hardening", len(failures) == 0, "required", fmt.Sprintf("%d/%d invalid transitions rejected", report.ViolationsRejected, report.ViolationsAttempted), nil, failures)
}

func LocalProxyIngressAdvPressureHardeningGate(report localproxyingressadversary.PressureHardeningReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidatePressureHardeningReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_pressure_hardening", len(failures) == 0, "required", fmt.Sprintf("%d pressure scenarios; %d overflows rejected", report.ScenarioCount, report.OverflowRejected), nil, failures)
}

func LocalProxyIngressAdvResetErrorIsolationGate(report localproxyingressadversary.ResetErrorIsolationReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateResetErrorIsolationReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_reset_error_isolation", len(failures) == 0, "required", fmt.Sprintf("%d resets and %d errors isolated", report.IsolatedResets, report.IsolatedTargetErrors), nil, failures)
}

func LocalProxyIngressAdvMappingCollapseGate(report, control localproxyingressadversary.IngressMappingCollapseReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateMappingCollapseReport(report, true); err != nil {
		failures = append(failures, "healthy mapping collapse report failed: "+err.Error())
	}
	if err := localproxyingressadversary.ValidateMappingCollapseReport(control, false); err != nil {
		failures = append(failures, "collapsed control not detected: "+err.Error())
	}
	return gate("localproxyingressadv_mapping_collapse", len(failures) == 0, "required", fmt.Sprintf("%d unique target bindings; control findings=%d", report.UniqueTargetBindings, len(control.CollapseFindings)), map[string]any{"mapping_collapse": report, "collapsed_control": control}, failures)
}

func LocalProxyIngressAdvGeneratedBackendParityGate(report localproxyingressadversary.LocalProxyIngressAdversarialParityReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateParityReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"localproxyingressadv_generated.go", "localproxyingressadv_test.go", "localproxyingressadv_parity_test.go", "localproxyingressadv_hygiene_test.go", "LocalProxyIngressAdversarialSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated marker "+marker)
				}
			}
		}
	}
	return gate("localproxyingressadv_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", report.ComparedScenarios), nil, failures)
}

func LocalProxyIngressAdvM27ReadinessGate(report localproxyingressadversary.ProxyIngressM27ReadinessReport) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateReadinessReport(report); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingressadv_m27_readiness", len(failures) == 0, "required", report.GoNoGoDecision, map[string]any{"readiness": report}, failures)
}

func LocalProxyIngressAdvTraceHygieneGate(set localproxyingressadversary.AdversarialFixtureSet) GateResult {
	failures := []string{}
	if err := localproxyingressadversary.ValidateAdversarialFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range []map[string]string{
		{"endpoint": "synthetic"},
		{"payload": "synthetic"},
		{"raw_bytes": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := localproxyingressadversary.ScanFixtureHygiene(tc); err == nil {
			failures = append(failures, "unsafe fixture field accepted")
		}
	}
	return gate("localproxyingressadv_trace_hygiene", len(failures) == 0, "required", "adversarial fixtures contain safe metadata only", nil, failures)
}

func LocalProxyIngressAdvMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLocalProxyIngressAdvAcceptsDescriptorAbuse,
		mutant.ModeLocalProxyIngressAdvAcceptsDataBeforeOpen,
		mutant.ModeLocalProxyIngressAdvAcceptsDataAfterClose,
		mutant.ModeLocalProxyIngressAdvAcceptsTerminalReopen,
		mutant.ModeLocalProxyIngressAdvUnboundedQueueGrowth,
		mutant.ModeLocalProxyIngressAdvIgnoresBackpressure,
		mutant.ModeLocalProxyIngressAdvResetCrossRequestLeak,
		mutant.ModeLocalProxyIngressAdvErrorCrossRequestLeak,
		mutant.ModeLocalProxyIngressAdvDescriptorLeak,
		mutant.ModeLocalProxyIngressAdvFixedMapping,
		mutant.ModeLocalProxyIngressAdvCollapseNotDetected,
		mutant.ModeLocalProxyIngressAdvReviewGoDespiteBlocker,
		mutant.ModeLocalProxyIngressAdvPayloadLeak,
		mutant.ModeLocalProxyIngressAdvSecretLeak,
		mutant.ModeLocalProxyIngressAdvGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	control := localproxyingressadversary.RunCollapsedMappingControl()
	if control.Conclusion != "failed" || len(control.CollapseFindings) == 0 {
		failures = append(failures, "collapsed mapping control not detected")
	}
	return gate("localproxyingressadv_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func LocalProxyIngressAdvFixtureDriftGate(report localproxyingressadversary.AdversarialFixtureComparison) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("localproxyingressadv_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localProxyIngressAdversarialFixtureComparison(ctx context.Context, path string, current localproxyingressadversary.AdversarialFixtureSet) localproxyingressadversary.AdversarialFixtureComparison {
	oldSet, err := localproxyingressadversary.LoadAdversarialFixtureSet(path)
	if err != nil {
		return localproxyingressadversary.AdversarialFixtureComparison{Version: localproxyingressadversary.Version, NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	regenerated, err := localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
	if err != nil {
		return localproxyingressadversary.AdversarialFixtureComparison{Version: localproxyingressadversary.Version, OldHash: oldSet.FixtureSetHash, NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localproxyingressadversary.CompareAdversarialFixtureSets(oldSet, regenerated)
}

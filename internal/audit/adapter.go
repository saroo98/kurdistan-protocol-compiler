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

	"kurdistan/internal/adapter"
	"kurdistan/internal/adapteradversary"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func RunAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := adapteradversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = adapteradversary.FullScenarios()
	}
	runs := adapteradversary.RunScenarioCorpus(ctx, profiles, scenarios)
	analysis := adapteradversary.AnalyzeRuns(runs, adapterCollapseThresholds(cfg.Thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		AdapterInterfaceContractsGate(),
		AdapterConfigValidationGate(),
		AdapterFlowLifecycleGate(),
		AdapterRuntimeBoundaryGate(ctx, profiles, scenarios, cfg.Thresholds),
		AdapterCapabilityCompatibilityGate(profiles),
		AdapterBackpressureGate(ctx, profiles),
		AdapterErrorResetMappingGate(ctx, profiles),
		AdapterTraceHygieneGate(ctx, profiles),
		AdapterCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		AdapterMutantDetectionGate(ctx, cfg.Thresholds),
		AdapterGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "adapter-" + cfg.Mode,
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

func AdapterInterfaceContractsGate() GateResult {
	cfg := adapter.DefaultConfig("contract", adapter.AdapterKindIngress)
	failures := []string{}
	if err := adapter.ValidateContract(cfg, adapter.DefaultCapabilityNames()); err != nil {
		failures = append(failures, err.Error())
	}
	desc := adapter.FlowDescriptor{ID: "flow-1", Class: "synthetic", Direction: "bidirectional", RequestClass: "interactive", PriorityClass: "interactive", MaxReadBytes: 1024, MaxWriteBytes: 1024, MetadataPolicy: "bucketed"}
	if err := adapter.ValidateFlowDescriptor(desc); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("adapter_interface_contracts", len(failures) == 0, "required", "adapter ingress/egress contract inputs validated", map[string]any{"interfaces": []string{"ingress", "egress"}}, failures)
}

func AdapterConfigValidationGate() GateResult {
	failures := []string{}
	if err := adapter.ValidateConfig(adapter.DefaultConfig("adapter", adapter.AdapterKindIngress)); err != nil {
		failures = append(failures, "safe config rejected")
	}
	bad := adapter.DefaultConfig("adapter", adapter.AdapterKindIngress)
	bad.MaxFlows = adapter.MaxAdapterFlows + 1
	if err := adapter.ValidateConfig(bad); err == nil {
		failures = append(failures, "unsafe max flows accepted")
	}
	bad = adapter.DefaultConfig("secret-token", adapter.AdapterKindIngress)
	if err := adapter.ValidateConfig(bad); err == nil {
		failures = append(failures, "secret-like config accepted")
	}
	return gate("adapter_config_validation", len(failures) == 0, "required", "adapter config validation and redaction checks run", nil, failures)
}

func AdapterFlowLifecycleGate() GateResult {
	caps := adapter.DefaultCapabilities()
	desc := adapter.FlowDescriptor{ID: "flow-1", Class: "synthetic", Direction: "bidirectional", RequestClass: "interactive", PriorityClass: "interactive", MaxReadBytes: 1024, MaxWriteBytes: 1024, MetadataPolicy: "bucketed"}
	flow, err := adapter.NewFlow(desc)
	failures := []string{}
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		if err := flow.Open(caps); err != nil {
			failures = append(failures, "open failed")
		}
		if err := flow.Transition(adapter.FlowHalfClosed, caps); err != nil {
			failures = append(failures, "half-close failed")
		}
		if err := flow.Close(caps); err != nil {
			failures = append(failures, "close failed")
		}
		if err := flow.Close(caps); err != nil {
			failures = append(failures, "idempotent close failed")
		}
		if err := flow.RecordWrite(1); err == nil {
			failures = append(failures, "write after close accepted")
		}
	}
	noHalf := caps
	noHalf.SupportsHalfClose = false
	flow, _ = adapter.NewFlow(desc)
	_ = flow.Open(noHalf)
	if err := flow.Transition(adapter.FlowHalfClosed, noHalf); err == nil {
		failures = append(failures, "half-close without capability accepted")
	}
	return gate("adapter_flow_lifecycle", len(failures) == 0, "required", "adapter flow lifecycle transitions checked", nil, failures)
}

func AdapterRuntimeBoundaryGate(ctx context.Context, profiles []*ir.Profile, scenarios []adapteradversary.Scenario, thresholds AuditThresholds) GateResult {
	runs := adapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios)
	report := adapteradversary.AnalyzeRuns(runs, adapterCollapseThresholds(thresholds))
	failures := adapterCorrectnessFailures(report)
	return gate("adapter_runtime_boundary", len(failures) == 0, "required", fmt.Sprintf("%d adapter/runtime scenario runs checked", report.Correctness.ScenarioRuns), map[string]any{
		"profile_count":  report.ProfileCount,
		"scenario_count": report.ScenarioCount,
		"correct_runs":   report.Correctness.CorrectRuns,
		"scenario_runs":  report.Correctness.ScenarioRuns,
		"correctness":    report.Correctness,
	}, failures)
}

func AdapterCapabilityCompatibilityGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		if err := adapter.RequireCapabilities(p.AdapterPolicy.RequiredCapabilities, adapter.DefaultCapabilityNames()); err != nil {
			failures = append(failures, p.ID)
		}
		if err := adapter.RequireCapabilities(p.AdapterPolicy.RequiredCapabilities, []string{adapter.CapabilityIngress}); err == nil {
			failures = append(failures, "capability downgrade accepted")
		}
	}
	return gate("adapter_capability_compatibility", len(failures) == 0, "required", "adapter capability compatibility and downgrade checks run", nil, failures)
}

func AdapterBackpressureGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := adapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioLargeFlowBackpressure)})
	events := 0
	failures := []string{}
	for _, run := range runs {
		events += run.Summary.BackpressureEvents
		if !run.Checks.BackpressureCorrect {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("adapter_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d adapter backpressure events observed", events), nil, failures)
}

func AdapterErrorResetMappingGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := adapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []adapteradversary.Scenario{
		adapteradversary.DefaultScenario(adapteradversary.ScenarioTargetErrorToFlowError),
		adapteradversary.DefaultScenario(adapteradversary.ScenarioTargetResetToFlowReset),
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
	return gate("adapter_error_reset_mapping", len(failures) == 0, "required", fmt.Sprintf("%d target errors and %d target resets mapped to adapter-safe outcomes", errors, resets), nil, failures)
}

func AdapterTraceHygieneGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := adapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioSingleFlowHappyPath)})
	failures := []string{}
	for _, run := range runs {
		if run.Summary.PayloadLogged || run.Summary.SecretLogged || !run.Checks.TraceHygiene {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("adapter_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d adapter traces checked for payload/secret hygiene", len(runs)), nil, failures)
}

func AdapterCollapseResistanceGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	runs := adapteradversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 8), []adapteradversary.Scenario{
		adapteradversary.DefaultScenario(adapteradversary.ScenarioManySmallFlows),
		adapteradversary.DefaultScenario(adapteradversary.ScenarioLargeFlowBackpressure),
	})
	report := adapteradversary.AnalyzeRuns(runs, adapterCollapseThresholds(thresholds))
	failures := adapterCollapseFailures(report)
	return gate("adapter_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d adapter collapse reports evaluated", len(report.CollapseReports)), map[string]any{
		"collapse_reports": report.CollapseReports,
	}, failures)
}

func AdapterMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeAdapterAcceptsInvalidFlow,
		mutant.ModeAdapterIgnoresBackpressure,
		mutant.ModeAdapterLeaksPayloadTrace,
		mutant.ModeAdapterLeaksSecretTrace,
		mutant.ModeAdapterAcceptsCapabilityDowngrade,
		mutant.ModeAdapterIgnoresMaxFlows,
		mutant.ModeAdapterWrongResetMapping,
		mutant.ModeAdapterPaddingOnlyDiversity,
	}
	detected := []string{}
	missed := []string{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 6100, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		runs := adapteradversary.RunMutantScenarioCorpus(ctx, mode, profiles, adapterMutantScenarios(mode))
		report := adapteradversary.AnalyzeRuns(runs, adapterCollapseThresholds(thresholds))
		if adapterMutantDetected(mode, report) {
			detected = append(detected, mode)
		} else {
			missed = append(missed, mode)
		}
	}
	return gate("adapter_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d adapter mutant modes detected", len(detected), len(modes)), map[string]any{"detected_modes": detected, "missed_modes": missed}, missed)
}

func AdapterGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("adapter_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
	if err != nil {
		return gate("adapter_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"adapter_generated.go", "AdapterDemo", "CaptureAdapterTrace", "adapter-demo", "adapter"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	return gate("adapter_generated_backend_parity", len(failures) == 0, "required", "generated backend adapter support markers checked", map[string]any{"scanner": "source-marker"}, failures)
}

func adapterCollapseThresholds(thresholds AuditThresholds) adapteradversary.CollapseThresholds {
	defaults := adapteradversary.DefaultCollapseThresholds()
	if thresholds.MaxAdapterAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxAdapterAdversaryDominantRatio
	}
	if thresholds.MinAdapterAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinAdapterAdversaryDiversityScore
	}
	if thresholds.MinAdapterScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinAdapterScenarioSuccess
	}
	return defaults
}

func adapterCorrectnessFailures(report adapteradversary.Report) []string {
	failures := []string{}
	if report.Correctness.MappingFailures > 0 {
		failures = append(failures, "adapter/runtime mapping failures")
	}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "adapter backpressure failures")
	}
	if report.Correctness.ResetFailures > 0 {
		failures = append(failures, "adapter reset failures")
	}
	if report.Correctness.ErrorResetFailures > 0 {
		failures = append(failures, "adapter error/reset mapping failures")
	}
	if report.Correctness.CapabilityFailures > 0 {
		failures = append(failures, "adapter capability downgrade failures")
	}
	if report.Correctness.MalformedFailures > 0 {
		failures = append(failures, "adapter malformed descriptor failures")
	}
	if report.Correctness.TraceHygieneFailures > 0 {
		failures = append(failures, "adapter trace hygiene failures")
	}
	return failures
}

func adapterCollapseFailures(report adapteradversary.Report) []string {
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

func adapterMutantScenarios(mode string) []adapteradversary.Scenario {
	switch mode {
	case mutant.ModeAdapterAcceptsInvalidFlow:
		return []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioMalformedFlowDescriptor)}
	case mutant.ModeAdapterAcceptsCapabilityDowngrade:
		return []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioCapabilityDowngrade)}
	case mutant.ModeAdapterIgnoresBackpressure:
		return []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioLargeFlowBackpressure)}
	case mutant.ModeAdapterWrongResetMapping:
		return []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioFlowResetIsolation)}
	default:
		return []adapteradversary.Scenario{adapteradversary.DefaultScenario(adapteradversary.ScenarioManySmallFlows)}
	}
}

func adapterMutantDetected(mode string, report adapteradversary.Report) bool {
	switch mode {
	case mutant.ModeAdapterAcceptsInvalidFlow:
		return report.Correctness.MalformedFailures > 0 || report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns
	case mutant.ModeAdapterIgnoresBackpressure:
		return report.Correctness.BackpressureFailures > 0
	case mutant.ModeAdapterLeaksPayloadTrace, mutant.ModeAdapterLeaksSecretTrace:
		return report.Correctness.TraceHygieneFailures > 0
	case mutant.ModeAdapterAcceptsCapabilityDowngrade:
		return report.Correctness.CapabilityFailures > 0 || report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns
	case mutant.ModeAdapterIgnoresMaxFlows:
		return report.Correctness.MappingFailures > 0 || report.Correctness.CorrectRuns < report.Correctness.ScenarioRuns
	case mutant.ModeAdapterWrongResetMapping:
		return report.Correctness.ResetFailures > 0
	case mutant.ModeAdapterPaddingOnlyDiversity:
		for _, collapse := range report.CollapseReports {
			if collapse.Conclusion != "passed" {
				return true
			}
		}
	}
	return false
}

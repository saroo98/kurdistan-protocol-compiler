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

	"kurdistan/internal/mutant"
	"kurdistan/internal/proxyegress"
)

type ProxyEgressAuditSummary struct {
	Version         string                                  `json:"version"`
	ScenarioCount   int                                     `json:"scenario_count"`
	TargetClasses   []string                                `json:"target_classes"`
	LifecycleChecks int                                     `json:"lifecycle_checks"`
	Backpressure    proxyegress.EgressBackpressureReport    `json:"backpressure"`
	ResetError      proxyegress.EgressResetErrorReport      `json:"reset_error"`
	Adaptive        proxyegress.EgressAdaptiveBindingReport `json:"adaptive_binding"`
	Comparison      proxyegress.EgressComparisonReport      `json:"comparison"`
	Conclusion      string                                  `json:"conclusion"`
}

func RunProxyEgressAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := proxyegress.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := proxyEgressComparison(filepath.Join(root, "testdata", "proxyegress", "egress-lifecycle-golden.json"), set)
	gates := ProxyEgressGates(set, comparison)
	summary := ProxyEgressAuditSummary{
		Version:         proxyegress.Version,
		ScenarioCount:   len(set.Scenarios),
		TargetClasses:   proxyEgressTargetClassStrings(set.Targets),
		LifecycleChecks: len(set.Lifecycle),
		Backpressure:    set.Backpressure,
		ResetError:      set.ResetError,
		Adaptive:        set.Adaptive,
		Comparison:      comparison,
		Conclusion:      "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "proxyegress-" + cfg.Mode,
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

func ProxyEgressGates(set proxyegress.EgressFixtureSet, comparison proxyegress.EgressComparisonReport) []GateResult {
	return []GateResult{
		ProxyEgressContractValidationGate(set),
		ProxyEgressTargetModelGate(set),
		ProxyEgressIngressMappingGate(set),
		ProxyEgressAdaptiveBindingGate(set),
		ProxyEgressLifecycleExecutionGate(set),
		ProxyEgressBackpressureGate(set),
		ProxyEgressResetErrorIsolationGate(set),
		ProxyEgressMisuseDetectionGate(set),
		ProxyEgressGeneratedBackendParityGate(set),
		ProxyEgressTraceHygieneGate(set),
		ProxyEgressMutantDetectionGate(),
		ProxyEgressFixtureDriftGate(comparison),
	}
}

func ProxyEgressContractValidationGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if err := proxyegress.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if len(set.Requests) == 0 || len(set.Mappings) == 0 {
		failures = append(failures, "missing request or mapping fixtures")
	}
	return gate("proxyegress_contract_validation", len(failures) == 0, "required", fmt.Sprintf("%d requests checked", len(set.Requests)), nil, failures)
}

func ProxyEgressTargetModelGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	classes := map[proxyegress.EgressTargetClass]bool{}
	for _, target := range set.Targets {
		classes[target.TargetClass] = true
		if err := proxyegress.ValidateTargetDescriptor(target); err != nil {
			failures = append(failures, err.Error())
		}
	}
	for _, required := range []proxyegress.EgressTargetClass{
		proxyegress.EgressTargetEchoSynthetic,
		proxyegress.EgressTargetFixedResponse,
		proxyegress.EgressTargetChunkedResponse,
		proxyegress.EgressTargetSlowResponse,
		proxyegress.EgressTargetLargeObject,
		proxyegress.EgressTargetResetMidstream,
		proxyegress.EgressTargetErrorResponse,
	} {
		if !classes[required] {
			failures = append(failures, "missing target class "+string(required))
		}
	}
	return gate("proxyegress_target_model", len(failures) == 0, "required", fmt.Sprintf("%d target classes", len(classes)), nil, failures)
}

func ProxyEgressIngressMappingGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.IngressMapping.Conclusion != "passed" {
		failures = append(failures, "ingress to egress mapping failed")
	}
	if !set.IngressMapping.BackpressurePreserved || !set.IngressMapping.ResetMappingPreserved || !set.IngressMapping.ErrorMappingPreserved || !set.IngressMapping.IsolationPreserved {
		failures = append(failures, "mapping did not preserve pressure/reset/error/isolation metadata")
	}
	return gate("proxyegress_ingress_mapping", len(failures) == 0, "required", fmt.Sprintf("%d streams mapped", set.IngressMapping.StreamsMapped), nil, failures)
}

func ProxyEgressAdaptiveBindingGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.Adaptive.Conclusion != "passed" {
		failures = append(failures, "adaptive binding failed")
	}
	if !set.Adaptive.BundleBound || !set.Adaptive.RaceBound || !set.Adaptive.HealthBound || !set.Adaptive.CarrierReviewBound || !set.Adaptive.MeasurementReviewBound {
		failures = append(failures, "missing adaptive prerequisite binding")
	}
	if set.Adaptive.HighRiskBlocked == 0 || set.Adaptive.ExperimentalBlocked == 0 || set.Adaptive.FailedHealthBlocked == 0 {
		failures = append(failures, "unsafe adaptive controls were not blocked")
	}
	return gate("proxyegress_adaptive_binding", len(failures) == 0, "required", fmt.Sprintf("%d bindings checked", set.Adaptive.BindingsChecked), nil, failures)
}

func ProxyEgressLifecycleExecutionGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	completed, failed, reset := 0, 0, 0
	for _, report := range set.Lifecycle {
		switch report.FinalState {
		case proxyegress.EgressStateCompleted:
			completed++
		case proxyegress.EgressStateFailed:
			failed++
		case proxyegress.EgressStateReset:
			reset++
		}
		if report.PayloadLogged || report.SecretLogged {
			failures = append(failures, "unsafe lifecycle trace flag")
		}
	}
	if completed == 0 || failed == 0 || reset == 0 {
		failures = append(failures, "missing completed/failed/reset lifecycle coverage")
	}
	return gate("proxyegress_lifecycle_execution", len(failures) == 0, "required", fmt.Sprintf("%d lifecycle reports", len(set.Lifecycle)), nil, failures)
}

func ProxyEgressBackpressureGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.Backpressure.Conclusion != "passed" || set.Backpressure.PressureEvents == 0 || !set.Backpressure.IsolationPreserved {
		failures = append(failures, "egress backpressure not preserved")
	}
	return gate("proxyegress_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d pressure events", set.Backpressure.PressureEvents), nil, failures)
}

func ProxyEgressResetErrorIsolationGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.ResetError.Conclusion != "passed" || set.ResetError.ResetEvents == 0 || set.ResetError.ErrorEvents == 0 || set.ResetError.CrossStreamLeaks != 0 {
		failures = append(failures, "reset/error isolation failed")
	}
	return gate("proxyegress_reset_error_isolation", len(failures) == 0, "required", fmt.Sprintf("%d resets, %d errors", set.ResetError.ResetEvents, set.ResetError.ErrorEvents), nil, failures)
}

func ProxyEgressMisuseDetectionGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.Conclusion != "passed" {
		failures = append(failures, set.Misuse.SuspiciousMetrics...)
	}
	for _, unsafe := range []map[string]string{
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver": "synthetic"},
		{"url": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := proxyegress.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe proxy egress metadata accepted")
		}
	}
	return gate("proxyegress_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d objects scanned", set.Misuse.ObjectsScanned), nil, failures)
}

func ProxyEgressGeneratedBackendParityGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"proxyegress_generated.go", "proxyegress_test.go", "proxyegress_parity_test.go", "proxyegress_hygiene_test.go", "ProxyEgressSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated proxyegress marker "+marker)
				}
			}
		}
	}
	return gate("proxyegress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", set.Parity.ComparedScenarios), nil, failures)
}

func ProxyEgressTraceHygieneGate(set proxyegress.EgressFixtureSet) GateResult {
	failures := []string{}
	if err := proxyegress.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("proxyegress_trace_hygiene", len(failures) == 0, "required", "proxy egress summaries contain safe metadata only", nil, failures)
}

func ProxyEgressMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeProxyEgressContainsEndpoint,
		mutant.ModeProxyEgressContainsDNSQuery,
		mutant.ModeProxyEgressContainsResolver,
		mutant.ModeProxyEgressContainsURL,
		mutant.ModeProxyEgressContainsPayload,
		mutant.ModeProxyEgressContainsSecret,
		mutant.ModeProxyEgressTargetNotSynthetic,
		mutant.ModeProxyEgressDescriptorAbuseAccepted,
		mutant.ModeProxyEgressHighRiskDefault,
		mutant.ModeProxyEgressExperimentalDefault,
		mutant.ModeProxyEgressFailedHealthAllowed,
		mutant.ModeProxyEgressBackpressureIgnored,
		mutant.ModeProxyEgressResetSwallowed,
		mutant.ModeProxyEgressErrorLeaksTarget,
		mutant.ModeProxyEgressAllTargetsSameShape,
		mutant.ModeProxyEgressGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("proxyegress_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d proxyegress mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func ProxyEgressFixtureDriftGate(report proxyegress.EgressComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("proxyegress_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func proxyEgressComparison(path string, current proxyegress.EgressFixtureSet) proxyegress.EgressComparisonReport {
	oldSet, err := proxyegress.LoadFixtureSet(path)
	if err != nil {
		return proxyegress.EgressComparisonReport{Version: proxyegress.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return proxyegress.CompareFixtureSets(oldSet, current)
}

func proxyEgressTargetClassStrings(targets []proxyegress.EgressTargetDescriptor) []string {
	seen := map[string]bool{}
	var out []string
	for _, target := range targets {
		value := string(target.TargetClass)
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}

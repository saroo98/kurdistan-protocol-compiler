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
	"kurdistan/internal/relaybridge"
)

type RelayBridgeAuditSummary struct {
	Version       string                                       `json:"version"`
	ScenarioCount int                                          `json:"scenario_count"`
	SessionCount  int                                          `json:"session_count"`
	StreamCount   int                                          `json:"stream_count"`
	Adaptive      relaybridge.RelayBridgeAdaptiveBindingReport `json:"adaptive_binding"`
	Misuse        relaybridge.RelayBridgeMisuseReport          `json:"misuse"`
	Parity        relaybridge.RelayBridgeParityReport          `json:"parity"`
	Comparison    relaybridge.RelayBridgeComparisonReport      `json:"comparison"`
	Conclusion    string                                       `json:"conclusion"`
}

func RunRelayBridgeAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := relaybridge.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := relayBridgeComparison(filepath.Join(root, "testdata", "relaybridge", "relaybridge-report-golden.json"), set)
	gates := RelayBridgeGates(set, comparison)
	summary := RelayBridgeAuditSummary{
		Version:       relaybridge.Version,
		ScenarioCount: len(set.Scenarios),
		SessionCount:  len(set.Sessions),
		StreamCount:   len(set.Streams),
		Adaptive:      set.Adaptive,
		Misuse:        set.Misuse,
		Parity:        set.Parity,
		Comparison:    comparison,
		Conclusion:    "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "relaybridge-" + cfg.Mode,
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

func RelayBridgeGates(set relaybridge.RelayBridgeFixtureSet, comparison relaybridge.RelayBridgeComparisonReport) []GateResult {
	return []GateResult{
		RelayBridgeSessionValidationGate(set),
		RelayBridgeStreamMappingGate(set),
		RelayBridgeAdaptiveRuntimeBindingGate(set),
		RelayBridgeBackpressureGate(set),
		RelayBridgeResetErrorIsolationGate(set),
		RelayBridgeStreamIsolationGate(set),
		RelayBridgeMisuseDetectionGate(set),
		RelayBridgeGeneratedBackendParityGate(set),
		RelayBridgeTraceHygieneGate(set),
		RelayBridgeMutantDetectionGate(),
		RelayBridgeFixtureDriftGate(comparison),
	}
}

func RelayBridgeSessionValidationGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if err := relaybridge.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if len(set.Sessions) == 0 {
		failures = append(failures, "missing bridge sessions")
	}
	return gate("relaybridge_session_validation", len(failures) == 0, "required", fmt.Sprintf("%d sessions checked", len(set.Sessions)), nil, failures)
}

func RelayBridgeStreamMappingGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if len(set.Streams) == 0 || !relaybridge.MappingPreserved(set.Sessions, set.Streams) {
		failures = append(failures, "stream mapping not preserved")
	}
	return gate("relaybridge_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d streams mapped", len(set.Streams)), nil, failures)
}

func RelayBridgeAdaptiveRuntimeBindingGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if set.Adaptive.Conclusion != "passed" {
		failures = append(failures, "adaptive bridge binding failed")
	}
	if !set.Adaptive.BundleBound || !set.Adaptive.RaceBound || !set.Adaptive.HealthBound || !set.Adaptive.CarrierReviewBound || !set.Adaptive.MeasurementReviewBound {
		failures = append(failures, "missing adaptive prerequisite binding")
	}
	if set.Adaptive.HighRiskBlocked == 0 || set.Adaptive.ExperimentalBlocked == 0 || set.Adaptive.FailedHealthBlocked == 0 {
		failures = append(failures, "unsafe adaptive bridge controls were not blocked")
	}
	return gate("relaybridge_adaptive_runtime_binding", len(failures) == 0, "required", fmt.Sprintf("%d bindings checked", set.Adaptive.BindingsChecked), nil, failures)
}

func RelayBridgeBackpressureGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	totalPressure := 0
	for _, report := range set.Reports {
		totalPressure += report.BackpressureEvents
	}
	if totalPressure == 0 {
		failures = append(failures, "bridge backpressure not observed")
	}
	return gate("relaybridge_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d backpressure events", totalPressure), nil, failures)
}

func RelayBridgeResetErrorIsolationGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	resets, errors, leaks := 0, 0, 0
	for _, report := range set.Reports {
		resets += report.ResetRequests
		errors += report.FailedRequests
		leaks += report.IsolationViolations
	}
	if resets == 0 || errors == 0 || leaks != 0 {
		failures = append(failures, "reset/error bridge isolation failed")
	}
	return gate("relaybridge_reset_error_isolation", len(failures) == 0, "required", fmt.Sprintf("%d resets, %d errors", resets, errors), nil, failures)
}

func RelayBridgeStreamIsolationGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if relaybridge.IsolationViolations(set.Streams) != 0 {
		failures = append(failures, "cross-stream isolation violation")
	}
	return gate("relaybridge_stream_isolation", len(failures) == 0, "required", fmt.Sprintf("%d streams isolated", len(set.Streams)), nil, failures)
}

func RelayBridgeMisuseDetectionGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.Conclusion != "passed" {
		failures = append(failures, set.Misuse.SuspiciousMetrics...)
	}
	for _, unsafe := range []map[string]string{
		{"endpoint": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
		{"real_relay": "synthetic"},
		{"dial_real": "synthetic"},
	} {
		if err := relaybridge.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe relay bridge metadata accepted")
		}
	}
	return gate("relaybridge_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d objects scanned", set.Misuse.ObjectsScanned), nil, failures)
}

func RelayBridgeGeneratedBackendParityGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"relaybridge_generated.go", "relaybridge_test.go", "relaybridge_parity_test.go", "relaybridge_hygiene_test.go", "RelayBridgeSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated relaybridge marker "+marker)
				}
			}
		}
	}
	return gate("relaybridge_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", set.Parity.ComparedScenarios), nil, failures)
}

func RelayBridgeTraceHygieneGate(set relaybridge.RelayBridgeFixtureSet) GateResult {
	failures := []string{}
	if err := relaybridge.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("relaybridge_trace_hygiene", len(failures) == 0, "required", "relay bridge summaries contain safe metadata only", nil, failures)
}

func RelayBridgeMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeRelayBridgeContainsEndpoint,
		mutant.ModeRelayBridgeContainsPayload,
		mutant.ModeRelayBridgeContainsSecret,
		mutant.ModeRelayBridgeDialsRealRelay,
		mutant.ModeRelayBridgeStreamIsolationBroken,
		mutant.ModeRelayBridgeBackpressureIgnored,
		mutant.ModeRelayBridgeResetSwallowed,
		mutant.ModeRelayBridgeErrorLeaksTarget,
		mutant.ModeRelayBridgeHighRiskDefault,
		mutant.ModeRelayBridgeExperimentalDefault,
		mutant.ModeRelayBridgeFailedHealthAllowed,
		mutant.ModeRelayBridgeAllStreamsSameShape,
		mutant.ModeRelayBridgeGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("relaybridge_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d relaybridge mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func RelayBridgeFixtureDriftGate(report relaybridge.RelayBridgeComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("relaybridge_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func relayBridgeComparison(path string, current relaybridge.RelayBridgeFixtureSet) relaybridge.RelayBridgeComparisonReport {
	oldSet, err := relaybridge.LoadFixtureSet(path)
	if err != nil {
		return relaybridge.RelayBridgeComparisonReport{Version: relaybridge.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return relaybridge.CompareFixtureSets(oldSet, current)
}

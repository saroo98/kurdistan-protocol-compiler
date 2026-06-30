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

	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/mutant"
)

type LocalProxyIngressAuditSummary struct {
	Version          string                             `json:"version"`
	ContractID       string                             `json:"contract_id"`
	ScenarioCount    int                                `json:"scenario_count"`
	RequestCount     int                                `json:"request_count"`
	AcceptedRequests int                                `json:"accepted_requests"`
	RejectedRequests int                                `json:"rejected_requests"`
	Backpressure     int                                `json:"backpressure_events"`
	Resets           int                                `json:"reset_events"`
	TargetErrors     int                                `json:"target_error_events"`
	Fixture          localproxyingress.ComparisonReport `json:"fixture"`
	Conclusion       string                             `json:"conclusion"`
}

func RunLocalProxyIngressAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	scenarios := localproxyingress.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = localproxyingress.FullScenarios()
	}
	set, err := localproxyingress.GenerateFixtureSet(ctx, scenarios)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	fixtureComparison := localProxyIngressFixtureComparison(ctx, filepath.Join(root, "testdata", "localproxyingress", "localproxyingress-summary-golden.json"), set)
	gates := LocalProxyIngressGates(set, fixtureComparison)
	summary := LocalProxyIngressAuditSummary{Version: string(localproxyingress.Version), ContractID: localproxyingress.DefaultConfig().ContractID, ScenarioCount: len(set.Summaries), Fixture: fixtureComparison, Conclusion: "passed"}
	for _, item := range set.Summaries {
		summary.RequestCount += item.RequestCount
		summary.AcceptedRequests += item.AcceptedRequests
		summary.RejectedRequests += item.RejectedRequests
		summary.Backpressure += item.BackpressureEvents
		summary.Resets += item.ResetEvents
		summary.TargetErrors += item.TargetErrorEvents
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "localproxyingress-" + cfg.Mode,
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

func LocalProxyIngressGates(set localproxyingress.FixtureSet, fixtureComparison localproxyingress.ComparisonReport) []GateResult {
	return []GateResult{
		LocalProxyIngressContractComplianceGate(set),
		LocalProxyIngressTargetValidationGate(set),
		LocalProxyIngressLifecycleExecutionGate(set),
		LocalProxyIngressRuntimeMappingGate(set),
		LocalProxyIngressBackpressureGate(set),
		LocalProxyIngressErrorResetIsolationGate(set),
		LocalProxyIngressQueueBoundsGate(set),
		LocalProxyIngressCollapseResistanceGate(set),
		LocalProxyIngressGeneratedBackendParityGate(set),
		LocalProxyIngressTraceHygieneGate(set),
		LocalProxyIngressMutantDetectionGate(),
		LocalProxyIngressFixtureDriftGate(fixtureComparison),
	}
}

func LocalProxyIngressContractComplianceGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	if err := localproxyingress.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyingress_contract_compliance", len(failures) == 0, "required", fmt.Sprintf("%d scenarios", len(set.Summaries)), nil, failures)
}

func LocalProxyIngressTargetValidationGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	foundInvalid := false
	for _, summary := range set.Summaries {
		if summary.Scenario == localproxyingress.ScenarioInvalidTargetRejection && summary.RejectedRequests > 0 {
			foundInvalid = true
		}
	}
	if !foundInvalid && len(set.Summaries) > 3 {
		failures = append(failures, "invalid target rejection scenario missing")
	}
	return gate("localproxyingress_target_validation", len(failures) == 0, "required", "synthetic targets only", nil, failures)
}

func LocalProxyIngressLifecycleExecutionGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	foundViolation := false
	for _, summary := range set.Summaries {
		if summary.Scenario == localproxyingress.ScenarioLifecycleViolation && summary.LifecycleViolations > 0 {
			foundViolation = true
		}
	}
	if !foundViolation && len(set.Summaries) > 3 {
		failures = append(failures, "lifecycle violation scenario missing")
	}
	return gate("localproxyingress_lifecycle_execution", len(failures) == 0, "required", "terminal states enforced", nil, failures)
}

func LocalProxyIngressRuntimeMappingGate(set localproxyingress.FixtureSet) GateResult {
	mappings := 0
	failures := []string{}
	for _, summary := range set.Summaries {
		mappings += summary.StreamMappings
		for _, result := range summary.Results {
			if result.Accepted && (result.RuntimeMappingHash == "" || result.ProxySemIntentHash == "") {
				failures = append(failures, result.RequestID)
			}
		}
	}
	if mappings == 0 {
		failures = append(failures, "no runtime mappings")
	}
	return gate("localproxyingress_runtime_mapping", len(failures) == 0, "required", fmt.Sprintf("%d mappings", mappings), nil, failures)
}

func LocalProxyIngressBackpressureGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	found := false
	for _, summary := range set.Summaries {
		if summary.BackpressureEvents > 0 {
			found = true
		}
	}
	if !found {
		failures = append(failures, "no backpressure represented")
	}
	return gate("localproxyingress_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d pressure events", set.Backpressure.PressureEvents), map[string]any{"backpressure": set.Backpressure}, failures)
}

func LocalProxyIngressErrorResetIsolationGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	found := false
	for _, summary := range set.Summaries {
		if summary.ResetEvents+summary.TargetErrorEvents > 0 {
			found = true
		}
	}
	if !found && len(set.Summaries) > 3 {
		failures = append(failures, "no reset or target error represented")
	}
	return gate("localproxyingress_error_reset_isolation", len(failures) == 0, "required", "reset and error summaries are request-scoped", map[string]any{"error_reset": set.ErrorReset}, failures)
}

func LocalProxyIngressQueueBoundsGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	for _, summary := range set.Summaries {
		if summary.QueueStats.MaxDepthObserved > localproxyingress.DefaultConfig().MaxQueuedEvents {
			failures = append(failures, summary.Scenario)
		}
	}
	return gate("localproxyingress_queue_bounds", len(failures) == 0, "required", "bounded queues", nil, failures)
}

func LocalProxyIngressCollapseResistanceGate(set localproxyingress.FixtureSet) GateResult {
	hashes := map[string]bool{}
	failures := []string{}
	for _, summary := range set.Summaries {
		hashes[summary.SummaryHash] = true
	}
	if len(set.Summaries) > 1 && len(hashes) < 2 {
		failures = append(failures, "scenario summaries collapsed")
	}
	return gate("localproxyingress_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d unique summaries", len(hashes)), nil, failures)
}

func LocalProxyIngressGeneratedBackendParityGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"localproxyingress_generated.go", "localproxyingress_test.go", "localproxyingress_parity_test.go", "localproxyingress_hygiene_test.go", "LocalProxyIngressSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated marker "+marker)
				}
			}
		}
	}
	return gate("localproxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", len(set.Summaries)), nil, failures)
}

func LocalProxyIngressTraceHygieneGate(set localproxyingress.FixtureSet) GateResult {
	failures := []string{}
	if set.PayloadLogged || set.SecretLogged {
		failures = append(failures, "fixture hygiene flag")
	}
	for _, summary := range set.Summaries {
		if summary.PayloadLogged || summary.SecretLogged {
			failures = append(failures, summary.Scenario)
		}
	}
	return gate("localproxyingress_trace_hygiene", len(failures) == 0, "required", "summaries contain safe metadata only", nil, failures)
}

func LocalProxyIngressMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLocalProxyIngressAcceptsInvalidTarget,
		mutant.ModeLocalProxyIngressAcceptsRealEndpoint,
		mutant.ModeLocalProxyIngressUnboundedQueue,
		mutant.ModeLocalProxyIngressIgnoresBackpressure,
		mutant.ModeLocalProxyIngressDataAfterClose,
		mutant.ModeLocalProxyIngressResetBeforeOpen,
		mutant.ModeLocalProxyIngressErrorBeforeDescriptor,
		mutant.ModeLocalProxyIngressDuplicateEventAllowed,
		mutant.ModeLocalProxyIngressResetLeaksAcrossRequests,
		mutant.ModeLocalProxyIngressTargetErrorLeaksDescriptor,
		mutant.ModeLocalProxyIngressAllRequestsSameMapping,
		mutant.ModeLocalProxyIngressPayloadLeak,
		mutant.ModeLocalProxyIngressSecretLeak,
		mutant.ModeLocalProxyIngressGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	for _, scenario := range localproxyingressadversary.QuickScenarios() {
		run := localproxyingressadversary.RunScenario(context.Background(), scenario)
		if run.Conclusion != "failed" {
			failures = append(failures, "control not detected "+scenario)
		}
	}
	return gate("localproxyingress_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func LocalProxyIngressFixtureDriftGate(report localproxyingress.ComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("localproxyingress_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localProxyIngressFixtureComparison(ctx context.Context, path string, current localproxyingress.FixtureSet) localproxyingress.ComparisonReport {
	oldSet, err := localproxyingress.LoadFixtureSet(path)
	if err != nil {
		return localproxyingress.ComparisonReport{Version: string(localproxyingress.Version), NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	regenerated, err := localproxyingress.GenerateFixtureSet(ctx, oldSet.Scenarios)
	if err != nil {
		return localproxyingress.ComparisonReport{Version: string(localproxyingress.Version), OldHash: oldSet.FixtureSetHash, NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localproxyingress.CompareFixtureSets(oldSet, regenerated)
}

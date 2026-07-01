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

	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/mutant"
)

type ConcreteLocalAdapterAuditSummary struct {
	Version        string                                       `json:"version"`
	ScenarioCount int                                          `json:"scenario_count"`
	SummaryCount  int                                          `json:"summary_count"`
	Comparison    concretelocaladapter.FixtureComparisonReport `json:"comparison"`
	Conclusion    string                                       `json:"conclusion"`
}

func RunConcreteLocalAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := concretelocaladapter.GenerateFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := concreteLocalAdapterComparison(filepath.Join(root, "testdata", "concretelocaladapter", "concretelocaladapter-golden.json"), set)
	gates := ConcreteLocalAdapterGates(set, comparison)
	summary := ConcreteLocalAdapterAuditSummary{
		Version:        concretelocaladapter.Version,
		ScenarioCount: len(set.Scenarios),
		SummaryCount:  len(set.Summaries),
		Comparison:    comparison,
		Conclusion:    "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "concretelocaladapter-" + cfg.Mode,
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

func ConcreteLocalAdapterGates(set concretelocaladapter.SocketFixtureSet, comparison concretelocaladapter.FixtureComparisonReport) []GateResult {
	return []GateResult{
		ConcreteLocalAdapterBindPolicyGate(set),
		ConcreteLocalAdapterLoopbackListenerGate(set),
		ConcreteLocalAdapterFlowLifecycleGate(set),
		ConcreteLocalAdapterRuntimeMappingGate(set),
		ConcreteLocalAdapterBackpressureGate(set),
		ConcreteLocalAdapterErrorResetIsolationGate(set),
		ConcreteLocalAdapterTraceHygieneGate(set),
		ConcreteLocalAdapterNoExternalIOGate(set),
		ConcreteLocalAdapterGeneratedBackendParityGate(set),
		ConcreteLocalAdapterMutantDetectionGate(),
		ConcreteLocalAdapterFixtureDriftGate(comparison),
	}
}

func ConcreteLocalAdapterBindPolicyGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := []string{}
	if err := concretelocaladapter.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.BindConfig.Host != "127.0.0.1" || set.BindConfig.Port != 0 {
		failures = append(failures, "fixture bind config is not loopback ephemeral")
	}
	if set.Misuse.ExternalRejected == 0 || set.Misuse.WildcardRejected == 0 {
		failures = append(failures, "external or wildcard bind controls missing")
	}
	return gate("concretelocaladapter_bind_policy", len(failures) == 0, "required", fmt.Sprintf("%d unsafe bind controls checked", set.Misuse.ObjectsChecked), nil, failures)
}

func ConcreteLocalAdapterLoopbackListenerGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	accepted := 0
	for _, summary := range set.Summaries {
		accepted += summary.ConnectionsAccepted
	}
	failures := []string{}
	if accepted == 0 {
		failures = append(failures, "no loopback listener probe executed")
	}
	return gate("concretelocaladapter_loopback_listener", len(failures) == 0, "required", fmt.Sprintf("%d loopback connections accepted", accepted), nil, failures)
}

func ConcreteLocalAdapterFlowLifecycleGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := []string{}
	opened, terminal := 0, 0
	for _, summary := range set.Summaries {
		opened += summary.FlowsOpened
		terminal += summary.FlowsClosed + summary.FlowsReset
		if summary.FlowsClosed+summary.FlowsReset > summary.FlowsOpened {
			failures = append(failures, "terminal flow count exceeds opened flows in "+summary.Scenario)
		}
	}
	if opened == 0 || terminal == 0 {
		failures = append(failures, "flow lifecycle not exercised")
	}
	return gate("concretelocaladapter_flow_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d opened flows; %d terminal flows", opened, terminal), nil, failures)
}

func ConcreteLocalAdapterRuntimeMappingGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := []string{}
	mapped := 0
	for _, summary := range set.Summaries {
		mapped += summary.RuntimeStreamsMapped
		if summary.RuntimeStreamsMapped != summary.FlowsOpened {
			failures = append(failures, "flow/runtime stream mapping drift in "+summary.Scenario)
		}
	}
	return gate("concretelocaladapter_runtime_mapping", len(failures) == 0, "required", fmt.Sprintf("%d runtime stream mappings checked", mapped), nil, failures)
}

func ConcreteLocalAdapterBackpressureGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	events := 0
	for _, summary := range set.Summaries {
		events += summary.BackpressureEvents
	}
	failures := []string{}
	if events == 0 {
		failures = append(failures, "no backpressure events observed")
	}
	return gate("concretelocaladapter_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d backpressure events observed", events), nil, failures)
}

func ConcreteLocalAdapterErrorResetIsolationGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	errorsSeen, resetsSeen := 0, 0
	for _, summary := range set.Summaries {
		errorsSeen += summary.TargetErrors
		resetsSeen += summary.TargetResets + summary.FlowsReset
	}
	failures := []string{}
	if errorsSeen == 0 || resetsSeen == 0 {
		failures = append(failures, "target error/reset isolation not exercised")
	}
	return gate("concretelocaladapter_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d errors and %d resets mapped safely", errorsSeen, resetsSeen), nil, failures)
}

func ConcreteLocalAdapterTraceHygieneGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := []string{}
	if err := concretelocaladapter.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"raw_payload": "x"}, {"encoded_bytes": "x"}, {"client_write_key": "x"}} {
		if err := concretelocaladapter.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe concrete local adapter metadata accepted")
		}
	}
	return gate("concretelocaladapter_trace_hygiene", len(failures) == 0, "required", "socket summaries contain safe metadata only", nil, failures)
}

func ConcreteLocalAdapterNoExternalIOGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.ExternalRejected == 0 || set.Misuse.WildcardRejected == 0 {
		failures = append(failures, "external or wildcard IO rejection control missing")
	}
	return gate("concretelocaladapter_no_external_io", len(failures) == 0, "required", "external and wildcard binds are rejected", nil, failures)
}

func ConcreteLocalAdapterGeneratedBackendParityGate(set concretelocaladapter.SocketFixtureSet) GateResult {
	failures := append([]string{}, set.Parity.UnexpectedDifferences...)
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, "generated/interpreted socket parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"concretelocaladapter_generated.go", "concretelocaladapter_test.go", "concretelocaladapter_parity_test.go", "concretelocaladapter_hygiene_test.go", "ConcreteLocalAdapterSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated concrete local adapter marker "+marker)
				}
			}
		}
	}
	return gate("concretelocaladapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d summaries compared", set.Parity.ComparedSummaries), nil, failures)
}

func ConcreteLocalAdapterMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeConcreteLocalAdapterAllowsExternalBind,
		mutant.ModeConcreteLocalAdapterAcceptsWildcardBind,
		mutant.ModeConcreteLocalAdapterIgnoresBackpressure,
		mutant.ModeConcreteLocalAdapterPayloadTraceLeak,
		mutant.ModeConcreteLocalAdapterSecretTraceLeak,
		mutant.ModeConcreteLocalAdapterWrongRuntimeMapping,
		mutant.ModeConcreteLocalAdapterAcceptsMalformedEvent,
		mutant.ModeConcreteLocalAdapterGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("concretelocaladapter_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d concrete local adapter mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func ConcreteLocalAdapterFixtureDriftGate(report concretelocaladapter.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("concretelocaladapter_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func concreteLocalAdapterComparison(path string, current concretelocaladapter.SocketFixtureSet) concretelocaladapter.FixtureComparisonReport {
	oldSet, err := concretelocaladapter.LoadFixtureSet(path)
	if err != nil {
		return concretelocaladapter.FixtureComparisonReport{Version: concretelocaladapter.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return concretelocaladapter.CompareFixtureSets(oldSet, current)
}

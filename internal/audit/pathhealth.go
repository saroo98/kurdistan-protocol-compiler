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
	"kurdistan/internal/pathhealth"
)

type PathHealthAuditSummary struct {
	Version           string                                `json:"version"`
	ScenarioCount     int                                   `json:"scenario_count"`
	ActivePathCount   int                                   `json:"active_path_count"`
	EventCount        int                                   `json:"event_count"`
	FailoverCount     int                                   `json:"failover_count"`
	QuarantineCount   int                                   `json:"quarantine_count"`
	ControlFindings   []string                              `json:"control_findings,omitempty"`
	FixtureComparison pathhealth.PathHealthComparisonReport `json:"fixture_comparison"`
	GeneratedParity   string                                `json:"generated_parity"`
	Conclusion        string                                `json:"conclusion"`
}

func RunPathHealthAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := pathhealth.GenerateFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := pathHealthFixtureComparison(filepath.Join(root, "testdata", "pathhealth", "pathhealth-report-golden.json"), set)
	gates := PathHealthGates(set, comparison)
	summary := PathHealthAuditSummary{
		Version:           string(pathhealth.Version),
		ScenarioCount:     len(set.Scenarios),
		ActivePathCount:   len(set.ActivePaths),
		EventCount:        len(set.Events),
		ControlFindings:   set.Controls.MisuseFindings,
		FixtureComparison: comparison,
		GeneratedParity:   set.Parity.Conclusion,
		Conclusion:        "passed",
	}
	for _, decision := range set.Decisions {
		if decision.Outcome != pathhealth.OutcomeNoFailoverNeeded {
			summary.FailoverCount++
		}
		if decision.Outcome == pathhealth.OutcomeFailoverQuarantined {
			summary.QuarantineCount++
		}
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "pathhealth-" + cfg.Mode,
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

func PathHealthGates(set pathhealth.PathHealthFixtureSet, comparison pathhealth.PathHealthComparisonReport) []GateResult {
	return []GateResult{
		PathHealthActiveMonitorGate(set),
		PathHealthDegradationDetectionGate(set),
		PathHealthScoreDecayGate(set),
		PathHealthFailoverDecisionGate(set),
		PathHealthRelayBurnQuarantineGate(set),
		PathHealthControlDetectionGate(set),
		PathHealthGeneratedBackendParityGate(set),
		PathHealthTraceHygieneGate(set),
		PathHealthMutantDetectionGate(set),
		PathHealthFixtureDriftGate(comparison),
	}
}

func PathHealthActiveMonitorGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	if err := pathhealth.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if len(set.Scenarios) < len(pathhealth.DefaultScenarios()) {
		failures = append(failures, "missing pathhealth scenarios")
	}
	return gate("pathhealth_active_monitor", len(failures) == 0, "required", fmt.Sprintf("%d active-path scenarios checked", len(set.Scenarios)), nil, failures)
}

func PathHealthDegradationDetectionGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	severe := 0
	degraded := 0
	for _, report := range set.Degradation {
		switch report.DegradationBucket {
		case "severe", "critical":
			severe++
		case "degraded":
			degraded++
		}
	}
	if severe == 0 || degraded == 0 {
		failures = append(failures, "degradation buckets did not cover degraded and severe cases")
	}
	return gate("pathhealth_degradation_detection", len(failures) == 0, "required", fmt.Sprintf("%d severe/critical and %d degraded reports", severe, degraded), nil, failures)
}

func PathHealthScoreDecayGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	zero := 0
	low := 0
	for _, score := range set.Scores {
		switch score.FinalScoreBucket {
		case "score_zero":
			zero++
		case "score_low":
			low++
		}
	}
	if zero == 0 || low == 0 {
		failures = append(failures, "score decay did not produce low and zero buckets")
	}
	return gate("pathhealth_score_decay", len(failures) == 0, "required", fmt.Sprintf("%d low and %d zero score outcomes", low, zero), nil, failures)
}

func PathHealthFailoverDecisionGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	completed := 0
	blocked := 0
	for _, decision := range set.Decisions {
		switch decision.Outcome {
		case pathhealth.OutcomeFailoverFallback, pathhealth.OutcomeFailoverVerified:
			completed++
		case pathhealth.OutcomeFailoverBlockedHighRisk, pathhealth.OutcomeFailoverBlockedExperiment, pathhealth.OutcomeFailoverNotPossible:
			blocked++
		}
	}
	if completed == 0 || blocked == 0 {
		failures = append(failures, "failover decisions did not include completed and blocked outcomes")
	}
	return gate("pathhealth_failover_decision", len(failures) == 0, "required", fmt.Sprintf("%d completed and %d blocked failover outcomes", completed, blocked), nil, failures)
}

func PathHealthRelayBurnQuarantineGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	quarantined := 0
	for _, decision := range set.Decisions {
		if decision.Outcome == pathhealth.OutcomeFailoverQuarantined {
			quarantined++
		}
	}
	if quarantined == 0 {
		failures = append(failures, "relay burn quarantine not represented")
	}
	return gate("pathhealth_relay_burn_quarantine", len(failures) == 0, "required", fmt.Sprintf("%d quarantine decisions", quarantined), nil, failures)
}

func PathHealthControlDetectionGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	for _, required := range []string{"health_never_degrades", "failover_never_triggers", "failover_to_burned_relay"} {
		if !containsPathHealthString(set.Controls.MisuseFindings, required) {
			failures = append(failures, "missing control finding "+required)
		}
	}
	return gate("pathhealth_control_detection", len(failures) == 0, "required", fmt.Sprintf("%d control findings", len(set.Controls.MisuseFindings)), nil, failures)
}

func PathHealthGeneratedBackendParityGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathhealth_generated.go", "pathhealth_test.go", "pathhealth_parity_test.go", "pathhealth_hygiene_test.go", "PathHealthSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathhealth marker "+marker)
				}
			}
		}
	}
	return gate("pathhealth_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d scenarios compared", set.Parity.ComparedScenarios), nil, failures)
}

func PathHealthTraceHygieneGate(set pathhealth.PathHealthFixtureSet) GateResult {
	failures := []string{}
	if err := pathhealth.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := pathhealth.ScanForLeak(tc); err == nil {
			failures = append(failures, "unsafe pathhealth metadata accepted")
		}
	}
	return gate("pathhealth_trace_hygiene", len(failures) == 0, "required", "pathhealth fixtures contain safe metadata only", nil, failures)
}

func PathHealthMutantDetectionGate(set pathhealth.PathHealthFixtureSet) GateResult {
	required := []string{
		mutant.ModePathHealthNoHealthMonitoring,
		mutant.ModePathHealthOverEagerFailover,
		mutant.ModePathHealthUnderEagerFailover,
		mutant.ModePathHealthIgnoresStallAfterHandshake,
		mutant.ModePathHealthIgnoresStallAfterData,
		mutant.ModePathHealthIgnoresResetBurst,
		mutant.ModePathHealthIgnoresBlackhole,
		mutant.ModePathHealthIgnoresRelayBurn,
		mutant.ModePathHealthFailoverToBurnedRelay,
		mutant.ModePathHealthHighRiskDefaultFailover,
		mutant.ModePathHealthExperimentalDefaultFailover,
		mutant.ModePathHealthNoScoreDecay,
		mutant.ModePathHealthNoConfidenceExpiry,
		mutant.ModePathHealthPayloadLeak,
		mutant.ModePathHealthSecretLeak,
		mutant.ModePathHealthGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	if set.Controls.Conclusion != "failed" {
		failures = append(failures, "pathhealth controls not detected")
	}
	return gate("pathhealth_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d pathhealth mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func PathHealthFixtureDriftGate(report pathhealth.PathHealthComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("pathhealth_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func pathHealthFixtureComparison(path string, current pathhealth.PathHealthFixtureSet) pathhealth.PathHealthComparisonReport {
	oldSet, err := pathhealth.LoadFixtureSet(path)
	if err != nil {
		return pathhealth.PathHealthComparisonReport{Version: string(pathhealth.Version), NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return pathhealth.CompareFixtureSets(oldSet, current)
}

func containsPathHealthString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

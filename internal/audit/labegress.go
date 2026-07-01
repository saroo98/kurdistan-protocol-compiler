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

	"kurdistan/internal/labegress"
	"kurdistan/internal/mutant"
)

func RunLabEgressAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := labegress.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := labEgressComparison(filepath.Join(root, "testdata", "labegress", "labegress-report-golden.json"), set)
	gates := LabEgressGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "labegress-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     100,
		Gates:            gates,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func LabEgressGates(set labegress.LabEgressFixtureSet, comparison labegress.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LabEgressAllowlistGate(set),
		LabEgressConnectorLifecycleGate(set),
		LabEgressFixtureExchangeGate(set),
		LabEgressBackpressureGate(set),
		LabEgressErrorResetIsolationGate(set),
		LabEgressHalfCloseGate(set),
		LabEgressQueueLimitGate(set),
		LabEgressTraceHygieneGate(set),
		LabEgressGeneratedBackendParityGate(set),
		LabEgressMutantDetectionGate(),
		LabEgressFixtureDriftGate(comparison),
	}
}

func LabEgressAllowlistGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if err := labegress.ValidateConfig(set.Config); err != nil {
		failures = append(failures, err.Error())
	}
	if set.Allowlist.UnsafeTargetsRejected < 4 {
		failures = append(failures, "unsafe target controls not rejected")
	}
	return gate("labegress_allowlist_validation", len(failures) == 0, "required", fmt.Sprintf("%d unsafe targets rejected", set.Allowlist.UnsafeTargetsRejected), nil, failures)
}

func LabEgressConnectorLifecycleGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Report.ConnectionsOpened == 0 || set.Report.ConnectionsClosed != set.Report.ConnectionsOpened {
		failures = append(failures, "connector lifecycle did not close cleanly")
	}
	return gate("labegress_connector_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d connections closed", set.Report.ConnectionsClosed), nil, failures)
}

func LabEgressFixtureExchangeGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Report.ChunksWritten == 0 || set.Report.ChunksRead == 0 {
		failures = append(failures, "fixture exchange did not move chunks")
	}
	return gate("labegress_fixture_exchange", len(failures) == 0, "required", fmt.Sprintf("%d/%d chunks written/read", set.Report.ChunksWritten, set.Report.ChunksRead), nil, failures)
}

func LabEgressBackpressureGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Report.BackpressureEvents == 0 {
		failures = append(failures, "no target-induced backpressure observed")
	}
	return gate("labegress_target_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d backpressure events", set.Report.BackpressureEvents), nil, failures)
}

func LabEgressErrorResetIsolationGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Report.TargetErrors == 0 || set.Report.TargetResets == 0 {
		failures = append(failures, "target error/reset isolation not exercised")
	}
	return gate("labegress_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d errors, %d resets", set.Report.TargetErrors, set.Report.TargetResets), nil, failures)
}

func LabEgressHalfCloseGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	found := false
	for _, exchange := range set.Report.Exchanges {
		found = found || exchange.HalfCloseObserved
	}
	if !found {
		failures = append(failures, "half-close scenario not observed")
	}
	return gate("labegress_half_close", len(failures) == 0, "required", "half-close metadata checked", nil, failures)
}

func LabEgressQueueLimitGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Config.MaxBufferedBytes <= 0 || set.Report.QueuePressureEvents == 0 {
		failures = append(failures, "bounded egress queue pressure not exercised")
	}
	return gate("labegress_queue_limits", len(failures) == 0, "required", fmt.Sprintf("%d queue pressure events", set.Report.QueuePressureEvents), nil, failures)
}

func LabEgressTraceHygieneGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if err := labegress.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if err := labegress.ScanForLeak(map[string]string{"raw_payload": "synthetic"}); err == nil {
		failures = append(failures, "unsafe lab egress trace marker accepted")
	}
	return gate("labegress_trace_hygiene", len(failures) == 0, "required", "lab egress summaries contain safe metadata only", nil, failures)
}

func LabEgressGeneratedBackendParityGate(set labegress.LabEgressFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.SemanticMatches != set.Parity.ComparedExchanges {
		failures = append(failures, "generated/interpreted lab egress parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"labegress_generated.go", "labegress_test.go", "labegress_parity_test.go", "labegress_hygiene_test.go", "LabEgressSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated lab egress marker "+marker)
				}
			}
		}
	}
	return gate("labegress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d exchanges compared", set.Parity.ComparedExchanges), nil, failures)
}

func LabEgressMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLabEgressAllowsExternalTarget,
		mutant.ModeLabEgressAllowsDNSResolution,
		mutant.ModeLabEgressLogsPayload,
		mutant.ModeLabEgressIgnoresBackpressure,
		mutant.ModeLabEgressWrongResetMapping,
		mutant.ModeLabEgressUnboundedResponse,
		mutant.ModeLabEgressGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("labegress_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d lab egress mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func LabEgressFixtureDriftGate(report labegress.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("labegress_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func labEgressComparison(path string, current labegress.LabEgressFixtureSet) labegress.FixtureComparisonReport {
	oldSet, err := labegress.LoadFixtureSet(path)
	if err != nil {
		return labegress.FixtureComparisonReport{Version: labegress.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return labegress.CompareFixtureSets(oldSet, current)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/contracts/android/androidruntime"
	"kurdistan/internal/testkit/mutant"
)

func RunAndroidRuntimeAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := androidruntime.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := androidRuntimeComparison(filepath.Join(root, "testdata", "androidruntime", "androidruntime-report-golden.json"), set)
	gates := AndroidRuntimeGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "androidruntime-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
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

func AndroidRuntimeGates(set androidruntime.FixtureSet, comparison androidruntime.FixtureComparisonReport) []GateResult {
	return []GateResult{
		AndroidRuntimeReportGate(set),
		AndroidRuntimeInitializationGate(set),
		AndroidRuntimeLifecycleGate(set),
		AndroidRuntimeStorageGate(set),
		AndroidRuntimeDiagnosticsGate(set),
		AndroidRuntimeConcurrencyGate(set),
		AndroidRuntimeCompatibilityGate(set),
		AndroidRuntimeShutdownGate(set),
		AndroidRuntimeMisuseGate(set),
		AndroidRuntimeGeneratedParityGate(set),
		AndroidRuntimeTraceHygieneGate(set),
		AndroidRuntimePublicClaimSafetyGate(set),
		AndroidRuntimeFixtureDriftGate(comparison),
	}
}

func AndroidRuntimeReportGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if set.Decision != androidruntime.DecisionReady || set.BlockerCount != 0 || set.RiskCount < 6 || set.Checklist.Failed != 0 {
		failures = append(failures, "Android local runtime report incomplete")
	}
	return gate("androidruntime_report", len(failures) == 0, "required", fmt.Sprintf("decision=%s blockers=%d risks=%d checklist_failed=%d", set.Decision, set.BlockerCount, set.RiskCount, set.Checklist.Failed), nil, failures)
}

func AndroidRuntimeInitializationGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if !set.Initialization.ProfileValidated || !set.Initialization.RuntimeInitialized || !set.Initialization.AndroidModeLocal || set.Initialization.VpnTrafficCaptured || set.Initialization.PublicNetworkDialed || len(set.Initialization.Steps) < 7 {
		failures = append(failures, "Android local runtime initialization unsafe")
	}
	return gate("androidruntime_initialization", len(failures) == 0, "required", set.Initialization.Policy, nil, failures)
}

func AndroidRuntimeLifecycleGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Lifecycle.Events) < 10 || len(set.Lifecycle.InvalidTransitionsRejected) < 5 || set.Lifecycle.StaleSessionReused || set.Lifecycle.UncontrolledBackgroundWork {
		failures = append(failures, "Android lifecycle state machine unsafe")
	}
	return gate("androidruntime_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d lifecycle events", len(set.Lifecycle.Events)), nil, failures)
}

func AndroidRuntimeStorageGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if set.Storage.RawPacketStored || set.Storage.SecretStored || set.Storage.PrivateEndpointStored || set.Storage.ProfileStorage == "" || set.Storage.TemporaryStateStorage == "" {
		failures = append(failures, "Android runtime storage boundary unsafe")
	}
	return gate("androidruntime_storage_boundaries", len(failures) == 0, "required", set.Storage.Policy, nil, failures)
}

func AndroidRuntimeDiagnosticsGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.RawPacketLogged || set.Diagnostics.DestinationMetadataLogged || set.Diagnostics.AutoUploadAllowed || len(set.Diagnostics.AllowedFields) < 9 || len(set.Diagnostics.FailureClasses) < 6 {
		failures = append(failures, "Android runtime diagnostics unsafe")
	}
	return gate("androidruntime_diagnostics", len(failures) == 0, "required", set.Diagnostics.Policy, nil, failures)
}

func AndroidRuntimeConcurrencyGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if set.Concurrency.UnboundedWorkers || set.Concurrency.UnboundedQueues || set.Concurrency.StaleSessionAllowed || set.Concurrency.MaxRuntimeTasks <= 0 || set.Concurrency.MaxLifecycleEvents < 32 || set.Concurrency.MaxDiagnosticEvents < 64 {
		failures = append(failures, "Android runtime concurrency unsafe")
	}
	return gate("androidruntime_concurrency", len(failures) == 0, "required", fmt.Sprintf("tasks=%d lifecycle_events=%d diagnostic_events=%d", set.Concurrency.MaxRuntimeTasks, set.Concurrency.MaxLifecycleEvents, set.Concurrency.MaxDiagnosticEvents), nil, failures)
}

func AndroidRuntimeCompatibilityGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if !set.Compatibility.M56ContractLinked || !set.Compatibility.M55OperationalLinked || !set.Compatibility.RelayAuthLinked || !set.Compatibility.CarrierSelectionLinked || !set.Compatibility.MeasurementReviewLinked || !set.Compatibility.CarrierReviewLinked || !set.Compatibility.PathHealthLinked || !set.Compatibility.GeneratedBackendCompatible || set.Compatibility.BypassesProfileValidation || set.Compatibility.BypassesOperationalHardening || set.Compatibility.AllowsGeneratedDrift {
		failures = append(failures, "Android runtime compatibility unsafe")
	}
	return gate("androidruntime_compatibility", len(failures) == 0, "required", set.Compatibility.Policy, nil, failures)
}

func AndroidRuntimeShutdownGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if !set.Shutdown.CloseIdempotent || !set.Shutdown.QueuesDrained || !set.Shutdown.DiagnosticsFlushed || set.Shutdown.LeakedWorkers != 0 || set.Shutdown.PostShutdownAllowed {
		failures = append(failures, "Android runtime shutdown unsafe")
	}
	return gate("androidruntime_shutdown", len(failures) == 0, "required", set.Shutdown.Policy, nil, failures)
}

func AndroidRuntimeMisuseGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range androidruntime.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(androidruntime.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("androidruntime_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(androidruntime.RequiredMisuseNames())-len(failures), len(androidruntime.RequiredMisuseNames())), nil, failures)
}

func AndroidRuntimeGeneratedParityGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "Android runtime generated/interpreted parity failed")
	}
	return gate("androidruntime_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func AndroidRuntimeTraceHygieneGate(set androidruntime.FixtureSet) GateResult {
	failures := []string{}
	if err := androidruntime.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.DestinationLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged {
		failures = append(failures, "Android runtime trace hygiene flags unsafe")
	}
	return gate("androidruntime_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func AndroidRuntimePublicClaimSafetyGate(set androidruntime.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "Android runtime public claim safety failed")
	}
	return gate("androidruntime_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func AndroidRuntimeFixtureDriftGate(report androidruntime.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "Android runtime fixture drift detected")
	}
	return gate("androidruntime_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func androidRuntimeComparison(path string, current androidruntime.FixtureSet) androidruntime.FixtureComparisonReport {
	oldSet, err := androidruntime.LoadFixtureSet(path)
	if err != nil {
		return androidruntime.FixtureComparisonReport{Version: androidruntime.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return androidruntime.CompareFixtureSets(oldSet, current)
}

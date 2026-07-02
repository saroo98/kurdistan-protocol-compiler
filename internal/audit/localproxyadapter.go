// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/localproxyadapter"
	"kurdistan/internal/mutant"
)

func RunLocalProxyAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localproxyadapter.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localProxyAdapterComparison(filepath.Join(root, "testdata", "localproxyadapter", "localproxyadapter-report-golden.json"), set)
	gates := LocalProxyAdapterGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "localproxyadapter-" + cfg.Mode,
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

func LocalProxyAdapterGates(set localproxyadapter.FixtureSet, comparison localproxyadapter.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LocalProxyAdapterSessionGate(set),
		LocalProxyAdapterRequestMappingGate(set),
		LocalProxyAdapterOpaqueContentGate(set),
		LocalProxyAdapterStreamLifecycleGate(set),
		LocalProxyAdapterBackpressureResetGate(set),
		LocalProxyAdapterCarrierSelectionGate(set),
		LocalProxyAdapterPipelineIntegrationGate(set),
		LocalProxyAdapterLabEgressGate(set),
		LocalProxyAdapterMeasurementReviewGate(set),
		LocalProxyAdapterResourceLimitGate(set),
		LocalProxyAdapterMisuseGate(set),
		LocalProxyAdapterGeneratedParityGate(set),
		LocalProxyAdapterTraceHygieneGate(set),
		LocalProxyAdapterFixtureDriftGate(comparison),
	}
}

func LocalProxyAdapterSessionGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if !set.Summary.Completed || set.Summary.SessionsOpened != 1 || set.Summary.SessionsClosed != 1 {
		failures = append(failures, "session lifecycle incomplete")
	}
	return gate("localproxyadapter_session_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d session opened and %d closed", set.Summary.SessionsOpened, set.Summary.SessionsClosed), nil, failures)
}

func LocalProxyAdapterRequestMappingGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Requests) < 3 || set.Summary.RequestsAccepted < 3 {
		failures = append(failures, "accepted request to stream mapping incomplete")
	}
	return gate("localproxyadapter_request_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d accepted requests", len(set.Requests)), nil, failures)
}

func LocalProxyAdapterOpaqueContentGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if len(set.StreamClasses) < 11 || set.PayloadLogged || set.SecretLogged {
		failures = append(failures, "opaque stream class coverage incomplete or unsafe")
	}
	return gate("localproxyadapter_opaque_content", len(failures) == 0, "required", fmt.Sprintf("%d stream classes", len(set.StreamClasses)), nil, failures)
}

func LocalProxyAdapterStreamLifecycleGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.StreamsOpened < 8 || set.Summary.StreamsClosed == 0 || set.Summary.StreamsReset == 0 || set.Summary.HalfClosesObserved == 0 {
		failures = append(failures, "stream close/reset/half-close coverage incomplete")
	}
	return gate("localproxyadapter_stream_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d opened, %d closed, %d reset", set.Summary.StreamsOpened, set.Summary.StreamsClosed, set.Summary.StreamsReset), nil, failures)
}

func LocalProxyAdapterBackpressureResetGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.BackpressureEvents == 0 || set.Summary.StreamsReset == 0 {
		failures = append(failures, "backpressure or reset not surfaced")
	}
	return gate("localproxyadapter_backpressure_reset", len(failures) == 0, "required", fmt.Sprintf("%d pressure events; %d resets", set.Summary.BackpressureEvents, set.Summary.StreamsReset), nil, failures)
}

func LocalProxyAdapterCarrierSelectionGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	for _, want := range []string{"multicarrierselect", "httpslikecarrier", "constrainedcarrier", "pathhealth", "pathrace", "carrierreview"} {
		if !containsLocalProxyAdapterString(set.Integration.RequiredGates, want) {
			failures = append(failures, "missing integration gate "+want)
		}
	}
	return gate("localproxyadapter_carrier_selection", len(failures) == 0, "required", fmt.Sprintf("%d carrier selections", set.Summary.CarrierSelections), nil, failures)
}

func LocalProxyAdapterPipelineIntegrationGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	for _, want := range []string{"localprotocoladapter", "loopbackrelay", "relaybridge", "localpipeline"} {
		if !containsLocalProxyAdapterString(set.Integration.RequiredGates, want) {
			failures = append(failures, "missing pipeline gate "+want)
		}
	}
	return gate("localproxyadapter_pipeline_integration", len(failures) == 0, "required", fmt.Sprintf("%d localpipeline mappings", set.Summary.LocalPipelineMappings), nil, failures)
}

func LocalProxyAdapterLabEgressGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if !containsLocalProxyAdapterString(set.Integration.RequiredGates, "labegress") || set.Summary.LabEgressExchanges == 0 {
		failures = append(failures, "labegress connector policy not exercised")
	}
	return gate("localproxyadapter_labegress_connector", len(failures) == 0, "required", fmt.Sprintf("%d labegress exchanges", set.Summary.LabEgressExchanges), nil, failures)
}

func LocalProxyAdapterMeasurementReviewGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if !containsLocalProxyAdapterString(set.Integration.RequiredGates, "measurementreview") || set.Summary.MeasurementReviews == 0 {
		failures = append(failures, "measurementreview enforcement missing")
	}
	return gate("localproxyadapter_measurementreview_enforcement", len(failures) == 0, "required", fmt.Sprintf("%d measurement reviews", set.Summary.MeasurementReviews), nil, failures)
}

func LocalProxyAdapterResourceLimitGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if len(set.ResourceLimits.PanicSafetyTargets) < 4 || len(set.ResourceLimits.RejectedControls) < 3 || set.Summary.ResourceLimitRejections < 3 {
		failures = append(failures, "resource and panic-safety controls incomplete")
	}
	return gate("localproxyadapter_resource_limits", len(failures) == 0, "required", fmt.Sprintf("%d rejected controls", set.Summary.ResourceLimitRejections), nil, failures)
}

func LocalProxyAdapterMisuseGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range localproxyadapter.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(localproxyadapter.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("localproxyadapter_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(localproxyadapter.RequiredMisuseNames())-len(failures), len(localproxyadapter.RequiredMisuseNames())), nil, failures)
}

func LocalProxyAdapterGeneratedParityGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 5 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("localproxyadapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func LocalProxyAdapterTraceHygieneGate(set localproxyadapter.FixtureSet) GateResult {
	failures := []string{}
	if err := localproxyadapter.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyadapter_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d stream runs scanned", len(set.Runs)), nil, failures)
}

func LocalProxyAdapterFixtureDriftGate(report localproxyadapter.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("localproxyadapter_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localProxyAdapterComparison(path string, current localproxyadapter.FixtureSet) localproxyadapter.FixtureComparisonReport {
	oldSet, err := localproxyadapter.LoadFixtureSet(path)
	if err != nil {
		return localproxyadapter.FixtureComparisonReport{Version: localproxyadapter.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localproxyadapter.CompareFixtureSets(oldSet, current)
}

func containsLocalProxyAdapterString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/localvpnadapter"
	"kurdistan/internal/mutant"
)

func RunLocalVPNAdapterAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localvpnadapter.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localVPNAdapterComparison(filepath.Join(root, "testdata", "localvpnadapter", "localvpnadapter-report-golden.json"), set)
	gates := LocalVPNAdapterGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "localvpnadapter-" + cfg.Mode,
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

func LocalVPNAdapterGates(set localvpnadapter.FixtureSet, comparison localvpnadapter.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LocalVPNAdapterLifecycleGate(set),
		LocalVPNAdapterFlowTaxonomyGate(set),
		LocalVPNAdapterFlowMappingGate(set),
		LocalVPNAdapterMTUGate(set),
		LocalVPNAdapterRetryResetBackpressureGate(set),
		LocalVPNAdapterKillSwitchGate(set),
		LocalVPNAdapterDNSBoundaryGate(set),
		LocalVPNAdapterIntegrationGate(set),
		LocalVPNAdapterResourceGate(set),
		LocalVPNAdapterPanicSafetyGate(set),
		LocalVPNAdapterMisuseGate(set),
		LocalVPNAdapterGeneratedParityGate(set),
		LocalVPNAdapterTraceHygieneGate(set),
		LocalVPNAdapterFixtureDriftGate(comparison),
	}
}

func LocalVPNAdapterLifecycleGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if !set.Summary.Completed || set.Summary.AdapterSessionsOpened != 1 || set.Summary.AdapterSessionsClosed != 1 {
		failures = append(failures, "adapter lifecycle incomplete")
	}
	return gate("localvpnadapter_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d session opened and %d closed", set.Summary.AdapterSessionsOpened, set.Summary.AdapterSessionsClosed), nil, failures)
}

func LocalVPNAdapterFlowTaxonomyGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Descriptors) < 10 || len(set.Config.AcceptedFlowClasses) < 6 {
		failures = append(failures, "packet flow taxonomy incomplete")
	}
	return gate("localvpnadapter_flow_descriptor_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d descriptors", len(set.Descriptors)), nil, failures)
}

func LocalVPNAdapterFlowMappingGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.RuntimeStreamsMapped < 7 || set.Summary.FlowDescriptorsAccepted < len(set.Descriptors) {
		failures = append(failures, "flow to stream mapping incomplete")
	}
	return gate("localvpnadapter_flow_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d runtime streams mapped", set.Summary.RuntimeStreamsMapped), nil, failures)
}

func LocalVPNAdapterMTUGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.MTUDecisions == 0 || set.Summary.FragmentationDecisions == 0 {
		failures = append(failures, "mtu or fragmentation handling missing")
	}
	return gate("localvpnadapter_mtu_fragmentation", len(failures) == 0, "required", fmt.Sprintf("%d MTU decisions", set.Summary.MTUDecisions), nil, failures)
}

func LocalVPNAdapterRetryResetBackpressureGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.RetryDecisions == 0 || set.Summary.BackpressureEvents == 0 || set.Summary.FlowsReset == 0 {
		failures = append(failures, "retry/reset/backpressure coverage incomplete")
	}
	return gate("localvpnadapter_retry_reset_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d retry decisions; %d pressure events; %d resets", set.Summary.RetryDecisions, set.Summary.BackpressureEvents, set.Summary.FlowsReset), nil, failures)
}

func LocalVPNAdapterKillSwitchGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.KillSwitchDecisions == 0 {
		failures = append(failures, "kill-switch semantics missing")
	}
	return gate("localvpnadapter_killswitch_policy", len(failures) == 0, "required", fmt.Sprintf("%d decisions", set.Summary.KillSwitchDecisions), nil, failures)
}

func LocalVPNAdapterDNSBoundaryGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Summary.DNSBoundaryChecks == 0 || set.Config.AllowDNSInterception {
		failures = append(failures, "DNS boundary unsafe or missing")
	}
	return gate("localvpnadapter_dns_boundary", len(failures) == 0, "required", fmt.Sprintf("%d checks", set.Summary.DNSBoundaryChecks), nil, failures)
}

func LocalVPNAdapterIntegrationGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	for _, want := range []string{"vpnsemantics", "localproxyadapter", "multicarrierselect", "relaybridge", "localpipeline", "pathhealth", "measurementreview", "hardening", "codegen"} {
		if !containsLocalVPNAdapterString(set.Integration.RequiredGates, want) {
			failures = append(failures, "missing integration gate "+want)
		}
	}
	return gate("localvpnadapter_integration", len(failures) == 0, "required", fmt.Sprintf("%d integration gates", len(set.Integration.RequiredGates)), nil, failures)
}

func LocalVPNAdapterResourceGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Resource.RejectedControls) < 4 || set.Summary.ResourceLimitRejections < 4 {
		failures = append(failures, "resource controls incomplete")
	}
	return gate("localvpnadapter_resource_limits", len(failures) == 0, "required", fmt.Sprintf("%d rejected controls", set.Summary.ResourceLimitRejections), nil, failures)
}

func LocalVPNAdapterPanicSafetyGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.PanicSafety.Checked < 5 || set.PanicSafety.Conclusion != "passed" {
		failures = append(failures, "panic-safety coverage incomplete")
	}
	return gate("localvpnadapter_panic_safety", len(failures) == 0, "required", fmt.Sprintf("%d panic-safety targets", set.PanicSafety.Checked), nil, failures)
}

func LocalVPNAdapterMisuseGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range localvpnadapter.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(localvpnadapter.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("localvpnadapter_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(localvpnadapter.RequiredMisuseNames())-len(failures), len(localvpnadapter.RequiredMisuseNames())), nil, failures)
}

func LocalVPNAdapterGeneratedParityGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("localvpnadapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func LocalVPNAdapterTraceHygieneGate(set localvpnadapter.FixtureSet) GateResult {
	failures := []string{}
	if err := localvpnadapter.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localvpnadapter_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures scanned", set.TraceHygiene.FixturesScanned), nil, failures)
}

func LocalVPNAdapterFixtureDriftGate(report localvpnadapter.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("localvpnadapter_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localVPNAdapterComparison(path string, current localvpnadapter.FixtureSet) localvpnadapter.FixtureComparisonReport {
	oldSet, err := localvpnadapter.LoadFixtureSet(path)
	if err != nil {
		return localvpnadapter.FixtureComparisonReport{Version: localvpnadapter.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localvpnadapter.CompareFixtureSets(oldSet, current)
}

func containsLocalVPNAdapterString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

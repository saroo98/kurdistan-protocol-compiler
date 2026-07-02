// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/mutant"
	"kurdistan/internal/vpnsemantics"
)

func RunVPNSemanticsAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := vpnsemantics.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := vpnSemanticsComparison(filepath.Join(root, "testdata", "vpnsemantics", "vpnsemantics-report-golden.json"), set)
	gates := VPNSemanticsGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "vpnsemantics-" + cfg.Mode,
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

func VPNSemanticsGates(set vpnsemantics.FixtureSet, comparison vpnsemantics.FixtureComparisonReport) []GateResult {
	return []GateResult{
		VPNSemanticsScopeGate(set),
		VPNSemanticsTaxonomyGate(set),
		VPNSemanticsFlowMappingGate(set),
		VPNSemanticsMTUGate(set),
		VPNSemanticsRetryResetBackpressureGate(set),
		VPNSemanticsDNSBoundaryGate(set),
		VPNSemanticsKillSwitchGate(set),
		VPNSemanticsDiagnosticsPrivacyGate(set),
		VPNSemanticsM51ContractGate(set),
		VPNSemanticsMisuseGate(set),
		VPNSemanticsGeneratedParityGate(set),
		VPNSemanticsTraceHygieneGate(set),
		VPNSemanticsFixtureDriftGate(comparison),
	}
}

func VPNSemanticsScopeGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Scope.Decision != vpnsemantics.DecisionReady || len(set.Scope.BlockedBehaviors) < 10 {
		failures = append(failures, "scope contract incomplete")
	}
	return gate("vpnsemantics_scope_contract", len(failures) == 0, "required", fmt.Sprintf("%d blocked behaviors", len(set.Scope.BlockedBehaviors)), nil, failures)
}

func VPNSemanticsTaxonomyGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Taxonomy.AppIdentityLogging || set.Taxonomy.ExactEndpointLogging || len(set.Taxonomy.PacketFlowClasses) < 6 {
		failures = append(failures, "packet-flow taxonomy unsafe or incomplete")
	}
	return gate("vpnsemantics_packet_flow_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d packet flow classes", len(set.Taxonomy.PacketFlowClasses)), nil, failures)
}

func VPNSemanticsFlowMappingGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Mapping.MappingRules) < 4 || len(set.Mapping.ResultMappings) < 4 {
		failures = append(failures, "flow-to-stream mapping incomplete")
	}
	return gate("vpnsemantics_flow_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d mapping rules", len(set.Mapping.MappingRules)), nil, failures)
}

func VPNSemanticsMTUGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.MTU.PacketDumpsAllowed || len(set.MTU.MTUBuckets) < 3 || len(set.MTU.Fragmentation) < 3 || len(set.MTU.Reassembly) < 3 {
		failures = append(failures, "MTU/fragmentation model unsafe or incomplete")
	}
	return gate("vpnsemantics_mtu_fragmentation", len(failures) == 0, "required", fmt.Sprintf("%d mtu buckets", len(set.MTU.MTUBuckets)), nil, failures)
}

func VPNSemanticsRetryResetBackpressureGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if len(set.MTU.RetryBuckets) < 3 || len(set.Mapping.ResetBuckets) < 4 || len(set.Mapping.BackpressureBuckets) < 4 {
		failures = append(failures, "retry/reset/backpressure buckets incomplete")
	}
	return gate("vpnsemantics_retry_reset_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d retry buckets; %d pressure buckets", len(set.MTU.RetryBuckets), len(set.Mapping.BackpressureBuckets)), nil, failures)
}

func VPNSemanticsDNSBoundaryGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Boundaries.RealDNSInterception || len(set.Boundaries.DNSBoundaryClasses) < 3 {
		failures = append(failures, "DNS boundary unsafe")
	}
	return gate("vpnsemantics_dns_boundary_policy", len(failures) == 0, "required", fmt.Sprintf("%d DNS boundary classes", len(set.Boundaries.DNSBoundaryClasses)), nil, failures)
}

func VPNSemanticsKillSwitchGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Boundaries.OSRouteModification || set.Boundaries.AndroidVpnService || len(set.Boundaries.KillSwitchPolicies) < 3 {
		failures = append(failures, "kill-switch semantics unsafe")
	}
	return gate("vpnsemantics_kill_switch_semantics", len(failures) == 0, "required", fmt.Sprintf("%d kill-switch policy classes", len(set.Boundaries.KillSwitchPolicies)), nil, failures)
}

func VPNSemanticsDiagnosticsPrivacyGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Boundaries.LocalDiagnosticsPolicy == "" || set.Boundaries.PrivacyReview != "measurementreview_required" || len(set.Taxonomy.PrivacyClasses) < 4 {
		failures = append(failures, "diagnostics/privacy composition incomplete")
	}
	return gate("vpnsemantics_diagnostics_privacy", len(failures) == 0, "required", set.Boundaries.LocalDiagnosticsPolicy, nil, failures)
}

func VPNSemanticsM51ContractGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.M51Contract.Decision != vpnsemantics.DecisionReady || len(set.M51Contract.AcceptanceRequirements) < 6 || len(set.M51Contract.MustNotImplement) < 8 {
		failures = append(failures, "M51 contract incomplete")
	}
	return gate("vpnsemantics_m51_contract", len(failures) == 0, "required", fmt.Sprintf("%d acceptance requirements", len(set.M51Contract.AcceptanceRequirements)), nil, failures)
}

func VPNSemanticsMisuseGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range vpnsemantics.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(vpnsemantics.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("vpnsemantics_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(vpnsemantics.RequiredMisuseNames())-len(failures), len(vpnsemantics.RequiredMisuseNames())), nil, failures)
}

func VPNSemanticsGeneratedParityGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 5 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("vpnsemantics_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func VPNSemanticsTraceHygieneGate(set vpnsemantics.FixtureSet) GateResult {
	failures := []string{}
	if err := vpnsemantics.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("vpnsemantics_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures scanned", len(set.Fixtures)), nil, failures)
}

func VPNSemanticsFixtureDriftGate(report vpnsemantics.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("vpnsemantics_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func vpnSemanticsComparison(path string, current vpnsemantics.FixtureSet) vpnsemantics.FixtureComparisonReport {
	oldSet, err := vpnsemantics.LoadFixtureSet(path)
	if err != nil {
		return vpnsemantics.FixtureComparisonReport{Version: vpnsemantics.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return vpnsemantics.CompareFixtureSets(oldSet, current)
}

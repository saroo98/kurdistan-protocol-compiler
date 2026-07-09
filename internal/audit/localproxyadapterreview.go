// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/contracts/proxy/localproxyadapterreview"
	"kurdistan/internal/testkit/mutant"
)

func RunLocalProxyAdapterReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := localproxyadapterreview.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := localProxyAdapterReviewComparison(filepath.Join(root, "testdata", "localproxyadapterreview", "localproxyadapterreview-report-golden.json"), set)
	gates := LocalProxyAdapterReviewGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "localproxyadapterreview-" + cfg.Mode,
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

func LocalProxyAdapterReviewGates(set localproxyadapterreview.FixtureSet, comparison localproxyadapterreview.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LocalProxyAdapterReviewScopeGate(set),
		LocalProxyAdapterReviewProtocolGate(set),
		LocalProxyAdapterReviewPayloadGate(set),
		LocalProxyAdapterReviewStreamMappingGate(set),
		LocalProxyAdapterReviewBackpressureResetGate(set),
		LocalProxyAdapterReviewTargetRedactionGate(set),
		LocalProxyAdapterReviewCarrierSelectorGate(set),
		LocalProxyAdapterReviewResourceLimitGate(set),
		LocalProxyAdapterReviewMisuseGate(set),
		LocalProxyAdapterReviewPublicClaimGate(set),
		LocalProxyAdapterReviewM49ContractGate(set),
		LocalProxyAdapterReviewGeneratedParityGate(set),
		LocalProxyAdapterReviewTraceHygieneGate(set),
		LocalProxyAdapterReviewFixtureDriftGate(comparison),
	}
}

func LocalProxyAdapterReviewScopeGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Scope.Decision != localproxyadapterreview.DecisionReady || len(set.Scope.BlockedBehaviors) < 10 {
		failures = append(failures, "scope contract incomplete")
	}
	return gate("localproxyadapterreview_scope_contract", len(failures) == 0, "required", fmt.Sprintf("%d blocked behaviors", len(set.Scope.BlockedBehaviors)), nil, failures)
}

func LocalProxyAdapterReviewProtocolGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Protocols.AcceptedProtocols) < 2 || len(set.Protocols.ParserStates) < 4 {
		failures = append(failures, "protocol acceptance contract incomplete")
	}
	return gate("localproxyadapterreview_protocol_acceptance", len(failures) == 0, "required", fmt.Sprintf("%d accepted local protocol classes", len(set.Protocols.AcceptedProtocols)), nil, failures)
}

func LocalProxyAdapterReviewPayloadGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Payload.PayloadLogged || set.Payload.RawPayloadCommitted || set.Payload.LoggingPolicy == "" {
		failures = append(failures, "payload handling contract unsafe")
	}
	return gate("localproxyadapterreview_payload_contract", len(failures) == 0, "required", set.Payload.LoggingPolicy, nil, failures)
}

func LocalProxyAdapterReviewStreamMappingGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if !set.StreamMapping.ExactTargetExcluded || !set.StreamMapping.ExactPortExcluded || len(set.StreamMapping.MappingRules) < 3 {
		failures = append(failures, "stream mapping contract incomplete")
	}
	return gate("localproxyadapterreview_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d stream classes", len(set.StreamMapping.StreamClasses)), nil, failures)
}

func LocalProxyAdapterReviewBackpressureResetGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.BackpressureReset.BackpressureSignals) < 3 || len(set.BackpressureReset.ResetSignals) < 3 || len(set.BackpressureReset.HalfCloseRules) == 0 {
		failures = append(failures, "backpressure/reset contract incomplete")
	}
	return gate("localproxyadapterreview_backpressure_reset", len(failures) == 0, "required", fmt.Sprintf("%d pressure signals; %d reset signals", len(set.BackpressureReset.BackpressureSignals), len(set.BackpressureReset.ResetSignals)), nil, failures)
}

func LocalProxyAdapterReviewTargetRedactionGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.TargetRedaction.ExactTargetPersist || set.TargetRedaction.ExactPortPersist || len(set.TargetRedaction.ForbiddenFields) < 6 {
		failures = append(failures, "target redaction preservation failed")
	}
	return gate("localproxyadapterreview_target_redaction", len(failures) == 0, "required", fmt.Sprintf("%d forbidden fields", len(set.TargetRedaction.ForbiddenFields)), nil, failures)
}

func LocalProxyAdapterReviewCarrierSelectorGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	for _, want := range []string{"localprotocoladapter", "loopbackrelay", "labegress", "localpipeline", "multicarrierselect", "measurementreview"} {
		if !containsLocalProxyAdapterReviewString(set.Integration.RequiredGates, want) {
			failures = append(failures, "missing integration gate "+want)
		}
	}
	return gate("localproxyadapterreview_carrier_selector_integration", len(failures) == 0, "required", fmt.Sprintf("%d required gates", len(set.Integration.RequiredGates)), nil, failures)
}

func LocalProxyAdapterReviewResourceLimitGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.ResourceLimits.PanicSafetyTargets) < 4 || set.ResourceLimits.MaxBufferedBytesClass == "" {
		failures = append(failures, "resource limit contract incomplete")
	}
	return gate("localproxyadapterreview_resource_limits", len(failures) == 0, "required", fmt.Sprintf("%d panic-safety targets", len(set.ResourceLimits.PanicSafetyTargets)), nil, failures)
}

func LocalProxyAdapterReviewMisuseGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.DetectedCount != len(localproxyadapterreview.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range localproxyadapterreview.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	return gate("localproxyadapterreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(localproxyadapterreview.RequiredMisuseNames())-len(failures), len(localproxyadapterreview.RequiredMisuseNames())), nil, failures)
}

func LocalProxyAdapterReviewPublicClaimGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.PublicClaims.UnsafeClaimsFound) > 0 || set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("localproxyadapterreview_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func LocalProxyAdapterReviewM49ContractGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.M49Contract.CommandName != "localproxyadapter" || set.M49Contract.Decision != localproxyadapterreview.DecisionReady || len(set.M49Contract.AcceptanceRequirements) < 6 {
		failures = append(failures, "M49 contract incomplete")
	}
	return gate("localproxyadapterreview_m49_contract", len(failures) == 0, "required", fmt.Sprintf("%d acceptance requirements", len(set.M49Contract.AcceptanceRequirements)), nil, failures)
}

func LocalProxyAdapterReviewGeneratedParityGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 4 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("localproxyadapterreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func LocalProxyAdapterReviewTraceHygieneGate(set localproxyadapterreview.FixtureSet) GateResult {
	failures := []string{}
	if err := localproxyadapterreview.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("localproxyadapterreview_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures scanned", len(set.Fixtures)), nil, failures)
}

func LocalProxyAdapterReviewFixtureDriftGate(report localproxyadapterreview.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("localproxyadapterreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func localProxyAdapterReviewComparison(path string, current localproxyadapterreview.FixtureSet) localproxyadapterreview.FixtureComparisonReport {
	oldSet, err := localproxyadapterreview.LoadFixtureSet(path)
	if err != nil {
		return localproxyadapterreview.FixtureComparisonReport{Version: localproxyadapterreview.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return localproxyadapterreview.CompareFixtureSets(oldSet, current)
}

func containsLocalProxyAdapterReviewString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

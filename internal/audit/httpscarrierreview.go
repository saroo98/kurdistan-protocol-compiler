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

	"kurdistan/internal/httpscarrierreview"
	"kurdistan/internal/mutant"
)

func RunHTTPSCarrierReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := httpscarrierreview.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := httpsCarrierReviewComparison(filepath.Join(root, "testdata", "httpscarrierreview", "httpscarrierreview-report-golden.json"), set)
	gates := HTTPSCarrierReviewGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "httpscarrierreview-" + cfg.Mode,
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

func HTTPSCarrierReviewGates(set httpscarrierreview.FixtureSet, comparison httpscarrierreview.FixtureComparisonReport) []GateResult {
	return []GateResult{
		HTTPSCarrierReviewScopeContractGate(set),
		HTTPSCarrierReviewShapeTaxonomyGate(set),
		HTTPSCarrierReviewStreamMappingGate(set),
		HTTPSCarrierReviewBackpressureContractGate(set),
		HTTPSCarrierReviewResetErrorContractGate(set),
		HTTPSCarrierReviewIntegrationContractGate(set),
		HTTPSCarrierReviewM42ContractGate(set),
		HTTPSCarrierReviewBlockerMatrixGate(set),
		HTTPSCarrierReviewRiskModelGate(set),
		HTTPSCarrierReviewChecklistGate(set),
		HTTPSCarrierReviewMisuseDetectionGate(set),
		HTTPSCarrierReviewGeneratedBackendParityGate(set),
		HTTPSCarrierReviewTraceHygieneGate(set),
		HTTPSCarrierReviewPublicClaimSafetyGate(set),
		HTTPSCarrierReviewMutantDetectionGate(),
		HTTPSCarrierReviewFixtureDriftGate(comparison),
	}
}

func HTTPSCarrierReviewScopeContractGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	required := map[string]bool{
		"real_tls_behavior":             false,
		"real_https_client_behavior":    false,
		"real_sni_routing":              false,
		"real_host_header_routing":      false,
		"real_domain_dependency":        false,
		"real_cdn_provider_integration": false,
		"public_network_egress":         false,
		"arbitrary_target_proxying":     false,
		"payload_logging":               false,
		"packet_capture":                false,
	}
	for _, blocker := range set.Scope {
		if _, ok := required[blocker.Name]; ok && blocker.Blocked {
			required[blocker.Name] = true
		}
	}
	for name, ok := range required {
		if !ok {
			failures = append(failures, "scope blocker missing: "+name)
		}
	}
	return gate("httpscarrierreview_scope_contract", len(failures) == 0, "required", fmt.Sprintf("%d blocked behaviors checked", len(set.Scope)), nil, failures)
}

func HTTPSCarrierReviewShapeTaxonomyGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.RequestShapes) < 4 || len(set.ResponseShapes) < 4 {
		failures = append(failures, "request/response shape taxonomy incomplete")
	}
	for _, shape := range set.ShapeTaxonomy {
		if !shape.ProfileSensitive || !shape.PayloadFree {
			failures = append(failures, "unsafe shape descriptor: "+shape.Name)
		}
	}
	return gate("httpscarrierreview_shape_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d shape descriptors checked", len(set.ShapeTaxonomy)), nil, failures)
}

func HTTPSCarrierReviewStreamMappingGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if !set.StreamMapping.IsolationRequired || !set.StreamMapping.ProfileSensitive {
		failures = append(failures, "stream mapping lacks isolation/profile sensitivity")
	}
	if set.StreamMapping.OpenMapping == "" || set.StreamMapping.ResetMapping == "" || set.StreamMapping.ErrorMapping == "" {
		failures = append(failures, "stream mapping incomplete")
	}
	return gate("httpscarrierreview_stream_mapping", len(failures) == 0, "required", "stream open close reset and error mappings locked", nil, failures)
}

func HTTPSCarrierReviewBackpressureContractGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if !set.Backpressure.QueueLimitRequired || !set.Backpressure.StreamWindowRequired || !set.Backpressure.SessionWindowRequired {
		failures = append(failures, "backpressure contract missing queue/stream/session limits")
	}
	if len(set.Backpressure.CarrierSignals) < 3 {
		failures = append(failures, "carrier backpressure signals incomplete")
	}
	return gate("httpscarrierreview_backpressure_contract", len(failures) == 0, "required", fmt.Sprintf("%d carrier pressure signals", len(set.Backpressure.CarrierSignals)), nil, failures)
}

func HTTPSCarrierReviewResetErrorContractGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if !set.ResetError.ResetIsolationRequired || !set.ResetError.ErrorIsolationRequired || !set.ResetError.UnsafeFallbackBlocked {
		failures = append(failures, "reset/error isolation contract incomplete")
	}
	return gate("httpscarrierreview_reset_error_contract", len(failures) == 0, "required", fmt.Sprintf("%d safe error buckets", len(set.ResetError.AllowedErrorBuckets)), nil, failures)
}

func HTTPSCarrierReviewIntegrationContractGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	required := map[string]bool{"relaybridge": false, "loopbackrelay": false, "labegress": false, "localpipeline": false, "pathhealth": false, "measurementreview": false}
	for _, integration := range set.Integration {
		if _, ok := required[integration.Layer]; ok && integration.Required && integration.Conclusion == "locked" {
			required[integration.Layer] = true
		}
	}
	for layer, ok := range required {
		if !ok {
			failures = append(failures, "missing integration contract "+layer)
		}
	}
	return gate("httpscarrierreview_integration_contract", len(failures) == 0, "required", fmt.Sprintf("%d integration contracts checked", len(set.Integration)), nil, failures)
}

func HTTPSCarrierReviewM42ContractGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.M42Contract) < 10 {
		failures = append(failures, "M42 acceptance criteria incomplete")
	}
	for _, criterion := range set.M42Contract {
		if !criterion.Required {
			failures = append(failures, "optional M42 criterion found: "+criterion.Name)
		}
	}
	return gate("httpscarrierreview_m42_contract", len(failures) == 0, "required", fmt.Sprintf("%d M42 criteria locked", len(set.M42Contract)), nil, failures)
}

func HTTPSCarrierReviewBlockerMatrixGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Blockers) < 10 {
		failures = append(failures, "blocker matrix incomplete")
	}
	for _, blocker := range set.Blockers {
		if !blocker.Blocked {
			failures = append(failures, "blocker not enforced: "+blocker.Name)
		}
	}
	return gate("httpscarrierreview_blocker_matrix", len(failures) == 0, "required", fmt.Sprintf("%d blockers enforced", len(set.Blockers)), nil, failures)
}

func HTTPSCarrierReviewRiskModelGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Risks) < 5 {
		failures = append(failures, "risk model incomplete")
	}
	return gate("httpscarrierreview_risk_model", len(failures) == 0, "required", fmt.Sprintf("%d risks checked", len(set.Risks)), nil, failures)
}

func HTTPSCarrierReviewChecklistGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	for _, item := range set.Checklist {
		if !item.Checked {
			failures = append(failures, "unchecked readiness item: "+item.Name)
		}
	}
	if set.Contract.Decision != httpscarrierreview.DecisionReady {
		failures = append(failures, "HTTPS carrier review decision not ready for M42")
	}
	return gate("httpscarrierreview_checklist", len(failures) == 0, "required", fmt.Sprintf("%d checklist items checked", len(set.Checklist)), nil, failures)
}

func HTTPSCarrierReviewMisuseDetectionGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.UnsafeDetected < 10 {
		failures = append(failures, "misuse detector did not cover required blockers")
	}
	if set.Misuse.PayloadLogged || set.Misuse.SecretLogged {
		failures = append(failures, "misuse report leaked unsafe metadata")
	}
	return gate("httpscarrierreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d unsafe controls detected", set.Misuse.UnsafeDetected), nil, failures)
}

func HTTPSCarrierReviewGeneratedBackendParityGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.SemanticMatches != set.Parity.ContractSections {
		failures = append(failures, "generated/interpreted HTTPS carrier review parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range set.Parity.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated HTTPS carrier review marker "+marker)
				}
			}
		}
	}
	return gate("httpscarrierreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func HTTPSCarrierReviewTraceHygieneGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if err := httpscarrierreview.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.PayloadLogged || set.SecretLogged || set.Contract.TraceHygiene.PayloadLogged || set.Contract.TraceHygiene.SecretLogged {
		failures = append(failures, "HTTPS carrier review trace hygiene failed")
	}
	return gate("httpscarrierreview_trace_hygiene", len(failures) == 0, "required", "fixture trace hygiene scanned", nil, failures)
}

func HTTPSCarrierReviewPublicClaimSafetyGate(set httpscarrierreview.FixtureSet) GateResult {
	failures := []string{}
	for _, claim := range []string{"guaranteed bypass", "undetectable", "production VPN", "working VPN app", "field-ready", "real HTTPS probing"} {
		if err := httpscarrierreview.ScanForLeak(map[string]string{"claim": claim}); err == nil {
			failures = append(failures, "unsafe public claim accepted: "+claim)
		}
	}
	return gate("httpscarrierreview_public_claim_safety", len(failures) == 0, "required", "public claim safety markers checked", nil, failures)
}

func HTTPSCarrierReviewMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeHTTPSCarrierReviewGoDespiteBlocker,
		mutant.ModeHTTPSCarrierReviewAllowsRealTLS,
		mutant.ModeHTTPSCarrierReviewAllowsSNIRouting,
		mutant.ModeHTTPSCarrierReviewAllowsHostHeaderRouting,
		mutant.ModeHTTPSCarrierReviewAllowsDomainDependency,
		mutant.ModeHTTPSCarrierReviewAllowsCDNProvider,
		mutant.ModeHTTPSCarrierReviewAllowsPublicNetwork,
		mutant.ModeHTTPSCarrierReviewAllowsArbitraryEgress,
		mutant.ModeHTTPSCarrierReviewAllowsPayloadForwarding,
		mutant.ModeHTTPSCarrierReviewAllowsPayloadLogging,
		mutant.ModeHTTPSCarrierReviewAllowsPacketCapture,
		mutant.ModeHTTPSCarrierReviewAllowsMeasurementUpload,
		mutant.ModeHTTPSCarrierReviewMissingShapeCollapseControls,
		mutant.ModeHTTPSCarrierReviewMissingProfileSensitivity,
		mutant.ModeHTTPSCarrierReviewMissingBackpressureMapping,
		mutant.ModeHTTPSCarrierReviewMissingResetIsolation,
		mutant.ModeHTTPSCarrierReviewCarrierReadinessBypass,
		mutant.ModeHTTPSCarrierReviewCarrierReviewBypass,
		mutant.ModeHTTPSCarrierReviewMeasurementReviewBypass,
		mutant.ModeHTTPSCarrierReviewLabEgressBypass,
		mutant.ModeHTTPSCarrierReviewPublicClaimRealHTTPS,
		mutant.ModeHTTPSCarrierReviewPublicClaimFieldReady,
		mutant.ModeHTTPSCarrierReviewPublicClaimWorkingVPN,
		mutant.ModeHTTPSCarrierReviewPublicClaimUndetectable,
		mutant.ModeHTTPSCarrierReviewPayloadLeak,
		mutant.ModeHTTPSCarrierReviewSecretLeak,
		mutant.ModeHTTPSCarrierReviewGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("httpscarrierreview_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d HTTPS carrier review mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func HTTPSCarrierReviewFixtureDriftGate(report httpscarrierreview.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("httpscarrierreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func httpsCarrierReviewComparison(path string, current httpscarrierreview.FixtureSet) httpscarrierreview.FixtureComparisonReport {
	oldSet, err := httpscarrierreview.LoadFixtureSet(path)
	if err != nil {
		return httpscarrierreview.FixtureComparisonReport{Version: httpscarrierreview.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return httpscarrierreview.CompareFixtureSets(oldSet, current)
}

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

	"kurdistan/internal/contracts/carrier/constrainedcarrierreview"
)

func RunConstrainedCarrierReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := constrainedcarrierreview.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := constrainedCarrierReviewComparison(filepath.Join(root, "testdata", "constrainedcarrierreview", "constrainedcarrierreview-report-golden.json"), set)
	gates := ConstrainedCarrierReviewGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "constrainedcarrierreview-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
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

func ConstrainedCarrierReviewGates(set constrainedcarrierreview.FixtureSet, comparison constrainedcarrierreview.FixtureComparisonReport) []GateResult {
	return []GateResult{
		ConstrainedCarrierReviewScopeContractGate(set),
		ConstrainedCarrierReviewResolverHarnessContractGate(set),
		ConstrainedCarrierReviewQueryShapeTaxonomyGate(set),
		ConstrainedCarrierReviewResponseShapeTaxonomyGate(set),
		ConstrainedCarrierReviewSizeTruncationContractGate(set),
		ConstrainedCarrierReviewRetryFailureContractGate(set),
		ConstrainedCarrierReviewStreamMappingGate(set),
		ConstrainedCarrierReviewPrivacyMeasurementGate(set),
		ConstrainedCarrierReviewM45ContractGate(set),
		ConstrainedCarrierReviewBlockerMatrixGate(set),
		ConstrainedCarrierReviewRiskModelGate(set),
		ConstrainedCarrierReviewChecklistGate(set),
		ConstrainedCarrierReviewMisuseDetectionGate(set),
		ConstrainedCarrierReviewGeneratedBackendParityGate(set),
		ConstrainedCarrierReviewTraceHygieneGate(set),
		ConstrainedCarrierReviewPublicClaimSafetyGate(),
		ConstrainedCarrierReviewMutantDetectionGate(),
		ConstrainedCarrierReviewFixtureDriftGate(comparison),
	}
}

func ConstrainedCarrierReviewScopeContractGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	scope := set.Report.Scope
	if !scope.LabOnly || !scope.LocalResolverHarnessOnly || !scope.NoPublicResolverDefault || !scope.NoRealQueryDefault || !scope.NoExactQueryLogging || !scope.NoResolverAddressLogging || !scope.NoDomainDependence || !scope.NoPayloadLogging {
		failures = append(failures, "scope contract permits blocked behavior")
	}
	if len(scope.BlockedBehaviors) < 12 {
		failures = append(failures, "blocked behavior list incomplete")
	}
	return gate("constrainedcarrierreview_scope_contract", len(failures) == 0, "required", fmt.Sprintf("%d blocked behaviors", len(scope.BlockedBehaviors)), nil, failures)
}

func ConstrainedCarrierReviewResolverHarnessContractGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	harness := set.Report.ResolverHarness
	if !harness.LocalOnly || !harness.DeterministicFixtureScope || !harness.LoopbackOnly {
		failures = append(failures, "resolver harness is not local deterministic loopback")
	}
	if harness.PublicResolverBehavior || harness.ResolverAddressPersisted || harness.ExactQueryPersisted || harness.WildcardResolverAllowed {
		failures = append(failures, "resolver harness allows blocked resolver behavior")
	}
	if len(harness.ResolverClassBuckets) < 4 {
		failures = append(failures, "resolver class buckets incomplete")
	}
	return gate("constrainedcarrierreview_resolver_harness_contract", len(failures) == 0, "required", fmt.Sprintf("%d resolver buckets", len(harness.ResolverClassBuckets)), nil, failures)
}

func ConstrainedCarrierReviewQueryShapeTaxonomyGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	controlCount := 0
	for _, shape := range set.Report.QueryShapes {
		if shape.Direction != "query" || shape.ShapeClass == "" || shape.StableHash == "" {
			failures = append(failures, "invalid query shape "+shape.ID)
		}
		if shape.Control {
			controlCount++
		}
	}
	if len(set.Report.QueryShapes) < 10 || controlCount < 3 {
		failures = append(failures, "query shape taxonomy lacks required control classes")
	}
	return gate("constrainedcarrierreview_query_shape_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d query shapes; %d controls", len(set.Report.QueryShapes), controlCount), nil, failures)
}

func ConstrainedCarrierReviewResponseShapeTaxonomyGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	controlCount := 0
	for _, shape := range set.Report.ResponseShapes {
		if shape.Direction != "response" || shape.ShapeClass == "" || shape.StableHash == "" {
			failures = append(failures, "invalid response shape "+shape.ID)
		}
		if shape.Control {
			controlCount++
		}
	}
	if len(set.Report.ResponseShapes) < 9 || controlCount < 2 {
		failures = append(failures, "response shape taxonomy lacks required control classes")
	}
	return gate("constrainedcarrierreview_response_shape_taxonomy", len(failures) == 0, "required", fmt.Sprintf("%d response shapes; %d controls", len(set.Report.ResponseShapes), controlCount), nil, failures)
}

func ConstrainedCarrierReviewSizeTruncationContractGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	size := set.Report.SizeTruncation
	if len(size.SizeBuckets) < 4 || len(size.TruncationBuckets) < 3 || len(size.RetryAfterTruncationClasses) < 3 || size.OversizeRejectionControls == 0 {
		failures = append(failures, "size/truncation contract incomplete")
	}
	if size.RawByteCountsStored || size.RawQueryResponseBytesStored {
		failures = append(failures, "raw constrained carrier bytes are stored")
	}
	return gate("constrainedcarrierreview_size_truncation_contract", len(failures) == 0, "required", fmt.Sprintf("%d truncation buckets", len(size.TruncationBuckets)), nil, failures)
}

func ConstrainedCarrierReviewRetryFailureContractGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	retry := set.Report.RetryFailure
	if len(retry.RetryBuckets) < 3 || len(retry.TimeoutBuckets) < 3 || len(retry.PoisonFailureBuckets) < 3 || retry.MaxRetryControls == 0 {
		failures = append(failures, "retry/failure contract incomplete")
	}
	if !retry.PathHealthPropagation || !retry.MeasurementReviewDiagnostics {
		failures = append(failures, "retry/failure contract missing pathhealth or measurementreview binding")
	}
	return gate("constrainedcarrierreview_retry_failure_contract", len(failures) == 0, "required", fmt.Sprintf("%d retry buckets", len(retry.RetryBuckets)), nil, failures)
}

func ConstrainedCarrierReviewStreamMappingGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	mapping := set.Report.StreamMapping
	if len(mapping.StreamClassMappings) < 4 || len(mapping.ResponseShapeMappings) < 4 {
		failures = append(failures, "stream mapping buckets incomplete")
	}
	if !mapping.MultiStreamIsolationRequired || !mapping.ResetIsolationRequired || !mapping.BackpressureMappingRequired || !mapping.ProfileSensitiveSelection {
		failures = append(failures, "stream mapping lacks isolation, backpressure, or profile sensitivity")
	}
	return gate("constrainedcarrierreview_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d stream mappings", len(mapping.StreamClassMappings)), nil, failures)
}

func ConstrainedCarrierReviewPrivacyMeasurementGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	privacy := set.Report.PrivacyMeasurement
	if !privacy.MeasurementReviewComposed || !privacy.LocalOnlyDiagnostics {
		failures = append(failures, "measurementreview is not composed into constrained carrier review")
	}
	if privacy.UploadAllowed || privacy.ExactQueryStored || privacy.ResolverAddressStored || privacy.AccountDeviceLocationData {
		failures = append(failures, "privacy contract permits unsafe measurement data")
	}
	return gate("constrainedcarrierreview_privacy_measurement", len(failures) == 0, "required", fmt.Sprintf("%d safe fields", len(privacy.SafeFields)), nil, failures)
}

func ConstrainedCarrierReviewM45ContractGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	contract := set.Report.M45Contract
	if contract.CommandName != "constrainedcarrier" || contract.Decision != constrainedcarrierreview.DecisionReady {
		failures = append(failures, "M45 implementation contract is not ready")
	}
	if len(contract.RequiredIntegrations) < 5 || len(contract.RequiredControls) < 6 || len(contract.RequiredMutants) < len(constrainedcarrierreview.RequiredMisuseNames()) {
		failures = append(failures, "M45 contract coverage incomplete")
	}
	return gate("constrainedcarrierreview_m45_contract", len(failures) == 0, "required", fmt.Sprintf("%d acceptance requirements", len(contract.AcceptanceRequirements)), nil, failures)
}

func ConstrainedCarrierReviewBlockerMatrixGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Blockers) < 8 {
		failures = append(failures, "blocker matrix incomplete")
	}
	for _, blocker := range set.Report.Blockers {
		if !blocker.Resolved {
			failures = append(failures, "unresolved blocker "+blocker.Name)
		}
	}
	return gate("constrainedcarrierreview_blocker_matrix", len(failures) == 0, "required", fmt.Sprintf("%d blockers resolved", len(set.Report.Blockers)), nil, failures)
}

func ConstrainedCarrierReviewRiskModelGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Risks) < 6 {
		failures = append(failures, "risk model incomplete")
	}
	for _, risk := range set.Report.Risks {
		if risk.Accepted {
			failures = append(failures, "risk accepted instead of gated: "+risk.Name)
		}
	}
	return gate("constrainedcarrierreview_risk_model", len(failures) == 0, "required", fmt.Sprintf("%d risks gated", len(set.Report.Risks)), nil, failures)
}

func ConstrainedCarrierReviewChecklistGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Checklist) < 10 {
		failures = append(failures, "checklist incomplete")
	}
	for _, item := range set.Report.Checklist {
		if !item.Checked {
			failures = append(failures, "unchecked item "+item.Name)
		}
	}
	return gate("constrainedcarrierreview_checklist", len(failures) == 0, "required", fmt.Sprintf("%d checklist items", len(set.Report.Checklist)), nil, failures)
}

func ConstrainedCarrierReviewMisuseDetectionGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.Misuse.DetectedCount != len(constrainedcarrierreview.RequiredMisuseNames()) {
		failures = append(failures, "misuse controls incomplete")
	}
	if set.Report.Misuse.PayloadLogged || set.Report.Misuse.SecretLogged {
		failures = append(failures, "misuse report leaked payload or secret metadata")
	}
	return gate("constrainedcarrierreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d misuse controls", set.Report.Misuse.DetectedCount), nil, failures)
}

func ConstrainedCarrierReviewGeneratedBackendParityGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	parity := set.Report.Parity
	if parity.Conclusion != "passed" || parity.ContractMatches < 10 || len(parity.UnexpectedDifferences) > 0 || parity.PayloadLogged || parity.SecretLogged {
		failures = append(failures, "generated/interpreted constrained carrier review parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range parity.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated constrained carrier review marker "+marker)
				}
			}
		}
	}
	return gate("constrainedcarrierreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(parity.GeneratedMarkers)), nil, failures)
}

func ConstrainedCarrierReviewTraceHygieneGate(set constrainedcarrierreview.FixtureSet) GateResult {
	failures := []string{}
	if err := constrainedcarrierreview.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		failures = append(failures, "constrained carrier review hygiene flags failed")
	}
	return gate("constrainedcarrierreview_trace_hygiene", len(failures) == 0, "required", "fixture trace hygiene scanned", nil, failures)
}

func ConstrainedCarrierReviewPublicClaimSafetyGate() GateResult {
	failures := []string{}
	for _, claim := range []string{"guaranteed bypass", "undetectable", "production VPN", "working VPN", "field-ready", "real DNS support", "public resolver support"} {
		if err := constrainedcarrierreview.ScanForLeak(map[string]string{"claim": claim}); err == nil {
			failures = append(failures, "unsafe public claim accepted: "+claim)
		}
	}
	return gate("constrainedcarrierreview_public_claim_safety", len(failures) == 0, "required", "public claim safety markers checked", nil, failures)
}

func ConstrainedCarrierReviewMutantDetectionGate() GateResult {
	required := constrainedcarrierreview.RequiredMisuseNames()
	failures := missingMutantModes(required)
	return gate("constrainedcarrierreview_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d constrained carrier review mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func ConstrainedCarrierReviewFixtureDriftGate(report constrainedcarrierreview.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("constrainedcarrierreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func constrainedCarrierReviewComparison(path string, current constrainedcarrierreview.FixtureSet) constrainedcarrierreview.FixtureComparisonReport {
	oldSet, err := constrainedcarrierreview.LoadFixtureSet(path)
	if err != nil {
		return constrainedcarrierreview.FixtureComparisonReport{Version: constrainedcarrierreview.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return constrainedcarrierreview.CompareFixtureSets(oldSet, current)
}

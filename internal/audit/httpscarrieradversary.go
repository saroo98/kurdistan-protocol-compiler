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

	"kurdistan/internal/httpscarrieradversary"
	"kurdistan/internal/mutant"
)

func RunHTTPSCarrierAdversaryAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := httpscarrieradversary.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := httpsCarrierAdversaryComparison(filepath.Join(root, "testdata", "httpscarrieradversary", "httpscarrieradversary-report-golden.json"), set)
	gates := HTTPSCarrierAdversaryGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "httpscarrieradversary-" + cfg.Mode,
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

func HTTPSCarrierAdversaryGates(set httpscarrieradversary.FixtureSet, comparison httpscarrieradversary.FixtureComparisonReport) []GateResult {
	return []GateResult{
		HTTPSCarrierAdversaryCollapseDetectionGate(set),
		HTTPSCarrierAdversaryProfileSensitivityGate(set),
		HTTPSCarrierAdversaryPaddingOnlyRejectionGate(set),
		HTTPSCarrierAdversaryUnsafeFallbackGate(set),
		HTTPSCarrierAdversaryTraceHygieneGate(set),
		HTTPSCarrierAdversaryReplayControlsGate(set),
		HTTPSCarrierAdversaryStreamIsolationGate(set),
		HTTPSCarrierAdversaryBackpressureGate(set),
		HTTPSCarrierAdversaryResetErrorGate(set),
		HTTPSCarrierAdversaryIntegrationBypassGate(set),
		HTTPSCarrierAdversaryPublicClaimSafetyGate(set),
		HTTPSCarrierAdversaryGeneratedBackendParityGate(set),
		HTTPSCarrierAdversaryMutantDetectionGate(),
		HTTPSCarrierAdversaryFixtureDriftGate(comparison),
	}
}

func HTTPSCarrierAdversaryCollapseDetectionGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	collapse := set.Report.Collapse
	if !collapse.FixedShapeDetected || !collapse.FixedRequestSequence || !collapse.FixedResponseSequence || !collapse.IdenticalShapePairCollapse {
		failures = append(failures, "collapse controls incomplete")
	}
	if !collapse.AcceptedProfilesNonCollapsed || collapse.DiversityScore < 0.50 || collapse.DominantShapeRatio > 0.50 {
		failures = append(failures, "accepted diversity baseline collapsed")
	}
	return gate("httpscarrieradversary_collapse_detection", len(failures) == 0, "required", fmt.Sprintf("diversity=%.2f dominant=%.2f pairs=%d", collapse.DiversityScore, collapse.DominantShapeRatio, len(collapse.AcceptedShapePairs)), nil, failures)
}

func HTTPSCarrierAdversaryProfileSensitivityGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	sensitivity := set.Report.ProfileSensitivity
	if sensitivity.ProfileClasses < 3 || sensitivity.DistinctShapeFingerprints < 8 || !sensitivity.ProfileInputsInfluence || !sensitivity.GeneratedProfileInfluence {
		failures = append(failures, "profile sensitivity evidence incomplete")
	}
	return gate("httpscarrieradversary_profile_sensitivity", len(failures) == 0, "required", fmt.Sprintf("%d fingerprints; %d generated markers", sensitivity.DistinctShapeFingerprints, len(sensitivity.GeneratedMarkersChecked)), nil, failures)
}

func HTTPSCarrierAdversaryPaddingOnlyRejectionGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	padding := set.Report.PaddingVariation
	if !padding.PaddingOnlyRejected || padding.StructuralClasses < 4 || padding.PaddingOnlyControls == 0 {
		failures = append(failures, "padding-only variation was not rejected")
	}
	return gate("httpscarrieradversary_padding_only_rejection", len(failures) == 0, "required", fmt.Sprintf("%d structural classes", padding.StructuralClasses), nil, failures)
}

func HTTPSCarrierAdversaryUnsafeFallbackGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	fallback := set.Report.UnsafeFallback
	if !fallback.FallbacksRejected || len(fallback.BlockedFallbackCategories) < 8 {
		failures = append(failures, "unsafe fallback categories incomplete")
	}
	return gate("httpscarrieradversary_unsafe_fallback_detection", len(failures) == 0, "required", fmt.Sprintf("%d fallback categories blocked", len(fallback.BlockedFallbackCategories)), nil, failures)
}

func HTTPSCarrierAdversaryTraceHygieneGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	if err := httpscarrieradversary.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	hygiene := set.Report.TraceHygiene
	if hygiene.PayloadLogged || hygiene.SecretLogged || len(hygiene.ForbiddenMarkersFound) > 0 || set.PayloadLogged || set.SecretLogged {
		failures = append(failures, "trace hygiene failed")
	}
	return gate("httpscarrieradversary_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures and %d generated outputs scanned", hygiene.FixturesScanned, hygiene.GeneratedOutputsScanned), nil, failures)
}

func HTTPSCarrierAdversaryReplayControlsGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	replay := set.Report.ReplayControls
	if replay.DuplicateCarrierMarkersRejected == 0 || replay.ReplayedSessionMarkersRejected == 0 || replay.ReplayedStreamMarkersRejected == 0 || replay.ProductionCryptoChanged {
		failures = append(failures, "replay/control-marker checks incomplete")
	}
	return gate("httpscarrieradversary_replay_controls", len(failures) == 0, "required", fmt.Sprintf("%d control marker classes", len(replay.ControlMarkers)), nil, failures)
}

func HTTPSCarrierAdversaryStreamIsolationGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	stream := set.Report.StreamIsolation
	if stream.MultiStreamFixtures == 0 || stream.CrossStreamResetControls == 0 || stream.CrossStreamPressureControls == 0 || stream.CrossStreamErrorControls == 0 || stream.IsolationFailures != 0 {
		failures = append(failures, "stream isolation controls incomplete")
	}
	return gate("httpscarrieradversary_stream_isolation", len(failures) == 0, "required", fmt.Sprintf("%d multi-stream fixtures", stream.MultiStreamFixtures), nil, failures)
}

func HTTPSCarrierAdversaryBackpressureGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	pressure := set.Report.Backpressure
	if pressure.IgnoredBackpressureControls == 0 || pressure.UnboundedQueueControls == 0 || pressure.HiddenPressureControls == 0 || pressure.BoundedPressureSummaries == 0 {
		failures = append(failures, "backpressure adversary controls incomplete")
	}
	return gate("httpscarrieradversary_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d bounded pressure summaries", pressure.BoundedPressureSummaries), nil, failures)
}

func HTTPSCarrierAdversaryResetErrorGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	reset := set.Report.ResetError
	if reset.ResetSwallowedControls == 0 || reset.SessionResetMisclassification == 0 || reset.RawErrorStringControls == 0 || reset.UnrelatedStreamResetControls == 0 || len(reset.SafeErrorClasses) == 0 {
		failures = append(failures, "reset/error adversary controls incomplete")
	}
	return gate("httpscarrieradversary_reset_error", len(failures) == 0, "required", fmt.Sprintf("%d safe error classes", len(reset.SafeErrorClasses)), nil, failures)
}

func HTTPSCarrierAdversaryIntegrationBypassGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	bypass := set.Report.IntegrationBypass
	if bypass.BypassesDetected == 0 || bypass.BypassesDetected != bypass.BypassesRejected || !bypass.CarrierReviewBound || !bypass.MeasurementReviewBound || !bypass.PathHealthBound {
		failures = append(failures, "integration bypass controls incomplete")
	}
	return gate("httpscarrieradversary_integration_bypass", len(failures) == 0, "required", fmt.Sprintf("%d bypass controls rejected", bypass.BypassesRejected), nil, failures)
}

func HTTPSCarrierAdversaryPublicClaimSafetyGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	claims := set.Report.PublicClaims
	if !claims.ClaimSafetyPassed || len(claims.UnsafeClaimsFound) > 0 {
		failures = append(failures, "public claim safety failed")
	}
	return gate("httpscarrieradversary_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d public docs scanned", len(claims.DocumentsScanned)), nil, failures)
}

func HTTPSCarrierAdversaryGeneratedBackendParityGate(set httpscarrieradversary.FixtureSet) GateResult {
	failures := []string{}
	parity := set.Report.GeneratedParity
	if parity.Conclusion != "passed" || len(parity.UnexpectedDifferences) > 0 || parity.PayloadLogged || parity.SecretLogged || !parity.ProfileSensitivity || !parity.PaddingOnlyRejected {
		failures = append(failures, "generated/interpreted adversary parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range parity.AdversarialMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated HTTPS carrier adversary marker "+marker)
				}
			}
		}
	}
	return gate("httpscarrieradversary_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(parity.AdversarialMarkers)), nil, failures)
}

func HTTPSCarrierAdversaryMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeHTTPSCarrierAdversaryFixedShape,
		mutant.ModeHTTPSCarrierAdversaryFixedRequestSequence,
		mutant.ModeHTTPSCarrierAdversaryFixedResponseSequence,
		mutant.ModeHTTPSCarrierAdversaryPaddingOnlyVariation,
		mutant.ModeHTTPSCarrierAdversaryProfileInsensitive,
		mutant.ModeHTTPSCarrierAdversaryGeneratedProfileIgnored,
		mutant.ModeHTTPSCarrierAdversaryPublicNetworkFallback,
		mutant.ModeHTTPSCarrierAdversaryArbitraryEgressFallback,
		mutant.ModeHTTPSCarrierAdversaryRealTLSFallback,
		mutant.ModeHTTPSCarrierAdversarySNIFallback,
		mutant.ModeHTTPSCarrierAdversaryHostHeaderFallback,
		mutant.ModeHTTPSCarrierAdversaryDomainFallback,
		mutant.ModeHTTPSCarrierAdversaryPayloadForwardingFallback,
		mutant.ModeHTTPSCarrierAdversaryMeasurementUploadFallback,
		mutant.ModeHTTPSCarrierAdversaryRawFixtureLeak,
		mutant.ModeHTTPSCarrierAdversaryPayloadLeak,
		mutant.ModeHTTPSCarrierAdversarySecretLeak,
		mutant.ModeHTTPSCarrierAdversaryReplayMarkerAccepted,
		mutant.ModeHTTPSCarrierAdversaryCrossStreamReset,
		mutant.ModeHTTPSCarrierAdversaryBackpressureIgnored,
		mutant.ModeHTTPSCarrierAdversaryResetSwallowed,
		mutant.ModeHTTPSCarrierAdversaryPipelineBypass,
		mutant.ModeHTTPSCarrierAdversaryGeneratedBackendDrift,
		mutant.ModeHTTPSCarrierAdversaryPublicClaimOverstatement,
	}
	failures := missingMutantModes(required)
	return gate("httpscarrieradversary_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d HTTPS carrier adversary mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func HTTPSCarrierAdversaryFixtureDriftGate(report httpscarrieradversary.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("httpscarrieradversary_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func httpsCarrierAdversaryComparison(path string, current httpscarrieradversary.FixtureSet) httpscarrieradversary.FixtureComparisonReport {
	oldSet, err := httpscarrieradversary.LoadFixtureSet(path)
	if err != nil {
		return httpscarrieradversary.FixtureComparisonReport{Version: httpscarrieradversary.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return httpscarrieradversary.CompareFixtureSets(oldSet, current)
}

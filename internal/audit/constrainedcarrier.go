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

	"kurdistan/internal/contracts/carrier/constrainedcarrier"
	"kurdistan/internal/mutant"
)

func RunConstrainedCarrierAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := constrainedcarrier.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := constrainedCarrierComparison(filepath.Join(root, "testdata", "constrainedcarrier", "constrainedcarrier-report-golden.json"), set)
	gates := ConstrainedCarrierGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "constrainedcarrier-" + cfg.Mode,
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

func ConstrainedCarrierGates(set constrainedcarrier.FixtureSet, comparison constrainedcarrier.FixtureComparisonReport) []GateResult {
	return []GateResult{
		ConstrainedCarrierHarnessGate(set),
		ConstrainedCarrierQueryShapesGate(set),
		ConstrainedCarrierResponseShapesGate(set),
		ConstrainedCarrierCapacityTruncationGate(set),
		ConstrainedCarrierRetryFailureGate(set),
		ConstrainedCarrierProfileSensitivityGate(set),
		ConstrainedCarrierStreamMappingGate(set),
		ConstrainedCarrierBackpressureGate(set),
		ConstrainedCarrierResetErrorGate(set),
		ConstrainedCarrierRelayIntegrationGate(set),
		ConstrainedCarrierPipelineIntegrationGate(set),
		ConstrainedCarrierLocalDiagnosticsGate(set),
		ConstrainedCarrierResourceLimitsGate(set),
		ConstrainedCarrierMisuseDetectionGate(set),
		ConstrainedCarrierGeneratedBackendParityGate(set),
		ConstrainedCarrierTraceHygieneGate(set),
		ConstrainedCarrierMutantDetectionGate(),
		ConstrainedCarrierFixtureDriftGate(comparison),
	}
}

func ConstrainedCarrierHarnessGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	h := set.Report.Harness
	if !h.LocalOnly || !h.DeterministicFixtureScope || !h.LoopbackOnly || h.PublicResolverBehavior || h.RealDNSQueryDefault || h.ResolverIPPersisted || h.ExactQueryPersisted || h.DomainDependent {
		failures = append(failures, "local deterministic resolver harness contract unsafe")
	}
	if !set.Report.PublicResolverBlocked || !set.Report.RealDNSQueryBlocked {
		failures = append(failures, "public resolver or real query blocker missing")
	}
	return gate("constrainedcarrier_harness", len(failures) == 0, "required", fmt.Sprintf("%d resolver buckets", len(h.ResolverClassBuckets)), nil, failures)
}

func ConstrainedCarrierQueryShapesGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	required := []string{"small_query_marker", "chunked_query_marker", "repeated_query_marker", "delayed_query_marker", "truncated_query_marker", "retry_query_marker", "failure_query_marker", "reset_query_marker"}
	for _, want := range required {
		if !containsConstrainedCarrierShape(set.Report.QueryShapes, want) {
			failures = append(failures, "missing query shape: "+want)
		}
	}
	for _, shape := range set.Report.QueryShapes {
		if !shape.ProfileSensitive || !shape.PayloadFree || shape.Hash == "" {
			failures = append(failures, "unsafe query shape: "+shape.ID)
		}
	}
	return gate("constrainedcarrier_query_shapes", len(failures) == 0, "required", fmt.Sprintf("%d query shapes", len(set.Report.QueryShapes)), nil, failures)
}

func ConstrainedCarrierResponseShapesGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	required := []string{"small_response_marker", "truncated_response_marker", "delayed_response_marker", "failure_response_marker", "retry_response_marker", "poison_failure_response_marker", "reset_response_marker"}
	for _, want := range required {
		if !containsConstrainedCarrierShape(set.Report.ResponseShapes, want) {
			failures = append(failures, "missing response shape: "+want)
		}
	}
	for _, shape := range set.Report.ResponseShapes {
		if !shape.ProfileSensitive || !shape.PayloadFree || shape.Hash == "" {
			failures = append(failures, "unsafe response shape: "+shape.ID)
		}
	}
	return gate("constrainedcarrier_response_shapes", len(failures) == 0, "required", fmt.Sprintf("%d response shapes", len(set.Report.ResponseShapes)), nil, failures)
}

func ConstrainedCarrierCapacityTruncationGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	s := set.Report.CapacityTruncation
	if len(s.CapacityBuckets) < 3 || len(s.TruncationBuckets) < 3 || len(s.TruncationToRetryMappings) == 0 || s.OversizedMarkersRejected == 0 || s.RawByteCountsStored || s.RawQueryResponseBytesStored {
		failures = append(failures, "capacity/truncation evidence incomplete")
	}
	return gate("constrainedcarrier_capacity_truncation", len(failures) == 0, "required", fmt.Sprintf("%d truncation buckets", len(s.TruncationBuckets)), nil, failures)
}

func ConstrainedCarrierRetryFailureGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	s := set.Report.RetryFailure
	if len(s.RetryBuckets) < 3 || len(s.FailureBuckets) < 3 || len(s.PoisonFailureBuckets) < 3 || !s.MaxRetryEnforced || s.RetryStormControls == 0 || !s.PathHealthFeedback || !s.MeasurementReviewDiagnostics {
		failures = append(failures, "retry/failure evidence incomplete")
	}
	return gate("constrainedcarrier_retry_failure", len(failures) == 0, "required", fmt.Sprintf("%d retry buckets", len(s.RetryBuckets)), nil, failures)
}

func ConstrainedCarrierProfileSensitivityGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	s := set.Report.ProfileSensitivity
	if s.ProfileCount < 3 || s.DiversityScore < 0.75 || len(s.QueryShapeFingerprints) < 6 || len(s.ResponseShapeFingerprints) < 4 || s.FixedShapeControls == 0 || s.PaddingOnlyControls == 0 || s.GeneratedProfileControls == 0 {
		failures = append(failures, "profile-sensitive selection evidence incomplete")
	}
	return gate("constrainedcarrier_profile_sensitivity", len(failures) == 0, "required", fmt.Sprintf("diversity=%.2f fingerprints=%d", s.DiversityScore, len(s.QueryShapeFingerprints)), nil, failures)
}

func ConstrainedCarrierStreamMappingGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.StreamsOpened < 4 || set.Report.StreamsClosed == 0 || set.Report.StreamResets == 0 {
		failures = append(failures, "stream open/close/reset evidence incomplete")
	}
	for _, stream := range set.Report.Streams {
		if !stream.Isolated || stream.QueryShape == "" || stream.ResponseShape == "" || stream.Hash == "" {
			failures = append(failures, "unsafe stream mapping")
		}
	}
	return gate("constrainedcarrier_stream_mapping", len(failures) == 0, "required", fmt.Sprintf("%d streams mapped", len(set.Report.Streams)), nil, failures)
}

func ConstrainedCarrierBackpressureGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	s := set.Report.Backpressure
	if len(s.CapacityPressureBuckets) < 2 || len(s.TruncationPressureBuckets) < 2 || !s.LocalPipelineSummary || !s.BoundedQueues || s.IgnoredPressureControls == 0 || s.BackpressureEvents == 0 {
		failures = append(failures, "backpressure evidence incomplete")
	}
	return gate("constrainedcarrier_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d backpressure events", s.BackpressureEvents), nil, failures)
}

func ConstrainedCarrierResetErrorGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	s := set.Report.ResetError
	if len(s.ResetBuckets) < 2 || len(s.SafeErrorClasses) < 3 || s.CrossStreamResetControls == 0 || s.StaleRetryControls == 0 || s.ResetsObserved == 0 || s.ErrorsObserved == 0 {
		failures = append(failures, "reset/error evidence incomplete")
	}
	return gate("constrainedcarrier_reset_error", len(failures) == 0, "required", fmt.Sprintf("%d resets and %d errors", s.ResetsObserved, s.ErrorsObserved), nil, failures)
}

func ConstrainedCarrierRelayIntegrationGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := missingConstrainedCarrierIntegration(set, []string{"loopbackrelay", "labegress", "relaybridge", "proxyegress"})
	return gate("constrainedcarrier_relay_integration", len(failures) == 0, "required", "loopbackrelay labegress relaybridge proxyegress mappings checked", nil, failures)
}

func ConstrainedCarrierPipelineIntegrationGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := missingConstrainedCarrierIntegration(set, []string{"localpipeline", "pathrace", "pathhealth", "carrierreview", "measurementreview"})
	if !set.Report.PathHealthEnforced || !set.Report.MeasurementReviewEnforced || !set.Report.CarrierReviewEnforced || !set.Report.LocalPipelineEnforced {
		failures = append(failures, "pipeline/review enforcement flags missing")
	}
	return gate("constrainedcarrier_pipeline_integration", len(failures) == 0, "required", "localpipeline pathhealth carrierreview measurementreview mappings checked", nil, failures)
}

func ConstrainedCarrierLocalDiagnosticsGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	d := set.Report.Diagnostics
	if !d.LocalOnlyDiagnostics || !d.AggregateOnly || d.UploadAllowed || d.ExactQueryStored || d.ResolverIPStored || d.ExactPortStored || d.AccountDeviceLocationData || len(d.SafeFields) < 6 {
		failures = append(failures, "local diagnostics privacy evidence incomplete")
	}
	return gate("constrainedcarrier_local_diagnostics", len(failures) == 0, "required", fmt.Sprintf("%d safe diagnostic fields", len(d.SafeFields)), nil, failures)
}

func ConstrainedCarrierResourceLimitsGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	limits := set.Report.ResourceLimits
	if limits.MaxSessions <= 0 || limits.MaxStreams <= 0 || limits.MaxQueryMarkers <= 0 || limits.MaxResponseMarkers <= 0 || limits.MaxRetries <= 0 || limits.MaxRetainedEvents <= 0 || limits.MaxQueueDepth <= 0 || !limits.DeterministicShutdown || !limits.PanicSafetyChecked || !limits.OversizedMarkerRejected {
		failures = append(failures, "resource limits incomplete")
	}
	return gate("constrainedcarrier_resource_limits", len(failures) == 0, "required", fmt.Sprintf("sessions=%d streams=%d retries=%d", limits.MaxSessions, limits.MaxStreams, limits.MaxRetries), nil, failures)
}

func ConstrainedCarrierMisuseDetectionGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.Misuse.DetectedCount < len(constrainedcarrier.RequiredMisuseNames()) || set.Report.Misuse.Conclusion != "passed" {
		failures = append(failures, "misuse scanner did not cover required controls")
	}
	if set.Report.Misuse.PayloadLogged || set.Report.Misuse.SecretLogged {
		failures = append(failures, "misuse report leaked unsafe metadata")
	}
	return gate("constrainedcarrier_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d misuse controls detected", set.Report.Misuse.DetectedCount), nil, failures)
}

func ConstrainedCarrierGeneratedBackendParityGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.Parity.Conclusion != "passed" || len(set.Report.Parity.UnexpectedDifferences) > 0 || set.Report.Parity.PayloadLogged || set.Report.Parity.SecretLogged {
		failures = append(failures, "generated/interpreted constrained carrier parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range set.Report.Parity.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated constrained carrier marker "+marker)
				}
			}
		}
	}
	return gate("constrainedcarrier_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Report.Parity.GeneratedMarkers)), nil, failures)
}

func ConstrainedCarrierTraceHygieneGate(set constrainedcarrier.FixtureSet) GateResult {
	failures := []string{}
	if err := constrainedcarrier.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		failures = append(failures, "constrained carrier trace hygiene failed")
	}
	return gate("constrainedcarrier_trace_hygiene", len(failures) == 0, "required", "fixtures and summaries scanned for unsafe material", nil, failures)
}

func ConstrainedCarrierMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeConstrainedCarrierPublicResolverAllowed,
		mutant.ModeConstrainedCarrierRealDNSQueryDefault,
		mutant.ModeConstrainedCarrierExactQueryLogged,
		mutant.ModeConstrainedCarrierResolverIPLogged,
		mutant.ModeConstrainedCarrierDomainDependencyAllowed,
		mutant.ModeConstrainedCarrierWildcardResolverAllowed,
		mutant.ModeConstrainedCarrierPublicNetworkAllowed,
		mutant.ModeConstrainedCarrierArbitraryEgressAllowed,
		mutant.ModeConstrainedCarrierPayloadForwardingAllowed,
		mutant.ModeConstrainedCarrierPayloadLoggingAllowed,
		mutant.ModeConstrainedCarrierPacketCaptureAllowed,
		mutant.ModeConstrainedCarrierMeasurementUploadAllowed,
		mutant.ModeConstrainedCarrierFixedQueryShape,
		mutant.ModeConstrainedCarrierPaddingOnlyVariation,
		mutant.ModeConstrainedCarrierProfileInsensitive,
		mutant.ModeConstrainedCarrierRetryStorm,
		mutant.ModeConstrainedCarrierTruncationMisclassified,
		mutant.ModeConstrainedCarrierPoisonFailureMisclassified,
		mutant.ModeConstrainedCarrierBackpressureIgnored,
		mutant.ModeConstrainedCarrierResetSwallowed,
		mutant.ModeConstrainedCarrierCrossStreamLeak,
		mutant.ModeConstrainedCarrierPathHealthBypass,
		mutant.ModeConstrainedCarrierMeasurementReviewBypass,
		mutant.ModeConstrainedCarrierGeneratedBackendDrift,
		mutant.ModeConstrainedCarrierPayloadLeak,
		mutant.ModeConstrainedCarrierSecretLeak,
	}
	modes := map[string]bool{}
	for _, mode := range mutant.Modes() {
		modes[mode] = true
	}
	failures := []string{}
	for _, want := range required {
		if !modes[want] {
			failures = append(failures, "missing mutant mode: "+want)
		}
	}
	return gate("constrainedcarrier_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d constrained carrier mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func ConstrainedCarrierFixtureDriftGate(report constrainedcarrier.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.ChangedEntries...)
	}
	return gate("constrainedcarrier_fixture_drift", len(failures) == 0, "required", report.Conclusion, nil, failures)
}

func constrainedCarrierComparison(path string, set constrainedcarrier.FixtureSet) constrainedcarrier.FixtureComparisonReport {
	oldSet, err := constrainedcarrier.LoadFixtureSet(path)
	if err != nil {
		return constrainedcarrier.FixtureComparisonReport{
			Version:        constrainedcarrier.Version,
			OldHash:        "missing",
			NewHash:        set.FixtureHash,
			ChangedEntries: []string{err.Error()},
			Conclusion:     "failed",
		}
	}
	return constrainedcarrier.CompareFixtureSets(oldSet, set)
}

func containsConstrainedCarrierShape(shapes []constrainedcarrier.ShapeClass, want string) bool {
	for _, shape := range shapes {
		if shape.ShapeClass == want {
			return true
		}
	}
	return false
}

func missingConstrainedCarrierIntegration(set constrainedcarrier.FixtureSet, required []string) []string {
	present := map[string]bool{}
	for _, integration := range set.Report.Integrations {
		if integration.Composed && integration.Conclusion == "passed" {
			present[integration.Layer] = true
		}
	}
	failures := []string{}
	for _, want := range required {
		if !present[want] {
			failures = append(failures, "missing integration: "+want)
		}
	}
	return failures
}

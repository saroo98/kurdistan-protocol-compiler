// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kurdistan/internal/adversary"
	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/mutant"
	"kurdistan/internal/relay"
	"kurdistan/internal/streamadversary"
	ktrace "kurdistan/internal/trace"
)

func ProfileCorpusDiversityGate(summary diversity.CorpusSummary, thresholds AuditThresholds) GateResult {
	details := map[string]any{
		"unique_first_contact_patterns":            summary.UniqueFirstContactPatterns,
		"unique_frame_grammar_combinations":        summary.UniqueFrameGrammarCombinations,
		"unique_scheduler_combinations":            summary.UniqueSchedulerCombinations,
		"unique_padding_combinations":              summary.UniquePaddingCombinations,
		"unique_invalid_input_policy_combinations": summary.UniqueInvalidInputPolicyCombinations,
		"structurally_different_pair_ratio":        structuralPairRatio(summary.ProfileDiversityReport),
		"min_structurally_different_pair_ratio":    thresholds.MinStructurallyDifferentPairRatio,
		"min_first_contact_patterns":               thresholds.MinFirstContactPatterns,
		"min_frame_grammar_combinations":           thresholds.MinFrameGrammarCombinations,
		"min_scheduler_combinations":               thresholds.MinSchedulerCombinations,
		"min_padding_combinations":                 thresholds.MinPaddingCombinations,
		"min_invalid_input_policy_combinations":    thresholds.MinInvalidInputCombinations,
	}
	failures := []string{}
	if summary.UniqueFirstContactPatterns < thresholds.MinFirstContactPatterns {
		failures = append(failures, "first-contact patterns below threshold")
	}
	if summary.UniqueFrameGrammarCombinations < thresholds.MinFrameGrammarCombinations {
		failures = append(failures, "frame grammar combinations below threshold")
	}
	if summary.UniqueSchedulerCombinations < thresholds.MinSchedulerCombinations {
		failures = append(failures, "scheduler combinations below threshold")
	}
	if summary.UniquePaddingCombinations < thresholds.MinPaddingCombinations {
		failures = append(failures, "padding combinations below threshold")
	}
	if summary.UniqueInvalidInputPolicyCombinations < thresholds.MinInvalidInputCombinations {
		failures = append(failures, "invalid-input combinations below threshold")
	}
	if structuralPairRatio(summary.ProfileDiversityReport) < thresholds.MinStructurallyDifferentPairRatio {
		failures = append(failures, "structurally different pair ratio below threshold")
	}
	return gate("profile_corpus_diversity", len(failures) == 0, "required", fmt.Sprintf("%d profiles checked; %d failures", summary.ProfileCount, len(failures)), details, failures)
}

func BlackBoxTraceDiversityGate(scan ktrace.TraceScanReport, thresholds AuditThresholds) GateResult {
	maxByMetric := map[string]float64{
		"first_frame_size":            thresholds.MaxSameFirstFrameSizeRatio,
		"first_contact_message_count": thresholds.MaxSameFirstContactCountRatio,
		"state_path_shape":            thresholds.MaxSameStatePathRatio,
		"frame_size_histogram":        thresholds.MaxSameFrameSizeHistogramRatio,
		"padding_histogram":           thresholds.MaxSamePaddingHistogramRatio,
		"invalid_input_result":        thresholds.MaxSameInvalidOutcomeRatio,
		"close_behavior":              thresholds.MaxSameCloseBehaviorRatio,
	}
	failures := []string{}
	details := map[string]any{"trace_count": scan.TraceCount}
	for _, metric := range scan.Metrics {
		maxAllowed, ok := maxByMetric[metric.Name]
		if !ok {
			continue
		}
		details[metric.Name+"_stability"] = metric.Stability
		details[metric.Name+"_unique_values"] = metric.UniqueValues
		if metric.Total >= 3 && metric.Stability > maxAllowed {
			failures = append(failures, metric.Name+" too stable")
		}
	}
	return gate("black_box_trace_diversity", len(failures) == 0, "required", fmt.Sprintf("%d traces scanned; %d suspicious metrics", scan.TraceCount, len(failures)), details, failures)
}

func AdversarialBlackBoxClusteringGate(ctx context.Context, profiles []*ir.Profile, traces [][]ktrace.Event, thresholds AuditThresholds) GateResult {
	cfg := adversary.AnalysisConfig{
		StartSeed:        1,
		TraceCount:       len(traces),
		ControlCount:     max(6, min(12, len(traces))),
		ClusterThreshold: thresholds.AdversaryClusterThreshold,
	}
	report := adversary.AnalyzeTraces(traces, cfg)
	stats := report.GeneratedClusterReport.PairwiseStats
	details := map[string]any{
		"trace_count":                         len(traces),
		"feature_vector_count":                report.FeatureVectorCount,
		"cluster_threshold":                   report.ClusterThreshold,
		"cluster_count":                       report.GeneratedClusterReport.ClusterCount,
		"largest_cluster_ratio":               report.GeneratedClusterReport.LargestClusterRatio,
		"average_distance":                    stats.AverageDistance,
		"different_profile_average_distance":  stats.DifferentProfileAverageDistance,
		"min_different_profile_distance":      thresholds.MinDifferentProfileDistance,
		"max_family_collapse_ratio":           thresholds.MaxKurdistanFamilyCollapseRatio,
		"max_same_profile_distance":           thresholds.MaxSameProfileDistance,
		"max_noisy_fixed_cluster_spread":      thresholds.MaxNoisyFixedClusterSpread,
		"max_fixed_control_cluster_spread":    thresholds.MaxFixedControlClusterSpread,
		"control_results":                     controlSummary(report.ControlResults),
		"generated_cluster_conclusion":        report.GeneratedClusterReport.Conclusion,
		"generated_pair_count":                stats.PairCount,
		"generated_different_profile_pairs":   stats.DifferentProfilePairs,
		"generated_same_profile_pairs":        stats.SameProfilePairs,
		"generated_largest_cluster_size":      report.GeneratedClusterReport.LargestClusterSize,
		"generated_pairwise_max_distance":     stats.MaxDistance,
		"generated_pairwise_min_distance":     stats.MinDistance,
		"generated_pairwise_average_distance": stats.AverageDistance,
	}
	failures := []string{}
	if len(traces) >= 3 &&
		report.GeneratedClusterReport.LargestClusterRatio >= thresholds.MaxKurdistanFamilyCollapseRatio &&
		stats.AverageDistance < thresholds.MinDifferentProfileDistance {
		failures = append(failures, "generated traces collapsed into one tight cluster")
	}
	if stats.DifferentProfilePairs > 0 && stats.DifferentProfileAverageDistance < thresholds.MinDifferentProfileDistance {
		failures = append(failures, "different profiles are too close under black-box distance")
	}
	sameDistance, sameClustered, err := sameProfileDistance(ctx, profiles, thresholds)
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		details["same_profile_distance"] = sameDistance
		details["same_profile_clustered"] = sameClustered
		if sameDistance > thresholds.MaxSameProfileDistance {
			failures = append(failures, "same-profile traces are too far apart")
		}
		if !sameClustered {
			failures = append(failures, "same-profile traces did not cluster together")
		}
	}
	if fixed := findControl(report.ControlResults, "fixed_protocol"); fixed == nil || fixed.ClusterReport.ClusterCount != 1 || fixed.ClusterReport.PairwiseStats.MaxDistance > thresholds.MaxFixedControlClusterSpread {
		failures = append(failures, "fixed synthetic control was not detected as fixed")
	}
	if noisy := findControl(report.ControlResults, "noisy_fixed_protocol"); noisy == nil || noisy.ClusterReport.ClusterCount != 1 || noisy.ClusterReport.PairwiseStats.MaxDistance > thresholds.MaxNoisyFixedClusterSpread {
		failures = append(failures, "noisy-fixed synthetic control was not detected as fixed-family")
	}
	return gate("adversarial_black_box_clustering", len(failures) == 0, "required", fmt.Sprintf("%d traces clustered into %d groups; %d failures", len(traces), report.GeneratedClusterReport.ClusterCount, len(failures)), details, failures)
}

func FixedSignatureGate(profiles []*ir.Profile, traces [][]ktrace.Event, thresholds AuditThresholds) GateResult {
	checks := map[string]ratioCheck{
		"first_byte":             dominantRatio(firstBytes(profiles)),
		"first_frame_length":     dominantRatio(traceValues(traces, firstFrameLength)),
		"semantic_sequence":      dominantRatio(traceValues(traces, semanticSequence)),
		"wire_symbol_sequence":   dominantRatio(traceValues(traces, wireSymbolSequence)),
		"failed_auth_policy":     dominantRatio(profileValues(profiles, func(p *ir.Profile) string { return p.InvalidInput.FailedAuth })),
		"malformed_frame_policy": dominantRatio(profileValues(profiles, func(p *ir.Profile) string { return p.InvalidInput.MalformedFrame })),
		"state_path":             dominantRatio(traceValues(traces, statePathShape)),
	}
	limits := map[string]float64{
		"first_byte":             thresholds.MaxSameFirstByteRatio,
		"first_frame_length":     thresholds.MaxSameFirstFrameSizeRatio,
		"semantic_sequence":      thresholds.MaxSameSemanticSequenceRatio,
		"wire_symbol_sequence":   thresholds.MaxSameWireSymbolSequenceRatio,
		"failed_auth_policy":     thresholds.MaxSameInvalidOutcomeRatio,
		"malformed_frame_policy": thresholds.MaxSameMalformedFramePolicyRatio,
		"state_path":             thresholds.MaxSameStatePathRatio,
	}
	failures := []string{}
	details := map[string]any{}
	for name, check := range checks {
		details[name+"_ratio"] = check.Ratio
		details[name+"_unique_values"] = check.UniqueValues
		if check.Total >= 3 && check.Ratio > limits[name] {
			failures = append(failures, name+" is too stable")
		}
	}
	return gate("fixed_signature", len(failures) == 0, "required", fmt.Sprintf("%d fixed-signature metrics checked; %d failures", len(checks), len(failures)), details, failures)
}

func CosmeticDifferenceGate() GateResult {
	a, err := compiler.Generate(11)
	if err != nil {
		return gate("cosmetic_difference", false, "required", err.Error(), nil, []string{err.Error()})
	}
	b := *a
	b.ID = "kp_cosmetic_gate"
	b.Seed = 9999
	b.GenerationHash = "cosmetic"
	for i := range b.Messages {
		b.Messages[i].WireSymbol += "_renamed"
	}
	for i := range b.FirstContact.Steps {
		b.FirstContact.Steps[i].WireSymbol += "_renamed"
	}
	profileReport := diversity.CompareProfileStructure(a, &b)
	traceA := []ktrace.Event{{TimeUnixNano: 1, ProfileID: a.ID, EventType: "first_contact", State: "s1", FrameBytes: 10}, {TimeUnixNano: 2, ProfileID: a.ID, EventType: "frame", Semantic: "data", FrameBytes: 20}}
	traceB := []ktrace.Event{{TimeUnixNano: 100, ProfileID: a.ID, EventType: "first_contact", State: "s1", FrameBytes: 10}, {TimeUnixNano: 101, ProfileID: a.ID, EventType: "frame", Semantic: "data", FrameBytes: 20}}
	traceReport := ktrace.CompareEvents(traceA, traceB)
	failures := []string{}
	if profileReport.Classification == diversity.ClassStructurallyDifferent {
		failures = append(failures, "cosmetic-only profile classified as structural")
	}
	if traceReport.MeaningfullyDifferent {
		failures = append(failures, "timestamp-only trace classified as meaningful difference")
	}
	return gate("cosmetic_difference", len(failures) == 0, "required", "cosmetic profile and timestamp-only trace controls evaluated", map[string]any{
		"profile_classification": profileReport.Classification,
		"trace_conclusion":       traceReport.Conclusion,
	}, failures)
}

func SameProfileConsistencyGate(ctx context.Context) GateResult {
	p, err := compiler.Generate(21)
	if err != nil {
		return gate("same_profile_consistency", false, "required", err.Error(), nil, []string{err.Error()})
	}
	a, err := labtrace.CaptureTrace(ctx, p, []byte("hello kurdistan"))
	if err != nil {
		return gate("same_profile_consistency", false, "required", err.Error(), nil, []string{err.Error()})
	}
	b, err := labtrace.CaptureTrace(ctx, p, []byte("hello kurdistan"))
	if err != nil {
		return gate("same_profile_consistency", false, "required", err.Error(), nil, []string{err.Error()})
	}
	report := ktrace.CompareEvents(a, b)
	distance := adversary.Distance(adversary.ExtractFeaturesWithMetadata("same_profile_a", "", a), adversary.ExtractFeaturesWithMetadata("same_profile_b", "", b))
	failures := []string{}
	if report.MeaningfullyDifferent && distance > DefaultThresholds().MaxSameProfileDistance {
		failures = append(failures, "same profile trace classified as meaningfully different")
	}
	summary := report.Conclusion
	if report.MeaningfullyDifferent && len(failures) == 0 {
		summary = "same-family by canonical feature distance"
	}
	return gate("same_profile_consistency", len(failures) == 0, "required", summary, map[string]any{"difference_score": report.DifferenceScore, "canonical_distance": distance}, failures)
}

func DifferentProfileSeparationGate(traces [][]ktrace.Event, thresholds AuditThresholds) GateResult {
	total, separated := 0, 0
	for i := 0; i < len(traces); i++ {
		for j := i + 1; j < len(traces); j++ {
			total++
			if ktrace.CompareEvents(traces[i], traces[j]).MeaningfullyDifferent {
				separated++
			}
		}
	}
	ratio := 1.0
	if total > 0 {
		ratio = float64(separated) / float64(total)
	}
	passed := ratio >= thresholds.MinDifferentTraceSeparationRatio
	failures := []string{}
	if !passed {
		failures = append(failures, "different-profile trace separation below threshold")
	}
	return gate("different_profile_separation", passed, "required", fmt.Sprintf("%d/%d trace pairs separated", separated, total), map[string]any{
		"separated_pairs": separated,
		"total_pairs":     total,
		"ratio":           ratio,
		"min_ratio":       thresholds.MinDifferentTraceSeparationRatio,
	}, failures)
}

func MalformedProbeBehaviorGate(profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	failedAuth := dominantRatio(profileValues(profiles, func(p *ir.Profile) string { return p.InvalidInput.FailedAuth }))
	malformed := dominantRatio(profileValues(profiles, func(p *ir.Profile) string { return p.InvalidInput.MalformedFrame }))
	failures := []string{}
	if failedAuth.Ratio > thresholds.MaxSameInvalidOutcomeRatio {
		failures = append(failures, "failed-auth behavior too stable")
	}
	if malformed.Ratio > thresholds.MaxSameMalformedFramePolicyRatio {
		failures = append(failures, "malformed-frame behavior too stable")
	}
	return gate("malformed_probe_behavior", len(failures) == 0, "required", "invalid-input behavior distribution checked", map[string]any{
		"failed_auth_ratio":      failedAuth.Ratio,
		"failed_auth_unique":     failedAuth.UniqueValues,
		"malformed_frame_ratio":  malformed.Ratio,
		"malformed_frame_unique": malformed.UniqueValues,
	}, failures)
}

func MultiStreamSemanticsGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	failures := []string{}
	checked := 0
	streamCounts := []string{}
	for _, p := range profiles {
		if p == nil || p.Stream.MaxConcurrentStreams < 2 {
			continue
		}
		count := min(4, p.Stream.MaxConcurrentStreams)
		if count < 2 {
			continue
		}
		requests := relay.DefaultMultiStreamDemoRequests(count)
		if count >= 3 {
			requests[count-1].ResetAfterOpen = true
		}
		result, events, err := relay.SimulateMultiStreamEcho(ctx, p, requests)
		if err != nil {
			failures = append(failures, p.ID+": "+err.Error())
			continue
		}
		checked++
		streamCounts = append(streamCounts, fmt.Sprint(result.OpenedStreams))
		if result.OpenedStreams != count {
			failures = append(failures, p.ID+": opened stream count mismatch")
		}
		if count >= 3 && result.ResetStreams != 1 {
			failures = append(failures, p.ID+": reset did not remain stream-local")
		}
		if result.ClosedStreams+result.ResetStreams != result.OpenedStreams {
			failures = append(failures, p.ID+": streams did not close or reset independently")
		}
		if !traceHasStreamMetadata(events) {
			failures = append(failures, p.ID+": missing stream trace metadata")
		}
		if checked >= 4 {
			break
		}
	}
	if checked == 0 {
		failures = append(failures, "no generated profile supported multi-stream semantics")
	}
	return gate("multi_stream_semantics", len(failures) == 0, "required", fmt.Sprintf("%d profiles exercised with local multi-stream echo", checked), map[string]any{
		"profiles_checked": checked,
		"stream_counts":    streamCounts,
	}, failures)
}

func MultiStreamDiversityGate(profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	combinations := profileValues(profiles, func(p *ir.Profile) string {
		return strings.Join([]string{
			p.Stream.IDStrategy,
			p.Stream.IDEncodingMode,
			fmt.Sprint(p.Stream.MaxConcurrentStreams),
			fmt.Sprint(p.Stream.InitialStreamWindowBytes),
			fmt.Sprint(p.Stream.InitialSessionWindowBytes),
			p.Stream.WindowUpdatePolicy,
			p.Stream.PriorityPolicy,
			p.Stream.ClosePolicy,
			p.Stream.ResetPolicy,
		}, "|")
	})
	encodings := profileValues(profiles, func(p *ir.Profile) string { return p.Stream.IDEncodingMode })
	priorities := profileValues(profiles, func(p *ir.Profile) string { return p.Stream.PriorityPolicy })
	windowUpdates := profileValues(profiles, func(p *ir.Profile) string { return p.Stream.WindowUpdatePolicy })
	failures := []string{}
	if uniqueStrings(combinations) < thresholds.MinStreamPolicyCombinations {
		failures = append(failures, "stream policy combinations below threshold")
	}
	if uniqueStrings(encodings) < thresholds.MinStreamIDEncodingModes {
		failures = append(failures, "stream id encoding modes below threshold")
	}
	if uniqueStrings(priorities) < 2 {
		failures = append(failures, "stream priority policies below threshold")
	}
	if uniqueStrings(windowUpdates) < 2 {
		failures = append(failures, "window update policies below threshold")
	}
	return gate("multi_stream_diversity", len(failures) == 0, "required", fmt.Sprintf("%d stream policy combinations across %d profiles", uniqueStrings(combinations), len(profiles)), map[string]any{
		"unique_stream_policy_combinations": uniqueStrings(combinations),
		"unique_stream_id_encodings":        uniqueStrings(encodings),
		"unique_priority_policies":          uniqueStrings(priorities),
		"unique_window_update_policies":     uniqueStrings(windowUpdates),
		"min_stream_policy_combinations":    thresholds.MinStreamPolicyCombinations,
		"min_stream_id_encoding_modes":      thresholds.MinStreamIDEncodingModes,
	}, failures)
}

func MultiStreamBackpressureGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	failures := []string{}
	checked := 0
	for _, p := range profiles {
		if p == nil || p.Stream.MaxConcurrentStreams < 2 {
			continue
		}
		large := make([]byte, p.Stream.InitialStreamWindowBytes+1)
		requests := []relay.MultiStreamRequest{
			{Label: "interactive", Priority: "interactive", Payload: []byte("short")},
			{Label: "backpressure", Priority: "bulk", Payload: large},
		}
		result, events, err := relay.SimulateMultiStreamEcho(ctx, p, requests)
		if err != nil {
			failures = append(failures, p.ID+": "+err.Error())
			continue
		}
		checked++
		if result.BackpressureEvents == 0 || result.WindowUpdateEvents == 0 {
			failures = append(failures, p.ID+": backpressure/window-update not represented")
		}
		if !traceHasBackpressure(events) {
			failures = append(failures, p.ID+": trace missing backpressure metadata")
		}
		break
	}
	if checked == 0 {
		failures = append(failures, "no profile available for backpressure check")
	}
	return gate("multi_stream_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d profile backpressure scenarios exercised", checked), map[string]any{
		"profiles_checked": checked,
	}, failures)
}

func MultiStreamAdversarialScenariosGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 3)
	scenarios := streamadversary.QuickScenarios()
	runs, err := streamadversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("multi_stream_adversarial_scenarios", false, "required", err.Error(), map[string]any{
			"profile_count":  len(selected),
			"scenario_count": len(scenarios),
		}, []string{err.Error()})
	}
	report := streamadversary.AnalyzeRuns(runs, streamCollapseThresholds(thresholds))
	failures := streamCorrectnessFailures(report)
	return gate("multi_stream_adversarial_scenarios", len(failures) == 0, "required", fmt.Sprintf("%d scenario runs checked; %d correctness failures", report.Correctness.ScenarioRuns, len(failures)), map[string]any{
		"profile_count":           report.ProfileCount,
		"scenario_count":          report.ScenarioCount,
		"correct_runs":            report.Correctness.CorrectRuns,
		"scenario_runs":           report.Correctness.ScenarioRuns,
		"backpressure_failures":   report.Correctness.BackpressureFailures,
		"scheduler_failures":      report.Correctness.SchedulerFailures,
		"reset_close_failures":    report.Correctness.ResetCloseFailures,
		"metadata_failures":       report.Correctness.MetadataFailures,
		"collapse_reports":        report.CollapseReports,
		"stream_adversary_result": report.Conclusion,
	}, failures)
}

func MultiStreamCollapseResistanceGate(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) GateResult {
	selected := selectProfiles(profiles, 8)
	scenarios := []streamadversary.Scenario{
		streamadversary.DefaultScenario(streamadversary.ScenarioBulkVsInteractive),
		streamadversary.DefaultScenario(streamadversary.ScenarioResetMidstream),
	}
	runs, err := streamadversary.RunScenarioCorpus(ctx, selected, scenarios)
	if err != nil {
		return gate("multi_stream_collapse_resistance", false, "required", err.Error(), map[string]any{
			"profile_count":  len(selected),
			"scenario_count": len(scenarios),
		}, []string{err.Error()})
	}
	report := streamadversary.AnalyzeRuns(runs, streamCollapseThresholds(thresholds))
	failures := collapseFailures(report)
	return gate("multi_stream_collapse_resistance", len(failures) == 0, "required", fmt.Sprintf("%d scenarios scanned; %d suspicious metrics", report.ScenarioCount, len(failures)), map[string]any{
		"profile_count":    report.ProfileCount,
		"scenario_count":   report.ScenarioCount,
		"collapse_reports": report.CollapseReports,
		"correctness":      report.Correctness,
	}, failures)
}

func MultiStreamMutantDetectionGate(ctx context.Context, thresholds AuditThresholds) GateResult {
	modes := []string{
		mutant.ModeFixedStreamIDStrategy,
		mutant.ModeFixedWindowUpdatePolicy,
		mutant.ModeFIFOSchedulerOnly,
		mutant.ModeFixedResetClosePolicy,
		mutant.ModeNoBackpressure,
		mutant.ModePaddingOnlyStreamDiversity,
	}
	detected := []string{}
	missed := []string{}
	modeDetails := map[string]any{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 1600, 6)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		scenarios := mutantScenarios(mode)
		runs, err := streamadversary.RunMutantScenarioCorpus(ctx, mode, profiles, scenarios)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		report := streamadversary.AnalyzeRuns(runs, streamCollapseThresholds(thresholds))
		reasons := mutantDetectionReasons(mode, report)
		modeDetails[mode] = map[string]any{
			"reasons":          reasons,
			"correctness":      report.Correctness,
			"collapse_reports": report.CollapseReports,
		}
		if len(reasons) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("multi_stream_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d stream mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
		"mode_details":   modeDetails,
	}, missed)
}

func streamCollapseThresholds(thresholds AuditThresholds) streamadversary.CollapseThresholds {
	defaults := streamadversary.DefaultCollapseThresholds()
	if thresholds.MaxStreamAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxStreamAdversaryDominantRatio
	}
	if thresholds.MinStreamAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinStreamAdversaryDiversityScore
	}
	if thresholds.MinStreamAdversaryScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinStreamAdversaryScenarioSuccess
	}
	return defaults
}

func selectProfiles(profiles []*ir.Profile, limit int) []*ir.Profile {
	selected := []*ir.Profile{}
	for _, p := range profiles {
		if p == nil {
			continue
		}
		selected = append(selected, p)
		if len(selected) >= limit {
			break
		}
	}
	return selected
}

func streamCorrectnessFailures(report streamadversary.Report) []string {
	failures := []string{}
	if report.Correctness.BackpressureFailures > 0 {
		failures = append(failures, "backpressure correctness failures")
	}
	if report.Correctness.SchedulerFailures > 0 {
		failures = append(failures, "scheduler correctness failures")
	}
	if report.Correctness.ResetCloseFailures > 0 {
		failures = append(failures, "reset/close correctness failures")
	}
	if report.Correctness.MetadataFailures > 0 {
		failures = append(failures, "missing safe stream trace metadata")
	}
	if report.Correctness.ScenarioRuns == 0 {
		failures = append(failures, "no stream adversary scenarios ran")
	}
	return failures
}

func collapseFailures(report streamadversary.Report) []string {
	failures := []string{}
	for _, collapse := range report.CollapseReports {
		if collapse.Conclusion == "passed" {
			continue
		}
		if len(collapse.SuspiciousMetrics) == 0 {
			failures = append(failures, collapse.Scenario+": diversity score below threshold")
			continue
		}
		for _, metric := range collapse.SuspiciousMetrics {
			failures = append(failures, collapse.Scenario+": "+metric)
		}
	}
	return failures
}

func mutantScenarios(mode string) []streamadversary.Scenario {
	switch mode {
	case mutant.ModeFIFOSchedulerOnly:
		return []streamadversary.Scenario{streamadversary.DefaultScenario(streamadversary.ScenarioBulkVsInteractive)}
	case mutant.ModeNoBackpressure, mutant.ModeFixedWindowUpdatePolicy:
		return []streamadversary.Scenario{streamadversary.DefaultScenario(streamadversary.ScenarioBlockedStream)}
	default:
		return []streamadversary.Scenario{streamadversary.DefaultScenario(streamadversary.ScenarioResetMidstream)}
	}
}

func mutantDetectionReasons(mode string, report streamadversary.Report) []string {
	reasons := []string{}
	switch mode {
	case mutant.ModeFIFOSchedulerOnly:
		if report.Correctness.SchedulerFailures > 0 {
			reasons = append(reasons, "scheduler correctness failed")
		}
	case mutant.ModeNoBackpressure:
		if report.Correctness.BackpressureFailures > 0 {
			reasons = append(reasons, "backpressure correctness failed")
		}
	}
	expected := map[string]string{
		mutant.ModeFixedStreamIDStrategy:      "stream_id_sequence",
		mutant.ModeFixedWindowUpdatePolicy:    "window_update_rhythm",
		mutant.ModeFixedResetClosePolicy:      "close_reset_outcome",
		mutant.ModePaddingOnlyStreamDiversity: "stream_behavior_fixed",
	}
	if metric := expected[mode]; metric != "" && reportHasSuspiciousMetric(report, metric) {
		reasons = append(reasons, metric)
	}
	return reasons
}

func reportHasSuspiciousMetric(report streamadversary.Report, metric string) bool {
	for _, collapse := range report.CollapseReports {
		for _, found := range collapse.SuspiciousMetrics {
			if found == metric {
				return true
			}
		}
	}
	return false
}

func traceHasStreamMetadata(events []ktrace.Event) bool {
	for _, ev := range events {
		if ev.StreamLabel != "" && ev.StreamEvent != "" && ev.StreamState != "" && ev.StreamWindowBucket != "" && ev.SessionWindowBucket != "" {
			return true
		}
	}
	return false
}

func traceHasBackpressure(events []ktrace.Event) bool {
	for _, ev := range events {
		if ev.Backpressure && ev.StreamWindowBucket != "" && ev.SessionWindowBucket != "" {
			return true
		}
	}
	return false
}

func FuzzPresenceGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("fuzz_presence", false, "required", err.Error(), nil, []string{err.Error()})
	}
	required := []string{
		"internal/framing/codec_fuzz_test.go",
		"internal/ir/validate_fuzz_test.go",
		"internal/fsm/interpreter_fuzz_test.go",
		"internal/trace/trace_fuzz_test.go",
	}
	missing := []string{}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel))); err != nil {
			missing = append(missing, rel)
		}
	}
	return gate("fuzz_presence", len(missing) == 0, "required", fmt.Sprintf("%d fuzz target files checked", len(required)), map[string]any{"required_files": required, "missing_files": missing}, missing)
}

func sameProfileDistance(ctx context.Context, profiles []*ir.Profile, thresholds AuditThresholds) (float64, bool, error) {
	if len(profiles) == 0 || profiles[0] == nil {
		return 0, false, fmt.Errorf("no profile available for same-profile control")
	}
	a, err := labtrace.CaptureTrace(ctx, profiles[0], []byte("hello kurdistan"))
	if err != nil {
		return 0, false, fmt.Errorf("same-profile trace A failed: %w", err)
	}
	b, err := labtrace.CaptureTrace(ctx, profiles[0], []byte("hello kurdistan"))
	if err != nil {
		return 0, false, fmt.Errorf("same-profile trace B failed: %w", err)
	}
	av := adversary.ExtractFeaturesWithMetadata("same_profile_a", "", a)
	bv := adversary.ExtractFeaturesWithMetadata("same_profile_b", "", b)
	distance := adversary.Distance(av, bv)
	clustered := adversary.Cluster([]adversary.FeatureVector{av, bv}, thresholds.AdversaryClusterThreshold).ClusterCount == 1
	return distance, clustered, nil
}

func controlSummary(results []adversary.ControlResult) []map[string]any {
	out := make([]map[string]any, 0, len(results))
	for _, result := range results {
		out = append(out, map[string]any{
			"name":                  result.Name,
			"cluster_count":         result.ClusterReport.ClusterCount,
			"max_distance":          result.ClusterReport.PairwiseStats.MaxDistance,
			"average_distance":      result.ClusterReport.PairwiseStats.AverageDistance,
			"suspiciously_tight":    result.SuspiciouslyTight,
			"largest_cluster_ratio": result.ClusterReport.LargestClusterRatio,
			"conclusion":            result.Conclusion,
		})
	}
	return out
}

func findControl(results []adversary.ControlResult, name string) *adversary.ControlResult {
	for i := range results {
		if results[i].Name == name {
			return &results[i]
		}
	}
	return nil
}

func gate(name string, passed bool, severity, summary string, details map[string]any, failures []string) GateResult {
	if details == nil {
		details = map[string]any{}
	}
	if len(failures) > 0 {
		details["failures"] = failures
	}
	return GateResult{Name: name, Passed: passed, Severity: severity, Summary: summary, Details: details}
}

type ratioCheck struct {
	Total        int
	UniqueValues int
	Ratio        float64
}

func dominantRatio(values []string) ratioCheck {
	counts := map[string]int{}
	for _, value := range values {
		if value == "" {
			continue
		}
		counts[value]++
	}
	check := ratioCheck{Total: len(values), UniqueValues: len(counts)}
	dominant := 0
	for _, count := range counts {
		if count > dominant {
			dominant = count
		}
	}
	if check.Total > 0 {
		check.Ratio = float64(dominant) / float64(check.Total)
	}
	return check
}

func structuralPairRatio(report diversity.ProfileDiversityReport) float64 {
	if report.PairCount == 0 {
		return 1
	}
	return float64(report.StructurallyDifferentPairs) / float64(report.PairCount)
}

func profileValues(profiles []*ir.Profile, fn func(*ir.Profile) string) []string {
	values := make([]string, 0, len(profiles))
	for _, p := range profiles {
		if p != nil {
			values = append(values, fn(p))
		}
	}
	return values
}

func traceValues(traces [][]ktrace.Event, fn func([]ktrace.Event) string) []string {
	values := make([]string, 0, len(traces))
	for _, events := range traces {
		values = append(values, fn(events))
	}
	return values
}

func firstBytes(profiles []*ir.Profile) []string {
	return profileValues(profiles, func(p *ir.Profile) string {
		if len(p.FirstContact.Steps) == 0 || len(p.FirstContact.Steps[0].WireSymbol) == 0 {
			return ""
		}
		return fmt.Sprintf("%02x", p.FirstContact.Steps[0].WireSymbol[0])
	})
}

func firstFrameLength(events []ktrace.Event) string {
	for _, ev := range events {
		if ev.FrameBytes > 0 {
			return fmt.Sprint(ev.FrameBytes)
		}
	}
	return ""
}

func semanticSequence(events []ktrace.Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.Semantic != "" {
			parts = append(parts, ev.Semantic)
		}
	}
	return strings.Join(parts, ">")
}

func wireSymbolSequence(events []ktrace.Event) string {
	parts := []string{}
	for _, ev := range events {
		if ev.WireSymbol != "" {
			parts = append(parts, "w")
		}
	}
	return strings.Join(parts, ">")
}

func statePathShape(events []ktrace.Event) string {
	indexes := map[string]int{}
	next := 0
	parts := []string{}
	for _, ev := range events {
		if ev.State == "" {
			continue
		}
		if _, ok := indexes[ev.State]; !ok {
			indexes[ev.State] = next
			next++
		}
		parts = append(parts, fmt.Sprintf("s%d", indexes[ev.State]))
	}
	return strings.Join(parts, ">")
}

func repoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd, nil
		}
		parent := filepath.Dir(wd)
		if parent == wd {
			return "", fmt.Errorf("could not find repo root")
		}
		wd = parent
	}
}

func syntheticFixedSignatureProfiles(n int) []*ir.Profile {
	base, _ := compiler.Generate(31)
	profiles := make([]*ir.Profile, 0, n)
	for i := 0; i < n; i++ {
		cp := *base
		cp.ID = fmt.Sprintf("kp_fixed_%d", i)
		cp.Seed = int64(i + 1)
		cp.GenerationHash = fmt.Sprintf("fixed_%d", i)
		profiles = append(profiles, &cp)
	}
	return profiles
}

func syntheticFixedSignatureTraces(n int) [][]ktrace.Event {
	traces := make([][]ktrace.Event, 0, n)
	for i := 0; i < n; i++ {
		traces = append(traces, []ktrace.Event{
			{ProfileID: fmt.Sprintf("kp_%d", i), EventType: "first_contact", State: "same-start", Semantic: "setup", WireSymbol: "same-wire", FrameBytes: 32},
			{ProfileID: fmt.Sprintf("kp_%d", i), EventType: "frame", Semantic: "data", WireSymbol: "same-data", FrameBytes: 64, PaddingBytes: 0},
		})
	}
	return traces
}

func sortGateNames(gates []GateResult) []string {
	names := make([]string, 0, len(gates))
	for _, gate := range gates {
		names = append(names, gate.Name)
	}
	sort.Strings(names)
	return names
}

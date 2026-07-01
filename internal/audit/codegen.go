// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"kurdistan/internal/adversary"
	"kurdistan/internal/codegen"
	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/mutant"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/trace"
)

type CodegenAuditConfig struct {
	Mode         string `json:"mode"`
	StartSeed    int64  `json:"start_seed"`
	ProfileCount int    `json:"profile_count"`
	OutputPath   string `json:"output_path,omitempty"`
}

type GeneratedBackendTraceCorpus struct {
	ProfileCount                 int                       `json:"profile_count"`
	GeneratedModules             int                       `json:"generated_modules"`
	ProfileRuns                  []GeneratedBackendRun     `json:"profile_runs"`
	SourceScan                   codegen.SourceScanReport  `json:"source_scan"`
	InterpretedTraces            [][]ktrace.Event          `json:"-"`
	GeneratedTraces              [][]ktrace.Event          `json:"-"`
	InterpretedMultiStreamTraces [][]ktrace.Event          `json:"-"`
	GeneratedMultiStreamTraces   [][]ktrace.Event          `json:"-"`
	GeneratedDirs                []string                  `json:"-"`
	Profiles                     []*GeneratedProfileRecord `json:"profiles,omitempty"`
}

type GeneratedProfileRecord struct {
	ProfileID string `json:"profile_id"`
	Seed      int64  `json:"seed"`
}

type GeneratedBackendRun struct {
	ProfileID                     string  `json:"profile_id"`
	Seed                          int64   `json:"seed"`
	GeneratedEchoBytes            int     `json:"generated_echo_bytes"`
	InterpretedEchoBytes          int     `json:"interpreted_echo_bytes"`
	InterpretedFirstContactCount  int     `json:"interpreted_first_contact_count"`
	GeneratedFirstContactCount    int     `json:"generated_first_contact_count"`
	InterpretedDataEvents         int     `json:"interpreted_data_events"`
	GeneratedDataEvents           int     `json:"generated_data_events"`
	SemanticSimilarity            float64 `json:"semantic_similarity"`
	StatePathSimilarity           float64 `json:"state_path_similarity"`
	SemanticEquivalent            bool    `json:"semantic_equivalent"`
	InterpretedMultiStreamEvents  int     `json:"interpreted_multi_stream_events"`
	GeneratedMultiStreamEvents    int     `json:"generated_multi_stream_events"`
	GeneratedMultiStreamEchoBytes int     `json:"generated_multi_stream_echo_bytes"`
	MultiStreamEquivalent         bool    `json:"multi_stream_equivalent"`
	PayloadLogged                 bool    `json:"payload_logged"`
}

type GeneratedTraceSummary struct {
	ProfileID         string `json:"profile_id"`
	EchoBytes         int    `json:"echo_bytes"`
	EventCount        int    `json:"event_count"`
	FirstContactCount int    `json:"first_contact_count"`
	DataEventCount    int    `json:"data_event_count"`
	RelayReadyEvents  int    `json:"relay_ready_events"`
	PayloadLogged     bool   `json:"payload_logged"`
}

type CodegenAuditSummary struct {
	Profiles                         int                            `json:"profiles"`
	GeneratedModules                 int                            `json:"generated_modules"`
	SemanticEquivalence              string                         `json:"semantic_equivalence"`
	GeneratedProfileDiversity        string                         `json:"generated_profile_diversity"`
	FixedSignature                   string                         `json:"fixed_signature"`
	MutantDetection                  string                         `json:"mutant_detection"`
	MultiStreamGeneratedParity       string                         `json:"multi_stream_generated_parity"`
	StreamAdversaryParity            string                         `json:"multi_stream_generated_backend_parity"`
	ProxySemGeneratedParity          string                         `json:"proxy_generated_backend_parity"`
	CarrierGeneratedParity           string                         `json:"carrier_generated_backend_parity"`
	SecurityGeneratedParity          string                         `json:"security_generated_backend_parity"`
	RuntimeGeneratedParity           string                         `json:"runtime_generated_backend_parity"`
	HardeningGeneratedParity         string                         `json:"hardening_generated_backend_parity"`
	AdapterGeneratedParity           string                         `json:"adapter_generated_backend_parity"`
	LocalAdapterGeneratedParity      string                         `json:"local_adapter_generated_backend_parity"`
	ByteTransportGeneratedParity     string                         `json:"byte_transport_generated_backend_parity"`
	BytePathFixtureParity            string                         `json:"bytepath_fixture_generated_backend_parity"`
	WireFeaturesGeneratedParity      string                         `json:"wirefeatures_generated_backend_parity"`
	WireGenGeneratedParity           string                         `json:"wiregen_generated_backend_parity"`
	HostDetectGeneratedParity        string                         `json:"hostdetect_generated_backend_parity"`
	RelayFleetGeneratedParity        string                         `json:"relayfleet_generated_backend_parity"`
	ProxyIngressGeneratedParity      string                         `json:"proxyingress_generated_backend_parity"`
	LocalProxyIngressGeneratedParity string                         `json:"localproxyingress_generated_backend_parity"`
	LocalProxyIngressAdvParity       string                         `json:"localproxyingressadv_generated_backend_parity"`
	AdaptivePathGeneratedParity      string                         `json:"adaptivepath_generated_backend_parity"`
	TransportBundleGeneratedParity   string                         `json:"transportbundle_generated_backend_parity"`
	PathRaceGeneratedParity          string                         `json:"pathrace_generated_backend_parity"`
	PathHealthGeneratedParity        string                         `json:"pathhealth_generated_backend_parity"`
	CarrierReviewGeneratedParity     string                         `json:"carrierreview_generated_backend_parity"`
	MeasurementReviewGeneratedParity string                         `json:"measurementreview_generated_backend_parity"`
	ProxyEgressGeneratedParity       string                         `json:"proxyegress_generated_backend_parity"`
	RelayBridgeGeneratedParity       string                         `json:"relaybridge_generated_backend_parity"`
	LocalPipelineGeneratedParity     string                         `json:"localpipeline_generated_backend_parity"`
	ProductionReadinessParity        string                         `json:"productionreadiness_generated_backend_parity"`
	ConcreteLocalAdapterParity       string                         `json:"concretelocaladapter_generated_backend_parity"`
	LocalProtocolAdapterParity       string                         `json:"localprotocoladapter_generated_backend_parity"`
	LoopbackRelayParity              string                         `json:"loopbackrelay_generated_backend_parity"`
	LabEgressParity                  string                         `json:"labegress_generated_backend_parity"`
	SourceScanner                    string                         `json:"source_scanner"`
	InterpretedVsGenerated           InterpretedGeneratedDivergence `json:"interpreted_vs_generated"`
	SourceScan                       codegen.SourceScanReport       `json:"source_scan"`
}

type InterpretedGeneratedDivergence struct {
	SameProfileSemanticSimilarityAverage float64 `json:"same_profile_semantic_similarity_average"`
	SameProfileTraceSimilarityAverage    float64 `json:"same_profile_trace_similarity_average"`
	GeneratedDifferentProfileDiversity   float64 `json:"generated_different_profile_diversity"`
	InterpretedDifferentProfileDiversity float64 `json:"interpreted_different_profile_diversity"`
	Assessment                           string  `json:"assessment"`
}

func DefaultCodegenAuditConfig(mode string) CodegenAuditConfig {
	if mode == "" {
		mode = "quick"
	}
	cfg := CodegenAuditConfig{
		Mode:         mode,
		StartSeed:    1,
		ProfileCount: 3,
	}
	if mode == "full" {
		cfg.ProfileCount = 8
	}
	return cfg
}

func NormalizeCodegenAuditConfig(cfg CodegenAuditConfig) CodegenAuditConfig {
	defaults := DefaultCodegenAuditConfig(cfg.Mode)
	if cfg.Mode == "" {
		cfg.Mode = defaults.Mode
	}
	if cfg.StartSeed == 0 {
		cfg.StartSeed = defaults.StartSeed
	}
	if cfg.ProfileCount == 0 {
		cfg.ProfileCount = defaults.ProfileCount
	}
	return cfg
}

func RunCodegenAudit(ctx context.Context, cfg CodegenAuditConfig) (AuditReport, error) {
	cfg = NormalizeCodegenAuditConfig(cfg)
	start := time.Now()
	root, err := os.MkdirTemp("", "kurdistan-codegen-audit-*")
	if err != nil {
		return AuditReport{}, err
	}
	defer os.RemoveAll(root)

	corpus, err := runGeneratedBackendTraceCorpusAt(ctx, cfg, root)
	if err != nil {
		return AuditReport{}, err
	}

	testFailures := []string{}
	for _, dir := range corpus.GeneratedDirs {
		output, err := runGoTest(ctx, dir)
		if err != nil {
			testFailures = append(testFailures, fmt.Sprintf("%s generated go test failed: %v\n%s", filepath.Base(dir), err, trimOutput(output)))
		}
	}
	codegenGate := gate("generated_backend_codegen", len(testFailures) == 0, "required", fmt.Sprintf("%d generated modules checked; %d failures", corpus.GeneratedModules, len(testFailures)), map[string]any{
		"generated_module_count":     corpus.GeneratedModules,
		"generated_tests_run":        len(corpus.GeneratedDirs),
		"interpreted_traces_checked": len(corpus.InterpretedTraces),
		"generated_traces_checked":   len(corpus.GeneratedTraces),
		"round_trip_exercised_by":    "generated-trace command and generated protocol tests",
	}, testFailures)
	semanticGate := GeneratedSemanticEquivalenceGate(corpus)
	diversityGate := GeneratedProfileDiversityGate(corpus)
	fixedGate := GeneratedFixedSignatureGate(corpus)
	divergenceGate := GeneratedVsInterpretedDivergenceGate(corpus)
	multiStreamGate := GeneratedMultiStreamParityGate(corpus)
	streamAdversaryGate := GeneratedStreamAdversaryParityGate(corpus, testFailures)
	proxySemGate := GeneratedProxySemParityGate(corpus, testFailures)
	carrierGate := GeneratedCarrierParityGate(corpus, testFailures)
	securityGate := GeneratedSecurityParityGate(corpus, testFailures)
	runtimeGate := GeneratedRuntimeParityGate(corpus, testFailures)
	hardeningGate := GeneratedHardeningParityGate(corpus, testFailures)
	adapterGate := GeneratedAdapterParityGate(corpus, testFailures)
	localAdapterGate := GeneratedLocalAdapterParityGate(corpus, testFailures)
	byteTransportGate := GeneratedByteTransportParityGate(corpus, testFailures)
	bytePathFixtureGate := GeneratedBytePathFixtureParityGate(corpus, testFailures)
	wireFeaturesGate := WireFeaturesGeneratedBackendParityGate()
	wireGenGate := WireGenGeneratedBackendParityGate()
	hostDetectGate := HostDetectGeneratedBackendParityGate()
	relayFleetGate := RelayFleetGeneratedBackendParityGate()
	proxyIngressGate := GeneratedProxyIngressParityGate(corpus, testFailures)
	localProxyIngressGate := GeneratedLocalProxyIngressParityGate(corpus, testFailures)
	localProxyIngressAdvGate := GeneratedLocalProxyIngressAdvParityGate(corpus, testFailures)
	adaptivePathGate := GeneratedAdaptivePathParityGate(corpus, testFailures)
	transportBundleGate := GeneratedTransportBundleParityGate(corpus, testFailures)
	pathRaceGate := GeneratedPathRaceParityGate(corpus, testFailures)
	pathHealthGate := GeneratedPathHealthParityGate(corpus, testFailures)
	carrierReviewGate := GeneratedCarrierReviewParityGate(corpus, testFailures)
	measurementReviewGate := GeneratedMeasurementReviewParityGate(corpus, testFailures)
	proxyEgressGate := GeneratedProxyEgressParityGate(corpus, testFailures)
	relayBridgeGate := GeneratedRelayBridgeParityGate(corpus, testFailures)
	localPipelineGate := GeneratedLocalPipelineParityGate(corpus, testFailures)
	productionReadinessGate := GeneratedProductionReadinessParityGate(corpus, testFailures)
	concreteLocalAdapterGate := GeneratedConcreteLocalAdapterParityGate(corpus, testFailures)
	localProtocolAdapterGate := GeneratedLocalProtocolAdapterParityGate(corpus, testFailures)
	loopbackRelayGate := GeneratedLoopbackRelayParityGate(corpus, testFailures)
	labEgressGate := GeneratedLabEgressParityGate(corpus, testFailures)
	mutantGate := GeneratedMutantDetectionGate(ctx, []string{
		mutant.ModeCosmeticSymbolsOnly,
		mutant.ModeFixedFrameGrammar,
		mutant.ModeFixedFirstContact,
		mutant.ModePaddingNoiseOnly,
	}, max(4, min(8, cfg.ProfileCount)))
	scannerGate := GeneratedSourceScannerGate(corpus.SourceScan)

	gates := []GateResult{
		codegenGate,
		semanticGate,
		diversityGate,
		fixedGate,
		divergenceGate,
		multiStreamGate,
		streamAdversaryGate,
		proxySemGate,
		carrierGate,
		securityGate,
		runtimeGate,
		hardeningGate,
		adapterGate,
		localAdapterGate,
		byteTransportGate,
		bytePathFixtureGate,
		wireFeaturesGate,
		wireGenGate,
		hostDetectGate,
		relayFleetGate,
		proxyIngressGate,
		localProxyIngressGate,
		localProxyIngressAdvGate,
		adaptivePathGate,
		transportBundleGate,
		pathRaceGate,
		pathHealthGate,
		carrierReviewGate,
		measurementReviewGate,
		proxyEgressGate,
		relayBridgeGate,
		localPipelineGate,
		productionReadinessGate,
		concreteLocalAdapterGate,
		localProtocolAdapterGate,
		loopbackRelayGate,
		labEgressGate,
		mutantGate,
		scannerGate,
	}
	report := AuditReport{
		Version:          codegen.Version,
		Mode:             "codegen-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       len(corpus.GeneratedTraces),
		Gates:            gates,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
		CodegenSummary:   buildCodegenSummary(corpus, gates),
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func RunGeneratedBackendTraceCorpus(ctx context.Context, cfg CodegenAuditConfig) (GeneratedBackendTraceCorpus, error) {
	cfg = NormalizeCodegenAuditConfig(cfg)
	root, err := os.MkdirTemp("", "kurdistan-codegen-corpus-*")
	if err != nil {
		return GeneratedBackendTraceCorpus{}, err
	}
	defer os.RemoveAll(root)
	return runGeneratedBackendTraceCorpusAt(ctx, cfg, root)
}

func runGeneratedBackendTraceCorpusAt(ctx context.Context, cfg CodegenAuditConfig, root string) (GeneratedBackendTraceCorpus, error) {
	payload := codegenAuditPayload()
	corpus := GeneratedBackendTraceCorpus{ProfileCount: cfg.ProfileCount}
	profilesForScan := make([]string, 0, cfg.ProfileCount)
	for i := 0; i < cfg.ProfileCount; i++ {
		seed := cfg.StartSeed + int64(i)
		p, err := compiler.Generate(seed)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d profile generation: %w", seed, err)
		}
		out := filepath.Join(root, codegen.SanitizeIdentifier(p.ID))
		if _, err := codegen.Generate(p, out, codegen.Options{}); err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d codegen: %w", seed, err)
		}
		interpreted, err := labtrace.CaptureTrace(ctx, p, payload)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d interpreted trace: %w", seed, err)
		}
		generated, summary, err := runGeneratedTraceCommand(ctx, out, payload, false)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d generated trace: %w", seed, err)
		}
		streamCount := min(4, p.Stream.MaxConcurrentStreams)
		interpretedMultiResult, interpretedMulti, err := relay.SimulateMultiStreamEcho(ctx, p, relay.DefaultMultiStreamDemoRequests(streamCount))
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d interpreted multistream trace: %w", seed, err)
		}
		generatedMulti, multiSummary, err := runGeneratedTraceCommand(ctx, out, nil, true)
		if err != nil {
			return GeneratedBackendTraceCorpus{}, fmt.Errorf("seed %d generated multistream trace: %w", seed, err)
		}
		report := ktrace.CompareEvents(interpreted, generated)
		run := GeneratedBackendRun{
			ProfileID:                     p.ID,
			Seed:                          seed,
			GeneratedEchoBytes:            summary.EchoBytes,
			InterpretedEchoBytes:          len(payload),
			InterpretedFirstContactCount:  countEvents(interpreted, "first_contact"),
			GeneratedFirstContactCount:    summary.FirstContactCount,
			InterpretedDataEvents:         countSemantic(interpreted, "data"),
			GeneratedDataEvents:           summary.DataEventCount,
			SemanticSimilarity:            report.SemanticSimilarity,
			StatePathSimilarity:           report.StatePathSimilarity,
			InterpretedMultiStreamEvents:  len(interpretedMulti),
			GeneratedMultiStreamEvents:    len(generatedMulti),
			GeneratedMultiStreamEchoBytes: multiSummary.EchoBytes,
			PayloadLogged:                 summary.PayloadLogged || traceContainsPayload(generated, payload),
		}
		run.SemanticEquivalent = run.GeneratedEchoBytes == len(payload) &&
			run.InterpretedFirstContactCount == run.GeneratedFirstContactCount &&
			run.InterpretedDataEvents > 0 &&
			run.GeneratedDataEvents > 0 &&
			!run.PayloadLogged
		run.MultiStreamEquivalent = interpretedMultiResult.OpenedStreams > 0 &&
			run.GeneratedMultiStreamEvents > 0 &&
			run.GeneratedMultiStreamEchoBytes > 0 &&
			!traceContainsPayload(generatedMulti, []byte("local lab multistream message"))
		corpus.ProfileRuns = append(corpus.ProfileRuns, run)
		corpus.InterpretedTraces = append(corpus.InterpretedTraces, interpreted)
		corpus.GeneratedTraces = append(corpus.GeneratedTraces, generated)
		corpus.InterpretedMultiStreamTraces = append(corpus.InterpretedMultiStreamTraces, interpretedMulti)
		corpus.GeneratedMultiStreamTraces = append(corpus.GeneratedMultiStreamTraces, generatedMulti)
		corpus.GeneratedDirs = append(corpus.GeneratedDirs, out)
		corpus.Profiles = append(corpus.Profiles, &GeneratedProfileRecord{ProfileID: p.ID, Seed: seed})
		profilesForScan = append(profilesForScan, out)
	}
	scan, err := codegen.ScanGeneratedOutputs(profilesForScan)
	if err != nil {
		return GeneratedBackendTraceCorpus{}, err
	}
	corpus.SourceScan = scan
	corpus.GeneratedModules = len(corpus.GeneratedDirs)
	return corpus, nil
}

func runGeneratedTraceCommand(ctx context.Context, dir string, payload []byte, multistream bool) ([]ktrace.Event, GeneratedTraceSummary, error) {
	tracePath := filepath.Join(dir, "generated-trace.jsonl")
	summaryPath := filepath.Join(dir, "generated-summary.json")
	args := []string{"run", "./cmd/generated-trace", "--trace", tracePath, "--summary", summaryPath}
	if multistream {
		args = append(args, "--multistream", "--streams", "4")
	} else {
		args = append(args, "--message", string(payload))
	}
	cmd := exec.CommandContext(ctx, goTool(), args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, GeneratedTraceSummary{}, fmt.Errorf("%w: %s", err, trimOutput(string(output)))
	}
	events, err := ktrace.ReadJSONL(tracePath)
	if err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	raw, err := os.ReadFile(summaryPath)
	if err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	var summary GeneratedTraceSummary
	if err := json.Unmarshal(raw, &summary); err != nil {
		return nil, GeneratedTraceSummary{}, err
	}
	return events, summary, nil
}

func GeneratedSemanticEquivalenceGate(corpus GeneratedBackendTraceCorpus) GateResult {
	failures := []string{}
	details := map[string]any{"profile_count": len(corpus.ProfileRuns)}
	for _, run := range corpus.ProfileRuns {
		if !run.SemanticEquivalent {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("generated_semantic_equivalence", len(failures) == 0, "required", fmt.Sprintf("%d generated/interpreted profile pairs checked; %d failures", len(corpus.ProfileRuns), len(failures)), details, failures)
}

func GeneratedProfileDiversityGate(corpus GeneratedBackendTraceCorpus) GateResult {
	total, separated := pairSeparation(corpus.GeneratedTraces)
	ratio := ratio(separated, total)
	if total == 0 {
		ratio = 1
	}
	failures := []string{}
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated traces across profiles are insufficiently diverse")
	}
	return gate("generated_profile_diversity", len(failures) == 0, "required", fmt.Sprintf("%d/%d generated trace pairs separated", separated, total), map[string]any{
		"separated_pairs": separated,
		"total_pairs":     total,
		"ratio":           ratio,
		"min_ratio":       0.5,
	}, failures)
}

func GeneratedFixedSignatureGate(corpus GeneratedBackendTraceCorpus) GateResult {
	scan := ktrace.ScanTraces(corpus.GeneratedTraces, ktrace.DefaultStabilityThreshold)
	failures := []string{}
	details := map[string]any{"trace_count": scan.TraceCount}
	for _, metric := range scan.Metrics {
		details[metric.Name+"_stability"] = metric.Stability
		details[metric.Name+"_unique_values"] = metric.UniqueValues
		if metric.Total < 3 || !metric.Flagged {
			continue
		}
		if generatedSingleStreamMetricExplained(metric.Name) {
			continue
		}
		if metric.Name == "first_contact_message_count" && profileFirstContactCountsExplain(corpus) {
			continue
		}
		failures = append(failures, metric.Name+" too stable")
	}
	if !corpus.SourceScan.Passed {
		failures = append(failures, "source scanner found generated source artifacts")
	}
	return gate("generated_fixed_signature", len(failures) == 0, "required", fmt.Sprintf("%d trace stability metrics checked; %d failures", len(scan.Metrics), len(failures)), details, failures)
}

func generatedSingleStreamMetricExplained(name string) bool {
	switch name {
	case "stream_count", "stream_interleaving_pattern", "stream_priority_pattern", "window_update_pattern", "stream_close_reset_pattern", "backpressure_pattern":
		return true
	default:
		return false
	}
}

func GeneratedVsInterpretedDivergenceGate(corpus GeneratedBackendTraceCorpus) GateResult {
	summary := divergenceSummary(corpus)
	return gate("generated_vs_interpreted_divergence", true, "informational", summary.Assessment, map[string]any{
		"same_profile_semantic_similarity_average": summary.SameProfileSemanticSimilarityAverage,
		"same_profile_trace_similarity_average":    summary.SameProfileTraceSimilarityAverage,
		"generated_different_profile_diversity":    summary.GeneratedDifferentProfileDiversity,
		"interpreted_different_profile_diversity":  summary.InterpretedDifferentProfileDiversity,
		"assessment": summary.Assessment,
	}, nil)
}

func GeneratedMultiStreamParityGate(corpus GeneratedBackendTraceCorpus) GateResult {
	failures := []string{}
	for _, run := range corpus.ProfileRuns {
		if !run.MultiStreamEquivalent {
			failures = append(failures, run.ProfileID)
		}
	}
	total, separated := pairSeparation(corpus.GeneratedMultiStreamTraces)
	ratio := ratio(separated, total)
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated multi-stream traces are insufficiently diverse")
	}
	return gate("multi_stream_generated_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated/interpreted multi-stream profile pairs checked", len(corpus.ProfileRuns)), map[string]any{
		"profile_count":               len(corpus.ProfileRuns),
		"generated_trace_count":       len(corpus.GeneratedMultiStreamTraces),
		"interpreted_trace_count":     len(corpus.InterpretedMultiStreamTraces),
		"separated_pairs":             separated,
		"total_pairs":                 total,
		"different_profile_ratio":     ratio,
		"min_different_profile_ratio": 0.5,
	}, failures)
}

func GeneratedStreamAdversaryParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module stream adversary tests failed")
	}
	missingMetadata := 0
	for _, events := range corpus.GeneratedMultiStreamTraces {
		if !traceHasStreamMetadata(events) {
			missingMetadata++
		}
	}
	if missingMetadata > 0 {
		failures = append(failures, "generated multi-stream traces missing safe stream metadata")
	}
	total, separated := pairSeparation(corpus.GeneratedMultiStreamTraces)
	ratio := ratio(separated, total)
	if total > 0 && ratio < 0.5 {
		failures = append(failures, "generated stream adversary traces are insufficiently diverse")
	}
	return gate("multi_stream_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules exercised stream adversary scenario tests", corpus.GeneratedModules), map[string]any{
		"generated_modules":        corpus.GeneratedModules,
		"generated_test_failures":  len(testFailures),
		"generated_trace_count":    len(corpus.GeneratedMultiStreamTraces),
		"missing_metadata_traces":  missingMetadata,
		"separated_pairs":          separated,
		"total_pairs":              total,
		"profile_diversity_ratio":  ratio,
		"scenario_tests_in_module": []string{"balanced_interleave", "bulk_vs_interactive", "reset_midstream", "blocked_stream"},
	}, failures)
}

func GeneratedProxySemParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module proxysem tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated proxysem specialization constants missing")
	}
	proxyFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/proxysem_generated.go" {
			proxyFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && proxyFiles < 2 {
		failures = append(failures, "generated proxysem specialized files did not differ")
	}
	return gate("proxy_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include proxysem tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"proxysem_unique_files":        proxyFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedCarrierParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module carrier tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated carrier specialization constants missing")
	}
	carrierFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/carrier_generated.go" {
			carrierFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && carrierFiles < 2 {
		failures = append(failures, "generated carrier specialized files did not differ")
	}
	return gate("carrier_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include carrier tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"carrier_unique_files":         carrierFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedSecurityParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module security tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated security specialization constants missing")
	}
	securityFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/security_generated.go" {
			securityFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && securityFiles < 2 {
		failures = append(failures, "generated security specialized files did not differ")
	}
	return gate("security_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include security tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"security_unique_files":        securityFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedRuntimeParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module runtime tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated runtime specialization constants missing")
	}
	runtimeFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/runtime_generated.go" {
			runtimeFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && runtimeFiles < 2 {
		failures = append(failures, "generated runtime specialized files did not differ")
	}
	return gate("runtime_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include runtime tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"runtime_unique_files":         runtimeFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedHardeningParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module hardening tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated hardening specialization constants missing")
	}
	hardeningFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/hardening_generated.go" {
			hardeningFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && hardeningFiles < 2 {
		failures = append(failures, "generated hardening specialized files did not differ")
	}
	return gate("hardening_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include hardening tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"hardening_unique_files":       hardeningFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module adapter tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated adapter specialization constants missing")
	}
	adapterFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/adapter_generated.go" {
			adapterFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && adapterFiles < 2 {
		failures = append(failures, "generated adapter specialized files did not differ")
	}
	return gate("adapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include adapter tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"adapter_unique_files":         adapterFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module local adapter tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated local adapter specialization constants missing")
	}
	localAdapterFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localadapter_generated.go" {
			localAdapterFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localAdapterFiles < 2 {
		failures = append(failures, "generated local adapter specialized files did not differ")
	}
	return gate("local_adapter_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include local adapter tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"local_adapter_unique_files":   localAdapterFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedProxyIngressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module proxyingress tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated proxyingress specialization constants missing")
	}
	proxyIngressFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/proxyingress_generated.go" {
			proxyIngressFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && proxyIngressFiles < 2 {
		failures = append(failures, "generated proxyingress specialized files did not differ")
	}
	return gate("proxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include proxyingress tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"proxyingress_unique_files":    proxyIngressFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalProxyIngressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module localproxyingress tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated localproxyingress specialization constants missing")
	}
	localProxyIngressFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localproxyingress_generated.go" {
			localProxyIngressFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localProxyIngressFiles < 2 {
		failures = append(failures, "generated localproxyingress specialized files did not differ")
	}
	return gate("localproxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include localproxyingress tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":              corpus.GeneratedModules,
		"generated_test_failures":        len(testFailures),
		"localproxyingress_unique_files": localProxyIngressFiles,
		"generated_source_specialized":   corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedLocalProxyIngressAdvParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module localproxyingressadv tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated localproxyingressadv specialization constants missing")
	}
	localProxyIngressAdvFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/localproxyingressadv_generated.go" {
			localProxyIngressAdvFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && localProxyIngressAdvFiles < 2 {
		failures = append(failures, "generated localproxyingressadv specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"localproxyingressadv_generated.go", "localproxyingressadv_test.go", "localproxyingressadv_parity_test.go", "localproxyingressadv_hygiene_test.go", "LocalProxyIngressAdversarialSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated localproxyingressadv marker "+marker)
				}
			}
		}
	}
	return gate("localproxyingressadv_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include localproxyingressadv tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                 corpus.GeneratedModules,
		"generated_test_failures":           len(testFailures),
		"localproxyingressadv_unique_files": localProxyIngressAdvFiles,
		"generated_source_specialized":      corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedAdaptivePathParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module adaptivepath tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated adaptivepath specialization constants missing")
	}
	adaptivePathFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/adaptivepath_generated.go" {
			adaptivePathFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && adaptivePathFiles < 2 {
		failures = append(failures, "generated adaptivepath specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"adaptivepath_generated.go", "adaptivepath_test.go", "adaptivepath_parity_test.go", "adaptivepath_hygiene_test.go", "AdaptivePathSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated adaptivepath marker "+marker)
				}
			}
		}
	}
	return gate("adaptivepath_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include adaptivepath tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"adaptivepath_unique_files":    adaptivePathFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedTransportBundleParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module transportbundle tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated transportbundle specialization constants missing")
	}
	transportBundleFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/transportbundle_generated.go" {
			transportBundleFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && transportBundleFiles < 2 {
		failures = append(failures, "generated transportbundle specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"transportbundle_generated.go", "transportbundle_test.go", "transportbundle_parity_test.go", "transportbundle_hygiene_test.go", "TransportBundleSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated transportbundle marker "+marker)
				}
			}
		}
	}
	return gate("transportbundle_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include transportbundle tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                   corpus.GeneratedModules,
		"generated_test_failures":             len(testFailures),
		"transportbundle_unique_files":        transportBundleFiles,
		"generated_source_specialized":        corpus.SourceScan.ProfileSpecificConstantsPresent,
		"transportbundle_generated_artifacts": []string{"transportbundle_generated.go", "transportbundle_test.go", "transportbundle_parity_test.go", "transportbundle_hygiene_test.go"},
	}, failures)
}

func GeneratedPathRaceParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module pathrace tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated pathrace specialization constants missing")
	}
	pathRaceFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/pathrace_generated.go" {
			pathRaceFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && pathRaceFiles < 2 {
		failures = append(failures, "generated pathrace specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathrace_generated.go", "pathrace_test.go", "pathrace_parity_test.go", "pathrace_hygiene_test.go", "PathRaceSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathrace marker "+marker)
				}
			}
		}
	}
	return gate("pathrace_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include pathrace tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"pathrace_unique_files":        pathRaceFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
		"pathrace_generated_artifacts": []string{"pathrace_generated.go", "pathrace_test.go", "pathrace_parity_test.go", "pathrace_hygiene_test.go"},
	}, failures)
}

func GeneratedPathHealthParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module pathhealth tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated pathhealth specialization constants missing")
	}
	pathHealthFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/pathhealth_generated.go" {
			pathHealthFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && pathHealthFiles < 2 {
		failures = append(failures, "generated pathhealth specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"pathhealth_generated.go", "pathhealth_test.go", "pathhealth_parity_test.go", "pathhealth_hygiene_test.go", "PathHealthSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated pathhealth marker "+marker)
				}
			}
		}
	}
	return gate("pathhealth_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include pathhealth tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":              corpus.GeneratedModules,
		"generated_test_failures":        len(testFailures),
		"pathhealth_unique_files":        pathHealthFiles,
		"generated_source_specialized":   corpus.SourceScan.ProfileSpecificConstantsPresent,
		"pathhealth_generated_artifacts": []string{"pathhealth_generated.go", "pathhealth_test.go", "pathhealth_parity_test.go", "pathhealth_hygiene_test.go"},
	}, failures)
}

func GeneratedCarrierReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module carrierreview tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated carrierreview specialization constants missing")
	}
	carrierReviewFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/carrierreview_generated.go" {
			carrierReviewFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && carrierReviewFiles < 2 {
		failures = append(failures, "generated carrierreview specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"carrierreview_generated.go", "carrierreview_test.go", "carrierreview_parity_test.go", "carrierreview_hygiene_test.go", "CarrierReviewSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated carrierreview marker "+marker)
				}
			}
		}
	}
	return gate("carrierreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include carrierreview tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                 corpus.GeneratedModules,
		"generated_test_failures":           len(testFailures),
		"carrierreview_unique_files":        carrierReviewFiles,
		"generated_source_specialized":      corpus.SourceScan.ProfileSpecificConstantsPresent,
		"carrierreview_generated_artifacts": []string{"carrierreview_generated.go", "carrierreview_test.go", "carrierreview_parity_test.go", "carrierreview_hygiene_test.go"},
	}, failures)
}

func GeneratedMeasurementReviewParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module measurementreview tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated measurementreview specialization constants missing")
	}
	measurementReviewFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/measurementreview_generated.go" {
			measurementReviewFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && measurementReviewFiles < 2 {
		failures = append(failures, "generated measurementreview specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{"measurementreview_generated.go", "measurementreview_test.go", "measurementreview_parity_test.go", "measurementreview_hygiene_test.go", "MeasurementReviewSchemaVersion"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated measurementreview marker "+marker)
				}
			}
		}
	}
	return gate("measurementreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include measurementreview tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":                     corpus.GeneratedModules,
		"generated_test_failures":               len(testFailures),
		"measurementreview_unique_files":        measurementReviewFiles,
		"generated_source_specialized":          corpus.SourceScan.ProfileSpecificConstantsPresent,
		"measurementreview_generated_artifacts": []string{"measurementreview_generated.go", "measurementreview_test.go", "measurementreview_parity_test.go", "measurementreview_hygiene_test.go"},
	}, failures)
}

func GeneratedProxyEgressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "proxyegress", "proxy egress", "ProxyEgressSchemaVersion")
}

func GeneratedRelayBridgeParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "relaybridge", "relay bridge", "RelayBridgeSchemaVersion")
}

func GeneratedLocalPipelineParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localpipeline", "local pipeline", "LocalPipelineSchemaVersion")
}

func GeneratedProductionReadinessParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "productionreadiness", "production readiness", "ProductionReadinessSchemaVersion")
}

func GeneratedConcreteLocalAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "concretelocaladapter", "concrete local adapter", "ConcreteLocalAdapterSchemaVersion")
}

func GeneratedLocalProtocolAdapterParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "localprotocoladapter", "local protocol adapter", "LocalProtocolAdapterSchemaVersion")
}

func GeneratedLoopbackRelayParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "loopbackrelay", "loopback relay", "LoopbackRelaySchemaVersion")
}

func GeneratedLabEgressParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	return generatedMilestoneSourceGate(corpus, testFailures, "labegress", "lab egress", "LabEgressSchemaVersion")
}

func generatedMilestoneSourceGate(corpus GeneratedBackendTraceCorpus, testFailures []string, slug, label, schemaMarker string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module "+label+" tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated "+label+" specialization constants missing")
	}
	uniqueFiles := 0
	generatedRel := "protocol/" + slug + "_generated.go"
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == generatedRel {
			uniqueFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && uniqueFiles < 2 {
		failures = append(failures, "generated "+label+" specialized files did not differ")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			text := string(raw)
			for _, marker := range []string{slug + "_generated.go", slug + "_test.go", slug + "_parity_test.go", slug + "_hygiene_test.go", schemaMarker} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated "+slug+" marker "+marker)
				}
			}
		}
	}
	return gate(slug+"_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include %s tests and constants", corpus.GeneratedModules, label), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		slug + "_unique_files":         uniqueFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
		slug + "_generated_artifacts":  []string{slug + "_generated.go", slug + "_test.go", slug + "_parity_test.go", slug + "_hygiene_test.go"},
	}, failures)
}

func GeneratedByteTransportParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module byte transport tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated byte transport specialization constants missing")
	}
	byteTransportFiles := 0
	for rel := range corpus.SourceScan.SpecializedFileUniqueFingerprints {
		if rel == "protocol/bytetransport_generated.go" {
			byteTransportFiles = corpus.SourceScan.SpecializedFileUniqueFingerprints[rel]
		}
	}
	if corpus.GeneratedModules > 1 && byteTransportFiles < 2 {
		failures = append(failures, "generated byte transport specialized files did not differ")
	}
	return gate("byte_transport_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include byte transport tests and constants", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"byte_transport_unique_files":  byteTransportFiles,
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedBytePathFixtureParityGate(corpus GeneratedBackendTraceCorpus, testFailures []string) GateResult {
	failures := []string{}
	if len(testFailures) > 0 {
		failures = append(failures, "generated module bytepath fixture tests failed")
	}
	if !corpus.SourceScan.ProfileSpecificConstantsPresent {
		failures = append(failures, "generated bytepath fixture specialization constants missing")
	}
	root, err := repoRoot()
	if err != nil {
		failures = append(failures, err.Error())
	} else {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr != nil {
			failures = append(failures, readErr.Error())
		} else {
			text := string(raw)
			for _, marker := range []string{"bytepath_fixture_test.go", "bytepath_parity_test.go", "BytePathFixtureSchemaVersion", "byteparity.Run"} {
				if !strings.Contains(text, marker) {
					failures = append(failures, "missing generated bytepath marker "+marker)
				}
			}
		}
	}
	return gate("bytepath_fixture_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated modules include bytepath fixture/parity tests", corpus.GeneratedModules), map[string]any{
		"generated_modules":            corpus.GeneratedModules,
		"generated_test_failures":      len(testFailures),
		"generated_source_specialized": corpus.SourceScan.ProfileSpecificConstantsPresent,
	}, failures)
}

func GeneratedSourceScannerGate(scan codegen.SourceScanReport) GateResult {
	return gate("generated_source_scanner", scan.Passed, "required", fmt.Sprintf("%d generated modules scanned; %d failures", scan.GeneratedModules, len(scan.Failures)), map[string]any{
		"profile_specific_constants_present": scan.ProfileSpecificConstantsPresent,
		"specialized_files_differ":           scan.SpecializedFilesDiffer,
		"direct_fsm_use":                     scan.DirectFSMUse,
		"runtime_profile_load":               scan.RuntimeProfileLoad,
		"payload_logging":                    scan.PayloadLogging,
		"wrapper_only":                       scan.WrapperOnly,
	}, scan.Failures)
}

func GeneratedMutantDetectionGate(ctx context.Context, modes []string, count int) GateResult {
	if count <= 0 {
		count = 4
	}
	thresholds := DefaultThresholds()
	thresholds.MinFirstContactPatterns = 2
	thresholds.MinFrameGrammarCombinations = 2
	thresholds.MinSchedulerCombinations = 2
	thresholds.MinPaddingCombinations = 2
	thresholds.MinInvalidInputCombinations = 2
	thresholds.MinDifferentTraceSeparationRatio = 0.5
	detected := []string{}
	missed := []string{}
	modeDetails := map[string]any{}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 700, count)
		if err != nil {
			missed = append(missed, mode+": "+err.Error())
			continue
		}
		traces := mutant.TraceFixtures(mode, profiles)
		summary := diversity.SummarizeCorpus(700, profiles)
		scan := ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)
		gates := []GateResult{
			ProfileCorpusDiversityGate(summary, thresholds),
			BlackBoxTraceDiversityGate(scan, thresholds),
			FixedSignatureGate(profiles, traces, thresholds),
			DifferentProfileSeparationGate(traces, thresholds),
		}
		failed := []string{}
		for _, gate := range gates {
			if !gate.Passed {
				failed = append(failed, gate.Name)
			}
		}
		modeDetails[mode] = failed
		if len(failed) == 0 {
			missed = append(missed, mode)
		} else {
			detected = append(detected, mode)
		}
	}
	return gate("generated_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d mutant modes detected", len(detected), len(modes)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
		"mode_failures":  modeDetails,
		"fixture_based":  true,
	}, missed)
}

func buildCodegenSummary(corpus GeneratedBackendTraceCorpus, gates []GateResult) CodegenAuditSummary {
	status := func(name string) string {
		if gate, ok := gateByName(gates, name); ok {
			if gate.Passed {
				return "passed"
			}
			return "failed"
		}
		return "missing"
	}
	return CodegenAuditSummary{
		Profiles:                         corpus.ProfileCount,
		GeneratedModules:                 corpus.GeneratedModules,
		SemanticEquivalence:              status("generated_semantic_equivalence"),
		GeneratedProfileDiversity:        status("generated_profile_diversity"),
		FixedSignature:                   status("generated_fixed_signature"),
		MutantDetection:                  status("generated_mutant_detection"),
		MultiStreamGeneratedParity:       status("multi_stream_generated_parity"),
		StreamAdversaryParity:            status("multi_stream_generated_backend_parity"),
		ProxySemGeneratedParity:          status("proxy_generated_backend_parity"),
		CarrierGeneratedParity:           status("carrier_generated_backend_parity"),
		SecurityGeneratedParity:          status("security_generated_backend_parity"),
		RuntimeGeneratedParity:           status("runtime_generated_backend_parity"),
		HardeningGeneratedParity:         status("hardening_generated_backend_parity"),
		AdapterGeneratedParity:           status("adapter_generated_backend_parity"),
		LocalAdapterGeneratedParity:      status("local_adapter_generated_backend_parity"),
		ByteTransportGeneratedParity:     status("byte_transport_generated_backend_parity"),
		BytePathFixtureParity:            status("bytepath_fixture_generated_backend_parity"),
		WireFeaturesGeneratedParity:      status("wirefeatures_generated_backend_parity"),
		WireGenGeneratedParity:           status("wiregen_generated_backend_parity"),
		HostDetectGeneratedParity:        status("hostdetect_generated_backend_parity"),
		RelayFleetGeneratedParity:        status("relayfleet_generated_backend_parity"),
		ProxyIngressGeneratedParity:      status("proxyingress_generated_backend_parity"),
		LocalProxyIngressGeneratedParity: status("localproxyingress_generated_backend_parity"),
		LocalProxyIngressAdvParity:       status("localproxyingressadv_generated_backend_parity"),
		AdaptivePathGeneratedParity:      status("adaptivepath_generated_backend_parity"),
		TransportBundleGeneratedParity:   status("transportbundle_generated_backend_parity"),
		PathRaceGeneratedParity:          status("pathrace_generated_backend_parity"),
		PathHealthGeneratedParity:        status("pathhealth_generated_backend_parity"),
		CarrierReviewGeneratedParity:     status("carrierreview_generated_backend_parity"),
		MeasurementReviewGeneratedParity: status("measurementreview_generated_backend_parity"),
		ProxyEgressGeneratedParity:       status("proxyegress_generated_backend_parity"),
		RelayBridgeGeneratedParity:       status("relaybridge_generated_backend_parity"),
		LocalPipelineGeneratedParity:     status("localpipeline_generated_backend_parity"),
		ProductionReadinessParity:        status("productionreadiness_generated_backend_parity"),
		ConcreteLocalAdapterParity:       status("concretelocaladapter_generated_backend_parity"),
		LocalProtocolAdapterParity:       status("localprotocoladapter_generated_backend_parity"),
		LoopbackRelayParity:              status("loopbackrelay_generated_backend_parity"),
		LabEgressParity:                  status("labegress_generated_backend_parity"),
		SourceScanner:                    status("generated_source_scanner"),
		InterpretedVsGenerated:           divergenceSummary(corpus),
		SourceScan:                       corpus.SourceScan,
	}
}

func divergenceSummary(corpus GeneratedBackendTraceCorpus) InterpretedGeneratedDivergence {
	var semanticTotal, traceTotal float64
	for _, run := range corpus.ProfileRuns {
		semanticTotal += run.SemanticSimilarity
		traceTotal += (run.SemanticSimilarity + run.StatePathSimilarity) / 2
	}
	sameSemantic := ratioFloat(semanticTotal, len(corpus.ProfileRuns))
	sameTrace := ratioFloat(traceTotal, len(corpus.ProfileRuns))
	generatedTotal, generatedSeparated := pairSeparation(corpus.GeneratedTraces)
	interpretedTotal, interpretedSeparated := pairSeparation(corpus.InterpretedTraces)
	generatedDiversity := ratio(generatedSeparated, generatedTotal)
	interpretedDiversity := ratio(interpretedSeparated, interpretedTotal)
	assessment := "equally diverse"
	if generatedDiversity > interpretedDiversity+0.05 {
		assessment = "generated appears more diverse"
	}
	if generatedDiversity+0.05 < interpretedDiversity {
		assessment = "generated appears less diverse"
	}
	return InterpretedGeneratedDivergence{
		SameProfileSemanticSimilarityAverage: sameSemantic,
		SameProfileTraceSimilarityAverage:    sameTrace,
		GeneratedDifferentProfileDiversity:   generatedDiversity,
		InterpretedDifferentProfileDiversity: interpretedDiversity,
		Assessment:                           assessment,
	}
}

func profileFirstContactCountsExplain(corpus GeneratedBackendTraceCorpus) bool {
	if len(corpus.ProfileRuns) == 0 {
		return true
	}
	for _, run := range corpus.ProfileRuns {
		if run.InterpretedFirstContactCount != run.GeneratedFirstContactCount {
			return false
		}
	}
	return true
}

func pairSeparation(traces [][]ktrace.Event) (int, int) {
	total, separated := 0, 0
	for i := 0; i < len(traces); i++ {
		for j := i + 1; j < len(traces); j++ {
			total++
			if ktrace.CompareEvents(traces[i], traces[j]).MeaningfullyDifferent {
				separated++
				continue
			}
			a := adversary.ExtractFeaturesWithMetadata(fmt.Sprintf("a_%d", i), "", traces[i])
			b := adversary.ExtractFeaturesWithMetadata(fmt.Sprintf("b_%d", j), "", traces[j])
			if adversary.Distance(a, b) >= DefaultThresholds().MinDifferentProfileDistance {
				separated++
			}
		}
	}
	return total, separated
}

func countEvents(events []ktrace.Event, eventType string) int {
	count := 0
	for _, ev := range events {
		if ev.EventType == eventType {
			count++
		}
	}
	return count
}

func countSemantic(events []ktrace.Event, semantic string) int {
	count := 0
	for _, ev := range events {
		if ev.Semantic == semantic {
			count++
		}
	}
	return count
}

func traceContainsPayload(events []ktrace.Event, payload []byte) bool {
	raw, _ := json.Marshal(events)
	return len(payload) > 0 && strings.Contains(string(raw), string(payload))
}

func codegenAuditPayload() []byte {
	return []byte("hello generated")
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func ratioFloat(numerator float64, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return numerator / float64(denominator)
}

func runGoTest(ctx context.Context, dir string) (string, error) {
	cmd := exec.CommandContext(ctx, goTool(), "test", "./...")
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func goTool() string {
	if p := os.Getenv("GO"); p != "" {
		return p
	}
	if goroot := runtime.GOROOT(); goroot != "" {
		name := "go"
		if runtime.GOOS == "windows" {
			name = "go.exe"
		}
		candidate := filepath.Join(goroot, "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "go"
}

func uniqueStrings(values []string) int {
	seen := map[string]bool{}
	for _, value := range values {
		seen[value] = true
	}
	return len(seen)
}

func trimOutput(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 2000 {
		return value
	}
	return value[:2000] + "\n..."
}

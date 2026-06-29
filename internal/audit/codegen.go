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
	Profiles                     int                            `json:"profiles"`
	GeneratedModules             int                            `json:"generated_modules"`
	SemanticEquivalence          string                         `json:"semantic_equivalence"`
	GeneratedProfileDiversity    string                         `json:"generated_profile_diversity"`
	FixedSignature               string                         `json:"fixed_signature"`
	MutantDetection              string                         `json:"mutant_detection"`
	MultiStreamGeneratedParity   string                         `json:"multi_stream_generated_parity"`
	StreamAdversaryParity        string                         `json:"multi_stream_generated_backend_parity"`
	ProxySemGeneratedParity      string                         `json:"proxy_generated_backend_parity"`
	CarrierGeneratedParity       string                         `json:"carrier_generated_backend_parity"`
	SecurityGeneratedParity      string                         `json:"security_generated_backend_parity"`
	RuntimeGeneratedParity       string                         `json:"runtime_generated_backend_parity"`
	HardeningGeneratedParity     string                         `json:"hardening_generated_backend_parity"`
	AdapterGeneratedParity       string                         `json:"adapter_generated_backend_parity"`
	LocalAdapterGeneratedParity  string                         `json:"local_adapter_generated_backend_parity"`
	ByteTransportGeneratedParity string                         `json:"byte_transport_generated_backend_parity"`
	SourceScanner                string                         `json:"source_scanner"`
	InterpretedVsGenerated       InterpretedGeneratedDivergence `json:"interpreted_vs_generated"`
	SourceScan                   codegen.SourceScanReport       `json:"source_scan"`
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
		Profiles:                     corpus.ProfileCount,
		GeneratedModules:             corpus.GeneratedModules,
		SemanticEquivalence:          status("generated_semantic_equivalence"),
		GeneratedProfileDiversity:    status("generated_profile_diversity"),
		FixedSignature:               status("generated_fixed_signature"),
		MutantDetection:              status("generated_mutant_detection"),
		MultiStreamGeneratedParity:   status("multi_stream_generated_parity"),
		StreamAdversaryParity:        status("multi_stream_generated_backend_parity"),
		ProxySemGeneratedParity:      status("proxy_generated_backend_parity"),
		CarrierGeneratedParity:       status("carrier_generated_backend_parity"),
		SecurityGeneratedParity:      status("security_generated_backend_parity"),
		RuntimeGeneratedParity:       status("runtime_generated_backend_parity"),
		HardeningGeneratedParity:     status("hardening_generated_backend_parity"),
		AdapterGeneratedParity:       status("adapter_generated_backend_parity"),
		LocalAdapterGeneratedParity:  status("local_adapter_generated_backend_parity"),
		ByteTransportGeneratedParity: status("byte_transport_generated_backend_parity"),
		SourceScanner:                status("generated_source_scanner"),
		InterpretedVsGenerated:       divergenceSummary(corpus),
		SourceScan:                   corpus.SourceScan,
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

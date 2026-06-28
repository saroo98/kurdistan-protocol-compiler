// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"time"

	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	ktrace "kurdistan/internal/trace"
)

func Run(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()

	profileStart := time.Now()
	profiles, err := diversity.GenerateProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	profileMillis := time.Since(profileStart).Milliseconds()
	corpusSummary := diversity.SummarizeCorpus(cfg.StartSeed, profiles)

	traceStart := time.Now()
	traces, err := captureTraces(ctx, profiles, cfg.TraceCount)
	if err != nil {
		return AuditReport{}, err
	}
	traceMillis := time.Since(traceStart).Milliseconds()
	traceScan := ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)

	gates := []GateResult{
		ProfileCorpusDiversityGate(corpusSummary, cfg.Thresholds),
		BlackBoxTraceDiversityGate(traceScan, cfg.Thresholds),
		AdversarialBlackBoxClusteringGate(ctx, profiles, traces, cfg.Thresholds),
		FixedSignatureGate(profiles, traces, cfg.Thresholds),
		CosmeticDifferenceGate(),
		SameProfileConsistencyGate(ctx),
		DifferentProfileSeparationGate(traces, cfg.Thresholds),
		MalformedProbeBehaviorGate(profiles, cfg.Thresholds),
		MultiStreamSemanticsGate(ctx, profiles, cfg.Thresholds),
		MultiStreamDiversityGate(profiles, cfg.Thresholds),
		MultiStreamBackpressureGate(ctx, profiles, cfg.Thresholds),
		MultiStreamAdversarialScenariosGate(ctx, profiles, cfg.Thresholds),
		MultiStreamCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		MultiStreamMutantDetectionGate(ctx, cfg.Thresholds),
		FuzzPresenceGate(),
	}

	benchmark := BenchmarkSummary{
		ProfileGenerationMillis: profileMillis,
		TraceGenerationMillis:   traceMillis,
		TotalMillis:             time.Since(start).Milliseconds(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       len(traces),
		Gates:            gates,
		CorpusSummary:    toJSONMap(corpusSummary.ProfileDiversityReport),
		TraceScanSummary: traceScan,
		BenchmarkSummary: benchmark,
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func captureTraces(ctx context.Context, profiles []*ir.Profile, traceCount int) ([][]ktrace.Event, error) {
	if traceCount > len(profiles) {
		traceCount = len(profiles)
	}
	traces := make([][]ktrace.Event, 0, traceCount)
	for i := 0; i < traceCount; i++ {
		events, err := labtrace.CaptureTrace(ctx, profiles[i], []byte("hello kurdistan"))
		if err != nil {
			return nil, err
		}
		traces = append(traces, events)
	}
	return traces, nil
}

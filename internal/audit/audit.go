// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"time"

	"kurdistan/internal/adapteradversary"
	"kurdistan/internal/carrieradversary"
	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/runtimeadversary"
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
	hardeningGates := HardeningGates(ctx, profiles, cfg)

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
		ProxySemanticsCorrectnessGate(ctx, profiles, proxyadversary.QuickScenarios(), cfg.Thresholds),
		ProxySemanticsDiversityGate(profiles, cfg.Thresholds),
		ProxyTargetBackpressureGate(ctx, profiles, cfg.Thresholds),
		ProxyErrorResetIsolationGate(ctx, profiles, cfg.Thresholds),
		ProxyMutantDetectionGate(ctx, cfg.Thresholds),
		ProxyGeneratedBackendParityGate(),
		CarrierSemanticsCorrectnessGate(ctx, profiles, carrieradversary.QuickScenarios(), cfg.Thresholds),
		CarrierDiversityGate(profiles, cfg.Thresholds),
		CarrierBackpressurePreservationGate(ctx, profiles, cfg.Thresholds),
		CarrierLossReorderRecoveryGate(ctx, profiles, cfg.Thresholds),
		CarrierProxySemParityGate(ctx, profiles, cfg.Thresholds),
		CarrierMutantDetectionGate(ctx, cfg.Thresholds),
		CarrierGeneratedBackendParityGate(),
		SecurityTranscriptBindingGate(profiles),
		SecurityKeyScheduleGate(profiles),
		SecurityNonceUniquenessGate(profiles),
		SecurityReplayRejectionGate(),
		SecurityDowngradeResistanceGate(profiles),
		SecurityCapabilityNegotiationGate(profiles),
		SecurityProfileCompatibilityGate(profiles),
		SecurityConfigHygieneGate(profiles),
		SecuritySecretTraceHygieneGate(profiles),
		SecurityMutantDetectionGate(ctx),
		SecurityGeneratedBackendParityGate(),
		RuntimeSessionLifecycleGate(ctx, profiles, runtimeadversary.QuickScenarios()),
		RuntimeCapabilityNegotiationGate(ctx, profiles),
		RuntimeProfileCompatibilityGate(ctx, profiles),
		RuntimeSecurityContextGate(ctx, profiles),
		RuntimeReplayRejectionGate(ctx, profiles),
		RuntimeStreamManagementGate(ctx, profiles),
		RuntimeBackpressureGate(ctx, profiles),
		RuntimeErrorResetIsolationGate(ctx, profiles),
		RuntimeTraceHygieneGate(ctx, profiles),
		RuntimeMutantDetectionGate(ctx),
		RuntimeGeneratedBackendParityGate(),
		AdapterInterfaceContractsGate(),
		AdapterConfigValidationGate(),
		AdapterFlowLifecycleGate(),
		AdapterRuntimeBoundaryGate(ctx, profiles, adapteradversary.QuickScenarios(), cfg.Thresholds),
		AdapterCapabilityCompatibilityGate(profiles),
		AdapterBackpressureGate(ctx, profiles),
		AdapterErrorResetMappingGate(ctx, profiles),
		AdapterTraceHygieneGate(ctx, profiles),
		AdapterCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		AdapterMutantDetectionGate(ctx, cfg.Thresholds),
		AdapterGeneratedBackendParityGate(),
		FuzzPresenceGate(),
	}
	gates = append(gates[:len(gates)-1], append(hardeningGates, gates[len(gates)-1])...)

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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"path/filepath"
	"time"

	"kurdistan/internal/adapteradversary"
	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/byteparity"
	"kurdistan/internal/bytetransportadversary"
	"kurdistan/internal/carrieradversary"
	"kurdistan/internal/classifierdata"
	"kurdistan/internal/diversity"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/localadapteradversary"
	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayfleet"
	"kurdistan/internal/runtimeadversary"
	ktrace "kurdistan/internal/trace"
	"kurdistan/internal/transportbundle"
	"kurdistan/internal/wireeval"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
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
	fixtureRoot, fixtureRootErr := repoRoot()
	if fixtureRootErr != nil {
		fixtureRoot = "."
	}
	bytepathFixturePath := filepath.Join(fixtureRoot, "testdata", "fixtures", "bytepath-golden.json")
	bytepathMalformedPath := filepath.Join(fixtureRoot, "testdata", "fixtures", "malformed-byte-corpus.json")
	protocolCorpusPath := filepath.Join(fixtureRoot, "testdata", "protocorpus", "corpus-v1.json")
	protocolBucketsPath := filepath.Join(fixtureRoot, "testdata", "protocorpus", "feature-buckets-v1.json")
	wireFeatureBaselinePath := filepath.Join(fixtureRoot, "testdata", "wirefeatures", "wirefeatures-golden.json")
	bytepathParity, parityErr := byteparity.Run(ctx, fixtures.DefaultSeeds(), fixtures.DefaultScenarios())
	if parityErr != nil {
		bytepathParity = byteparity.ByteParityReport{Conclusion: "failed", UnexpectedDifferences: []string{parityErr.Error()}}
	}
	protocolCorpus, corpusErr := protocorpus.LoadManifest(protocolCorpusPath)
	if corpusErr != nil {
		protocolCorpus = protocorpus.CorpusManifest{Version: protocorpus.CorpusSchemaVersion}
	}
	bytepathManifest, fixtureErr := fixtures.LoadManifest(bytepathFixturePath)
	wireFeatureVectors := []wirefeatures.WireFeatureVector{}
	wireFeatureExtraction := wirefeatures.FeatureExtractionReport{Conclusion: "failed", InvalidFeatures: []string{"bytepath fixture load failed"}}
	if fixtureErr == nil {
		wireFeatureVectors, wireFeatureExtraction = wirefeatures.ExtractFromFixtureManifest(bytepathManifest)
	}
	wireFeatureComparison := wirefeatures.CompareToCorpus(wireFeatureVectors, protocolCorpus)
	wireFeatureCollapse := wirefeatures.ScanCollapse(wireFeatureVectors)
	wireGenBaselinePath := filepath.Join(fixtureRoot, "testdata", "wiregen", "wiregen-policy-golden.json")
	wireEvalBaselinePath := filepath.Join(fixtureRoot, "testdata", "wireeval", "wireeval-dataset-golden.json")
	wireGenPolicies := make([]wiregen.WireShapePolicy, 0, len(profiles))
	for _, profile := range profiles {
		wireGenPolicies = append(wireGenPolicies, wiregen.FromIRPolicy(profile.WireShape))
	}
	wireGenVectors := expectedVectorsForProfiles(wireGenPolicies, wiregencompare.DefaultScenarios())
	wireEvalDataset, wireEvalErr := wireeval.BuildDataset(ctx, protocolCorpus, wireeval.BuildOptions{Seeds: wireeval.DefaultSeeds(), Scenarios: wireeval.DefaultScenarios(), SplitMode: wireeval.DefaultSplitMode(), Controls: true})
	wireEvalCSV, wireEvalJSONL := []byte{}, []byte{}
	hostDetectBaselinePath := filepath.Join(fixtureRoot, "testdata", "hostdetect", "host-observations-golden.json")
	hostDetectSummary := hostdetect.HostDetectSummary{}
	hostDetectErr := wireEvalErr
	relayFleetSummary := relayfleet.RelayFleetSummary{}
	relayFleetErr := wireEvalErr
	relayFleetBaselinePath := filepath.Join(fixtureRoot, "testdata", "relayfleet", "relayfleet-golden.json")
	relayFleetComparison := relayfleet.RelayFleetComparisonReport{Version: string(relayfleet.Version), Conclusion: "failed"}
	proxyIngressSet, proxyIngressErr := proxyingress.GoldenFixtureSet()
	proxyIngressReview, proxyIngressMisuse, proxyIngressParity, proxyIngressReviewErr := proxyingressreview.GenerateGoldenReview()
	proxyIngressComparison, _ := proxyingress.VerifyContract(ctx, filepath.Join(fixtureRoot, "testdata", "proxyingress", "proxyingress-contract-golden.json"))
	localProxyIngressSet, localProxyIngressErr := localproxyingress.GenerateFixtureSet(ctx, localproxyingress.QuickScenarios())
	localProxyIngressComparison := localProxyIngressFixtureComparison(ctx, filepath.Join(fixtureRoot, "testdata", "localproxyingress", "localproxyingress-summary-golden.json"), localProxyIngressSet)
	localProxyIngressAdvSet, localProxyIngressAdvErr := localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
	localProxyIngressAdvComparison := localProxyIngressAdversarialFixtureComparison(ctx, filepath.Join(fixtureRoot, "testdata", "localproxyingressadversary", "adversarial-corpus-golden.json"), localProxyIngressAdvSet)
	adaptivePathSet, adaptivePathErr := adaptivepath.GenerateFixtureSet(ctx)
	adaptivePathComparison := adaptivePathFixtureComparison(ctx, filepath.Join(fixtureRoot, "testdata", "adaptivepath", "path-candidates-golden.json"), adaptivePathSet)
	transportBundleSet, transportBundleErr := transportbundle.GenerateFixtureSet(ctx)
	transportBundleComparison := transportBundleFixtureComparison(filepath.Join(fixtureRoot, "testdata", "transportbundle", "bundle-manifest-golden.json"), transportBundleSet)
	if wireEvalErr == nil {
		wireEvalCSV, _ = classifierdata.ExportCSV(wireEvalDataset.Records)
		wireEvalJSONL, _ = classifierdata.ExportJSONL(wireEvalDataset.Records)
		hostDetectSummary, hostDetectErr = hostdetect.Run(wireEvalDataset, hostdetect.DefaultBuildOptions())
		if hostDetectErr == nil {
			relayFleetSummary, relayFleetErr = relayfleet.Run(wireEvalDataset, hostDetectSummary, relayfleet.DefaultOptions())
			relayFleetComparison, _ = relayfleet.VerifyFleet(ctx, relayFleetBaselinePath)
		} else {
			relayFleetErr = hostDetectErr
		}
	}

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
		LocalAdapterCorrectnessGate(ctx, profiles, localadapteradversary.QuickScenarios(), cfg.Thresholds),
		LocalAdapterFlowLifecycleGate(ctx, profiles),
		LocalAdapterRuntimeIntegrationGate(ctx, profiles, localadapteradversary.QuickScenarios(), cfg.Thresholds),
		LocalAdapterBackpressureGate(ctx, profiles),
		LocalAdapterErrorResetIsolationGate(ctx, profiles),
		LocalAdapterSequenceIntegrityGate(ctx, profiles),
		LocalAdapterTraceHygieneGate(ctx, profiles),
		LocalAdapterCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		LocalAdapterMutantDetectionGate(ctx, cfg.Thresholds),
		LocalAdapterGeneratedBackendParityGate(),
		ByteTransportEncodingCorrectnessGate(ctx, profiles, bytetransportadversary.QuickScenarios(), cfg.Thresholds),
		ByteTransportFragmentationReassemblyGate(ctx, profiles),
		ByteTransportPipeBackpressureGate(ctx, profiles),
		ByteTransportSequenceIntegrityGate(ctx, profiles),
		ByteTransportCorruptionRejectionGate(ctx, profiles),
		ByteTransportRuntimeIntegrationGate(ctx, profiles, bytetransportadversary.QuickScenarios(), cfg.Thresholds),
		ByteTransportErrorResetIsolationGate(ctx, profiles),
		ByteTransportTraceHygieneGate(ctx, profiles),
		ByteTransportCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		ByteTransportMutantDetectionGate(ctx, cfg.Thresholds),
		ByteTransportGeneratedBackendParityGate(),
		BytePathFixtureDriftGate(ctx, bytepathFixturePath),
		BytePathFixtureStabilityGate(ctx, bytepathFixturePath),
		BytePathGeneratedInterpretedParityGate(bytepathParity),
		BytePathMalformedCorpusGate(bytepathMalformedPath, fixtures.DefaultMalformedCorpus()),
		BytePathRegressionBaselinesGate(bytepathFixturePath),
		BytePathFixtureTraceHygieneGate(bytepathFixturePath),
		ProtocolCorpusSchemaValidGate(protocolCorpusPath),
		ProtocolCorpusFeatureTaxonomyGate(protocolCorpus, protocolBucketsPath),
		ProtocolCorpusEntryCoverageGate(protocolCorpus),
		ProtocolCorpusTraceHygieneGate(protocolCorpus),
		WireFeaturesExtractionGate(wireFeatureExtraction),
		WireFeaturesFirstNModelGate(wireFeatureVectors),
		WireFeaturesCorpusComparisonGate(wireFeatureComparison),
		WireFeaturesCollapseResistanceGate(wireFeatureCollapse),
		WireFeaturesGeneratedBackendParityGate(),
		WireFeaturesMutantDetectionGate(),
		WireFeaturesBaselineGate(ctx, wireFeatureBaselinePath, bytepathFixturePath, protocolCorpusPath),
	}
	gates = append(gates, WireGenGates(ctx, profiles, wireGenPolicies, wireGenVectors, protocolCorpus, wireGenBaselinePath)...)
	if wireEvalErr == nil {
		gates = append(gates, WireEvalGates(ctx, wireEvalDataset, wireEvalCSV, wireEvalJSONL, wireEvalBaselinePath)...)
	} else {
		gates = append(gates, gate("wireeval_dataset_build", false, "required", wireEvalErr.Error(), nil, []string{wireEvalErr.Error()}))
	}
	if hostDetectErr == nil {
		gates = append(gates, HostDetectGates(ctx, wireEvalDataset, hostDetectSummary, hostdetect.DefaultAssignmentModes(), hostdetect.DefaultTimelineWindows(), hostDetectBaselinePath)...)
	} else {
		gates = append(gates, gate("hostdetect_observation_build", false, "required", hostDetectErr.Error(), nil, []string{hostDetectErr.Error()}))
	}
	if relayFleetErr == nil {
		gates = append(gates, RelayFleetGates(relayFleetSummary, relayFleetComparison)...)
	} else {
		gates = append(gates, gate("relayfleet_lifecycle_integrity", false, "required", relayFleetErr.Error(), nil, []string{relayFleetErr.Error()}))
	}
	if proxyIngressErr == nil && proxyIngressReviewErr == nil {
		gates = append(gates, ProxyIngressGates(proxyIngressSet, proxyIngressReview, proxyIngressMisuse, proxyIngressParity, proxyIngressComparison)...)
	} else {
		msg := "proxyingress fixture build failed"
		if proxyIngressErr != nil {
			msg = proxyIngressErr.Error()
		} else if proxyIngressReviewErr != nil {
			msg = proxyIngressReviewErr.Error()
		}
		gates = append(gates, gate("proxyingress_contract_validation", false, "required", msg, nil, []string{msg}))
	}
	if localProxyIngressErr == nil {
		gates = append(gates, LocalProxyIngressGates(localProxyIngressSet, localProxyIngressComparison)...)
	} else {
		gates = append(gates, gate("localproxyingress_contract_compliance", false, "required", localProxyIngressErr.Error(), nil, []string{localProxyIngressErr.Error()}))
	}
	if localProxyIngressAdvErr == nil {
		gates = append(gates, LocalProxyIngressAdversarialGates(localProxyIngressAdvSet, localProxyIngressAdvComparison)...)
	} else {
		gates = append(gates, gate("localproxyingressadv_corpus_validation", false, "required", localProxyIngressAdvErr.Error(), nil, []string{localProxyIngressAdvErr.Error()}))
	}
	if adaptivePathErr == nil {
		gates = append(gates, AdaptivePathGates(adaptivePathSet, adaptivePathComparison)...)
		gates = append(gates, AdaptivePathRoadmapPublicDocsGate())
	} else {
		gates = append(gates, gate("adaptivepath_candidate_taxonomy", false, "required", adaptivePathErr.Error(), nil, []string{adaptivePathErr.Error()}))
	}
	if transportBundleErr == nil {
		gates = append(gates, TransportBundleGates(transportBundleSet, transportBundleComparison)...)
	} else {
		gates = append(gates, gate("transportbundle_policy_validation", false, "required", transportBundleErr.Error(), nil, []string{transportBundleErr.Error()}))
	}
	gates = append(gates, FuzzPresenceGate())
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

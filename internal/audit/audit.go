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
	"kurdistan/internal/carriercollapse"
	"kurdistan/internal/carrierreadiness"
	"kurdistan/internal/carrierreview"
	"kurdistan/internal/classifierdata"
	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/constrainedcarrier"
	"kurdistan/internal/constrainedcarrierreview"
	"kurdistan/internal/diversity"
	"kurdistan/internal/fixtures"
	"kurdistan/internal/hostdetect"
	"kurdistan/internal/httpscarrieradversary"
	"kurdistan/internal/httpscarrierreview"
	"kurdistan/internal/httpslikecarrier"
	"kurdistan/internal/ir"
	"kurdistan/internal/keyexchangeplan"
	"kurdistan/internal/labegress"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/localadapteradversary"
	"kurdistan/internal/localpipeline"
	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/localproxyadapter"
	"kurdistan/internal/localproxyadapterreview"
	"kurdistan/internal/localproxyingress"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/localvpnadapter"
	"kurdistan/internal/loopbackrelay"
	"kurdistan/internal/measurementreview"
	"kurdistan/internal/multicarrierselect"
	"kurdistan/internal/pathhealth"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/productionreadiness"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/proxyadversary"
	"kurdistan/internal/proxyegress"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayauthplan"
	"kurdistan/internal/relaybridge"
	"kurdistan/internal/relayfleet"
	"kurdistan/internal/relayprocess"
	"kurdistan/internal/runtimeadversary"
	ktrace "kurdistan/internal/trace"
	"kurdistan/internal/transportbundle"
	"kurdistan/internal/vpnsemantics"
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
	pathRaceSet, pathRaceErr := pathrace.GenerateFixtureSet(ctx)
	pathRaceComparison := pathRaceFixtureComparison(filepath.Join(fixtureRoot, "testdata", "pathrace", "pathrace-report-golden.json"), pathRaceSet)
	pathHealthSet, pathHealthErr := pathhealth.GenerateFixtureSet(ctx)
	pathHealthComparison := pathHealthFixtureComparison(filepath.Join(fixtureRoot, "testdata", "pathhealth", "pathhealth-report-golden.json"), pathHealthSet)
	carrierReview, carrierReviewErr := carrierreview.GenerateReview()
	carrierReviewDrift := carrierReviewComparison(filepath.Join(fixtureRoot, "testdata", "carrierreview", "carrierreview-golden.json"), carrierReview)
	measurementReview, measurementReviewErr := measurementreview.GenerateReview()
	measurementReviewDrift := measurementReviewComparison(filepath.Join(fixtureRoot, "testdata", "measurementreview", "measurementreview-golden.json"), measurementReview)
	proxyEgressSet, proxyEgressErr := proxyegress.GenerateFixtureSet()
	proxyEgressDrift := proxyEgressComparison(filepath.Join(fixtureRoot, "testdata", "proxyegress", "egress-lifecycle-golden.json"), proxyEgressSet)
	relayBridgeSet, relayBridgeErr := relaybridge.GenerateFixtureSet()
	relayBridgeDrift := relayBridgeComparison(filepath.Join(fixtureRoot, "testdata", "relaybridge", "relaybridge-report-golden.json"), relayBridgeSet)
	localPipelineSet, localPipelineErr := localpipeline.GenerateFixtureSet()
	localPipelineDrift := localPipelineComparison(filepath.Join(fixtureRoot, "testdata", "localpipeline", "localpipeline-golden.json"), localPipelineSet)
	productionReadinessReview, productionReadinessErr := productionreadiness.GenerateReview()
	productionReadinessDrift := productionReadinessComparison(filepath.Join(fixtureRoot, "testdata", "productionreadiness", "productionreadiness-golden.json"), productionReadinessReview)
	concreteLocalAdapterSet, concreteLocalAdapterErr := concretelocaladapter.GenerateFixtureSet(ctx)
	concreteLocalAdapterDrift := concreteLocalAdapterComparison(filepath.Join(fixtureRoot, "testdata", "concretelocaladapter", "concretelocaladapter-golden.json"), concreteLocalAdapterSet)
	localProtocolAdapterSet, localProtocolAdapterErr := localprotocoladapter.GenerateFixtureSet()
	localProtocolAdapterDrift := localProtocolAdapterComparison(filepath.Join(fixtureRoot, "testdata", "localprotocoladapter", "localprotocoladapter-report-golden.json"), localProtocolAdapterSet)
	loopbackRelaySet, loopbackRelayErr := loopbackrelay.GenerateFixtureSet()
	loopbackRelayDrift := loopbackRelayComparison(filepath.Join(fixtureRoot, "testdata", "loopbackrelay", "loopbackrelay-report-golden.json"), loopbackRelaySet)
	labEgressSet, labEgressErr := labegress.GenerateFixtureSet()
	labEgressDrift := labEgressComparison(filepath.Join(fixtureRoot, "testdata", "labegress", "labegress-report-golden.json"), labEgressSet)
	carrierReadinessSet, carrierReadinessErr := carrierreadiness.GenerateFixtureSet()
	carrierReadinessDrift := carrierReadinessComparison(filepath.Join(fixtureRoot, "testdata", "carrierreadiness", "carrierreadiness-golden.json"), carrierReadinessSet)
	httpsCarrierReviewSet, httpsCarrierReviewErr := httpscarrierreview.GenerateFixtureSet()
	httpsCarrierReviewDrift := httpsCarrierReviewComparison(filepath.Join(fixtureRoot, "testdata", "httpscarrierreview", "httpscarrierreview-report-golden.json"), httpsCarrierReviewSet)
	httpsLikeCarrierSet, httpsLikeCarrierErr := httpslikecarrier.GenerateFixtureSet()
	httpsLikeCarrierDrift := httpsLikeCarrierComparison(filepath.Join(fixtureRoot, "testdata", "httpslikecarrier", "httpslikecarrier-report-golden.json"), httpsLikeCarrierSet)
	httpsCarrierAdversarySet, httpsCarrierAdversaryErr := httpscarrieradversary.GenerateFixtureSet()
	httpsCarrierAdversaryDrift := httpsCarrierAdversaryComparison(filepath.Join(fixtureRoot, "testdata", "httpscarrieradversary", "httpscarrieradversary-report-golden.json"), httpsCarrierAdversarySet)
	constrainedCarrierReviewSet, constrainedCarrierReviewErr := constrainedcarrierreview.GenerateFixtureSet()
	constrainedCarrierReviewDrift := constrainedCarrierReviewComparison(filepath.Join(fixtureRoot, "testdata", "constrainedcarrierreview", "constrainedcarrierreview-report-golden.json"), constrainedCarrierReviewSet)
	constrainedCarrierSet, constrainedCarrierErr := constrainedcarrier.GenerateFixtureSet()
	constrainedCarrierDrift := constrainedCarrierComparison(filepath.Join(fixtureRoot, "testdata", "constrainedcarrier", "constrainedcarrier-report-golden.json"), constrainedCarrierSet)
	multiCarrierSelectSet, multiCarrierSelectErr := multicarrierselect.GenerateFixtureSet()
	multiCarrierSelectDrift := multiCarrierSelectComparison(filepath.Join(fixtureRoot, "testdata", "multicarrierselect", "multicarrierselect-report-golden.json"), multiCarrierSelectSet)
	carrierCollapseSet, carrierCollapseErr := carriercollapse.GenerateFixtureSet()
	carrierCollapseDrift := carrierCollapseComparison(filepath.Join(fixtureRoot, "testdata", "carriercollapse", "carriercollapse-report-golden.json"), carrierCollapseSet)
	localProxyAdapterReviewSet, localProxyAdapterReviewErr := localproxyadapterreview.GenerateFixtureSet()
	localProxyAdapterReviewDrift := localProxyAdapterReviewComparison(filepath.Join(fixtureRoot, "testdata", "localproxyadapterreview", "localproxyadapterreview-report-golden.json"), localProxyAdapterReviewSet)
	localProxyAdapterSet, localProxyAdapterErr := localproxyadapter.GenerateFixtureSet()
	localProxyAdapterDrift := localProxyAdapterComparison(filepath.Join(fixtureRoot, "testdata", "localproxyadapter", "localproxyadapter-report-golden.json"), localProxyAdapterSet)
	vpnSemanticsSet, vpnSemanticsErr := vpnsemantics.GenerateFixtureSet()
	vpnSemanticsDrift := vpnSemanticsComparison(filepath.Join(fixtureRoot, "testdata", "vpnsemantics", "vpnsemantics-report-golden.json"), vpnSemanticsSet)
	localVPNAdapterSet, localVPNAdapterErr := localvpnadapter.GenerateFixtureSet()
	localVPNAdapterDrift := localVPNAdapterComparison(filepath.Join(fixtureRoot, "testdata", "localvpnadapter", "localvpnadapter-report-golden.json"), localVPNAdapterSet)
	relayProcessSet, relayProcessErr := relayprocess.GenerateFixtureSet()
	relayProcessDrift := relayProcessComparison(filepath.Join(fixtureRoot, "testdata", "relayprocess", "relayprocess-report-golden.json"), relayProcessSet)
	keyExchangePlanSet, keyExchangePlanErr := keyexchangeplan.GenerateFixtureSet()
	keyExchangePlanDrift := keyExchangePlanComparison(filepath.Join(fixtureRoot, "testdata", "keyexchangeplan", "keyexchangeplan-report-golden.json"), keyExchangePlanSet)
	relayAuthPlanSet, relayAuthPlanErr := relayauthplan.GenerateFixtureSet()
	relayAuthPlanDrift := relayAuthPlanComparison(filepath.Join(fixtureRoot, "testdata", "relayauthplan", "relayauthplan-report-golden.json"), relayAuthPlanSet)
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
	if pathRaceErr == nil {
		gates = append(gates, PathRaceGates(pathRaceSet, pathRaceComparison)...)
	} else {
		gates = append(gates, gate("pathrace_scenario_validation", false, "required", pathRaceErr.Error(), nil, []string{pathRaceErr.Error()}))
	}
	if pathHealthErr == nil {
		gates = append(gates, PathHealthGates(pathHealthSet, pathHealthComparison)...)
	} else {
		gates = append(gates, gate("pathhealth_active_monitor", false, "required", pathHealthErr.Error(), nil, []string{pathHealthErr.Error()}))
	}
	if carrierReviewErr == nil {
		gates = append(gates, CarrierReviewGates(carrierReview, carrierReviewDrift)...)
	} else {
		gates = append(gates, gate("carrierreview_family_descriptors", false, "required", carrierReviewErr.Error(), nil, []string{carrierReviewErr.Error()}))
	}
	if measurementReviewErr == nil {
		gates = append(gates, MeasurementReviewGates(measurementReview, measurementReviewDrift)...)
	} else {
		gates = append(gates, gate("measurementreview_observation_schema", false, "required", measurementReviewErr.Error(), nil, []string{measurementReviewErr.Error()}))
	}
	if proxyEgressErr == nil {
		gates = append(gates, ProxyEgressGates(proxyEgressSet, proxyEgressDrift)...)
	} else {
		gates = append(gates, gate("proxyegress_contract_validation", false, "required", proxyEgressErr.Error(), nil, []string{proxyEgressErr.Error()}))
	}
	if relayBridgeErr == nil {
		gates = append(gates, RelayBridgeGates(relayBridgeSet, relayBridgeDrift)...)
	} else {
		gates = append(gates, gate("relaybridge_session_validation", false, "required", relayBridgeErr.Error(), nil, []string{relayBridgeErr.Error()}))
	}
	if localPipelineErr == nil {
		gates = append(gates, LocalPipelineGates(localPipelineSet, localPipelineDrift)...)
	} else {
		gates = append(gates, gate("localpipeline_correctness", false, "required", localPipelineErr.Error(), nil, []string{localPipelineErr.Error()}))
	}
	if productionReadinessErr == nil {
		gates = append(gates, ProductionReadinessGates(productionReadinessReview, productionReadinessDrift)...)
	} else {
		gates = append(gates, gate("productionreadiness_inventory", false, "required", productionReadinessErr.Error(), nil, []string{productionReadinessErr.Error()}))
	}
	if concreteLocalAdapterErr == nil {
		gates = append(gates, ConcreteLocalAdapterGates(concreteLocalAdapterSet, concreteLocalAdapterDrift)...)
	} else {
		gates = append(gates, gate("concretelocaladapter_bind_policy", false, "required", concreteLocalAdapterErr.Error(), nil, []string{concreteLocalAdapterErr.Error()}))
	}
	if localProtocolAdapterErr == nil {
		gates = append(gates, LocalProtocolAdapterGates(localProtocolAdapterSet, localProtocolAdapterDrift)...)
	} else {
		gates = append(gates, gate("localprotocoladapter_config_validation", false, "required", localProtocolAdapterErr.Error(), nil, []string{localProtocolAdapterErr.Error()}))
	}
	if loopbackRelayErr == nil {
		gates = append(gates, LoopbackRelayGates(loopbackRelaySet, loopbackRelayDrift)...)
	} else {
		gates = append(gates, gate("loopbackrelay_bind_policy", false, "required", loopbackRelayErr.Error(), nil, []string{loopbackRelayErr.Error()}))
	}
	if labEgressErr == nil {
		gates = append(gates, LabEgressGates(labEgressSet, labEgressDrift)...)
	} else {
		gates = append(gates, gate("labegress_allowlist_validation", false, "required", labEgressErr.Error(), nil, []string{labEgressErr.Error()}))
	}
	if carrierReadinessErr == nil {
		gates = append(gates, CarrierReadinessGates(carrierReadinessSet, carrierReadinessDrift)...)
	} else {
		gates = append(gates, gate("carrierreadiness_inventory", false, "required", carrierReadinessErr.Error(), nil, []string{carrierReadinessErr.Error()}))
	}
	if httpsCarrierReviewErr == nil {
		gates = append(gates, HTTPSCarrierReviewGates(httpsCarrierReviewSet, httpsCarrierReviewDrift)...)
	} else {
		gates = append(gates, gate("httpscarrierreview_scope_contract", false, "required", httpsCarrierReviewErr.Error(), nil, []string{httpsCarrierReviewErr.Error()}))
	}
	if httpsLikeCarrierErr == nil {
		gates = append(gates, HTTPSLikeCarrierGates(httpsLikeCarrierSet, httpsLikeCarrierDrift)...)
	} else {
		gates = append(gates, gate("httpslikecarrier_scope", false, "required", httpsLikeCarrierErr.Error(), nil, []string{httpsLikeCarrierErr.Error()}))
	}
	if httpsCarrierAdversaryErr == nil {
		gates = append(gates, HTTPSCarrierAdversaryGates(httpsCarrierAdversarySet, httpsCarrierAdversaryDrift)...)
	} else {
		gates = append(gates, gate("httpscarrieradversary_collapse_detection", false, "required", httpsCarrierAdversaryErr.Error(), nil, []string{httpsCarrierAdversaryErr.Error()}))
	}
	if constrainedCarrierReviewErr == nil {
		gates = append(gates, ConstrainedCarrierReviewGates(constrainedCarrierReviewSet, constrainedCarrierReviewDrift)...)
	} else {
		gates = append(gates, gate("constrainedcarrierreview_scope_contract", false, "required", constrainedCarrierReviewErr.Error(), nil, []string{constrainedCarrierReviewErr.Error()}))
	}
	if constrainedCarrierErr == nil {
		gates = append(gates, ConstrainedCarrierGates(constrainedCarrierSet, constrainedCarrierDrift)...)
	} else {
		gates = append(gates, gate("constrainedcarrier_harness", false, "required", constrainedCarrierErr.Error(), nil, []string{constrainedCarrierErr.Error()}))
	}
	if multiCarrierSelectErr == nil {
		gates = append(gates, MultiCarrierSelectGates(multiCarrierSelectSet, multiCarrierSelectDrift)...)
	} else {
		gates = append(gates, gate("multicarrierselect_inventory", false, "required", multiCarrierSelectErr.Error(), nil, []string{multiCarrierSelectErr.Error()}))
	}
	if carrierCollapseErr == nil {
		gates = append(gates, CarrierCollapseGates(carrierCollapseSet, carrierCollapseDrift)...)
	} else {
		gates = append(gates, gate("carriercollapse_family_diversity", false, "required", carrierCollapseErr.Error(), nil, []string{carrierCollapseErr.Error()}))
	}
	if localProxyAdapterReviewErr == nil {
		gates = append(gates, LocalProxyAdapterReviewGates(localProxyAdapterReviewSet, localProxyAdapterReviewDrift)...)
	} else {
		gates = append(gates, gate("localproxyadapterreview_scope_contract", false, "required", localProxyAdapterReviewErr.Error(), nil, []string{localProxyAdapterReviewErr.Error()}))
	}
	if localProxyAdapterErr == nil {
		gates = append(gates, LocalProxyAdapterGates(localProxyAdapterSet, localProxyAdapterDrift)...)
	} else {
		gates = append(gates, gate("localproxyadapter_session_lifecycle", false, "required", localProxyAdapterErr.Error(), nil, []string{localProxyAdapterErr.Error()}))
	}
	if vpnSemanticsErr == nil {
		gates = append(gates, VPNSemanticsGates(vpnSemanticsSet, vpnSemanticsDrift)...)
	} else {
		gates = append(gates, gate("vpnsemantics_scope_contract", false, "required", vpnSemanticsErr.Error(), nil, []string{vpnSemanticsErr.Error()}))
	}
	if localVPNAdapterErr == nil {
		gates = append(gates, LocalVPNAdapterGates(localVPNAdapterSet, localVPNAdapterDrift)...)
	} else {
		gates = append(gates, gate("localvpnadapter_lifecycle", false, "required", localVPNAdapterErr.Error(), nil, []string{localVPNAdapterErr.Error()}))
	}
	if relayProcessErr == nil {
		gates = append(gates, RelayProcessGates(relayProcessSet, relayProcessDrift)...)
	} else {
		gates = append(gates, gate("relayprocess_role_inventory", false, "required", relayProcessErr.Error(), nil, []string{relayProcessErr.Error()}))
	}
	if keyExchangePlanErr == nil {
		gates = append(gates, KeyExchangePlanGates(keyExchangePlanSet, keyExchangePlanDrift)...)
	} else {
		gates = append(gates, gate("keyexchangeplan_design_inventory", false, "required", keyExchangePlanErr.Error(), nil, []string{keyExchangePlanErr.Error()}))
	}
	if relayAuthPlanErr == nil {
		gates = append(gates, RelayAuthPlanGates(relayAuthPlanSet, relayAuthPlanDrift)...)
	} else {
		gates = append(gates, gate("relayauthplan_inventory", false, "required", relayAuthPlanErr.Error(), nil, []string{relayAuthPlanErr.Error()}))
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

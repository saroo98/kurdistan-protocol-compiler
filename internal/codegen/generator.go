// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package codegen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/contracts/android/androidcarrier"
	"kurdistan/internal/contracts/android/androidreview"
	"kurdistan/internal/contracts/android/androidruntime"
	"kurdistan/internal/contracts/android/androidvpnservice"
	"kurdistan/internal/contracts/carrier/carriercollapse"
	"kurdistan/internal/contracts/carrier/carrierreadiness"
	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/contracts/carrier/constrainedcarrier"
	"kurdistan/internal/contracts/carrier/constrainedcarrierreview"
	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
	"kurdistan/internal/contracts/carrier/httpscarrierreview"
	"kurdistan/internal/contracts/carrier/httpslikecarrier"
	"kurdistan/internal/contracts/carrier/multicarrierselect"
	"kurdistan/internal/contracts/lab/labegress"
	"kurdistan/internal/contracts/lab/localpipeline"
	"kurdistan/internal/contracts/lab/loopbackrelay"
	"kurdistan/internal/contracts/proxy/localproxyadapterreview"
	"kurdistan/internal/contracts/proxy/proxyingressreview"
	"kurdistan/internal/contracts/readiness/keyexchangeplan"
	"kurdistan/internal/contracts/readiness/measurementreview"
	"kurdistan/internal/contracts/readiness/operationalhardening"
	"kurdistan/internal/contracts/readiness/productionreadiness"
	"kurdistan/internal/contracts/vpn/localvpnadapter"
	"kurdistan/internal/contracts/vpn/vpnsemantics"
	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/localproxyadapter"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/operator/relayauthplan"
	"kurdistan/internal/operator/relaybridge"
	"kurdistan/internal/operator/relayprocess"
	"kurdistan/internal/pathhealth"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/proxyegress"
	"kurdistan/internal/transportbundle"
)

type Options struct {
	Force       bool
	GeneratedAt time.Time
	ModulePath  string
	RepoRoot    string
}

type Result struct {
	OutputDir string   `json:"output_dir"`
	Manifest  Manifest `json:"manifest"`
	Files     []string `json:"files"`
}

func Generate(p *ir.Profile, out string, opts Options) (Result, error) {
	if err := ir.Validate(p); err != nil {
		return Result{}, err
	}
	if out == "" {
		return Result{}, fmt.Errorf("output directory is required")
	}
	if p.Auth.TestKeyHex != derivedAuthTestKeyHex(p.ID, p.Seed) {
		return Result{}, fmt.Errorf("profile auth key is not derivable test-only material")
	}
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now().UTC()
	}
	repoRoot := opts.RepoRoot
	var err error
	if repoRoot == "" {
		repoRoot, err = findRepoRoot()
		if err != nil {
			return Result{}, err
		}
	}
	modulePath := opts.ModulePath
	if modulePath == "" {
		modulePath = "kurdistan/generated/" + sanitizeModuleSuffix(p.ID)
	}
	absOut, err := filepath.Abs(out)
	if err != nil {
		return Result{}, err
	}
	if err := prepareOutput(absOut, opts.Force); err != nil {
		return Result{}, err
	}

	generatedAt := opts.GeneratedAt.UTC().Format(time.RFC3339)
	manifest := NewManifest(p, generatedAt)
	files, err := renderFiles(p, modulePath, repoRoot, manifest)
	if err != nil {
		return Result{}, err
	}
	if opts.Force {
		if err := cleanGeneratedOutput(absOut); err != nil {
			return Result{}, err
		}
	}
	for _, file := range files {
		path := filepath.Join(absOut, filepath.FromSlash(file.RelPath))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return Result{}, err
		}
		if err := os.WriteFile(path, []byte(file.Content), 0o600); err != nil {
			return Result{}, err
		}
	}
	relPaths := make([]string, 0, len(files))
	for _, file := range files {
		relPaths = append(relPaths, file.RelPath)
	}
	return Result{OutputDir: absOut, Manifest: manifest, Files: relPaths}, nil
}

func prepareOutput(out string, force bool) error {
	info, err := os.Stat(out)
	if err != nil {
		if os.IsNotExist(err) {
			return os.MkdirAll(out, 0o755)
		}
		return err
	}
	if !info.IsDir() {
		if !force {
			return fmt.Errorf("output path exists and is not a directory")
		}
		return fmt.Errorf("cannot force overwrite non-directory output")
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		return err
	}
	if len(entries) > 0 && !force {
		return fmt.Errorf("output directory exists; use --force to overwrite generated files")
	}
	return nil
}

func cleanGeneratedOutput(out string) error {
	for _, rel := range []string{
		"go.mod",
		"README.md",
		"manifest.json",
		"protocol",
		filepath.Join("cmd", "generated-client"),
		filepath.Join("cmd", "generated-server"),
		filepath.Join("cmd", "generated-echo"),
		filepath.Join("cmd", "generated-trace"),
	} {
		if err := os.RemoveAll(filepath.Join(out, rel)); err != nil {
			return err
		}
	}
	return nil
}

func renderFiles(p *ir.Profile, modulePath, repoRoot string, manifest Manifest) ([]generatedFile, error) {
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	manifestRaw = append(manifestRaw, '\n')
	goFiles, err := renderGoFiles(p, modulePath)
	if err != nil {
		return nil, err
	}
	files := []generatedFile{
		{RelPath: "go.mod", Content: goMod(modulePath, repoRoot)},
		{RelPath: "README.md", Content: readme(p)},
		{RelPath: "manifest.json", Content: string(manifestRaw)},
	}
	files = append(files, goFiles...)
	return files, nil
}

func renderGoFiles(p *ir.Profile, modulePath string) ([]generatedFile, error) {
	profileStatic, err := renderGo(genTmpl001, quote(p.ID), p.Seed, quote(p.GenerationHash), quote(Version), quote(SourceBackend), profileLiteral(p))
	if err != nil {
		return nil, err
	}

	states, err := renderGo(genTmpl002, stateConsts(p.States), transitionsLiteral(p.Transitions), firstContactLiteral(p.FirstContact.Steps))
	if err != nil {
		return nil, err
	}

	framing, err := renderGo(genTmpl003, quote(p.FrameGrammar.LengthMode), quote(p.FrameGrammar.TypeMode), quote(p.FrameGrammar.FragmentationMode), quote(p.FrameGrammar.ChecksumMode), quote(p.FrameGrammar.PaddingPlacement), quoteSlice(p.FrameGrammar.HeaderOrder), semanticWireMap(p.Messages), messageBounds(p.Messages))
	if err != nil {
		return nil, err
	}

	streamSource, err := renderGo(genTmpl004, quote(p.Stream.IDStrategy), quote(p.Stream.IDEncodingMode), p.Stream.MaxConcurrentStreams, p.Stream.InitialStreamWindowBytes, p.Stream.InitialSessionWindowBytes, quote(p.Stream.WindowUpdatePolicy), quote(p.Stream.PriorityPolicy), quote(p.Stream.ClosePolicy), quote(p.Stream.ResetPolicy), p.Stream.MaxStreamID)
	if err != nil {
		return nil, err
	}

	proxySemSource, err := renderGo(genTmpl005, quote(p.ProxySemantics.RelayIntentEncoding), quote(p.ProxySemantics.TargetDescriptorEncoding), quote(p.ProxySemantics.RequestClassEncoding), quote(p.ProxySemantics.ResponseModeEncoding), quote(p.ProxySemantics.TargetErrorPolicy), quote(p.ProxySemantics.TargetClosePolicy), quote(p.ProxySemantics.TargetResetPolicy), quote(p.ProxySemantics.TargetMetadataPolicy), quote(p.ProxySemantics.RelayOpenOrderingPolicy), quote(p.ProxySemantics.RelayIntentPaddingPolicy), quote(p.ProxySemantics.TargetClassMapping), p.ProxySemantics.MaxRequestBytes, p.ProxySemantics.MaxResponseBytes, quoteSlice(p.ProxySemantics.TargetClasses), proxySemanticWireMap(p.Messages))
	if err != nil {
		return nil, err
	}

	carrierSource, err := renderGo(genTmpl006, quote(p.CarrierPolicy.CarrierFamily), quote(p.CarrierPolicy.EnvelopeEncoding), quote(p.CarrierPolicy.FlushPolicy), quote(p.CarrierPolicy.BatchPolicy), quote(p.CarrierPolicy.ChunkingPolicy), quote(p.CarrierPolicy.ReliabilityPolicy), quote(p.CarrierPolicy.ReorderPolicy), quote(p.CarrierPolicy.BackpressurePolicy), quote(p.CarrierPolicy.PriorityMappingPolicy), quote(p.CarrierPolicy.EnvelopePaddingPolicy), quote(p.CarrierPolicy.TimingBucketPolicy), p.CarrierPolicy.MaxEnvelopeBytes, p.CarrierPolicy.MaxMessagesPerEnvelope, p.CarrierPolicy.MaxCarrierQueueDepth, p.CarrierPolicy.MaxRetryCount)
	if err != nil {
		return nil, err
	}

	securitySource, err := renderGo(genTmpl007, quote(p.Security.SecurityVersion), quote(p.Security.TranscriptMode), quote(p.Security.KDFSuite), quote(p.Security.AEADSuite), quote(p.Security.MACSuite), quote(p.Security.NonceMode), quote(p.Security.ReplayPolicy), p.Security.ReplayWindowSize, quote(p.Security.DowngradePolicy), quote(p.Security.CapabilityNegotiationPolicy), quote(p.Security.ProfileCompatibilityPolicy), quote(p.Security.KeyRotationPolicy), quote(p.Security.ConfigValidationPolicy), quote(p.Security.SecureEnvelopeMode), p.Security.MaxSessionMessages, p.Security.MaxKeyLifetimeMessages, quoteSlice(p.Compatibility.RequiredCapabilities))
	if err != nil {
		return nil, err
	}

	runtimeSource, err := renderGo(genTmpl008, quote(p.ID), quote(p.GenerationHash), quote(p.Compatibility.SchemaVersion), quote(p.Security.SecurityVersion), quote(p.CarrierPolicy.CarrierFamily+"/"+p.CarrierPolicy.EnvelopeEncoding+"/"+p.CarrierPolicy.FlushPolicy), quote(p.Stream.IDStrategy+"/"+p.Stream.PriorityPolicy+"/"+p.Stream.WindowUpdatePolicy), quote(p.ProxySemantics.RelayIntentEncoding+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.ProxySemantics.ResponseModeEncoding), p.Stream.MaxConcurrentStreams)
	if err != nil {
		return nil, err
	}

	hardeningSource, err := renderGo(genTmpl009, quote(p.ID), quote(p.GenerationHash), quote(Version), p.Limits.MaxFrameBytes, p.Limits.MaxPayloadBytes, p.Stream.MaxConcurrentStreams, p.CarrierPolicy.MaxCarrierQueueDepth)
	if err != nil {
		return nil, err
	}

	adapterSource, err := renderGo(genTmpl010, quote(p.ID), quote(p.AdapterPolicy.FlowLifecyclePolicy), quote(p.AdapterPolicy.RuntimeMappingPolicy), quote(p.AdapterPolicy.TracePolicy), quote(p.AdapterPolicy.ErrorMappingPolicy), quote(p.AdapterPolicy.BackpressurePolicy), p.AdapterPolicy.MaxFlows, p.AdapterPolicy.MaxFlowBytes, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxEvents, quoteSlice(p.AdapterPolicy.RequiredCapabilities))
	if err != nil {
		return nil, err
	}

	localAdapterMaxChunk := p.AdapterPolicy.MaxFlowBytes
	if localAdapterMaxChunk > 256*1024 {
		localAdapterMaxChunk = 256 * 1024
	}
	localAdapterSource, err := renderGo(genTmpl011, quote(p.ID), quote("small_burst_source"), quote(p.AdapterPolicy.FlowLifecyclePolicy), quote(p.AdapterPolicy.RuntimeMappingPolicy), quote(p.AdapterPolicy.BackpressurePolicy), p.AdapterPolicy.MaxFlows, localAdapterMaxChunk, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxEvents)
	if err != nil {
		return nil, err
	}

	byteMaxFrame := p.Limits.MaxFrameBytes
	if byteMaxFrame > 64*1024 {
		byteMaxFrame = 64 * 1024
	}
	if byteMaxFrame < 4096 {
		byteMaxFrame = 4096
	}
	byteMaxPayload := p.Limits.MaxPayloadBytes
	if byteMaxPayload > 16*1024 {
		byteMaxPayload = 16 * 1024
	}
	if byteMaxPayload > byteMaxFrame/2 {
		byteMaxPayload = byteMaxFrame / 2
	}
	byteTransportSource, err := renderGo(genTmpl012, quote(p.ID), byteMaxFrame, byteMaxPayload, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxBufferedBytes, quote(p.FrameGrammar.FragmentationMode), quote(p.Security.ReplayPolicy))
	if err != nil {
		return nil, err
	}

	protocolCorpusSource, err := renderGo(genTmpl013, quote(p.ID))
	if err != nil {
		return nil, err
	}

	wireFeaturesSource, err := renderGo(genTmpl014, quote(p.ID))
	if err != nil {
		return nil, err
	}

	wireGenSource, err := renderGo(genTmpl015, quote(p.WireShape.Version), quote(p.WireShape.PolicyID), quote(p.WireShape.PolicyHash), quote(p.WireShape.SelectedFamily), quote(p.WireShape.SelectedCorpusEntry), quote(p.ID), quoteSlice(p.WireShape.FrameSizePlan.SizeBuckets), quoteSlice(p.WireShape.FragmentRhythmPlan.FragmentBuckets), quoteSlice(p.WireShape.PhasePlan.PhaseSequence))
	if err != nil {
		return nil, err
	}

	wireEvalSource, err := renderGo(genTmpl016, quote(p.ID))
	if err != nil {
		return nil, err
	}

	hostDetectSource, err := renderGo(genTmpl017, quote(p.ID))
	if err != nil {
		return nil, err
	}

	relayFleetSource, err := renderGo(genTmpl018, quote(p.ID), p.Seed, quote(p.WireShape.PolicyHash), quote(p.WireShape.SelectedFamily), quote(relayFleetAssignmentMode(p.Seed)), quote(relayFleetChurnMode(p.Seed)), quote(relayFleetMigrationMode(p.Seed)), min(8, max(6, p.Stream.MaxConcurrentStreams)))
	if err != nil {
		return nil, err
	}

	proxyIngressSource, err := renderGo(genTmpl019, quote(p.ID), quote(proxyingressreview.HashValue(proxyingressreview.DefaultFailureModes())))
	if err != nil {
		return nil, err
	}

	localProxyIngressSource, err := renderGo(genTmpl020, quote(p.ID))
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvDescriptorClasses := localProxyIngressAdversarialDescriptorClasses(localproxyingressadversary.DescriptorAbuseCases())
	localProxyIngressAdvSource, err := renderGo(genTmpl021, quote(localproxyingressadversary.Version), quote(p.ID), quote(localproxyingressadversary.CorpusID), quoteSlice(localproxyingressadversary.RequiredScenarioIDs()), quoteSlice(localProxyIngressAdvDescriptorClasses), quoteSlice(localproxyingressadversary.LifecycleAbuseScenarios()), quoteSlice(localproxyingressadversary.PressureScenarios()), quoteSlice(localproxyingressadversary.ResetErrorScenarios()))
	if err != nil {
		return nil, err
	}

	adaptivePathSource, err := renderGo(genTmpl022, quote(string(adaptivepath.Version)), quote(p.ID), p.Seed, quoteSlice(adaptivePathCandidateFamilies()), quoteSlice(adaptivePathConditionClasses()), quoteSlice(adaptivePathObservationKinds()), quoteSlice(adaptivePathFreshnessClasses()), quoteSlice(adaptivePathTTLClasses()), quoteSlice(adaptivePathUncertaintyBuckets()), quoteSlice(adaptivePathViabilityStates()), quoteSlice(adaptivePathHighRiskFamilies()), quoteSlice(adaptivePathGatedFamilies()), quoteSlice(adaptivepath.ForbiddenMarkers()))
	if err != nil {
		return nil, err
	}

	transportBundleSource, err := renderGo(genTmpl023, quote(string(transportbundle.Version)), quote(p.ID), p.Seed, quoteSlice(transportBundleModeStrings()), quoteSlice(transportBundleCandidateRoles()), quoteSlice(transportbundle.ForbiddenMarkers()), quote(transportbundle.DefaultPolicy(12345, transportbundle.BundleModeBalancedAdaptive).PolicyHash))
	if err != nil {
		return nil, err
	}

	pathRaceSource, err := renderGo(genTmpl024, quote(string(pathrace.Version)), quote(p.ID), p.Seed, quoteSlice(pathRaceModeStrings()), quoteSlice(pathRaceEventKindStrings()), quoteSlice(pathRaceStateStrings()), quoteSlice(pathrace.ForbiddenMarkers()), quote(pathrace.DefaultSchedulerPolicy(pathrace.RaceModeVerifiedUsable).PolicyHash), quote(pathrace.DefaultScoringPolicy().PolicyHash))
	if err != nil {
		return nil, err
	}

	pathHealthSource, err := renderGo(genTmpl025, quote(string(pathhealth.Version)), quote(p.ID), p.Seed, quoteSlice(pathhealth.HealthStates()), quoteSlice(pathhealth.HealthEventKinds()), quoteSlice(pathhealth.FailoverOutcomes()), quoteSlice(pathhealth.ForbiddenMarkers()), quote(pathhealth.DefaultPolicy().PolicyHash))
	if err != nil {
		return nil, err
	}

	carrierReviewSource, err := renderGo(genTmpl026, quote(carrierreview.Version), quote(p.ID), p.Seed, quoteSlice(carrierReviewFamilies()), quoteSlice(carrierReviewReadinessClasses()), quoteSlice(carrierreview.ForbiddenMarkers()), quote(carrierreview.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	measurementReviewSource, err := renderGo(genTmpl027, quote(measurementreview.Version), quote(p.ID), p.Seed, quoteSlice(measurementReviewObservationFields()), quoteSlice(measurementreview.AllowedRedactionClasses()), quoteSlice(measurementreview.AllowedConsentModes()), quoteSlice(measurementreview.AllowedRetentionClasses()), quoteSlice(measurementreview.ForbiddenMarkers()), quote(measurementreview.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	proxyEgressSource, err := renderGo(genTmpl028, quote(proxyegress.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.CarrierPolicy.CarrierFamily), quoteSlice(proxyEgressTargetClasses()), quoteSlice(proxyEgressLifecycleStates()), quote(proxyegress.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	relayBridgeSource, err := renderGo(genTmpl029, quote(relaybridge.Version), quote(p.ID), p.Seed, quote(p.Stream.PriorityPolicy+"/"+p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.BackpressurePolicy), quoteSlice(relayBridgeStates()), quoteSlice(relayBridgeScenarioClasses()), quote(relaybridge.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	localPipelineSource, err := renderGo(genTmpl030, quote(localpipeline.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.ResponseModeEncoding+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.WireShape.PolicyID), quoteSlice(localPipelineScenarioKinds()), quoteSlice(localPipelineStates()), quote(localpipeline.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	productionReadinessSource, err := renderGo(genTmpl031, quote(productionreadiness.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.Security.CapabilityNegotiationPolicy+"/"+p.WireShape.PolicyID), quoteSlice(productionReadinessContracts()), quoteSlice(productionReadinessBoundaries()), quote(productionreadiness.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterSource, err := renderGo(genTmpl032, quote(concretelocaladapter.Version), quote(p.ID), p.Seed, quote(concretelocaladapter.BindClassLoopbackOnly), quote(p.AdapterPolicy.RuntimeMappingPolicy), 16, 64*1024, quote(concretelocaladapter.RecommendedNextMilestone), quoteSlice(concreteLocalAdapterScenarios()))
	if err != nil {
		return nil, err
	}

	localProtocolAdapterSource, err := renderGo(genTmpl033, quote(localprotocoladapter.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.RelayIntentEncoding+"/"+p.WireShape.PolicyID), localprotocoladapter.DefaultConfig().MaxRequestLineBytes, localprotocoladapter.DefaultConfig().MaxParserTransitions, quote(localprotocoladapter.RecommendedNextMilestone), quoteSlice(localProtocolAdapterFamilies()), quoteSlice(localProtocolAdapterScenarios()), quoteSlice(localProtocolAdapterParserStates()))
	if err != nil {
		return nil, err
	}

	loopbackRelaySource, err := renderGo(genTmpl034, quote(loopbackrelay.Version), quote(p.ID), p.Seed, quote(loopbackrelay.BindPolicyLoopbackOnly), quote(loopbackrelay.DialPolicyLoopbackOnly), loopbackrelay.DefaultConfig().MaxSessions, loopbackrelay.DefaultConfig().MaxFrameBytes, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(loopbackrelay.RecommendedNextMilestone), quoteSlice(loopbackRelayScenarios()))
	if err != nil {
		return nil, err
	}

	labEgressSource, err := renderGo(genTmpl035, quote(labegress.Version), quote(p.ID), p.Seed, quote(labegress.ConnectorPolicyLoopbackAllowlist), labegress.DefaultConfig().MaxConnections, labegress.DefaultConfig().MaxResponseBytes, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.CarrierPolicy.CarrierFamily), quote(labegress.RecommendedNextMilestone), quoteSlice(labEgressScenarios()), quoteSlice(labEgressTargetClasses()))
	if err != nil {
		return nil, err
	}

	carrierReadinessSource, err := renderGo(genTmpl036, quote(carrierreadiness.Version), quote(p.ID), p.Seed, quote(carrierreadiness.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(carrierreadiness.RecommendedNextMilestone), quoteSlice(carrierReadinessFutureMilestones()), quoteSlice(carrierReadinessBoundaryNames()))
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewSource, err := renderGo(genTmpl037, quote(httpscarrierreview.Version), quote(p.ID), p.Seed, quote(httpscarrierreview.BackendVersion), quote(httpscarrierreview.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpscarrierreview.RecommendedNextMilestone), len(httpsCarrierReviewRequestShapeNames()), len(httpsCarrierReviewResponseShapeNames()), quoteSlice(httpsCarrierReviewBlockedBehaviorNames()), quoteSlice(httpsCarrierReviewM42Criteria()))
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierSource, err := renderGo(genTmpl038, quote(httpslikecarrier.Version), quote(p.ID), p.Seed, quote(httpslikecarrier.BackendVersion), quote(httpslikecarrier.CarrierFamily), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpslikecarrier.RecommendedNextMilestone), httpslikecarrier.DefaultConfig().MaxMarkerBytes, len(httpsLikeCarrierRequestShapeClasses()), len(httpsLikeCarrierResponseShapeClasses()), quoteSlice(httpsLikeCarrierBlockedScopes()), quoteSlice(httpsLikeCarrierRequestShapeClasses()), quoteSlice(httpsLikeCarrierResponseShapeClasses()), quoteSlice(httpsLikeCarrierSessionStates()), quoteSlice(httpsLikeCarrierStreamStates()), quoteSlice(httpsLikeCarrierMisuseControls()))
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversarySource, err := renderGo(genTmpl039, quote(httpscarrieradversary.Version), quote(p.ID), p.Seed, quote(httpscarrieradversary.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpscarrieradversary.RecommendedNextMilestone), len(httpsCarrierAdversaryCollapseControls()), len(httpsCarrierAdversaryUnsafeFallbackControls()), len(httpsCarrierAdversaryForbiddenControls()), quoteSlice(httpsCarrierAdversaryScenarios()), quoteSlice(httpsCarrierAdversaryCollapseControls()), quoteSlice(httpsCarrierAdversaryUnsafeFallbackControls()), quoteSlice(httpsCarrierAdversaryReplayControls()), quoteSlice(httpsCarrierAdversaryStreamControls()), quoteSlice(httpsCarrierAdversaryForbiddenControls()))
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewSource, err := renderGo(genTmpl040, quote(constrainedcarrierreview.Version), quote(p.ID), p.Seed, quote(constrainedcarrierreview.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(constrainedcarrierreview.RecommendedNextMilestone), len(constrainedCarrierReviewQueryShapeClasses()), len(constrainedCarrierReviewResponseShapeClasses()), len(constrainedCarrierReviewResolverBuckets()), len(constrainedCarrierReviewM45Requirements()), quoteSlice(constrainedCarrierReviewBlockedBehaviors()), quoteSlice(constrainedCarrierReviewResolverBuckets()), quoteSlice(constrainedCarrierReviewQueryShapeClasses()), quoteSlice(constrainedCarrierReviewResponseShapeClasses()), quoteSlice(constrainedCarrierReviewM45Requirements()), quoteSlice(constrainedcarrierreview.RequiredMisuseNames()))
	if err != nil {
		return nil, err
	}

	constrainedCarrierSource, err := renderGo(genTmpl041, quote(constrainedcarrier.Version), quote(p.ID), p.Seed, quote(constrainedcarrier.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(constrainedcarrier.CarrierFamily), quote(constrainedcarrier.RecommendedNextMilestone), len(constrainedcarrier.QueryShapeClasses()), len(constrainedcarrier.ResponseShapeClasses()), len(constrainedcarrier.CapacityBuckets()), len(constrainedcarrier.RetryBuckets()), len(constrainedcarrier.FailureBuckets()), quoteSlice(constrainedcarrier.QueryShapeClasses()), quoteSlice(constrainedcarrier.ResponseShapeClasses()), quoteSlice(constrainedcarrier.CapacityBuckets()), quoteSlice(constrainedcarrier.RetryBuckets()), quoteSlice(constrainedcarrier.FailureBuckets()), quoteSlice(constrainedcarrier.BlockedScopes()), quoteSlice(constrainedcarrier.RequiredMisuseNames()))
	if err != nil {
		return nil, err
	}

	multiCarrierSelectSource, err := renderGo(genTmpl042, quote(multicarrierselect.Version), quote(p.ID), p.Seed, quote(multicarrierselect.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(multicarrierselect.RecommendedNextMilestone), len(multicarrierselect.RequiredFamilyClasses()), len(multicarrierselect.RequiredDecisionClasses()), len(multicarrierselect.RequiredMisuseNames()), quoteSlice(multicarrierselect.RequiredFamilyClasses()), quoteSlice(multicarrierselect.RequiredDecisionClasses()), quoteSlice(multicarrierselect.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	carrierCollapseSource, err := renderGo(genTmpl043, quote(carriercollapse.Version), quote(p.ID), p.Seed, quote(carriercollapse.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(carriercollapse.RecommendedNextMilestone), len(carriercollapse.RequiredMutationNames()), len(carriercollapse.RequiredAuditDimensions()), quoteSlice(carriercollapse.RequiredCollapseClasses()), quoteSlice(carriercollapse.RequiredMutationNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewSource, err := renderGo(genTmpl044, quote(localproxyadapterreview.Version), quote(p.ID), p.Seed, quote(localproxyadapterreview.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localproxyadapterreview.RecommendedNextMilestone), len(localproxyadapterreview.RequiredMisuseNames()), quote(localproxyadapterreview.DecisionReady), quote("byte_counts_buckets_and_flags_only"), quote("target_bucket_only"), quoteSlice(localproxyadapterreview.RequiredMisuseNames()), quoteSlice([]string{"local_socks_like_stream_adapter_semantics", "local_http_connect_like_stream_adapter_semantics"}), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localProxyAdapterSource, err := renderGo(genTmpl045, quote(localproxyadapter.Version), quote(p.ID), p.Seed, quote(localproxyadapter.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localproxyadapter.RecommendedNextMilestone), len(localproxyadapter.RequiredMisuseNames()), quote("profile_bounded_streams"), quote("opaque_symbolic_classes_only"), quoteSlice(localproxyadapter.DefaultStreamClasses()), quoteSlice(localproxyadapter.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	vpnSemanticsSource, err := renderGo(genTmpl046, quote(vpnsemantics.Version), quote(p.ID), p.Seed, quote(vpnsemantics.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote("M51: local desktop packet adapter prototype"), len(vpnsemantics.RequiredMisuseNames()), quote(vpnsemantics.DecisionReady), quote("class_buckets_only"), quoteSlice([]string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "reset_flow", "backpressure_flow", "control_misuse_flow"}), quoteSlice(vpnsemantics.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localVPNAdapterSource, err := renderGo(genTmpl047, quote(localvpnadapter.Version), quote(p.ID), p.Seed, quote(localvpnadapter.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localvpnadapter.RecommendedNextMilestone), len(localvpnadapter.RequiredMisuseNames()), quote("class_buckets_only"), quoteSlice([]string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "fragmented_flow", "retry_backpressure_flow", "reset_flow", "kill_switch_flow"}), quoteSlice(localvpnadapter.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	relayProcessSource, err := renderGo(genTmpl048, quote(relayprocess.Version), quote(p.ID), p.Seed, quote(relayprocess.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(relayprocess.RecommendedNextMilestone), 3, 5, len(relayprocess.RequiredMisuseNames()), quote("structured_safe_metadata_only"), quoteSlice(relayprocess.RequiredMisuseNames()), quoteSlice([]string{"client_process", "relay_process", "supervisor_process"}), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	keyExchangePlanSource, err := renderGo(genTmpl049, quote(keyexchangeplan.Version), quote(p.ID), p.Seed, quote(keyexchangeplan.BackendVersion), quote(p.Security.TranscriptMode), quote(p.Security.NonceMode), quote(p.Security.CapabilityNegotiationPolicy+"/"+p.Security.DowngradePolicy), quote(keyexchangeplan.RecommendedNextMilestone), 10, len(keyexchangeplan.RequiredMisuseNames()), quoteSlice(keyexchangeplan.RequiredMisuseNames()), quoteSlice(keyexchangeplan.DefaultTranscriptBindingReport().BoundComponents), quoteSlice([]string{p.Security.TranscriptMode, p.Security.NonceMode, p.Security.ReplayPolicy, p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy}))
	if err != nil {
		return nil, err
	}

	relayAuthPlanSource, err := renderGo(genTmpl050, quote(relayauthplan.Version), quote(p.ID), p.Seed, quote(relayauthplan.BackendVersion), quote(p.Security.CapabilityNegotiationPolicy+"/"+p.Security.DowngradePolicy+"/"+p.CarrierPolicy.CarrierFamily), quote("bounded_epoch_rotation_with_required_overlap_window"), quote("fail_closed_with_safe_bucketed_diagnostics"), quote(relayauthplan.RecommendedNextMilestone), 15, len(relayauthplan.RequiredMisuseNames()), quoteSlice(relayauthplan.RequiredMisuseNames()), quoteSlice(relayauthplan.DefaultIdentityBindingPolicyReport().BoundComponents), quoteSlice([]string{p.Security.CapabilityNegotiationPolicy, p.Security.DowngradePolicy, p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.ReplayPolicy}))
	if err != nil {
		return nil, err
	}

	operationalHardeningSource, err := renderGo(genTmpl051, quote(operationalhardening.Version), quote(p.ID), p.Seed, quote(operationalhardening.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.ReplayPolicy), quote(p.Security.ConfigValidationPolicy+"/"+p.Security.ProfileCompatibilityPolicy), quote(p.Stream.ClosePolicy+"/"+p.Stream.ResetPolicy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote("structured_redacted_operational_status"), quote("fail_closed_profile_rotation_required"), quote("bucketed_redacted_operational_health"), quote(operationalhardening.RecommendedNextMilestone), len(operationalhardening.DefaultResourceLimitReport().Bounds), len(operationalhardening.RequiredMisuseNames()), quoteSlice(operationalhardening.DefaultConfigValidationReport().SafeErrorClasses), quoteSlice(operationalhardening.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.Security.ReplayPolicy, p.Security.DowngradePolicy, p.Security.ProfileCompatibilityPolicy}))
	if err != nil {
		return nil, err
	}

	androidReviewSource, err := renderGo(genTmpl052, quote(androidreview.Version), quote(p.ID), p.Seed, quote(androidreview.BackendVersion), quote(androidreview.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.ReplayPolicy), quote("platform_permission_first_foreground_service_bounded"), quote("local_user_export_only_redacted_diagnostic_bundle"), quote("fail_closed_on_profile_permission_runtime_or_carrier_invalid"), quote(androidreview.RecommendedNextMilestone), len(androidreview.DefaultUIStateReport().States), len(androidreview.RequiredMisuseNames()), quoteSlice(androidreview.DefaultUIStateReport().States), quoteSlice(androidreview.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidRuntimeSource, err := renderGo(genTmpl053, quote(androidruntime.Version), quote(p.ID), p.Seed, quote(androidruntime.BackendVersion), quote(androidruntime.DecisionReady), quote(androidruntime.DefaultInitializationReport().Policy), quote(androidruntime.DefaultLifecycleReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidruntime.DefaultDiagnosticsReport().Policy), quote(androidruntime.DefaultConcurrencyReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(p.Security.ProfileCompatibilityPolicy+"/"+p.Security.CapabilityNegotiationPolicy+"/"+p.Security.ReplayPolicy), quote(androidruntime.RecommendedNextMilestone), len(androidruntime.DefaultLifecycleReport().Events), len(androidruntime.RequiredMisuseNames()), quoteSlice(androidruntime.DefaultLifecycleReport().Events), quoteSlice(androidruntime.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidVPNServiceSource, err := renderGo(genTmpl054, quote(androidvpnservice.Version), quote(p.ID), p.Seed, quote(androidvpnservice.BackendVersion), quote(androidvpnservice.DecisionReady), quote(androidvpnservice.DefaultPermissionReport().Policy), quote(androidvpnservice.DefaultLifecycleReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidvpnservice.DefaultPacketFlowReport().Policy+"/"+p.Stream.IDEncodingMode), quote(androidvpnservice.DefaultKillSwitchReport().Policy), quote(androidvpnservice.DefaultDiagnosticsReport().Policy), quote(androidvpnservice.DefaultReconnectReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidvpnservice.DefaultIntegrationReport().Policy+"/"+p.Security.ProfileCompatibilityPolicy), quote(androidvpnservice.RecommendedNextMilestone), len(androidvpnservice.RequiredVpnStates()), androidvpnservice.DefaultPacketFlowReport().RuntimeStreamsMapped, len(androidvpnservice.RequiredMisuseNames()), quoteSlice(androidvpnservice.RequiredVpnStates()), quoteSlice(androidvpnservice.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Stream.IDEncodingMode, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidCarrierSource, err := renderGo(genTmpl055, quote(androidcarrier.Version), quote(p.ID), p.Seed, quote(androidcarrier.BackendVersion), quote(androidcarrier.DecisionReady), quote(androidcarrier.DefaultRuntimePathReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidcarrier.DefaultUIStateReport().Policy), quote(androidcarrier.DefaultCarrierSelectionReport().Policy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidcarrier.DefaultRelayCompatibilityReport().Policy+"/"+p.Security.ProfileCompatibilityPolicy), quote(androidcarrier.DefaultFlowIntegrationReport().Policy+"/"+p.Stream.IDEncodingMode), quote(androidcarrier.DefaultReconnectFallbackReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidcarrier.DefaultProfileValidationReport().Policy+"/"+p.Security.CapabilityNegotiationPolicy), quote(androidcarrier.RecommendedNextMilestone), len(androidcarrier.RequiredUIStates()), androidcarrier.DefaultFlowIntegrationReport().RuntimeStreamsMapped, androidcarrier.DefaultFlowIntegrationReport().CarrierEnvelopesMapped, len(androidcarrier.RequiredMisuseNames()), quoteSlice(androidcarrier.RequiredUIStates()), quoteSlice(androidcarrier.DefaultFailureDiagnosticsReport().FailureClasses), quoteSlice(androidcarrier.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Stream.IDEncodingMode, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	scheduler, err := renderGo(genTmpl056, quote(p.Scheduler.Mode), p.Scheduler.MaxBatchBytes, p.Scheduler.FlushIntervalMs, p.Scheduler.MaxInFlightFrames, quote(p.Scheduler.PriorityMode))
	if err != nil {
		return nil, err
	}

	invalid, err := renderGo(genTmpl057, quote(p.InvalidInput.UnknownFirstMessage), quote(p.InvalidInput.MalformedFrame), quote(p.InvalidInput.FailedAuth), quote(p.InvalidInput.Replay), p.InvalidInput.DelayMsMin, p.InvalidInput.DelayMsMax, p.Limits.MaxFrameBytes, p.Limits.MaxPayloadBytes, p.Limits.MaxStates, p.Limits.MaxTransitions, p.Limits.MaxSessionMillis)
	if err != nil {
		return nil, err
	}

	auth, err := renderGo(genTmpl058, quote(p.Auth.Mode), quote(p.Auth.KeyID), p.Auth.NonceBytes, quote(p.Auth.ProofMessage))
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewTestSource, err := renderGo(genTmpl059)
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewParityTestSource, err := renderGo(genTmpl060)
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewHygieneTestSource, err := renderGo(genTmpl061)
	if err != nil {
		return nil, err
	}

	localProxyAdapterTestSource, err := renderGo(genTmpl062)
	if err != nil {
		return nil, err
	}

	localProxyAdapterParityTestSource, err := renderGo(genTmpl063)
	if err != nil {
		return nil, err
	}

	localProxyAdapterHygieneTestSource, err := renderGo(genTmpl064)
	if err != nil {
		return nil, err
	}

	vpnSemanticsTestSource, err := renderGo(genTmpl065)
	if err != nil {
		return nil, err
	}

	vpnSemanticsParityTestSource, err := renderGo(genTmpl066)
	if err != nil {
		return nil, err
	}

	vpnSemanticsHygieneTestSource, err := renderGo(genTmpl067)
	if err != nil {
		return nil, err
	}

	localVPNAdapterTestSource, err := renderGo(genTmpl068)
	if err != nil {
		return nil, err
	}

	localVPNAdapterParityTestSource, err := renderGo(genTmpl069)
	if err != nil {
		return nil, err
	}

	localVPNAdapterHygieneTestSource, err := renderGo(genTmpl070)
	if err != nil {
		return nil, err
	}

	relayProcessTestSource, err := renderGo(genTmpl071)
	if err != nil {
		return nil, err
	}

	relayProcessParityTestSource, err := renderGo(genTmpl072)
	if err != nil {
		return nil, err
	}

	relayProcessHygieneTestSource, err := renderGo(genTmpl073)
	if err != nil {
		return nil, err
	}

	keyExchangePlanTestSource, err := renderGo(genTmpl074)
	if err != nil {
		return nil, err
	}

	keyExchangePlanParityTestSource, err := renderGo(genTmpl075)
	if err != nil {
		return nil, err
	}

	keyExchangePlanHygieneTestSource, err := renderGo(genTmpl076)
	if err != nil {
		return nil, err
	}

	operationalHardeningTestSource, err := renderGo(genTmpl077)
	if err != nil {
		return nil, err
	}

	operationalHardeningParityTestSource, err := renderGo(genTmpl078)
	if err != nil {
		return nil, err
	}

	operationalHardeningHygieneTestSource, err := renderGo(genTmpl079)
	if err != nil {
		return nil, err
	}

	androidReviewTestSource, err := renderGo(genTmpl080)
	if err != nil {
		return nil, err
	}

	androidReviewParityTestSource, err := renderGo(genTmpl081)
	if err != nil {
		return nil, err
	}

	androidReviewHygieneTestSource, err := renderGo(genTmpl082)
	if err != nil {
		return nil, err
	}

	androidRuntimeTestSource, err := renderGo(genTmpl083)
	if err != nil {
		return nil, err
	}

	androidRuntimeParityTestSource, err := renderGo(genTmpl084)
	if err != nil {
		return nil, err
	}

	androidRuntimeHygieneTestSource, err := renderGo(genTmpl085)
	if err != nil {
		return nil, err
	}

	androidVPNServiceTestSource, err := renderGo(genTmpl086)
	if err != nil {
		return nil, err
	}

	androidVPNServiceParityTestSource, err := renderGo(genTmpl087)
	if err != nil {
		return nil, err
	}

	androidVPNServiceHygieneTestSource, err := renderGo(genTmpl088)
	if err != nil {
		return nil, err
	}

	androidCarrierTestSource, err := renderGo(genTmpl089)
	if err != nil {
		return nil, err
	}

	androidCarrierParityTestSource, err := renderGo(genTmpl090)
	if err != nil {
		return nil, err
	}

	androidCarrierHygieneTestSource, err := renderGo(genTmpl091)
	if err != nil {
		return nil, err
	}

	relayAuthPlanTestSource, err := renderGo(genTmpl092)
	if err != nil {
		return nil, err
	}

	relayAuthPlanParityTestSource, err := renderGo(genTmpl093)
	if err != nil {
		return nil, err
	}

	relayAuthPlanHygieneTestSource, err := renderGo(genTmpl094)
	if err != nil {
		return nil, err
	}

	protocol, err := renderGo(genTmpl095)
	if err != nil {
		return nil, err
	}

	testSource, err := renderGo(genTmpl096)
	if err != nil {
		return nil, err
	}

	multiStreamTestSource, err := renderGo(genTmpl097)
	if err != nil {
		return nil, err
	}

	proxySemTestSource, err := renderGo(genTmpl098)
	if err != nil {
		return nil, err
	}

	proxySemAdversaryTestSource, err := renderGo(genTmpl099)
	if err != nil {
		return nil, err
	}

	carrierTestSource, err := renderGo(genTmpl100)
	if err != nil {
		return nil, err
	}

	carrierAdversaryTestSource, err := renderGo(genTmpl101)
	if err != nil {
		return nil, err
	}

	securityTestSource, err := renderGo(genTmpl102)
	if err != nil {
		return nil, err
	}

	securityAdversaryTestSource, err := renderGo(genTmpl103)
	if err != nil {
		return nil, err
	}

	runtimeTestSource, err := renderGo(genTmpl104)
	if err != nil {
		return nil, err
	}

	runtimeAdversaryTestSource, err := renderGo(genTmpl105)
	if err != nil {
		return nil, err
	}

	hardeningTestSource, err := renderGo(genTmpl106)
	if err != nil {
		return nil, err
	}

	adapterTestSource, err := renderGo(genTmpl107)
	if err != nil {
		return nil, err
	}

	adapterAdversaryTestSource, err := renderGo(genTmpl108)
	if err != nil {
		return nil, err
	}

	localAdapterTestSource, err := renderGo(genTmpl109)
	if err != nil {
		return nil, err
	}

	localAdapterAdversaryTestSource, err := renderGo(genTmpl110)
	if err != nil {
		return nil, err
	}

	byteTransportTestSource, err := renderGo(genTmpl111)
	if err != nil {
		return nil, err
	}

	byteTransportAdversaryTestSource, err := renderGo(genTmpl112)
	if err != nil {
		return nil, err
	}

	bytePathFixtureTestSource, err := renderGo(genTmpl113)
	if err != nil {
		return nil, err
	}

	bytePathParityTestSource, err := renderGo(genTmpl114)
	if err != nil {
		return nil, err
	}

	protocolCorpusTestSource, err := renderGo(genTmpl115)
	if err != nil {
		return nil, err
	}

	wireFeaturesTestSource, err := renderGo(genTmpl116)
	if err != nil {
		return nil, err
	}

	wireGenTestSource, err := renderGo(genTmpl117)
	if err != nil {
		return nil, err
	}

	wireGenParityTestSource, err := renderGo(genTmpl118)
	if err != nil {
		return nil, err
	}

	wireGenFeaturesTestSource, err := renderGo(genTmpl119)
	if err != nil {
		return nil, err
	}

	wireEvalTestSource, err := renderGo(genTmpl120)
	if err != nil {
		return nil, err
	}

	wireEvalExportTestSource, err := renderGo(genTmpl121)
	if err != nil {
		return nil, err
	}

	wireEvalParityTestSource, err := renderGo(genTmpl122)
	if err != nil {
		return nil, err
	}

	hostDetectTestSource, err := renderGo(genTmpl123)
	if err != nil {
		return nil, err
	}

	hostDetectParityTestSource, err := renderGo(genTmpl124)
	if err != nil {
		return nil, err
	}

	hostDetectHygieneTestSource, err := renderGo(genTmpl125)
	if err != nil {
		return nil, err
	}

	relayFleetTestSource, err := renderGo(genTmpl126)
	if err != nil {
		return nil, err
	}

	relayFleetParityTestSource, err := renderGo(genTmpl127)
	if err != nil {
		return nil, err
	}

	relayFleetHygieneTestSource, err := renderGo(genTmpl128)
	if err != nil {
		return nil, err
	}

	proxyIngressTestSource, err := renderGo(genTmpl129)
	if err != nil {
		return nil, err
	}

	proxyIngressParityTestSource, err := renderGo(genTmpl130)
	if err != nil {
		return nil, err
	}

	proxyIngressHygieneTestSource, err := renderGo(genTmpl131)
	if err != nil {
		return nil, err
	}

	localProxyIngressTestSource, err := renderGo(genTmpl132)
	if err != nil {
		return nil, err
	}

	localProxyIngressParityTestSource, err := renderGo(genTmpl133)
	if err != nil {
		return nil, err
	}

	localProxyIngressHygieneTestSource, err := renderGo(genTmpl134)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvTestSource, err := renderGo(genTmpl135)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvParityTestSource, err := renderGo(genTmpl136)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvHygieneTestSource, err := renderGo(genTmpl137)
	if err != nil {
		return nil, err
	}

	adaptivePathTestSource, err := renderGo(genTmpl138)
	if err != nil {
		return nil, err
	}

	adaptivePathParityTestSource, err := renderGo(genTmpl139)
	if err != nil {
		return nil, err
	}

	adaptivePathHygieneTestSource, err := renderGo(genTmpl140)
	if err != nil {
		return nil, err
	}

	transportBundleTestSource, err := renderGo(genTmpl141)
	if err != nil {
		return nil, err
	}

	transportBundleParityTestSource, err := renderGo(genTmpl142)
	if err != nil {
		return nil, err
	}

	transportBundleHygieneTestSource, err := renderGo(genTmpl143)
	if err != nil {
		return nil, err
	}

	pathRaceTestSource, err := renderGo(genTmpl144)
	if err != nil {
		return nil, err
	}

	pathRaceParityTestSource, err := renderGo(genTmpl145)
	if err != nil {
		return nil, err
	}

	pathRaceHygieneTestSource, err := renderGo(genTmpl146)
	if err != nil {
		return nil, err
	}

	pathHealthTestSource, err := renderGo(genTmpl147)
	if err != nil {
		return nil, err
	}

	pathHealthParityTestSource, err := renderGo(genTmpl148)
	if err != nil {
		return nil, err
	}

	pathHealthHygieneTestSource, err := renderGo(genTmpl149)
	if err != nil {
		return nil, err
	}

	carrierReviewTestSource, err := renderGo(genTmpl150)
	if err != nil {
		return nil, err
	}

	carrierReviewParityTestSource, err := renderGo(genTmpl151)
	if err != nil {
		return nil, err
	}

	carrierReviewHygieneTestSource, err := renderGo(genTmpl152)
	if err != nil {
		return nil, err
	}

	measurementReviewTestSource, err := renderGo(genTmpl153)
	if err != nil {
		return nil, err
	}

	measurementReviewParityTestSource, err := renderGo(genTmpl154)
	if err != nil {
		return nil, err
	}

	measurementReviewHygieneTestSource, err := renderGo(genTmpl155)
	if err != nil {
		return nil, err
	}

	proxyEgressTestSource, err := renderGo(genTmpl156)
	if err != nil {
		return nil, err
	}

	proxyEgressParityTestSource, err := renderGo(genTmpl157)
	if err != nil {
		return nil, err
	}

	proxyEgressHygieneTestSource, err := renderGo(genTmpl158)
	if err != nil {
		return nil, err
	}

	relayBridgeTestSource, err := renderGo(genTmpl159)
	if err != nil {
		return nil, err
	}

	relayBridgeParityTestSource, err := renderGo(genTmpl160)
	if err != nil {
		return nil, err
	}

	relayBridgeHygieneTestSource, err := renderGo(genTmpl161)
	if err != nil {
		return nil, err
	}

	localPipelineTestSource, err := renderGo(genTmpl162)
	if err != nil {
		return nil, err
	}

	localPipelineParityTestSource, err := renderGo(genTmpl163)
	if err != nil {
		return nil, err
	}

	localPipelineHygieneTestSource, err := renderGo(genTmpl164)
	if err != nil {
		return nil, err
	}

	productionReadinessTestSource, err := renderGo(genTmpl165)
	if err != nil {
		return nil, err
	}

	productionReadinessParityTestSource, err := renderGo(genTmpl166)
	if err != nil {
		return nil, err
	}

	productionReadinessHygieneTestSource, err := renderGo(genTmpl167)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterTestSource, err := renderGo(genTmpl168)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterParityTestSource, err := renderGo(genTmpl169)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterHygieneTestSource, err := renderGo(genTmpl170)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterTestSource, err := renderGo(genTmpl171)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterParityTestSource, err := renderGo(genTmpl172)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterHygieneTestSource, err := renderGo(genTmpl173)
	if err != nil {
		return nil, err
	}

	loopbackRelayTestSource, err := renderGo(genTmpl174)
	if err != nil {
		return nil, err
	}

	loopbackRelayParityTestSource, err := renderGo(genTmpl175)
	if err != nil {
		return nil, err
	}

	loopbackRelayHygieneTestSource, err := renderGo(genTmpl176)
	if err != nil {
		return nil, err
	}

	labEgressTestSource, err := renderGo(genTmpl177)
	if err != nil {
		return nil, err
	}

	labEgressParityTestSource, err := renderGo(genTmpl178)
	if err != nil {
		return nil, err
	}

	labEgressHygieneTestSource, err := renderGo(genTmpl179)
	if err != nil {
		return nil, err
	}

	carrierReadinessTestSource, err := renderGo(genTmpl180)
	if err != nil {
		return nil, err
	}

	carrierReadinessParityTestSource, err := renderGo(genTmpl181)
	if err != nil {
		return nil, err
	}

	carrierReadinessHygieneTestSource, err := renderGo(genTmpl182)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewTestSource, err := renderGo(genTmpl183)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewParityTestSource, err := renderGo(genTmpl184)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewHygieneTestSource, err := renderGo(genTmpl185)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierTestSource, err := renderGo(genTmpl186)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierParityTestSource, err := renderGo(genTmpl187)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierHygieneTestSource, err := renderGo(genTmpl188)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryTestSource, err := renderGo(genTmpl189)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryParityTestSource, err := renderGo(genTmpl190)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryHygieneTestSource, err := renderGo(genTmpl191)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewTestSource, err := renderGo(genTmpl192)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewParityTestSource, err := renderGo(genTmpl193)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewHygieneTestSource, err := renderGo(genTmpl194)
	if err != nil {
		return nil, err
	}

	constrainedCarrierTestSource, err := renderGo(genTmpl195)
	if err != nil {
		return nil, err
	}

	constrainedCarrierParityTestSource, err := renderGo(genTmpl196)
	if err != nil {
		return nil, err
	}

	constrainedCarrierHygieneTestSource, err := renderGo(genTmpl197)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectTestSource, err := renderGo(genTmpl198)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectParityTestSource, err := renderGo(genTmpl199)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectHygieneTestSource, err := renderGo(genTmpl200)
	if err != nil {
		return nil, err
	}

	carrierCollapseTestSource, err := renderGo(genTmpl201)
	if err != nil {
		return nil, err
	}

	carrierCollapseParityTestSource, err := renderGo(genTmpl202)
	if err != nil {
		return nil, err
	}

	carrierCollapseHygieneTestSource, err := renderGo(genTmpl203)
	if err != nil {
		return nil, err
	}

	benchSource, err := renderGo(genTmpl204)
	if err != nil {
		return nil, err
	}

	traceCapture, err := renderGo(genTmpl205)
	if err != nil {
		return nil, err
	}

	probeSource, err := renderGo(genTmpl206)
	if err != nil {
		return nil, err
	}

	client, err := renderCommand(modulePath, "generated-client")
	if err != nil {
		return nil, err
	}
	server, err := renderCommand(modulePath, "generated-server")
	if err != nil {
		return nil, err
	}
	echo, err := renderCommand(modulePath, "generated-echo")
	if err != nil {
		return nil, err
	}
	traceCommand, err := renderCommand(modulePath, "generated-trace")
	if err != nil {
		return nil, err
	}

	return []generatedFile{
		{RelPath: "protocol/profile_static.go", Content: profileStatic, Go: true},
		{RelPath: "protocol/states_generated.go", Content: states, Go: true},
		{RelPath: "protocol/framing_generated.go", Content: framing, Go: true},
		{RelPath: "protocol/stream_generated.go", Content: streamSource, Go: true},
		{RelPath: "protocol/proxysem_generated.go", Content: proxySemSource, Go: true},
		{RelPath: "protocol/carrier_generated.go", Content: carrierSource, Go: true},
		{RelPath: "protocol/security_generated.go", Content: securitySource, Go: true},
		{RelPath: "protocol/runtime_generated.go", Content: runtimeSource, Go: true},
		{RelPath: "protocol/hardening_generated.go", Content: hardeningSource, Go: true},
		{RelPath: "protocol/adapter_generated.go", Content: adapterSource, Go: true},
		{RelPath: "protocol/localadapter_generated.go", Content: localAdapterSource, Go: true},
		{RelPath: "protocol/bytetransport_generated.go", Content: byteTransportSource, Go: true},
		{RelPath: "protocol/protocorpus_generated.go", Content: protocolCorpusSource, Go: true},
		{RelPath: "protocol/wirefeatures_generated.go", Content: wireFeaturesSource, Go: true},
		{RelPath: "protocol/wiregen_generated.go", Content: wireGenSource, Go: true},
		{RelPath: "protocol/wireeval_generated.go", Content: wireEvalSource, Go: true},
		{RelPath: "protocol/hostdetect_generated.go", Content: hostDetectSource, Go: true},
		{RelPath: "protocol/relayfleet_generated.go", Content: relayFleetSource, Go: true},
		{RelPath: "protocol/proxyingress_generated.go", Content: proxyIngressSource, Go: true},
		{RelPath: "protocol/localproxyingress_generated.go", Content: localProxyIngressSource, Go: true},
		{RelPath: "protocol/localproxyingressadv_generated.go", Content: localProxyIngressAdvSource, Go: true},
		{RelPath: "protocol/adaptivepath_generated.go", Content: adaptivePathSource, Go: true},
		{RelPath: "protocol/transportbundle_generated.go", Content: transportBundleSource, Go: true},
		{RelPath: "protocol/pathrace_generated.go", Content: pathRaceSource, Go: true},
		{RelPath: "protocol/pathhealth_generated.go", Content: pathHealthSource, Go: true},
		{RelPath: "protocol/carrierreview_generated.go", Content: carrierReviewSource, Go: true},
		{RelPath: "protocol/measurementreview_generated.go", Content: measurementReviewSource, Go: true},
		{RelPath: "protocol/proxyegress_generated.go", Content: proxyEgressSource, Go: true},
		{RelPath: "protocol/relaybridge_generated.go", Content: relayBridgeSource, Go: true},
		{RelPath: "protocol/localpipeline_generated.go", Content: localPipelineSource, Go: true},
		{RelPath: "protocol/productionreadiness_generated.go", Content: productionReadinessSource, Go: true},
		{RelPath: "protocol/concretelocaladapter_generated.go", Content: concreteLocalAdapterSource, Go: true},
		{RelPath: "protocol/localprotocoladapter_generated.go", Content: localProtocolAdapterSource, Go: true},
		{RelPath: "protocol/loopbackrelay_generated.go", Content: loopbackRelaySource, Go: true},
		{RelPath: "protocol/labegress_generated.go", Content: labEgressSource, Go: true},
		{RelPath: "protocol/carrierreadiness_generated.go", Content: carrierReadinessSource, Go: true},
		{RelPath: "protocol/httpscarrierreview_generated.go", Content: httpsCarrierReviewSource, Go: true},
		{RelPath: "protocol/httpslikecarrier_generated.go", Content: httpsLikeCarrierSource, Go: true},
		{RelPath: "protocol/httpscarrieradversary_generated.go", Content: httpsCarrierAdversarySource, Go: true},
		{RelPath: "protocol/constrainedcarrierreview_generated.go", Content: constrainedCarrierReviewSource, Go: true},
		{RelPath: "protocol/constrainedcarrier_generated.go", Content: constrainedCarrierSource, Go: true},
		{RelPath: "protocol/multicarrierselect_generated.go", Content: multiCarrierSelectSource, Go: true},
		{RelPath: "protocol/carriercollapse_generated.go", Content: carrierCollapseSource, Go: true},
		{RelPath: "protocol/localproxyadapterreview_generated.go", Content: localProxyAdapterReviewSource, Go: true},
		{RelPath: "protocol/localproxyadapter_generated.go", Content: localProxyAdapterSource, Go: true},
		{RelPath: "protocol/vpnsemantics_generated.go", Content: vpnSemanticsSource, Go: true},
		{RelPath: "protocol/localvpnadapter_generated.go", Content: localVPNAdapterSource, Go: true},
		{RelPath: "protocol/relayprocess_generated.go", Content: relayProcessSource, Go: true},
		{RelPath: "protocol/scheduler_generated.go", Content: scheduler, Go: true},
		{RelPath: "protocol/invalid_input_generated.go", Content: invalid, Go: true},
		{RelPath: "protocol/auth_generated.go", Content: auth, Go: true},
		{RelPath: "protocol/protocol.go", Content: protocol, Go: true},
		{RelPath: "protocol/trace_capture_generated.go", Content: traceCapture, Go: true},
		{RelPath: "protocol/protocol_test.go", Content: testSource, Go: true},
		{RelPath: "protocol/multistream_test.go", Content: multiStreamTestSource, Go: true},
		{RelPath: "protocol/proxysem_test.go", Content: proxySemTestSource, Go: true},
		{RelPath: "protocol/proxyadversary_test.go", Content: proxySemAdversaryTestSource, Go: true},
		{RelPath: "protocol/carrier_test.go", Content: carrierTestSource, Go: true},
		{RelPath: "protocol/carrieradversary_test.go", Content: carrierAdversaryTestSource, Go: true},
		{RelPath: "protocol/security_test.go", Content: securityTestSource, Go: true},
		{RelPath: "protocol/securityadversary_test.go", Content: securityAdversaryTestSource, Go: true},
		{RelPath: "protocol/runtime_test.go", Content: runtimeTestSource, Go: true},
		{RelPath: "protocol/runtimeadversary_test.go", Content: runtimeAdversaryTestSource, Go: true},
		{RelPath: "protocol/hardening_test.go", Content: hardeningTestSource, Go: true},
		{RelPath: "protocol/adapter_test.go", Content: adapterTestSource, Go: true},
		{RelPath: "protocol/adapteradversary_test.go", Content: adapterAdversaryTestSource, Go: true},
		{RelPath: "protocol/localadapter_test.go", Content: localAdapterTestSource, Go: true},
		{RelPath: "protocol/localadapteradversary_test.go", Content: localAdapterAdversaryTestSource, Go: true},
		{RelPath: "protocol/bytetransport_test.go", Content: byteTransportTestSource, Go: true},
		{RelPath: "protocol/bytetransportadversary_test.go", Content: byteTransportAdversaryTestSource, Go: true},
		{RelPath: "protocol/bytepath_fixture_test.go", Content: bytePathFixtureTestSource, Go: true},
		{RelPath: "protocol/bytepath_parity_test.go", Content: bytePathParityTestSource, Go: true},
		{RelPath: "protocol/protocorpus_test.go", Content: protocolCorpusTestSource, Go: true},
		{RelPath: "protocol/wirefeatures_test.go", Content: wireFeaturesTestSource, Go: true},
		{RelPath: "protocol/wiregen_test.go", Content: wireGenTestSource, Go: true},
		{RelPath: "protocol/wiregen_parity_test.go", Content: wireGenParityTestSource, Go: true},
		{RelPath: "protocol/wiregenfeatures_test.go", Content: wireGenFeaturesTestSource, Go: true},
		{RelPath: "protocol/wireeval_test.go", Content: wireEvalTestSource, Go: true},
		{RelPath: "protocol/wireeval_export_test.go", Content: wireEvalExportTestSource, Go: true},
		{RelPath: "protocol/wireeval_parity_test.go", Content: wireEvalParityTestSource, Go: true},
		{RelPath: "protocol/hostdetect_test.go", Content: hostDetectTestSource, Go: true},
		{RelPath: "protocol/hostdetect_parity_test.go", Content: hostDetectParityTestSource, Go: true},
		{RelPath: "protocol/hostdetect_hygiene_test.go", Content: hostDetectHygieneTestSource, Go: true},
		{RelPath: "protocol/relayfleet_test.go", Content: relayFleetTestSource, Go: true},
		{RelPath: "protocol/relayfleet_parity_test.go", Content: relayFleetParityTestSource, Go: true},
		{RelPath: "protocol/relayfleet_hygiene_test.go", Content: relayFleetHygieneTestSource, Go: true},
		{RelPath: "protocol/proxyingress_test.go", Content: proxyIngressTestSource, Go: true},
		{RelPath: "protocol/proxyingress_parity_test.go", Content: proxyIngressParityTestSource, Go: true},
		{RelPath: "protocol/proxyingress_hygiene_test.go", Content: proxyIngressHygieneTestSource, Go: true},
		{RelPath: "protocol/localproxyingress_test.go", Content: localProxyIngressTestSource, Go: true},
		{RelPath: "protocol/localproxyingress_parity_test.go", Content: localProxyIngressParityTestSource, Go: true},
		{RelPath: "protocol/localproxyingress_hygiene_test.go", Content: localProxyIngressHygieneTestSource, Go: true},
		{RelPath: "protocol/localproxyingressadv_test.go", Content: localProxyIngressAdvTestSource, Go: true},
		{RelPath: "protocol/localproxyingressadv_parity_test.go", Content: localProxyIngressAdvParityTestSource, Go: true},
		{RelPath: "protocol/localproxyingressadv_hygiene_test.go", Content: localProxyIngressAdvHygieneTestSource, Go: true},
		{RelPath: "protocol/adaptivepath_test.go", Content: adaptivePathTestSource, Go: true},
		{RelPath: "protocol/adaptivepath_parity_test.go", Content: adaptivePathParityTestSource, Go: true},
		{RelPath: "protocol/adaptivepath_hygiene_test.go", Content: adaptivePathHygieneTestSource, Go: true},
		{RelPath: "protocol/transportbundle_test.go", Content: transportBundleTestSource, Go: true},
		{RelPath: "protocol/transportbundle_parity_test.go", Content: transportBundleParityTestSource, Go: true},
		{RelPath: "protocol/transportbundle_hygiene_test.go", Content: transportBundleHygieneTestSource, Go: true},
		{RelPath: "protocol/pathrace_test.go", Content: pathRaceTestSource, Go: true},
		{RelPath: "protocol/pathrace_parity_test.go", Content: pathRaceParityTestSource, Go: true},
		{RelPath: "protocol/pathrace_hygiene_test.go", Content: pathRaceHygieneTestSource, Go: true},
		{RelPath: "protocol/pathhealth_test.go", Content: pathHealthTestSource, Go: true},
		{RelPath: "protocol/pathhealth_parity_test.go", Content: pathHealthParityTestSource, Go: true},
		{RelPath: "protocol/pathhealth_hygiene_test.go", Content: pathHealthHygieneTestSource, Go: true},
		{RelPath: "protocol/carrierreview_test.go", Content: carrierReviewTestSource, Go: true},
		{RelPath: "protocol/carrierreview_parity_test.go", Content: carrierReviewParityTestSource, Go: true},
		{RelPath: "protocol/carrierreview_hygiene_test.go", Content: carrierReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/measurementreview_test.go", Content: measurementReviewTestSource, Go: true},
		{RelPath: "protocol/measurementreview_parity_test.go", Content: measurementReviewParityTestSource, Go: true},
		{RelPath: "protocol/measurementreview_hygiene_test.go", Content: measurementReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/proxyegress_test.go", Content: proxyEgressTestSource, Go: true},
		{RelPath: "protocol/proxyegress_parity_test.go", Content: proxyEgressParityTestSource, Go: true},
		{RelPath: "protocol/proxyegress_hygiene_test.go", Content: proxyEgressHygieneTestSource, Go: true},
		{RelPath: "protocol/relaybridge_test.go", Content: relayBridgeTestSource, Go: true},
		{RelPath: "protocol/relaybridge_parity_test.go", Content: relayBridgeParityTestSource, Go: true},
		{RelPath: "protocol/relaybridge_hygiene_test.go", Content: relayBridgeHygieneTestSource, Go: true},
		{RelPath: "protocol/localpipeline_test.go", Content: localPipelineTestSource, Go: true},
		{RelPath: "protocol/localpipeline_parity_test.go", Content: localPipelineParityTestSource, Go: true},
		{RelPath: "protocol/localpipeline_hygiene_test.go", Content: localPipelineHygieneTestSource, Go: true},
		{RelPath: "protocol/productionreadiness_test.go", Content: productionReadinessTestSource, Go: true},
		{RelPath: "protocol/productionreadiness_parity_test.go", Content: productionReadinessParityTestSource, Go: true},
		{RelPath: "protocol/productionreadiness_hygiene_test.go", Content: productionReadinessHygieneTestSource, Go: true},
		{RelPath: "protocol/concretelocaladapter_test.go", Content: concreteLocalAdapterTestSource, Go: true},
		{RelPath: "protocol/concretelocaladapter_parity_test.go", Content: concreteLocalAdapterParityTestSource, Go: true},
		{RelPath: "protocol/concretelocaladapter_hygiene_test.go", Content: concreteLocalAdapterHygieneTestSource, Go: true},
		{RelPath: "protocol/localprotocoladapter_test.go", Content: localProtocolAdapterTestSource, Go: true},
		{RelPath: "protocol/localprotocoladapter_parity_test.go", Content: localProtocolAdapterParityTestSource, Go: true},
		{RelPath: "protocol/localprotocoladapter_hygiene_test.go", Content: localProtocolAdapterHygieneTestSource, Go: true},
		{RelPath: "protocol/loopbackrelay_test.go", Content: loopbackRelayTestSource, Go: true},
		{RelPath: "protocol/loopbackrelay_parity_test.go", Content: loopbackRelayParityTestSource, Go: true},
		{RelPath: "protocol/loopbackrelay_hygiene_test.go", Content: loopbackRelayHygieneTestSource, Go: true},
		{RelPath: "protocol/labegress_test.go", Content: labEgressTestSource, Go: true},
		{RelPath: "protocol/labegress_parity_test.go", Content: labEgressParityTestSource, Go: true},
		{RelPath: "protocol/labegress_hygiene_test.go", Content: labEgressHygieneTestSource, Go: true},
		{RelPath: "protocol/carrierreadiness_test.go", Content: carrierReadinessTestSource, Go: true},
		{RelPath: "protocol/carrierreadiness_parity_test.go", Content: carrierReadinessParityTestSource, Go: true},
		{RelPath: "protocol/carrierreadiness_hygiene_test.go", Content: carrierReadinessHygieneTestSource, Go: true},
		{RelPath: "protocol/httpscarrierreview_test.go", Content: httpsCarrierReviewTestSource, Go: true},
		{RelPath: "protocol/httpscarrierreview_parity_test.go", Content: httpsCarrierReviewParityTestSource, Go: true},
		{RelPath: "protocol/httpscarrierreview_hygiene_test.go", Content: httpsCarrierReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/httpslikecarrier_test.go", Content: httpsLikeCarrierTestSource, Go: true},
		{RelPath: "protocol/httpslikecarrier_parity_test.go", Content: httpsLikeCarrierParityTestSource, Go: true},
		{RelPath: "protocol/httpslikecarrier_hygiene_test.go", Content: httpsLikeCarrierHygieneTestSource, Go: true},
		{RelPath: "protocol/httpscarrieradversary_test.go", Content: httpsCarrierAdversaryTestSource, Go: true},
		{RelPath: "protocol/httpscarrieradversary_parity_test.go", Content: httpsCarrierAdversaryParityTestSource, Go: true},
		{RelPath: "protocol/httpscarrieradversary_hygiene_test.go", Content: httpsCarrierAdversaryHygieneTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrierreview_test.go", Content: constrainedCarrierReviewTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrierreview_parity_test.go", Content: constrainedCarrierReviewParityTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrierreview_hygiene_test.go", Content: constrainedCarrierReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrier_test.go", Content: constrainedCarrierTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrier_parity_test.go", Content: constrainedCarrierParityTestSource, Go: true},
		{RelPath: "protocol/constrainedcarrier_hygiene_test.go", Content: constrainedCarrierHygieneTestSource, Go: true},
		{RelPath: "protocol/multicarrierselect_test.go", Content: multiCarrierSelectTestSource, Go: true},
		{RelPath: "protocol/multicarrierselect_parity_test.go", Content: multiCarrierSelectParityTestSource, Go: true},
		{RelPath: "protocol/multicarrierselect_hygiene_test.go", Content: multiCarrierSelectHygieneTestSource, Go: true},
		{RelPath: "protocol/carriercollapse_test.go", Content: carrierCollapseTestSource, Go: true},
		{RelPath: "protocol/carriercollapse_parity_test.go", Content: carrierCollapseParityTestSource, Go: true},
		{RelPath: "protocol/carriercollapse_hygiene_test.go", Content: carrierCollapseHygieneTestSource, Go: true},
		{RelPath: "protocol/localproxyadapterreview_test.go", Content: localProxyAdapterReviewTestSource, Go: true},
		{RelPath: "protocol/localproxyadapterreview_parity_test.go", Content: localProxyAdapterReviewParityTestSource, Go: true},
		{RelPath: "protocol/localproxyadapterreview_hygiene_test.go", Content: localProxyAdapterReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/localproxyadapter_test.go", Content: localProxyAdapterTestSource, Go: true},
		{RelPath: "protocol/localproxyadapter_parity_test.go", Content: localProxyAdapterParityTestSource, Go: true},
		{RelPath: "protocol/localproxyadapter_hygiene_test.go", Content: localProxyAdapterHygieneTestSource, Go: true},
		{RelPath: "protocol/vpnsemantics_test.go", Content: vpnSemanticsTestSource, Go: true},
		{RelPath: "protocol/vpnsemantics_parity_test.go", Content: vpnSemanticsParityTestSource, Go: true},
		{RelPath: "protocol/vpnsemantics_hygiene_test.go", Content: vpnSemanticsHygieneTestSource, Go: true},
		{RelPath: "protocol/localvpnadapter_test.go", Content: localVPNAdapterTestSource, Go: true},
		{RelPath: "protocol/localvpnadapter_parity_test.go", Content: localVPNAdapterParityTestSource, Go: true},
		{RelPath: "protocol/localvpnadapter_hygiene_test.go", Content: localVPNAdapterHygieneTestSource, Go: true},
		{RelPath: "protocol/relayprocess_test.go", Content: relayProcessTestSource, Go: true},
		{RelPath: "protocol/relayprocess_parity_test.go", Content: relayProcessParityTestSource, Go: true},
		{RelPath: "protocol/relayprocess_hygiene_test.go", Content: relayProcessHygieneTestSource, Go: true},
		{RelPath: "protocol/keyexchangeplan_generated.go", Content: keyExchangePlanSource, Go: true},
		{RelPath: "protocol/keyexchangeplan_test.go", Content: keyExchangePlanTestSource, Go: true},
		{RelPath: "protocol/keyexchangeplan_parity_test.go", Content: keyExchangePlanParityTestSource, Go: true},
		{RelPath: "protocol/keyexchangeplan_hygiene_test.go", Content: keyExchangePlanHygieneTestSource, Go: true},
		{RelPath: "protocol/relayauthplan_generated.go", Content: relayAuthPlanSource, Go: true},
		{RelPath: "protocol/relayauthplan_test.go", Content: relayAuthPlanTestSource, Go: true},
		{RelPath: "protocol/relayauthplan_parity_test.go", Content: relayAuthPlanParityTestSource, Go: true},
		{RelPath: "protocol/relayauthplan_hygiene_test.go", Content: relayAuthPlanHygieneTestSource, Go: true},
		{RelPath: "protocol/operationalhardening_generated.go", Content: operationalHardeningSource, Go: true},
		{RelPath: "protocol/operationalhardening_test.go", Content: operationalHardeningTestSource, Go: true},
		{RelPath: "protocol/operationalhardening_parity_test.go", Content: operationalHardeningParityTestSource, Go: true},
		{RelPath: "protocol/operationalhardening_hygiene_test.go", Content: operationalHardeningHygieneTestSource, Go: true},
		{RelPath: "protocol/androidreview_generated.go", Content: androidReviewSource, Go: true},
		{RelPath: "protocol/androidreview_test.go", Content: androidReviewTestSource, Go: true},
		{RelPath: "protocol/androidreview_parity_test.go", Content: androidReviewParityTestSource, Go: true},
		{RelPath: "protocol/androidreview_hygiene_test.go", Content: androidReviewHygieneTestSource, Go: true},
		{RelPath: "protocol/androidruntime_generated.go", Content: androidRuntimeSource, Go: true},
		{RelPath: "protocol/androidruntime_test.go", Content: androidRuntimeTestSource, Go: true},
		{RelPath: "protocol/androidruntime_parity_test.go", Content: androidRuntimeParityTestSource, Go: true},
		{RelPath: "protocol/androidruntime_hygiene_test.go", Content: androidRuntimeHygieneTestSource, Go: true},
		{RelPath: "protocol/androidvpnservice_generated.go", Content: androidVPNServiceSource, Go: true},
		{RelPath: "protocol/androidvpnservice_test.go", Content: androidVPNServiceTestSource, Go: true},
		{RelPath: "protocol/androidvpnservice_parity_test.go", Content: androidVPNServiceParityTestSource, Go: true},
		{RelPath: "protocol/androidvpnservice_hygiene_test.go", Content: androidVPNServiceHygieneTestSource, Go: true},
		{RelPath: "protocol/androidcarrier_generated.go", Content: androidCarrierSource, Go: true},
		{RelPath: "protocol/androidcarrier_test.go", Content: androidCarrierTestSource, Go: true},
		{RelPath: "protocol/androidcarrier_parity_test.go", Content: androidCarrierParityTestSource, Go: true},
		{RelPath: "protocol/androidcarrier_hygiene_test.go", Content: androidCarrierHygieneTestSource, Go: true},
		{RelPath: "protocol/protocol_bench_test.go", Content: benchSource, Go: true},
		{RelPath: "protocol/probe_test.go", Content: probeSource, Go: true},
		{RelPath: "cmd/generated-client/main.go", Content: client, Go: true},
		{RelPath: "cmd/generated-server/main.go", Content: server, Go: true},
		{RelPath: "cmd/generated-echo/main.go", Content: echo, Go: true},
		{RelPath: "cmd/generated-trace/main.go", Content: traceCommand, Go: true},
	}, nil
}

func renderCommand(modulePath, name string) (string, error) {
	importPath := modulePath + "/protocol"
	switch name {
	case "generated-client":
		return renderGo(genTmpl207, quote(importPath))
	case "generated-server":
		return renderGo(genTmpl208, quote(importPath))
	case "generated-echo":
		return renderGo(genTmpl209, quote(importPath))
	case "generated-trace":
		return renderGo(genTmpl210, quote(importPath))
	default:
		return "", fmt.Errorf("unknown generated command %q", name)
	}
}

func derivedAuthTestKeyHex(id string, seed int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("test-only-key:%s:%d", id, seed)))
	return hex.EncodeToString(sum[:])
}

func findRepoRoot() (string, error) {
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
			return "", fmt.Errorf("could not find repository go.mod")
		}
		wd = parent
	}
}

func IsGeneratedWrapperOnly(source string) bool {
	markers := []string{"LoadProfile", "cmd/kclient", "cmd/kserver", "kclient", "kserver"}
	for _, marker := range markers {
		if strings.Contains(source, marker) {
			return true
		}
	}
	return false
}

func relayFleetAssignmentMode(seed int64) string {
	modes := []string{"one_profile_per_relay", "profile_rotation", "family_rotation", "wire_policy_rotation", "risk_aware_profile_refresh"}
	return modes[int(seed)%len(modes)]
}

func relayFleetChurnMode(seed int64) string {
	modes := []string{"fixed_interval_churn", "risk_threshold_churn", "observation_count_churn", "profile_reuse_churn", "mixed_policy_churn"}
	return modes[int(seed)%len(modes)]
}

func relayFleetMigrationMode(seed int64) string {
	modes := []string{"graceful_profile_migration", "relay_to_relay_migration", "risk_triggered_migration", "session_boundary_migration"}
	return modes[int(seed)%len(modes)]
}

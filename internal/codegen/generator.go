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
	"kurdistan/internal/androidcarrier"
	"kurdistan/internal/androidreview"
	"kurdistan/internal/androidruntime"
	"kurdistan/internal/androidvpnservice"
	"kurdistan/internal/carriercollapse"
	"kurdistan/internal/carrierreadiness"
	"kurdistan/internal/carrierreview"
	"kurdistan/internal/concretelocaladapter"
	"kurdistan/internal/constrainedcarrier"
	"kurdistan/internal/constrainedcarrierreview"
	"kurdistan/internal/httpscarrieradversary"
	"kurdistan/internal/httpscarrierreview"
	"kurdistan/internal/httpslikecarrier"
	"kurdistan/internal/keyexchangeplan"
	"kurdistan/internal/labegress"
	"kurdistan/internal/localpipeline"
	"kurdistan/internal/localprotocoladapter"
	"kurdistan/internal/localproxyadapter"
	"kurdistan/internal/localproxyadapterreview"
	"kurdistan/internal/localproxyingressadversary"
	"kurdistan/internal/localvpnadapter"
	"kurdistan/internal/loopbackrelay"
	"kurdistan/internal/measurementreview"
	"kurdistan/internal/multicarrierselect"
	"kurdistan/internal/operationalhardening"
	"kurdistan/internal/pathhealth"
	"kurdistan/internal/pathrace"
	"kurdistan/internal/productionreadiness"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/proxyegress"
	"kurdistan/internal/proxyingressreview"
	"kurdistan/internal/relayauthplan"
	"kurdistan/internal/relaybridge"
	"kurdistan/internal/relayprocess"
	"kurdistan/internal/transportbundle"
	"kurdistan/internal/vpnsemantics"
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
	profileStatic, err := renderGo(`package protocol

import "kurdistan/internal/protocol/ir"

const ProfileID = %[1]s
const ProfileSeed int64 = %[2]d
const GenerationHash = %[3]s
const GeneratorVersion = %[4]s
const SourceBackend = %[5]s

func StaticProfile() *ir.Profile {
	p := generatedProfileWithoutAuthKey()
	p.Auth.TestKeyHex = DerivedAuthTestKeyHex()
	return &p
}

func generatedProfileWithoutAuthKey() ir.Profile {
	return %[6]s
}
`, quote(p.ID), p.Seed, quote(p.GenerationHash), quote(Version), quote(SourceBackend), profileLiteral(p))
	if err != nil {
		return nil, err
	}

	states, err := renderGo(`package protocol

%[1]s

type GeneratedTransition struct {
	From         string
	To           string
	Role         string
	OnMessage    string
	EmitsMessage string
	RequiresAuth bool
}

type GeneratedFirstContactStep struct {
	Index       int
	Role        string
	Direction   string
	Message     string
	WireSymbol  string
	FromState   string
	ToState     string
	PayloadSize int
	Proof       bool
	Decoy       bool
}

var transitionTable = %[2]s

var firstContactSequence = %[3]s

func TransitionTable() []GeneratedTransition {
	out := make([]GeneratedTransition, len(transitionTable))
	copy(out, transitionTable)
	return out
}

func FirstContactSequence() []GeneratedFirstContactStep {
	out := make([]GeneratedFirstContactStep, len(firstContactSequence))
	copy(out, firstContactSequence)
	return out
}
`, stateConsts(p.States), transitionsLiteral(p.Transitions), firstContactLiteral(p.FirstContact.Steps))
	if err != nil {
		return nil, err
	}

	framing, err := renderGo(`package protocol

import (
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/ir"
)

const FrameLengthMode = %[1]s
const FrameTypeMode = %[2]s
const FrameFragmentationMode = %[3]s
const FrameChecksumMode = %[4]s
const FramePaddingPlacement = %[5]s

var HeaderOrder = %[6]s
var semanticWireSymbols = %[7]s
var messageBounds = %[8]s

type GeneratedMessageBounds struct {
	Direction      string
	MinPayloadSize int
	MaxPayloadSize int
}

func SemanticWireSymbols() map[string]string {
	out := make(map[string]string, len(semanticWireSymbols))
	for semantic, wire := range semanticWireSymbols {
		out[semantic] = wire
	}
	return out
}

func EncodeData(payload []byte) ([][]byte, error) {
	return framing.EncodeOperation(StaticProfile(), framing.Operation{Semantic: ir.SemanticData, StreamID: DefaultStreamID, Payload: payload}, ProfileSeed+1)
}

func DecodeFrames(frames [][]byte) (framing.Operation, []framing.DecodedFrame, error) {
	return framing.DecodeFrames(StaticProfile(), frames)
}
`, quote(p.FrameGrammar.LengthMode), quote(p.FrameGrammar.TypeMode), quote(p.FrameGrammar.FragmentationMode), quote(p.FrameGrammar.ChecksumMode), quote(p.FrameGrammar.PaddingPlacement), quoteSlice(p.FrameGrammar.HeaderOrder), semanticWireMap(p.Messages), messageBounds(p.Messages))
	if err != nil {
		return nil, err
	}

	streamSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/observe/trace"
)

const DefaultStreamID uint32 = 1
const StreamIDStrategy = %[1]s
const StreamIDEncodingMode = %[2]s
const StreamMaxConcurrentStreams = %[3]d
const StreamInitialWindowBytes = %[4]d
const StreamInitialSessionWindowBytes = %[5]d
const StreamWindowUpdatePolicy = %[6]s
const StreamPriorityPolicy = %[7]s
const StreamClosePolicy = %[8]s
const StreamResetPolicy = %[9]s
const StreamMaxID uint32 = %[10]d

func MultiStreamDemo(ctx context.Context, streamCount int) (relay.MultiStreamResult, []ktrace.Event, error) {
	if streamCount <= 0 {
		streamCount = 3
	}
	if streamCount > StreamMaxConcurrentStreams {
		streamCount = StreamMaxConcurrentStreams
	}
	requests := relay.DefaultMultiStreamDemoRequests(streamCount)
	return relay.SimulateMultiStreamEcho(ctx, StaticProfile(), requests)
}

func CaptureMultiStreamTrace(ctx context.Context, streamCount int) ([]ktrace.Event, relay.MultiStreamResult, error) {
	result, events, err := MultiStreamDemo(ctx, streamCount)
	return events, result, err
}
`, quote(p.Stream.IDStrategy), quote(p.Stream.IDEncodingMode), p.Stream.MaxConcurrentStreams, p.Stream.InitialStreamWindowBytes, p.Stream.InitialSessionWindowBytes, quote(p.Stream.WindowUpdatePolicy), quote(p.Stream.PriorityPolicy), quote(p.Stream.ClosePolicy), quote(p.Stream.ResetPolicy), p.Stream.MaxStreamID)
	if err != nil {
		return nil, err
	}

	proxySemSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/proxyadversary"
	ktrace "kurdistan/internal/observe/trace"
)

const ProxyRelayIntentEncoding = %[1]s
const ProxyTargetDescriptorEncoding = %[2]s
const ProxyRequestClassEncoding = %[3]s
const ProxyResponseModeEncoding = %[4]s
const ProxyTargetErrorPolicy = %[5]s
const ProxyTargetClosePolicy = %[6]s
const ProxyTargetResetPolicy = %[7]s
const ProxyTargetMetadataPolicy = %[8]s
const ProxyRelayOpenOrderingPolicy = %[9]s
const ProxyRelayIntentPaddingPolicy = %[10]s
const ProxyTargetClassMapping = %[11]s
const ProxyMaxRequestBytes = %[12]d
const ProxyMaxResponseBytes = %[13]d

var ProxyTargetClasses = %[14]s
var ProxySemanticWireSymbols = %[15]s

type ProxySemDemoResult struct {
	Streams            int      `+"`json:\"streams\"`"+`
	TargetClasses      []string `+"`json:\"target_classes\"`"+`
	TargetErrors       int      `+"`json:\"target_errors\"`"+`
	TargetResets       int      `+"`json:\"target_resets\"`"+`
	BackpressureEvents int      `+"`json:\"backpressure_events\"`"+`
	EventCount          int      `+"`json:\"event_count\"`"+`
}

func ProxySemDemo(ctx context.Context, targets string, streamCount int) (ProxySemDemoResult, []ktrace.Event, error) {
	if streamCount <= 0 {
		streamCount = 4
	}
	if streamCount > StreamMaxConcurrentStreams {
		streamCount = StreamMaxConcurrentStreams
	}
	scenario := proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets)
	if targets == "small" {
		scenario = proxyadversary.DefaultScenario(proxyadversary.ScenarioManySmallRequests)
	}
	scenario.StreamCount = streamCount
	run, err := proxyadversary.RunScenario(ctx, StaticProfile(), scenario)
	if err != nil {
		return ProxySemDemoResult{}, nil, err
	}
	return ProxySemDemoResult{
		Streams:            streamCount,
		TargetClasses:      run.TargetClasses,
		TargetErrors:       run.Checks.TargetErrorCount,
		TargetResets:       run.Checks.TargetResetCount,
		BackpressureEvents: run.Checks.BackpressureEvents,
		EventCount:          len(run.Events),
	}, run.Events, nil
}

func CaptureProxySemTrace(ctx context.Context, targets string, streamCount int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := ProxySemDemo(ctx, targets, streamCount)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	summary := TraceCaptureSummary{
		ProfileID:      ProfileID,
		EventCount:     len(events),
		DataEventCount: result.Streams,
	}
	return events, summary, nil
}
`, quote(p.ProxySemantics.RelayIntentEncoding), quote(p.ProxySemantics.TargetDescriptorEncoding), quote(p.ProxySemantics.RequestClassEncoding), quote(p.ProxySemantics.ResponseModeEncoding), quote(p.ProxySemantics.TargetErrorPolicy), quote(p.ProxySemantics.TargetClosePolicy), quote(p.ProxySemantics.TargetResetPolicy), quote(p.ProxySemantics.TargetMetadataPolicy), quote(p.ProxySemantics.RelayOpenOrderingPolicy), quote(p.ProxySemantics.RelayIntentPaddingPolicy), quote(p.ProxySemantics.TargetClassMapping), p.ProxySemantics.MaxRequestBytes, p.ProxySemantics.MaxResponseBytes, quoteSlice(p.ProxySemantics.TargetClasses), proxySemanticWireMap(p.Messages))
	if err != nil {
		return nil, err
	}

	carrierSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/carrieradversary"
	ktrace "kurdistan/internal/observe/trace"
)

const CarrierFamily = %[1]s
const CarrierEnvelopeEncoding = %[2]s
const CarrierFlushPolicy = %[3]s
const CarrierBatchPolicy = %[4]s
const CarrierChunkingPolicy = %[5]s
const CarrierReliabilityPolicy = %[6]s
const CarrierReorderPolicy = %[7]s
const CarrierBackpressurePolicy = %[8]s
const CarrierPriorityMappingPolicy = %[9]s
const CarrierEnvelopePaddingPolicy = %[10]s
const CarrierTimingBucketPolicy = %[11]s
const CarrierMaxEnvelopeBytes = %[12]d
const CarrierMaxMessagesPerEnvelope = %[13]d
const CarrierMaxQueueDepth = %[14]d
const CarrierMaxRetryCount = %[15]d

type CarrierDemoResult struct {
	Family             string `+"`json:\"family\"`"+`
	Scenario           string `+"`json:\"scenario\"`"+`
	EnvelopeCount      int    `+"`json:\"envelope_count\"`"+`
	SemanticMessages    int    `+"`json:\"semantic_messages\"`"+`
	BackpressureEvents int    `+"`json:\"backpressure_events\"`"+`
	ReorderEvents      int    `+"`json:\"reorder_events\"`"+`
	RetryEvents        int    `+"`json:\"retry_events\"`"+`
	EventCount         int    `+"`json:\"event_count\"`"+`
}

func CarrierDemo(ctx context.Context, carrierName string, streamCount int) (CarrierDemoResult, []ktrace.Event, error) {
	if streamCount <= 0 {
		streamCount = 4
	}
	if streamCount > StreamMaxConcurrentStreams {
		streamCount = StreamMaxConcurrentStreams
	}
	scenario := carrieradversary.DefaultScenario(carrieradversary.ScenarioMixedCarrierMatrix)
	if carrierName != "" && carrierName != "mixed" {
		scenario.CarrierFamily = carrierName
	}
	scenario.StreamCount = streamCount
	run, err := carrieradversary.RunScenario(ctx, StaticProfile(), scenario)
	if err != nil {
		return CarrierDemoResult{}, nil, err
	}
	return CarrierDemoResult{
		Family:             run.Family,
		Scenario:           run.Scenario,
		EnvelopeCount:      run.Checks.EnvelopeCount,
		SemanticMessages:    run.Checks.SemanticMessageCount,
		BackpressureEvents: run.Checks.BackpressureEvents,
		ReorderEvents:      run.Checks.ReorderEvents,
		RetryEvents:        run.Checks.RetryEvents,
		EventCount:         len(run.Events),
	}, run.Events, nil
}

func CaptureCarrierTrace(ctx context.Context, carrierName string, streamCount int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := CarrierDemo(ctx, carrierName, streamCount)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	summary := TraceCaptureSummary{
		ProfileID:      ProfileID,
		EventCount:     len(events),
		DataEventCount: result.SemanticMessages,
	}
	return events, summary, nil
}
`, quote(p.CarrierPolicy.CarrierFamily), quote(p.CarrierPolicy.EnvelopeEncoding), quote(p.CarrierPolicy.FlushPolicy), quote(p.CarrierPolicy.BatchPolicy), quote(p.CarrierPolicy.ChunkingPolicy), quote(p.CarrierPolicy.ReliabilityPolicy), quote(p.CarrierPolicy.ReorderPolicy), quote(p.CarrierPolicy.BackpressurePolicy), quote(p.CarrierPolicy.PriorityMappingPolicy), quote(p.CarrierPolicy.EnvelopePaddingPolicy), quote(p.CarrierPolicy.TimingBucketPolicy), p.CarrierPolicy.MaxEnvelopeBytes, p.CarrierPolicy.MaxMessagesPerEnvelope, p.CarrierPolicy.MaxCarrierQueueDepth, p.CarrierPolicy.MaxRetryCount)
	if err != nil {
		return nil, err
	}

	securitySource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/crypto/security"
	ktrace "kurdistan/internal/observe/trace"
)

const SecurityVersion = %[1]s
const SecurityTranscriptMode = %[2]s
const SecurityKDFSuite = %[3]s
const SecurityAEADSuite = %[4]s
const SecurityMACSuite = %[5]s
const SecurityNonceMode = %[6]s
const SecurityReplayPolicy = %[7]s
const SecurityReplayWindowSize = %[8]d
const SecurityDowngradePolicy = %[9]s
const SecurityCapabilityNegotiationPolicy = %[10]s
const SecurityProfileCompatibilityPolicy = %[11]s
const SecurityKeyRotationPolicy = %[12]s
const SecurityConfigValidationPolicy = %[13]s
const SecuritySecureEnvelopeMode = %[14]s
const SecurityMaxSessionMessages = %[15]d
const SecurityMaxKeyLifetimeMessages = %[16]d

var RequiredCapabilities = %[17]s

func SecuritySuite() security.Suite {
	return security.Suite{KDF: SecurityKDFSuite, AEAD: SecurityAEADSuite, MAC: SecurityMACSuite, Transcript: "transcript_sha256_v1"}
}

func SecurityTranscriptInput() (security.TranscriptInput, error) {
	p := StaticProfile()
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.TranscriptInput{}, err
	}
	return security.TranscriptInput{
		ProfileID:           ProfileID,
		ProfileHash:         hash,
		CompilerHash:        GeneratorVersion,
		SemanticMappingHash: GenerationHash,
		FSMPolicy:           "generated-state-table",
		FramingPolicy:       FrameLengthMode + "/" + FrameTypeMode + "/" + FrameFragmentationMode,
		SchedulerPolicy:     SchedulerMode + "/" + SchedulerPriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        StreamIDStrategy + "/" + StreamPriorityPolicy + "/" + StreamWindowUpdatePolicy,
		ProxyPolicy:         ProxyTargetDescriptorEncoding + "/" + ProxyResponseModeEncoding,
		CarrierPolicy:       CarrierFamily + "/" + CarrierEnvelopeEncoding + "/" + CarrierFlushPolicy,
		Capabilities:        RequiredCapabilities,
		SessionNonce:        []byte("generated-security-session"),
		Suite:               SecuritySuite(),
		OrderedStatePath:    []string{FirstContactSequence()[0].FromState, FirstContactSequence()[len(FirstContactSequence())-1].ToState},
	}, nil
}

func SecurityContext() (security.SecurityContext, error) {
	input, err := SecurityTranscriptInput()
	if err != nil {
		return security.SecurityContext{}, err
	}
	return security.BuildContext(input)
}

func SecurityDemo(ctx context.Context, streams int) (SecurityDemoResult, []ktrace.Event, error) {
	_ = ctx
	if streams <= 0 {
		streams = 4
	}
	securityContext, err := SecurityContext()
	if err != nil {
		return SecurityDemoResult{}, nil, err
	}
	keys, err := security.DeriveKeySchedule([]byte("generated-security-demo-secret"), securityContext.TranscriptHash, securityContext.Suite)
	if err != nil {
		return SecurityDemoResult{}, nil, err
	}
	codec, err := security.NewEnvelopeCodec(securityContext, keys, "client")
	if err != nil {
		return SecurityDemoResult{}, nil, err
	}
	events := make([]ktrace.Event, 0, streams)
	for i := 0; i < streams; i++ {
		env, err := codec.Seal(security.EnvelopeMetadata{StreamID: uint64(i + 1), Semantic: "target_response", CarrierFamily: CarrierFamily, MetadataClass: "generated"}, make([]byte, 16+i))
		if err != nil {
			return SecurityDemoResult{}, nil, err
		}
		events = append(events, security.SecureEnvelopeTrace(securityContext, env))
	}
	return SecurityDemoResult{
		TranscriptHash: securityContext.TranscriptHash,
		CapabilityHash: securityContext.CapabilityHash,
		EnvelopeCount:  len(events),
	}, events, nil
}

func CaptureSecurityTrace(ctx context.Context, streamCount int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := SecurityDemo(ctx, streamCount)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.EnvelopeCount}, nil
}

type SecurityDemoResult struct {
	TranscriptHash string
	CapabilityHash string
	EnvelopeCount  int
}
`, quote(p.Security.SecurityVersion), quote(p.Security.TranscriptMode), quote(p.Security.KDFSuite), quote(p.Security.AEADSuite), quote(p.Security.MACSuite), quote(p.Security.NonceMode), quote(p.Security.ReplayPolicy), p.Security.ReplayWindowSize, quote(p.Security.DowngradePolicy), quote(p.Security.CapabilityNegotiationPolicy), quote(p.Security.ProfileCompatibilityPolicy), quote(p.Security.KeyRotationPolicy), quote(p.Security.ConfigValidationPolicy), quote(p.Security.SecureEnvelopeMode), p.Security.MaxSessionMessages, p.Security.MaxKeyLifetimeMessages, quoteSlice(p.Compatibility.RequiredCapabilities))
	if err != nil {
		return nil, err
	}

	runtimeSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/proxyadversary"
	kruntime "kurdistan/internal/runtime"
	ktrace "kurdistan/internal/observe/trace"
)

const RuntimeProfileID = %[1]s
const RuntimeProfileHash = %[2]s
const RuntimeCompatibilitySchema = %[3]s
const RuntimeSecurityVersion = %[4]s
const RuntimeCarrierPolicy = %[5]s
const RuntimeStreamPolicy = %[6]s
const RuntimeProxyPolicy = %[7]s
const RuntimeMaxSessions = 4
const RuntimeMaxStreams = %[8]d
const RuntimeMaxEvents = 4096
const RuntimeTracePayloadHygiene = true
const RuntimeTraceSecretHygiene = true

func RuntimeDemo(ctx context.Context, streams int) (kruntime.HarnessSummary, []ktrace.Event, error) {
	if streams <= 0 {
		streams = 4
	}
	return kruntime.RunLocalHarness(ctx, StaticProfile(), kruntime.HarnessOptions{
		Scenario: proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets),
		StreamCount: streams,
		ClientSecret: []byte("generated-runtime-demo-secret"),
		ServerSecret: []byte("generated-runtime-demo-secret"),
	})
}

func CaptureRuntimeTrace(ctx context.Context, streams int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := RuntimeDemo(ctx, streams)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.StreamsOpened}, nil
}
`, quote(p.ID), quote(p.GenerationHash), quote(p.Compatibility.SchemaVersion), quote(p.Security.SecurityVersion), quote(p.CarrierPolicy.CarrierFamily+"/"+p.CarrierPolicy.EnvelopeEncoding+"/"+p.CarrierPolicy.FlushPolicy), quote(p.Stream.IDStrategy+"/"+p.Stream.PriorityPolicy+"/"+p.Stream.WindowUpdatePolicy), quote(p.ProxySemantics.RelayIntentEncoding+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.ProxySemantics.ResponseModeEncoding), p.Stream.MaxConcurrentStreams)
	if err != nil {
		return nil, err
	}

	hardeningSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/hardening"
	ktrace "kurdistan/internal/observe/trace"
)

const HardeningProfileID = %[1]s
const HardeningProfileHash = %[2]s
const HardeningGeneratorVersion = %[3]s
const HardeningMaxFrameBytes = %[4]d
const HardeningMaxPayloadBytes = %[5]d
const HardeningMaxStreams = %[6]d
const HardeningMaxCarrierQueueDepth = %[7]d
const HardeningTracePayloadHygiene = true
const HardeningTraceSecretHygiene = true

type HardeningDemoResult struct {
	ProfileID      string `+"`json:\"profile_id\"`"+`
	ChecksRun      int    `+"`json:\"checks_run\"`"+`
	FailedChecks   int    `+"`json:\"failed_checks\"`"+`
	PayloadLogged  bool   `+"`json:\"payload_logged\"`"+`
	SecretLogged   bool   `+"`json:\"secret_logged\"`"+`
	Generator      string `+"`json:\"generator\"`"+`
}

func HardeningDemo(ctx context.Context, streams int) (HardeningDemoResult, []ktrace.Event, error) {
	if streams <= 0 {
		streams = 4
	}
	report := hardening.Run(ctx, []*ir.Profile{StaticProfile()}, hardening.Options{Mode: "generated", ProfileCount: 1})
	result, events, err := RuntimeDemo(ctx, streams)
	if err != nil {
		return HardeningDemoResult{}, nil, err
	}
	hygiene := hardening.ScanEvents(events)
	failed := len(report.FailedChecks)
	if !hygiene.Passed || result.PayloadLogged || result.SecretLogged {
		failed++
	}
	return HardeningDemoResult{
		ProfileID:     ProfileID,
		ChecksRun:     len(report.Results),
		FailedChecks:  failed,
		PayloadLogged: result.PayloadLogged,
		SecretLogged:  result.SecretLogged,
		Generator:     HardeningGeneratorVersion,
	}, events, nil
}

func CaptureHardeningTrace(ctx context.Context, streams int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := HardeningDemo(ctx, streams)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.ChecksRun, PayloadLogged: result.PayloadLogged || result.SecretLogged}, nil
}
`, quote(p.ID), quote(p.GenerationHash), quote(Version), p.Limits.MaxFrameBytes, p.Limits.MaxPayloadBytes, p.Stream.MaxConcurrentStreams, p.CarrierPolicy.MaxCarrierQueueDepth)
	if err != nil {
		return nil, err
	}

	adapterSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/adapter"
	"kurdistan/internal/adapteradversary"
	kruntime "kurdistan/internal/runtime"
	ktrace "kurdistan/internal/observe/trace"
)

const AdapterGeneratedProfileID = %[1]s
const AdapterFlowLifecyclePolicy = %[2]s
const AdapterRuntimeMappingPolicy = %[3]s
const AdapterTracePolicy = %[4]s
const AdapterErrorMappingPolicy = %[5]s
const AdapterBackpressurePolicy = %[6]s
const AdapterMaxFlows = %[7]d
const AdapterMaxFlowBytes = %[8]d
const AdapterMaxBufferedBytes = %[9]d
const AdapterMaxEvents = %[10]d
const AdapterTracePayloadHygiene = true
const AdapterTraceSecretHygiene = true

var AdapterRequiredCapabilities = %[11]s

func AdapterConfig() adapter.AdapterConfig {
	return adapter.AdapterConfig{
		Name: "generated-adapter",
		Kind: adapter.AdapterKindIngress,
		RuntimeID: "generated-runtime",
		MaxFlows: AdapterMaxFlows,
		MaxFlowBytes: AdapterMaxFlowBytes,
		MaxBufferedBytes: AdapterMaxBufferedBytes,
		MaxEvents: AdapterMaxEvents,
		TraceEnabled: true,
		Capabilities: append([]string(nil), AdapterRequiredCapabilities...),
	}
}

func AdapterDemo(ctx context.Context, flows int) (adapter.AdapterHarnessSummary, []ktrace.Event, error) {
	if flows <= 0 {
		flows = 4
	}
	if flows > AdapterMaxFlows {
		flows = AdapterMaxFlows
	}
	result, err := kruntime.RunAdapterBoundary(ctx, StaticProfile(), kruntime.AdapterBoundaryOptions{
		Scenario: "generated_adapter_demo",
		FlowCount: flows,
		BytesPerFlow: 256,
		Backpressure: flows > 1,
		MaxFlows: AdapterMaxFlows,
		MaxStreams: StreamMaxConcurrentStreams,
	})
	if err != nil {
		return adapter.AdapterHarnessSummary{}, nil, err
	}
	return result.Summary, result.Events, nil
}

func CaptureAdapterTrace(ctx context.Context, flows int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := AdapterDemo(ctx, flows)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.FlowsOpened, PayloadLogged: result.PayloadLogged || result.SecretLogged}, nil
}

func AdapterAdversaryDemo(ctx context.Context, scenario string) (adapteradversary.ScenarioRun, error) {
	if scenario == "" {
		scenario = adapteradversary.ScenarioManySmallFlows
	}
	return adapteradversary.RunScenario(ctx, StaticProfile(), adapteradversary.DefaultScenario(scenario)), nil
}
`, quote(p.ID), quote(p.AdapterPolicy.FlowLifecyclePolicy), quote(p.AdapterPolicy.RuntimeMappingPolicy), quote(p.AdapterPolicy.TracePolicy), quote(p.AdapterPolicy.ErrorMappingPolicy), quote(p.AdapterPolicy.BackpressurePolicy), p.AdapterPolicy.MaxFlows, p.AdapterPolicy.MaxFlowBytes, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxEvents, quoteSlice(p.AdapterPolicy.RequiredCapabilities))
	if err != nil {
		return nil, err
	}

	localAdapterMaxChunk := p.AdapterPolicy.MaxFlowBytes
	if localAdapterMaxChunk > 256*1024 {
		localAdapterMaxChunk = 256 * 1024
	}
	localAdapterSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/localadapter"
	"kurdistan/internal/localadapteradversary"
	ktrace "kurdistan/internal/observe/trace"
)

const LocalAdapterGeneratedProfileID = %[1]s
const LocalAdapterSourceModel = %[2]s
const LocalAdapterSinkModel = "memory_sink"
const LocalAdapterFlowLifecyclePolicy = %[3]s
const LocalAdapterRuntimeMappingPolicy = %[4]s
const LocalAdapterBackpressurePolicy = %[5]s
const LocalAdapterMaxFlows = %[6]d
const LocalAdapterMaxChunkBytes = %[7]d
const LocalAdapterMaxBufferedBytes = %[8]d
const LocalAdapterMaxEvents = %[9]d
const LocalAdapterTracePayloadHygiene = true
const LocalAdapterTraceSecretHygiene = true

func LocalAdapterConfig() localadapter.LocalAdapterConfig {
	cfg := localadapter.DefaultConfig("generated-local-adapter")
	cfg.RuntimeID = "generated-runtime"
	cfg.MaxFlows = LocalAdapterMaxFlows
	cfg.MaxChunkBytes = LocalAdapterMaxChunkBytes
	cfg.MaxBufferedBytes = LocalAdapterMaxBufferedBytes
	cfg.MaxEvents = LocalAdapterMaxEvents
	cfg.DeterministicSeed = uint64(ProfileSeed)
	return cfg
}

func LocalAdapterDemo(ctx context.Context, flows int) (localadapter.LocalAdapterSummary, []ktrace.Event, error) {
	if flows <= 0 {
		flows = 4
	}
	if flows > LocalAdapterMaxFlows {
		flows = LocalAdapterMaxFlows
	}
	scenario := localadapter.DefaultScenario(localadapter.ScenarioManySmallFlows)
	scenario.FlowCount = flows
	result, err := localadapter.RunScenario(ctx, StaticProfile(), scenario, LocalAdapterConfig())
	return result.Summary, result.Events, err
}

func CaptureLocalAdapterTrace(ctx context.Context, flows int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := LocalAdapterDemo(ctx, flows)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.FlowsOpened, PayloadLogged: result.PayloadLogged || result.SecretLogged}, nil
}

func LocalAdapterAdversaryDemo(ctx context.Context, scenario string) (localadapteradversary.ScenarioRun, error) {
	if scenario == "" {
		scenario = localadapteradversary.ScenarioManySmall
	}
	return localadapteradversary.RunScenario(ctx, StaticProfile(), localadapteradversary.DefaultScenario(scenario)), nil
}
`, quote(p.ID), quote("small_burst_source"), quote(p.AdapterPolicy.FlowLifecyclePolicy), quote(p.AdapterPolicy.RuntimeMappingPolicy), quote(p.AdapterPolicy.BackpressurePolicy), p.AdapterPolicy.MaxFlows, localAdapterMaxChunk, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxEvents)
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
	byteTransportSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/observe/bytetransport"
	"kurdistan/internal/bytetransportadversary"
	ktrace "kurdistan/internal/observe/trace"
)

const ByteTransportGeneratedProfileID = %[1]s
const ByteTransportMaxFrameBytes = %[2]d
const ByteTransportMaxPayloadBytes = %[3]d
const ByteTransportMaxBufferedBytes = %[4]d
const ByteTransportMaxFragments = 16
const ByteTransportMaxReassemblyBytes = %[5]d
const ByteTransportMaxPipeQueueDepth = 64
const ByteTransportFragmentPolicy = %[6]s
const ByteTransportSequencePolicy = %[7]s
const ByteTransportTracePayloadHygiene = true
const ByteTransportTraceSecretHygiene = true
const BytePathFixtureSchemaVersion = "bytepath-fixture-v1"
const BytePathFixtureGeneratedProfileID = %[1]s

func ByteTransportConfig() bytetransport.ByteTransportConfig {
	cfg := bytetransport.DefaultConfig("generated-byte-transport")
	cfg.RuntimeID = "generated-runtime"
	cfg.MaxFrameBytes = ByteTransportMaxFrameBytes
	cfg.MaxPayloadBytes = ByteTransportMaxPayloadBytes
	cfg.MaxBufferedBytes = ByteTransportMaxBufferedBytes
	cfg.MaxFragments = ByteTransportMaxFragments
	cfg.MaxReassemblyBytes = ByteTransportMaxReassemblyBytes
	cfg.MaxPipeQueueDepth = ByteTransportMaxPipeQueueDepth
	cfg.DeterministicSeed = uint64(ProfileSeed)
	return cfg
}

func ByteTransportDemo(ctx context.Context, flows int) (bytetransport.ByteTransportSummary, []ktrace.Event, error) {
	if flows <= 0 {
		flows = 4
	}
	scenario := bytetransport.DefaultScenario(bytetransport.ScenarioManySmall)
	scenario.FlowCount = flows
	result, err := bytetransport.RunScenario(ctx, StaticProfile(), scenario, ByteTransportConfig())
	return result.Summary, result.Events, err
}

func CaptureByteTransportTrace(ctx context.Context, flows int) ([]ktrace.Event, TraceCaptureSummary, error) {
	result, events, err := ByteTransportDemo(ctx, flows)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	return events, TraceCaptureSummary{ProfileID: ProfileID, EventCount: len(events), DataEventCount: result.FramesEncoded, PayloadLogged: result.PayloadLogged || result.SecretLogged}, nil
}

func ByteTransportAdversaryDemo(ctx context.Context, scenario string) (bytetransportadversary.ScenarioRun, error) {
	if scenario == "" {
		scenario = bytetransportadversary.ScenarioManySmall
	}
	return bytetransportadversary.RunScenario(ctx, StaticProfile(), bytetransportadversary.DefaultScenario(scenario)), nil
}
`, quote(p.ID), byteMaxFrame, byteMaxPayload, p.AdapterPolicy.MaxBufferedBytes, p.AdapterPolicy.MaxBufferedBytes, quote(p.FrameGrammar.FragmentationMode), quote(p.Security.ReplayPolicy))
	if err != nil {
		return nil, err
	}

	protocolCorpusSource, err := renderGo(`package protocol

import "kurdistan/internal/observe/protocorpus"

const ProtocolCorpusSchemaVersion = "protocorpus-v1"
const ProtocolCorpusFeatureSchemaVersion = "wirefeatures-v1"
const ProtocolCorpusGeneratedProfileID = %[1]s

var GeneratedProtocolPhases = []string{"greeting", "handshake", "control", "data", "close", "reset"}
var GeneratedProtocolFieldKinds = []string{"type", "length", "version", "nonce_like", "key_like", "certificate_like", "reserved", "padding_length", "padding", "payload", "auth_tag_like", "unknown_encrypted"}

func GeneratedProtocolCorpus() protocorpus.CorpusManifest {
	return protocorpus.DefaultCorpus()
}

func GeneratedProtocolCorpusSummary() protocorpus.CorpusSummary {
	return protocorpus.Summarize(GeneratedProtocolCorpus())
}
`, quote(p.ID))
	if err != nil {
		return nil, err
	}

	wireFeaturesSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/fixtures"
	"kurdistan/internal/observe/protocorpus"
	"kurdistan/internal/observe/wirefeatures"
)

const WireFeatureSchemaVersion = "wirefeatures-v1"
const WireFeatureGeneratedProfileID = %[1]s
const WireFeatureFirstNModel = "bucketed-firstn-v1"
const WireFeatureSummarySchema = "wirefeature-summary-v1"

func GeneratedWireFeatureBaseline(ctx context.Context) (wirefeatures.BaselineManifest, error) {
	manifest, err := fixtures.GenerateBytePathManifest(ctx, fixtures.ManifestOptions{
		FixtureSet: "generated-wirefeatures",
		Backend: fixtures.BackendGen,
		ProfileSeeds: []int{int(ProfileSeed)},
		ScenarioNames: []string{"byte_single_flow_echo", "byte_corruption_rejection", "byte_replay_rejection"},
		BackendVersion: GeneratorVersion,
	})
	if err != nil {
		return wirefeatures.BaselineManifest{}, err
	}
	return wirefeatures.GenerateBaseline(ctx, manifest, protocorpus.DefaultCorpus())
}

func GeneratedWireFeatureVectors(ctx context.Context) ([]wirefeatures.WireFeatureVector, error) {
	baseline, err := GeneratedWireFeatureBaseline(ctx)
	if err != nil {
		return nil, err
	}
	return baseline.FeatureVectors, nil
}
`, quote(p.ID))
	if err != nil {
		return nil, err
	}

	wireGenSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/observe/protocorpus"
	"kurdistan/internal/observe/wirefeatures"
	"kurdistan/internal/observe/wiregen"
	"kurdistan/internal/observe/wiregencompare"
)

const WireGenPolicyVersion = %[1]s
const WireGenPolicyID = %[2]s
const WireGenPolicyHash = %[3]s
const WireGenSelectedFamily = %[4]s
const WireGenSelectedCorpusEntry = %[5]s
const WireGenFirstNModel = "generated-wiregen-firstn-v1"
const WireGenGeneratedProfileID = %[6]s

var WireGenFrameSizeBuckets = %[7]s
var WireGenFragmentBuckets = %[8]s
var WireGenPhaseSequence = %[9]s

func GeneratedWireShapePolicy() wiregen.WireShapePolicy {
	return wiregen.FromIRPolicy(StaticProfile().WireShape)
}

func ValidateGeneratedWireShapePolicy() error {
	return wiregen.ValidatePolicy(GeneratedWireShapePolicy(), protocorpus.DefaultCorpus())
}

func GeneratedWireGenVectors(ctx context.Context) ([]wirefeatures.WireFeatureVector, error) {
	_ = ctx
	policy := GeneratedWireShapePolicy()
	return []wirefeatures.WireFeatureVector{
		wiregencompare.ExpectedVector(policy, "byte_single_flow_echo", "generated", ProfileID),
		wiregencompare.ExpectedVector(policy, "byte_corruption_rejection", "generated", ProfileID),
		wiregencompare.ExpectedVector(policy, "byte_replay_rejection", "generated", ProfileID),
	}, nil
}

func GeneratedWireGenBaseline(ctx context.Context) (wiregencompare.BaselineManifest, error) {
	return wiregencompare.GenerateBaseline(ctx, protocorpus.DefaultCorpus(), []int{int(ProfileSeed)}, []string{"byte_single_flow_echo", "byte_corruption_rejection", "byte_replay_rejection"})
}
`, quote(p.WireShape.Version), quote(p.WireShape.PolicyID), quote(p.WireShape.PolicyHash), quote(p.WireShape.SelectedFamily), quote(p.WireShape.SelectedCorpusEntry), quote(p.ID), quoteSlice(p.WireShape.FrameSizePlan.SizeBuckets), quoteSlice(p.WireShape.FragmentRhythmPlan.FragmentBuckets), quoteSlice(p.WireShape.PhasePlan.PhaseSequence))
	if err != nil {
		return nil, err
	}

	wireEvalSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/observe/classifierdata"
	"kurdistan/internal/observe/protocorpus"
	"kurdistan/internal/observe/wireeval"
)

const WireEvalDatasetVersion = "wireeval-v1"
const WireEvalGeneratedProfileID = %[1]s
const WireEvalSplitMode = "profile_holdout"

var WireEvalRequiredColumns = classifierdata.Columns()
var WireEvalForbiddenColumns = classifierdata.ForbiddenColumns()

func GeneratedWireEvalDataset(ctx context.Context) (wireeval.Dataset, error) {
	return wireeval.BuildDataset(ctx, protocorpus.DefaultCorpus(), wireeval.BuildOptions{
		Seeds: []int{int(ProfileSeed), int(ProfileSeed) + 1, int(ProfileSeed) + 2, int(ProfileSeed) + 3},
		Scenarios: []string{"byte_single_flow_echo", "byte_corruption_rejection", "byte_replay_rejection"},
		SplitMode: WireEvalSplitMode,
		Backend: "generated",
		Controls: true,
	})
}

func GeneratedWireEvalCSV(ctx context.Context) ([]byte, error) {
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		return nil, err
	}
	return classifierdata.ExportCSV(dataset.Records)
}

func GeneratedWireEvalJSONL(ctx context.Context) ([]byte, error) {
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		return nil, err
	}
	return classifierdata.ExportJSONL(dataset.Records)
}
`, quote(p.ID))
	if err != nil {
		return nil, err
	}

	hostDetectSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/observe/hostdetect"
)

const HostDetectSchemaVersion = "hostdetect-v1"
const HostDetectGeneratedProfileID = %[1]s
const HostDetectAssignmentMode = hostdetect.AssignControlCollapsed
const HostDetectWindow = hostdetect.WindowMedium
const HostDetectHostCount = 6

var HostDetectForbiddenMarkers = []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "destination_address", "secret"}

func GeneratedHostDetectSummary(ctx context.Context) (hostdetect.HostDetectSummary, error) {
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		return hostdetect.HostDetectSummary{}, err
	}
	return hostdetect.Run(dataset, hostdetect.BuildOptions{
		AssignmentMode: HostDetectAssignmentMode,
		Window: HostDetectWindow,
		HostCount: HostDetectHostCount,
	})
}
`, quote(p.ID))
	if err != nil {
		return nil, err
	}

	relayFleetSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/relayfleet"
)

const RelayFleetSchemaVersion = "relayfleet-v1"
const RelayFleetGeneratedProfileID = %[1]s
const RelayFleetProfileSeedAnchor = %[2]d
const RelayFleetWirePolicyHash = %[3]s
const RelayFleetSelectedFamily = %[4]s
const RelayFleetAssignmentMode = %[5]s
const RelayFleetChurnMode = %[6]s
const RelayFleetMigrationMode = %[7]s
const RelayFleetMaxActiveRelays = %[8]d
const RelayFleetProfileReuseLimit = 2
const RelayFleetWirePolicyReuseLimit = 2

var RelayFleetForbiddenMarkers = []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "endpoint", "real_host", "cloud_provider", "secret"}

func GeneratedRelayFleetSummary(ctx context.Context) (relayfleet.RelayFleetSummary, error) {
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		return relayfleet.RelayFleetSummary{}, err
	}
	hostSummary, err := GeneratedHostDetectSummary(ctx)
	if err != nil {
		return relayfleet.RelayFleetSummary{}, err
	}
	policy := relayfleet.DefaultPolicy()
	policy.Name = "generated_relayfleet_" + RelayFleetGeneratedProfileID
	policy.AssignmentMode = RelayFleetAssignmentMode
	policy.ChurnMode = RelayFleetChurnMode
	policy.MigrationMode = RelayFleetMigrationMode
	policy.MaxActiveRelays = RelayFleetMaxActiveRelays
	policy.ProfileReuseLimit = RelayFleetProfileReuseLimit
	policy.WirePolicyReuseLimit = RelayFleetWirePolicyReuseLimit
	return relayfleet.Run(dataset, hostSummary, relayfleet.Options{
		RelayCount: 6,
		ProfileSeeds: []int{int(ProfileSeed), int(ProfileSeed) + 1, int(ProfileSeed) + 2, int(ProfileSeed) + 3, int(ProfileSeed) + 4, int(ProfileSeed) + 5, int(ProfileSeed) + 6, int(ProfileSeed) + 7},
		Policy: policy,
		IncludeControls: true,
		GeneratedBackend: true,
	})
}
`, quote(p.ID), p.Seed, quote(p.WireShape.PolicyHash), quote(p.WireShape.SelectedFamily), quote(relayFleetAssignmentMode(p.Seed)), quote(relayFleetChurnMode(p.Seed)), quote(relayFleetMigrationMode(p.Seed)), min(8, max(6, p.Stream.MaxConcurrentStreams)))
	if err != nil {
		return nil, err
	}

	proxyIngressSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
)

const ProxyIngressSchemaVersion = "proxyingress-v1"
const ProxyIngressGeneratedProfileID = %[1]s
const ProxyIngressContractID = "proxyingress_contract_v1"
const ProxyIngressMaxConcurrentRequests = 16
const ProxyIngressMaxTargetDescriptorBytes = 256
const ProxyIngressDesignDecision = "go_for_deterministic_prototype"

var ProxyIngressSupportedKinds = []string{"synthetic_connect", "synthetic_associate", "synthetic_bind"}
var ProxyIngressSupportedTargetKinds = []string{"synthetic_name", "synthetic_service", "opaque_descriptor"}
var ProxyIngressRequiredCapabilities = []string{"stream_open", "stream_data", "stream_close", "stream_reset", "backpressure", "target_descriptor", "target_error", "target_reset", "target_close", "secure_context_required", "replay_rejection_required", "trace_hygiene_required", "bounded_queue_required"}
var ProxyIngressForbiddenFields = []string{"raw_content", "network_address", "lookup", "listener", "sensitive_material", "provider_metadata"}
var ProxyIngressFailureModeMatrixHash = %[2]s

func GeneratedProxyIngressContract() proxyingress.ProxyIngressContract {
	return proxyingress.DefaultContract()
}

func GeneratedProxyIngressReview() (proxyingressreview.ProxyIngressDesignReview, error) {
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		return proxyingressreview.ProxyIngressDesignReview{}, err
	}
	return proxyingressreview.RunReview(set.Contract, set.Requests, set.Mappings, set.Lifecycle, proxyingressreview.DefaultFailureModes())
}
`, quote(p.ID), quote(proxyingressreview.HashValue(proxyingressreview.DefaultFailureModes())))
	if err != nil {
		return nil, err
	}

	localProxyIngressSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/localproxyingress"
)

const LocalProxyIngressSchemaVersion = "localproxyingress-v1"
const LocalProxyIngressGeneratedProfileID = %[1]s
const LocalProxyIngressMaxConcurrentRequests = 16
const LocalProxyIngressMaxQueuedEvents = 96
const LocalProxyIngressMaxEventsPerRequest = 24
const LocalProxyIngressTracePayloadHygiene = true
const LocalProxyIngressTraceSecretHygiene = true

var LocalProxyIngressScenarios = []string{"single_connect_echo", "many_small_connects", "large_request_fragmented", "mixed_request_classes", "slow_drip_request", "reset_mid_request", "target_error_after_open", "backpressure_pressure", "invalid_target_rejection", "lifecycle_violation_rejection", "queue_overflow_rejection", "duplicate_event_rejection"}
var LocalProxyIngressEventKinds = []string{"open", "data", "close", "reset", "target_error", "backpressure"}
var LocalProxyIngressForbiddenFields = []string{"raw_content", "network_address", "lookup", "listener", "sensitive_material", "provider_metadata"}

func GeneratedLocalProxyIngressConfig() localproxyingress.LocalProxyIngressConfig {
	cfg := localproxyingress.DefaultConfig()
	cfg.MaxConcurrentRequests = LocalProxyIngressMaxConcurrentRequests
	cfg.MaxQueuedEvents = LocalProxyIngressMaxQueuedEvents
	cfg.MaxEventsPerRequest = LocalProxyIngressMaxEventsPerRequest
	return cfg
}

func GeneratedLocalProxyIngressSummary(ctx context.Context, scenario string) (localproxyingress.LocalProxyIngressSummary, error) {
	if scenario == "" {
		scenario = localproxyingress.ScenarioSingleConnectEcho
	}
	return localproxyingress.RunScenario(ctx, scenario, GeneratedLocalProxyIngressConfig())
}

func GeneratedLocalProxyIngressFixtureSet(ctx context.Context) (localproxyingress.FixtureSet, error) {
	return localproxyingress.GenerateFixtureSet(ctx, localproxyingress.QuickScenarios())
}
`, quote(p.ID))
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvDescriptorClasses := localProxyIngressAdversarialDescriptorClasses(localproxyingressadversary.DescriptorAbuseCases())
	localProxyIngressAdvSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/localproxyingressadversary"
)

const LocalProxyIngressAdversarialSchemaVersion = %[1]s
const LocalProxyIngressAdversarialGeneratedProfileID = %[2]s
const LocalProxyIngressAdversarialCorpusID = %[3]s
const LocalProxyIngressAdversarialReadinessDecision = "go_for_local_proxy_egress_model"

var LocalProxyIngressAdversarialScenarioClasses = %[4]s
var LocalProxyIngressAdversarialDescriptorClasses = %[5]s
var LocalProxyIngressAdversarialLifecycleClasses = %[6]s
var LocalProxyIngressAdversarialPressureClasses = %[7]s
var LocalProxyIngressAdversarialResetErrorClasses = %[8]s
var LocalProxyIngressAdversarialCollapseFindings = []string{"all_targets_same_binding", "all_requests_same_stream_class", "all_scenarios_same_lifecycle_pattern", "all_error_cases_same_error_bucket", "all_reset_cases_same_reset_bucket", "backpressure_never_mapped", "invalid_targets_mapped_as_valid", "mapping_hash_changes_but_features_same", "features_change_but_policy_constant", "padding_only_event_variation", "generated_backend_ignores_mapping"}
var LocalProxyIngressAdversarialForbiddenFields = []string{"endpoint", "payload", "raw_bytes", "secret", "dns_query", "host_header", "sni", "cloud_provider"}

func GeneratedLocalProxyIngressAdversarialFixtureSet(ctx context.Context) (localproxyingressadversary.AdversarialFixtureSet, error) {
	return localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
}

func GeneratedLocalProxyIngressAdversarialReadiness(ctx context.Context) (localproxyingressadversary.ProxyIngressM27ReadinessReport, error) {
	set, err := localproxyingressadversary.GenerateAdversarialFixtureSet(ctx)
	if err != nil {
		return localproxyingressadversary.ProxyIngressM27ReadinessReport{}, err
	}
	return set.Readiness, nil
}
`, quote(localproxyingressadversary.Version), quote(p.ID), quote(localproxyingressadversary.CorpusID), quoteSlice(localproxyingressadversary.RequiredScenarioIDs()), quoteSlice(localProxyIngressAdvDescriptorClasses), quoteSlice(localproxyingressadversary.LifecycleAbuseScenarios()), quoteSlice(localproxyingressadversary.PressureScenarios()), quoteSlice(localproxyingressadversary.ResetErrorScenarios()))
	if err != nil {
		return nil, err
	}

	adaptivePathSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/adaptivepath"
)

const AdaptivePathSchemaVersion = %[1]s
const AdaptivePathGeneratedProfileID = %[2]s
const AdaptivePathGeneratedProfileSeed int64 = %[3]d

var AdaptivePathCandidateFamilies = %[4]s
var AdaptivePathConditionClasses = %[5]s
var AdaptivePathObservationKinds = %[6]s
var AdaptivePathFreshnessClasses = %[7]s
var AdaptivePathTTLClasses = %[8]s
var AdaptivePathUncertaintyBuckets = %[9]s
var AdaptivePathViabilityStates = %[10]s
var AdaptivePathHighRiskFamilies = %[11]s
var AdaptivePathGatedFamilies = %[12]s
var AdaptivePathForbiddenFields = %[13]s

func GeneratedAdaptivePathFixtureSet(ctx context.Context) (adaptivepath.AdaptivePathFixtureSet, error) {
	return adaptivepath.GenerateFixtureSet(ctx)
}

func GeneratedAdaptivePathDecisionSet(ctx context.Context) (adaptivepath.CandidateDecisionSet, error) {
	set, err := adaptivepath.GenerateFixtureSet(ctx)
	if err != nil {
		return adaptivepath.CandidateDecisionSet{}, err
	}
	return set.DecisionInputs, nil
}

func GeneratedAdaptivePathParity(ctx context.Context) (adaptivepath.AdaptivePathParityReport, error) {
	set, err := adaptivepath.GenerateFixtureSet(ctx)
	if err != nil {
		return adaptivepath.AdaptivePathParityReport{}, err
	}
	return set.Parity, nil
}

func GeneratedAdaptivePathMisuse(ctx context.Context) (adaptivepath.AdaptivePathMisuseReport, error) {
	set, err := adaptivepath.GenerateFixtureSet(ctx)
	if err != nil {
		return adaptivepath.AdaptivePathMisuseReport{}, err
	}
	return set.MisuseReport, nil
}
`, quote(string(adaptivepath.Version)), quote(p.ID), p.Seed, quoteSlice(adaptivePathCandidateFamilies()), quoteSlice(adaptivePathConditionClasses()), quoteSlice(adaptivePathObservationKinds()), quoteSlice(adaptivePathFreshnessClasses()), quoteSlice(adaptivePathTTLClasses()), quoteSlice(adaptivePathUncertaintyBuckets()), quoteSlice(adaptivePathViabilityStates()), quoteSlice(adaptivePathHighRiskFamilies()), quoteSlice(adaptivePathGatedFamilies()), quoteSlice(adaptivepath.ForbiddenMarkers()))
	if err != nil {
		return nil, err
	}

	transportBundleSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/transportbundle"
)

const TransportBundleSchemaVersion = %[1]s
const TransportBundleGeneratedProfileID = %[2]s
const TransportBundleGeneratedProfileSeed int64 = %[3]d

var TransportBundleModes = %[4]s
var TransportBundleCandidateRoles = %[5]s
var TransportBundleForbiddenFields = %[6]s
var TransportBundlePrimaryPolicyHash = %[7]s

func GeneratedTransportBundleFixtureSet(ctx context.Context) (transportbundle.TransportBundleFixtureSet, error) {
	return transportbundle.GenerateFixtureSet(ctx)
}

func GeneratedTransportBundleManifest(ctx context.Context) (transportbundle.TransportBundleManifest, error) {
	set, err := transportbundle.GenerateFixtureSet(ctx)
	if err != nil {
		return transportbundle.TransportBundleManifest{}, err
	}
	return set.Manifest, nil
}

func GeneratedTransportBundleParity(ctx context.Context) (transportbundle.TransportBundleParityReport, error) {
	set, err := transportbundle.GenerateFixtureSet(ctx)
	if err != nil {
		return transportbundle.TransportBundleParityReport{}, err
	}
	return set.Parity, nil
}

func GeneratedTransportBundleCollapse(ctx context.Context) (transportbundle.BundleCollapseReport, error) {
	set, err := transportbundle.GenerateFixtureSet(ctx)
	if err != nil {
		return transportbundle.BundleCollapseReport{}, err
	}
	return set.CollapseReport, nil
}
`, quote(string(transportbundle.Version)), quote(p.ID), p.Seed, quoteSlice(transportBundleModeStrings()), quoteSlice(transportBundleCandidateRoles()), quoteSlice(transportbundle.ForbiddenMarkers()), quote(transportbundle.DefaultPolicy(12345, transportbundle.BundleModeBalancedAdaptive).PolicyHash))
	if err != nil {
		return nil, err
	}

	pathRaceSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/pathrace"
)

const PathRaceSchemaVersion = %[1]s
const PathRaceGeneratedProfileID = %[2]s
const PathRaceGeneratedProfileSeed int64 = %[3]d

var PathRaceModes = %[4]s
var PathRaceEventKinds = %[5]s
var PathRaceStates = %[6]s
var PathRaceForbiddenFields = %[7]s
var PathRaceDefaultSchedulerPolicyHash = %[8]s
var PathRaceDefaultScoringPolicyHash = %[9]s

func GeneratedPathRaceFixtureSet(ctx context.Context) (pathrace.PathRaceFixtureSet, error) {
	return pathrace.GenerateFixtureSet(ctx)
}

func GeneratedPathRaceParity(ctx context.Context) (pathrace.PathRaceParityReport, error) {
	set, err := pathrace.GenerateFixtureSet(ctx)
	if err != nil {
		return pathrace.PathRaceParityReport{}, err
	}
	return set.Parity, nil
}

func GeneratedPathRaceMisuse(ctx context.Context) (pathrace.PathRaceMisuseReport, error) {
	set, err := pathrace.GenerateFixtureSet(ctx)
	if err != nil {
		return pathrace.PathRaceMisuseReport{}, err
	}
	return set.Controls, nil
}
`, quote(string(pathrace.Version)), quote(p.ID), p.Seed, quoteSlice(pathRaceModeStrings()), quoteSlice(pathRaceEventKindStrings()), quoteSlice(pathRaceStateStrings()), quoteSlice(pathrace.ForbiddenMarkers()), quote(pathrace.DefaultSchedulerPolicy(pathrace.RaceModeVerifiedUsable).PolicyHash), quote(pathrace.DefaultScoringPolicy().PolicyHash))
	if err != nil {
		return nil, err
	}

	pathHealthSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/pathhealth"
)

const PathHealthSchemaVersion = %[1]s
const PathHealthGeneratedProfileID = %[2]s
const PathHealthGeneratedProfileSeed int64 = %[3]d

var PathHealthStates = %[4]s
var PathHealthEventKinds = %[5]s
var PathHealthFailoverOutcomes = %[6]s
var PathHealthForbiddenFields = %[7]s
var PathHealthDefaultPolicyHash = %[8]s

func GeneratedPathHealthFixtureSet(ctx context.Context) (pathhealth.PathHealthFixtureSet, error) {
	return pathhealth.GenerateFixtureSet(ctx)
}

func GeneratedPathHealthParity(ctx context.Context) (pathhealth.PathHealthParityReport, error) {
	set, err := pathhealth.GenerateFixtureSet(ctx)
	if err != nil {
		return pathhealth.PathHealthParityReport{}, err
	}
	return set.Parity, nil
}

func GeneratedPathHealthMisuse(ctx context.Context) (pathhealth.PathHealthMisuseReport, error) {
	set, err := pathhealth.GenerateFixtureSet(ctx)
	if err != nil {
		return pathhealth.PathHealthMisuseReport{}, err
	}
	return set.Controls, nil
}
`, quote(string(pathhealth.Version)), quote(p.ID), p.Seed, quoteSlice(pathhealth.HealthStates()), quoteSlice(pathhealth.HealthEventKinds()), quoteSlice(pathhealth.FailoverOutcomes()), quoteSlice(pathhealth.ForbiddenMarkers()), quote(pathhealth.DefaultPolicy().PolicyHash))
	if err != nil {
		return nil, err
	}

	carrierReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/carrierreview"
)

const CarrierReviewSchemaVersion = %[1]s
const CarrierReviewGeneratedProfileID = %[2]s
const CarrierReviewGeneratedProfileSeed int64 = %[3]d

var CarrierReviewFamilies = %[4]s
var CarrierReviewReadinessClasses = %[5]s
var CarrierReviewForbiddenFields = %[6]s
var CarrierReviewRecommendedNextMilestone = %[7]s

func GeneratedCarrierReview() (carrierreview.CarrierFamilyReview, error) {
	return carrierreview.GenerateReview()
}
`, quote(carrierreview.Version), quote(p.ID), p.Seed, quoteSlice(carrierReviewFamilies()), quoteSlice(carrierReviewReadinessClasses()), quoteSlice(carrierreview.ForbiddenMarkers()), quote(carrierreview.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	measurementReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/measurementreview"
)

const MeasurementReviewSchemaVersion = %[1]s
const MeasurementReviewGeneratedProfileID = %[2]s
const MeasurementReviewGeneratedProfileSeed int64 = %[3]d

var MeasurementReviewObservationFields = %[4]s
var MeasurementReviewRedactionClasses = %[5]s
var MeasurementReviewConsentModes = %[6]s
var MeasurementReviewRetentionClasses = %[7]s
var MeasurementReviewForbiddenFields = %[8]s
var MeasurementReviewRecommendedNextMilestone = %[9]s

func GeneratedMeasurementReview() (measurementreview.MeasurementReview, error) {
	return measurementreview.GenerateReview()
}
`, quote(measurementreview.Version), quote(p.ID), p.Seed, quoteSlice(measurementReviewObservationFields()), quoteSlice(measurementreview.AllowedRedactionClasses()), quoteSlice(measurementreview.AllowedConsentModes()), quoteSlice(measurementreview.AllowedRetentionClasses()), quoteSlice(measurementreview.ForbiddenMarkers()), quote(measurementreview.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	proxyEgressSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/proxyegress"
)

const ProxyEgressSchemaVersion = %[1]s
const ProxyEgressGeneratedProfileID = %[2]s
const ProxyEgressGeneratedProfileSeed int64 = %[3]d
const ProxyEgressMappingPolicy = %[4]s

var ProxyEgressTargetClasses = %[5]s
var ProxyEgressLifecycleStates = %[6]s
var ProxyEgressRecommendedNextMilestone = %[7]s

func GeneratedProxyEgressFixture() (proxyegress.EgressFixtureSet, error) {
	return proxyegress.GenerateFixtureSet()
}

func GeneratedProxyEgressParity() (proxyegress.EgressParityReport, error) {
	set, err := proxyegress.GenerateFixtureSet()
	if err != nil {
		return proxyegress.EgressParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(proxyegress.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.CarrierPolicy.CarrierFamily), quoteSlice(proxyEgressTargetClasses()), quoteSlice(proxyEgressLifecycleStates()), quote(proxyegress.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	relayBridgeSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/relaybridge"
)

const RelayBridgeSchemaVersion = %[1]s
const RelayBridgeGeneratedProfileID = %[2]s
const RelayBridgeGeneratedProfileSeed int64 = %[3]d
const RelayBridgeMappingPolicy = %[4]s

var RelayBridgeStates = %[5]s
var RelayBridgeScenarioClasses = %[6]s
var RelayBridgeRecommendedNextMilestone = %[7]s

func GeneratedRelayBridgeFixture() (relaybridge.RelayBridgeFixtureSet, error) {
	return relaybridge.GenerateFixtureSet()
}

func GeneratedRelayBridgeParity() (relaybridge.RelayBridgeParityReport, error) {
	set, err := relaybridge.GenerateFixtureSet()
	if err != nil {
		return relaybridge.RelayBridgeParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(relaybridge.Version), quote(p.ID), p.Seed, quote(p.Stream.PriorityPolicy+"/"+p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.BackpressurePolicy), quoteSlice(relayBridgeStates()), quoteSlice(relayBridgeScenarioClasses()), quote(relaybridge.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	localPipelineSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/localpipeline"
)

const LocalPipelineSchemaVersion = %[1]s
const LocalPipelineGeneratedProfileID = %[2]s
const LocalPipelineGeneratedProfileSeed int64 = %[3]d
const LocalPipelineBoundaryPolicy = %[4]s

var LocalPipelineScenarioKinds = %[5]s
var LocalPipelineStates = %[6]s
var LocalPipelineRecommendedNextMilestone = %[7]s

func GeneratedLocalPipelineFixture() (localpipeline.PipelineFixtureSet, error) {
	return localpipeline.GenerateFixtureSet()
}

func GeneratedLocalPipelineParity() (localpipeline.PipelineParityReport, error) {
	set, err := localpipeline.GenerateFixtureSet()
	if err != nil {
		return localpipeline.PipelineParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(localpipeline.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.ResponseModeEncoding+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.WireShape.PolicyID), quoteSlice(localPipelineScenarioKinds()), quoteSlice(localPipelineStates()), quote(localpipeline.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	productionReadinessSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/productionreadiness"
)

const ProductionReadinessSchemaVersion = %[1]s
const ProductionReadinessGeneratedProfileID = %[2]s
const ProductionReadinessGeneratedProfileSeed int64 = %[3]d
const ProductionReadinessBoundaryPolicy = %[4]s

var ProductionReadinessContracts = %[5]s
var ProductionReadinessBoundaries = %[6]s
var ProductionReadinessRecommendedNextMilestone = %[7]s

func GeneratedProductionReadinessReview() (productionreadiness.ProductionReadinessReview, error) {
	return productionreadiness.GenerateReview()
}

func GeneratedProductionReadinessParity() (productionreadiness.ReadinessParityReport, error) {
	review, err := productionreadiness.GenerateReview()
	if err != nil {
		return productionreadiness.ReadinessParityReport{}, err
	}
	return review.Parity, nil
}
`, quote(productionreadiness.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.Security.CapabilityNegotiationPolicy+"/"+p.WireShape.PolicyID), quoteSlice(productionReadinessContracts()), quoteSlice(productionReadinessBoundaries()), quote(productionreadiness.RecommendedNextMilestone))
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterSource, err := renderGo(`package protocol

import (
	"context"

	"kurdistan/internal/concretelocaladapter"
)

const ConcreteLocalAdapterSchemaVersion = %[1]s
const ConcreteLocalAdapterGeneratedProfileID = %[2]s
const ConcreteLocalAdapterGeneratedProfileSeed int64 = %[3]d
const ConcreteLocalAdapterBindClass = %[4]s
const ConcreteLocalAdapterRuntimeMappingPolicy = %[5]s
const ConcreteLocalAdapterMaxConnections = %[6]d
const ConcreteLocalAdapterMaxBufferedBytes = %[7]d
const ConcreteLocalAdapterRecommendedNextMilestone = %[8]s

var ConcreteLocalAdapterScenarios = %[9]s

func GeneratedConcreteLocalAdapterFixtureSet(ctx context.Context) (concretelocaladapter.SocketFixtureSet, error) {
	return concretelocaladapter.GenerateFixtureSet(ctx)
}

func GeneratedConcreteLocalAdapterParity(ctx context.Context) (concretelocaladapter.SocketParityReport, error) {
	set, err := concretelocaladapter.GenerateFixtureSet(ctx)
	if err != nil {
		return concretelocaladapter.SocketParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(concretelocaladapter.Version), quote(p.ID), p.Seed, quote(concretelocaladapter.BindClassLoopbackOnly), quote(p.AdapterPolicy.RuntimeMappingPolicy), 16, 64*1024, quote(concretelocaladapter.RecommendedNextMilestone), quoteSlice(concreteLocalAdapterScenarios()))
	if err != nil {
		return nil, err
	}

	localProtocolAdapterSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/localprotocoladapter"
)

const LocalProtocolAdapterSchemaVersion = %[1]s
const LocalProtocolAdapterGeneratedProfileID = %[2]s
const LocalProtocolAdapterGeneratedProfileSeed int64 = %[3]d
const LocalProtocolAdapterRuntimeMappingPolicy = %[4]s
const LocalProtocolAdapterMaxRequestBytes = %[5]d
const LocalProtocolAdapterMaxEvents = %[6]d
const LocalProtocolAdapterRecommendedNextMilestone = %[7]s

var LocalProtocolAdapterFamilies = %[8]s
var LocalProtocolAdapterScenarios = %[9]s
var LocalProtocolAdapterParserStates = %[10]s

func GeneratedLocalProtocolAdapterFixtureSet() (localprotocoladapter.LocalProtocolFixtureSet, error) {
	return localprotocoladapter.GenerateFixtureSet()
}

func GeneratedLocalProtocolAdapterParity() (localprotocoladapter.LocalProtocolParityReport, error) {
	set, err := localprotocoladapter.GenerateFixtureSet()
	if err != nil {
		return localprotocoladapter.LocalProtocolParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(localprotocoladapter.Version), quote(p.ID), p.Seed, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.RelayIntentEncoding+"/"+p.WireShape.PolicyID), localprotocoladapter.DefaultConfig().MaxRequestLineBytes, localprotocoladapter.DefaultConfig().MaxParserTransitions, quote(localprotocoladapter.RecommendedNextMilestone), quoteSlice(localProtocolAdapterFamilies()), quoteSlice(localProtocolAdapterScenarios()), quoteSlice(localProtocolAdapterParserStates()))
	if err != nil {
		return nil, err
	}

	loopbackRelaySource, err := renderGo(`package protocol

import (
	"kurdistan/internal/loopbackrelay"
)

const LoopbackRelaySchemaVersion = %[1]s
const LoopbackRelayGeneratedProfileID = %[2]s
const LoopbackRelayGeneratedProfileSeed int64 = %[3]d
const LoopbackRelayBindPolicy = %[4]s
const LoopbackRelayDialPolicy = %[5]s
const LoopbackRelayMaxSessions = %[6]d
const LoopbackRelayMaxFrameBytes = %[7]d
const LoopbackRelayRuntimePolicy = %[8]s
const LoopbackRelayRecommendedNextMilestone = %[9]s

var LoopbackRelayScenarios = %[10]s

func GeneratedLoopbackRelayFixtureSet() (loopbackrelay.LoopbackRelayFixtureSet, error) {
	return loopbackrelay.GenerateFixtureSet()
}

func GeneratedLoopbackRelayParity() (loopbackrelay.LoopbackParityReport, error) {
	set, err := loopbackrelay.GenerateFixtureSet()
	if err != nil {
		return loopbackrelay.LoopbackParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(loopbackrelay.Version), quote(p.ID), p.Seed, quote(loopbackrelay.BindPolicyLoopbackOnly), quote(loopbackrelay.DialPolicyLoopbackOnly), loopbackrelay.DefaultConfig().MaxSessions, loopbackrelay.DefaultConfig().MaxFrameBytes, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(loopbackrelay.RecommendedNextMilestone), quoteSlice(loopbackRelayScenarios()))
	if err != nil {
		return nil, err
	}

	labEgressSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/labegress"
)

const LabEgressSchemaVersion = %[1]s
const LabEgressGeneratedProfileID = %[2]s
const LabEgressGeneratedProfileSeed int64 = %[3]d
const LabEgressConnectorPolicy = %[4]s
const LabEgressMaxConnections = %[5]d
const LabEgressMaxResponseBytes = %[6]d
const LabEgressRuntimePolicy = %[7]s
const LabEgressRecommendedNextMilestone = %[8]s

var LabEgressScenarios = %[9]s
var LabEgressTargetClasses = %[10]s

func GeneratedLabEgressFixtureSet() (labegress.LabEgressFixtureSet, error) {
	return labegress.GenerateFixtureSet()
}

func GeneratedLabEgressParity() (labegress.LabEgressParityReport, error) {
	set, err := labegress.GenerateFixtureSet()
	if err != nil {
		return labegress.LabEgressParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(labegress.Version), quote(p.ID), p.Seed, quote(labegress.ConnectorPolicyLoopbackAllowlist), labegress.DefaultConfig().MaxConnections, labegress.DefaultConfig().MaxResponseBytes, quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.ProxySemantics.TargetDescriptorEncoding+"/"+p.CarrierPolicy.CarrierFamily), quote(labegress.RecommendedNextMilestone), quoteSlice(labEgressScenarios()), quoteSlice(labEgressTargetClasses()))
	if err != nil {
		return nil, err
	}

	carrierReadinessSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/carrierreadiness"
)

const CarrierReadinessSchemaVersion = %[1]s
const CarrierReadinessGeneratedProfileID = %[2]s
const CarrierReadinessGeneratedProfileSeed int64 = %[3]d
const CarrierReadinessDecision = %[4]s
const CarrierReadinessRuntimePolicy = %[5]s
const CarrierReadinessRecommendedNextMilestone = %[6]s

var CarrierReadinessFutureMilestones = %[7]s
var CarrierReadinessBoundaryNames = %[8]s

func GeneratedCarrierReadinessFixtureSet() (carrierreadiness.FixtureSet, error) {
	return carrierreadiness.GenerateFixtureSet()
}

func GeneratedCarrierReadinessParity() (carrierreadiness.ParityReport, error) {
	set, err := carrierreadiness.GenerateFixtureSet()
	if err != nil {
		return carrierreadiness.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(carrierreadiness.Version), quote(p.ID), p.Seed, quote(carrierreadiness.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(carrierreadiness.RecommendedNextMilestone), quoteSlice(carrierReadinessFutureMilestones()), quoteSlice(carrierReadinessBoundaryNames()))
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/httpscarrierreview"
)

const HTTPSCarrierReviewSchemaVersion = %[1]s
const HTTPSCarrierReviewGeneratedProfileID = %[2]s
const HTTPSCarrierReviewGeneratedProfileSeed int64 = %[3]d
const HTTPSCarrierReviewBackendVersion = %[4]s
const HTTPSCarrierReviewDecision = %[5]s
const HTTPSCarrierReviewRuntimePolicy = %[6]s
const HTTPSCarrierReviewRecommendedNextMilestone = %[7]s
const HTTPSCarrierReviewRequestShapeCount = %[8]d
const HTTPSCarrierReviewResponseShapeCount = %[9]d

var HTTPSCarrierReviewBlockedBehaviors = %[10]s
var HTTPSCarrierReviewM42Criteria = %[11]s

func GeneratedHTTPSCarrierReviewFixtureSet() (httpscarrierreview.FixtureSet, error) {
	return httpscarrierreview.GenerateFixtureSet()
}

func GeneratedHTTPSCarrierReviewParity() (httpscarrierreview.ParityReport, error) {
	set, err := httpscarrierreview.GenerateFixtureSet()
	if err != nil {
		return httpscarrierreview.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(httpscarrierreview.Version), quote(p.ID), p.Seed, quote(httpscarrierreview.BackendVersion), quote(httpscarrierreview.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpscarrierreview.RecommendedNextMilestone), len(httpsCarrierReviewRequestShapeNames()), len(httpsCarrierReviewResponseShapeNames()), quoteSlice(httpsCarrierReviewBlockedBehaviorNames()), quoteSlice(httpsCarrierReviewM42Criteria()))
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/httpslikecarrier"
)

const HTTPSLikeCarrierSchemaVersion = %[1]s
const HTTPSLikeCarrierGeneratedProfileID = %[2]s
const HTTPSLikeCarrierGeneratedProfileSeed int64 = %[3]d
const HTTPSLikeCarrierBackendVersion = %[4]s
const HTTPSLikeCarrierFamily = %[5]s
const HTTPSLikeCarrierRuntimePolicy = %[6]s
const HTTPSLikeCarrierRecommendedNextMilestone = %[7]s
const HTTPSLikeCarrierMaxMarkerBytes = %[8]d
const HTTPSLikeCarrierRequestShapeCount = %[9]d
const HTTPSLikeCarrierResponseShapeCount = %[10]d

var HTTPSLikeCarrierBlockedScopes = %[11]s
var HTTPSLikeCarrierRequestShapeClasses = %[12]s
var HTTPSLikeCarrierResponseShapeClasses = %[13]s
var HTTPSLikeCarrierSessionStates = %[14]s
var HTTPSLikeCarrierStreamStates = %[15]s
var HTTPSLikeCarrierMisuseControls = %[16]s

func GeneratedHTTPSLikeCarrierFixtureSet() (httpslikecarrier.FixtureSet, error) {
	return httpslikecarrier.GenerateFixtureSet()
}

func GeneratedHTTPSLikeCarrierParity() (httpslikecarrier.ParityReport, error) {
	set, err := httpslikecarrier.GenerateFixtureSet()
	if err != nil {
		return httpslikecarrier.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(httpslikecarrier.Version), quote(p.ID), p.Seed, quote(httpslikecarrier.BackendVersion), quote(httpslikecarrier.CarrierFamily), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpslikecarrier.RecommendedNextMilestone), httpslikecarrier.DefaultConfig().MaxMarkerBytes, len(httpsLikeCarrierRequestShapeClasses()), len(httpsLikeCarrierResponseShapeClasses()), quoteSlice(httpsLikeCarrierBlockedScopes()), quoteSlice(httpsLikeCarrierRequestShapeClasses()), quoteSlice(httpsLikeCarrierResponseShapeClasses()), quoteSlice(httpsLikeCarrierSessionStates()), quoteSlice(httpsLikeCarrierStreamStates()), quoteSlice(httpsLikeCarrierMisuseControls()))
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversarySource, err := renderGo(`package protocol

import (
	"kurdistan/internal/httpscarrieradversary"
)

const HTTPSCarrierAdversarySchemaVersion = %[1]s
const HTTPSCarrierAdversaryGeneratedProfileID = %[2]s
const HTTPSCarrierAdversaryGeneratedProfileSeed int64 = %[3]d
const HTTPSCarrierAdversaryBackendVersion = %[4]s
const HTTPSCarrierAdversaryRuntimePolicy = %[5]s
const HTTPSCarrierAdversaryRecommendedNextMilestone = %[6]s
const HTTPSCarrierAdversaryCollapseControlCount = %[7]d
const HTTPSCarrierAdversaryUnsafeFallbackControlCount = %[8]d
const HTTPSCarrierAdversaryForbiddenControlCount = %[9]d

var HTTPSCarrierAdversaryScenarios = %[10]s
var HTTPSCarrierAdversaryCollapseControls = %[11]s
var HTTPSCarrierAdversaryUnsafeFallbackControls = %[12]s
var HTTPSCarrierAdversaryReplayControls = %[13]s
var HTTPSCarrierAdversaryStreamControls = %[14]s
var HTTPSCarrierAdversaryForbiddenControls = %[15]s

func GeneratedHTTPSCarrierAdversaryFixtureSet() (httpscarrieradversary.FixtureSet, error) {
	return httpscarrieradversary.GenerateFixtureSet()
}

func GeneratedHTTPSCarrierAdversaryParity() (httpscarrieradversary.GeneratedParityReport, error) {
	set, err := httpscarrieradversary.GenerateFixtureSet()
	if err != nil {
		return httpscarrieradversary.GeneratedParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(httpscarrieradversary.Version), quote(p.ID), p.Seed, quote(httpscarrieradversary.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(httpscarrieradversary.RecommendedNextMilestone), len(httpsCarrierAdversaryCollapseControls()), len(httpsCarrierAdversaryUnsafeFallbackControls()), len(httpsCarrierAdversaryForbiddenControls()), quoteSlice(httpsCarrierAdversaryScenarios()), quoteSlice(httpsCarrierAdversaryCollapseControls()), quoteSlice(httpsCarrierAdversaryUnsafeFallbackControls()), quoteSlice(httpsCarrierAdversaryReplayControls()), quoteSlice(httpsCarrierAdversaryStreamControls()), quoteSlice(httpsCarrierAdversaryForbiddenControls()))
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/constrainedcarrierreview"
)

const ConstrainedCarrierReviewSchemaVersion = %[1]s
const ConstrainedCarrierReviewGeneratedProfileID = %[2]s
const ConstrainedCarrierReviewGeneratedProfileSeed int64 = %[3]d
const ConstrainedCarrierReviewBackendVersion = %[4]s
const ConstrainedCarrierReviewRuntimePolicy = %[5]s
const ConstrainedCarrierReviewRecommendedNextMilestone = %[6]s
const ConstrainedCarrierReviewQueryShapeCount = %[7]d
const ConstrainedCarrierReviewResponseShapeCount = %[8]d
const ConstrainedCarrierReviewResolverBucketCount = %[9]d
const ConstrainedCarrierReviewM45RequirementCount = %[10]d

var ConstrainedCarrierReviewBlockedBehaviors = %[11]s
var ConstrainedCarrierReviewResolverBuckets = %[12]s
var ConstrainedCarrierReviewQueryShapeClasses = %[13]s
var ConstrainedCarrierReviewResponseShapeClasses = %[14]s
var ConstrainedCarrierReviewM45Requirements = %[15]s
var ConstrainedCarrierReviewMisuseControls = %[16]s

func GeneratedConstrainedCarrierReviewFixtureSet() (constrainedcarrierreview.FixtureSet, error) {
	return constrainedcarrierreview.GenerateFixtureSet()
}

func GeneratedConstrainedCarrierReviewParity() (constrainedcarrierreview.ParityReport, error) {
	set, err := constrainedcarrierreview.GenerateFixtureSet()
	if err != nil {
		return constrainedcarrierreview.ParityReport{}, err
	}
	return set.Report.Parity, nil
}
`, quote(constrainedcarrierreview.Version), quote(p.ID), p.Seed, quote(constrainedcarrierreview.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(constrainedcarrierreview.RecommendedNextMilestone), len(constrainedCarrierReviewQueryShapeClasses()), len(constrainedCarrierReviewResponseShapeClasses()), len(constrainedCarrierReviewResolverBuckets()), len(constrainedCarrierReviewM45Requirements()), quoteSlice(constrainedCarrierReviewBlockedBehaviors()), quoteSlice(constrainedCarrierReviewResolverBuckets()), quoteSlice(constrainedCarrierReviewQueryShapeClasses()), quoteSlice(constrainedCarrierReviewResponseShapeClasses()), quoteSlice(constrainedCarrierReviewM45Requirements()), quoteSlice(constrainedcarrierreview.RequiredMisuseNames()))
	if err != nil {
		return nil, err
	}

	constrainedCarrierSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/constrainedcarrier"
)

const ConstrainedCarrierSchemaVersion = %[1]s
const ConstrainedCarrierGeneratedProfileID = %[2]s
const ConstrainedCarrierGeneratedProfileSeed int64 = %[3]d
const ConstrainedCarrierBackendVersion = %[4]s
const ConstrainedCarrierRuntimePolicy = %[5]s
const ConstrainedCarrierFamily = %[6]s
const ConstrainedCarrierRecommendedNextMilestone = %[7]s
const ConstrainedCarrierQueryShapeCount = %[8]d
const ConstrainedCarrierResponseShapeCount = %[9]d
const ConstrainedCarrierCapacityBucketCount = %[10]d
const ConstrainedCarrierRetryBucketCount = %[11]d
const ConstrainedCarrierFailureBucketCount = %[12]d

var ConstrainedCarrierQueryShapeClasses = %[13]s
var ConstrainedCarrierResponseShapeClasses = %[14]s
var ConstrainedCarrierCapacityBuckets = %[15]s
var ConstrainedCarrierRetryBuckets = %[16]s
var ConstrainedCarrierFailureBuckets = %[17]s
var ConstrainedCarrierBlockedScopes = %[18]s
var ConstrainedCarrierMisuseControls = %[19]s

func GeneratedConstrainedCarrierFixtureSet() (constrainedcarrier.FixtureSet, error) {
	return constrainedcarrier.GenerateFixtureSet()
}

func GeneratedConstrainedCarrierParity() (constrainedcarrier.ParityReport, error) {
	set, err := constrainedcarrier.GenerateFixtureSet()
	if err != nil {
		return constrainedcarrier.ParityReport{}, err
	}
	return set.Report.Parity, nil
}
`, quote(constrainedcarrier.Version), quote(p.ID), p.Seed, quote(constrainedcarrier.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(constrainedcarrier.CarrierFamily), quote(constrainedcarrier.RecommendedNextMilestone), len(constrainedcarrier.QueryShapeClasses()), len(constrainedcarrier.ResponseShapeClasses()), len(constrainedcarrier.CapacityBuckets()), len(constrainedcarrier.RetryBuckets()), len(constrainedcarrier.FailureBuckets()), quoteSlice(constrainedcarrier.QueryShapeClasses()), quoteSlice(constrainedcarrier.ResponseShapeClasses()), quoteSlice(constrainedcarrier.CapacityBuckets()), quoteSlice(constrainedcarrier.RetryBuckets()), quoteSlice(constrainedcarrier.FailureBuckets()), quoteSlice(constrainedcarrier.BlockedScopes()), quoteSlice(constrainedcarrier.RequiredMisuseNames()))
	if err != nil {
		return nil, err
	}

	multiCarrierSelectSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/multicarrierselect"
)

const MultiCarrierSelectSchemaVersion = %[1]s
const MultiCarrierSelectGeneratedProfileID = %[2]s
const MultiCarrierSelectGeneratedProfileSeed int64 = %[3]d
const MultiCarrierSelectBackendVersion = %[4]s
const MultiCarrierSelectRuntimePolicy = %[5]s
const MultiCarrierSelectRecommendedNextMilestone = %[6]s
const MultiCarrierSelectFamilyClassCount = %[7]d
const MultiCarrierSelectDecisionClassCount = %[8]d
const MultiCarrierSelectMisuseControlCount = %[9]d

var MultiCarrierSelectFamilyClasses = %[10]s
var MultiCarrierSelectDecisionClasses = %[11]s
var MultiCarrierSelectMisuseControls = %[12]s
var MultiCarrierSelectProfileSelectionHints = %[13]s

func GeneratedMultiCarrierSelectFixtureSet() (multicarrierselect.FixtureSet, error) {
	return multicarrierselect.GenerateFixtureSet()
}

func GeneratedMultiCarrierSelectParity() (multicarrierselect.ParityReport, error) {
	set, err := multicarrierselect.GenerateFixtureSet()
	if err != nil {
		return multicarrierselect.ParityReport{}, err
	}
	return set.Report.Parity, nil
}

func GeneratedMultiCarrierSelectCandidate(policyClass string) multicarrierselect.CarrierCandidate {
	return multicarrierselect.SelectCarrier(int(MultiCarrierSelectGeneratedProfileSeed), policyClass)
}
`, quote(multicarrierselect.Version), quote(p.ID), p.Seed, quote(multicarrierselect.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(multicarrierselect.RecommendedNextMilestone), len(multicarrierselect.RequiredFamilyClasses()), len(multicarrierselect.RequiredDecisionClasses()), len(multicarrierselect.RequiredMisuseNames()), quoteSlice(multicarrierselect.RequiredFamilyClasses()), quoteSlice(multicarrierselect.RequiredDecisionClasses()), quoteSlice(multicarrierselect.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	carrierCollapseSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/carriercollapse"
)

const CarrierCollapseSchemaVersion = %[1]s
const CarrierCollapseGeneratedProfileID = %[2]s
const CarrierCollapseGeneratedProfileSeed int64 = %[3]d
const CarrierCollapseBackendVersion = %[4]s
const CarrierCollapseRuntimePolicy = %[5]s
const CarrierCollapseRecommendedNextMilestone = %[6]s
const CarrierCollapseControlCount = %[7]d
const CarrierCollapseDimensionCount = %[8]d

var CarrierCollapseClasses = %[9]s
var CarrierCollapseControls = %[10]s
var CarrierCollapseProfileHints = %[11]s

func GeneratedCarrierCollapseFixtureSet() (carriercollapse.FixtureSet, error) {
	return carriercollapse.GenerateFixtureSet()
}

func GeneratedCarrierCollapseParity() (carriercollapse.ParityReport, error) {
	set, err := carriercollapse.GenerateFixtureSet()
	if err != nil {
		return carriercollapse.ParityReport{}, err
	}
	return set.Report.Parity, nil
}
`, quote(carriercollapse.Version), quote(p.ID), p.Seed, quote(carriercollapse.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(carriercollapse.RecommendedNextMilestone), len(carriercollapse.RequiredMutationNames()), len(carriercollapse.RequiredAuditDimensions()), quoteSlice(carriercollapse.RequiredCollapseClasses()), quoteSlice(carriercollapse.RequiredMutationNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/localproxyadapterreview"
)

const LocalProxyAdapterReviewSchemaVersion = %[1]s
const LocalProxyAdapterReviewGeneratedProfileID = %[2]s
const LocalProxyAdapterReviewGeneratedProfileSeed int64 = %[3]d
const LocalProxyAdapterReviewBackendVersion = %[4]s
const LocalProxyAdapterReviewRuntimePolicy = %[5]s
const LocalProxyAdapterReviewRecommendedNextMilestone = %[6]s
const LocalProxyAdapterReviewControlCount = %[7]d
const LocalProxyAdapterReviewM49Decision = %[8]s
const LocalProxyAdapterReviewPayloadPolicy = %[9]s
const LocalProxyAdapterReviewTargetRedaction = %[10]s

var LocalProxyAdapterReviewControls = %[11]s
var LocalProxyAdapterReviewAcceptedProtocols = %[12]s
var LocalProxyAdapterReviewProfileHints = %[13]s

func GeneratedLocalProxyAdapterReviewFixtureSet() (localproxyadapterreview.FixtureSet, error) {
	return localproxyadapterreview.GenerateFixtureSet()
}

func GeneratedLocalProxyAdapterReviewParity() (localproxyadapterreview.ParityReport, error) {
	set, err := localproxyadapterreview.GenerateFixtureSet()
	if err != nil {
		return localproxyadapterreview.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(localproxyadapterreview.Version), quote(p.ID), p.Seed, quote(localproxyadapterreview.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localproxyadapterreview.RecommendedNextMilestone), len(localproxyadapterreview.RequiredMisuseNames()), quote(localproxyadapterreview.DecisionReady), quote("byte_counts_buckets_and_flags_only"), quote("target_bucket_only"), quoteSlice(localproxyadapterreview.RequiredMisuseNames()), quoteSlice([]string{"local_socks_like_stream_adapter_semantics", "local_http_connect_like_stream_adapter_semantics"}), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localProxyAdapterSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/localproxyadapter"
)

const LocalProxyAdapterSchemaVersion = %[1]s
const LocalProxyAdapterGeneratedProfileID = %[2]s
const LocalProxyAdapterGeneratedProfileSeed int64 = %[3]d
const LocalProxyAdapterBackendVersion = %[4]s
const LocalProxyAdapterRuntimePolicy = %[5]s
const LocalProxyAdapterRecommendedNextMilestone = %[6]s
const LocalProxyAdapterControlCount = %[7]d
const LocalProxyAdapterMaxStreamsClass = %[8]s
const LocalProxyAdapterPayloadPolicy = %[9]s

var LocalProxyAdapterStreamClasses = %[10]s
var LocalProxyAdapterControls = %[11]s
var LocalProxyAdapterProfileHints = %[12]s

func GeneratedLocalProxyAdapterFixtureSet() (localproxyadapter.FixtureSet, error) {
	return localproxyadapter.GenerateFixtureSet()
}

func GeneratedLocalProxyAdapterParity() (localproxyadapter.ParityReport, error) {
	set, err := localproxyadapter.GenerateFixtureSet()
	if err != nil {
		return localproxyadapter.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(localproxyadapter.Version), quote(p.ID), p.Seed, quote(localproxyadapter.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localproxyadapter.RecommendedNextMilestone), len(localproxyadapter.RequiredMisuseNames()), quote("profile_bounded_streams"), quote("opaque_symbolic_classes_only"), quoteSlice(localproxyadapter.DefaultStreamClasses()), quoteSlice(localproxyadapter.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	vpnSemanticsSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/vpnsemantics"
)

const PacketSemanticsSchemaVersion = %[1]s
const PacketSemanticsGeneratedProfileID = %[2]s
const PacketSemanticsGeneratedProfileSeed int64 = %[3]d
const PacketSemanticsBackendVersion = %[4]s
const PacketSemanticsRuntimePolicy = %[5]s
const PacketSemanticsRecommendedNextMilestone = %[6]s
const PacketSemanticsControlCount = %[7]d
const PacketSemanticsM51Decision = %[8]s
const PacketSemanticsPayloadPolicy = %[9]s

var PacketSemanticsFlowClasses = %[10]s
var PacketSemanticsControls = %[11]s
var PacketSemanticsProfileHints = %[12]s

func GeneratedPacketSemanticsFixtureSet() (vpnsemantics.FixtureSet, error) {
	return vpnsemantics.GenerateFixtureSet()
}

func GeneratedPacketSemanticsParity() (vpnsemantics.ParityReport, error) {
	set, err := vpnsemantics.GenerateFixtureSet()
	if err != nil {
		return vpnsemantics.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(vpnsemantics.Version), quote(p.ID), p.Seed, quote(vpnsemantics.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote("M51: local desktop packet adapter prototype"), len(vpnsemantics.RequiredMisuseNames()), quote(vpnsemantics.DecisionReady), quote("class_buckets_only"), quoteSlice([]string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "reset_flow", "backpressure_flow", "control_misuse_flow"}), quoteSlice(vpnsemantics.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	localVPNAdapterSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/localvpnadapter"
)

const PacketAdapterSchemaVersion = %[1]s
const PacketAdapterGeneratedProfileID = %[2]s
const PacketAdapterGeneratedProfileSeed int64 = %[3]d
const PacketAdapterBackendVersion = %[4]s
const PacketAdapterRuntimePolicy = %[5]s
const PacketAdapterRecommendedNextMilestone = %[6]s
const PacketAdapterControlCount = %[7]d
const PacketAdapterPayloadPolicy = %[8]s

var PacketAdapterFlowClasses = %[9]s
var PacketAdapterControls = %[10]s
var PacketAdapterProfileHints = %[11]s

func GeneratedPacketAdapterFixtureSet() (localvpnadapter.FixtureSet, error) {
	return localvpnadapter.GenerateFixtureSet()
}

func GeneratedPacketAdapterParity() (localvpnadapter.ParityReport, error) {
	set, err := localvpnadapter.GenerateFixtureSet()
	if err != nil {
		return localvpnadapter.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(localvpnadapter.Version), quote(p.ID), p.Seed, quote(localvpnadapter.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(localvpnadapter.RecommendedNextMilestone), len(localvpnadapter.RequiredMisuseNames()), quote("class_buckets_only"), quoteSlice([]string{"tcp_like_flow", "udp_like_flow", "dns_boundary_flow", "fragmented_flow", "retry_backpressure_flow", "reset_flow", "kill_switch_flow"}), quoteSlice(localvpnadapter.RequiredMisuseNames()), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	relayProcessSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/relayprocess"
)

const RelayProcessSchemaVersion = %[1]s
const RelayProcessGeneratedProfileID = %[2]s
const RelayProcessGeneratedProfileSeed int64 = %[3]d
const RelayProcessBackendVersion = %[4]s
const RelayProcessRuntimePolicy = %[5]s
const RelayProcessRecommendedNextMilestone = %[6]s
const RelayProcessRoleCount = %[7]d
const RelayProcessLifecycleCount = %[8]d
const RelayProcessMisuseCount = %[9]d
const RelayProcessLoggingPolicy = %[10]s

var RelayProcessControls = %[11]s
var RelayProcessRoles = %[12]s
var RelayProcessProfileHints = %[13]s

func GeneratedRelayProcessFixtureSet() (relayprocess.FixtureSet, error) {
	return relayprocess.GenerateFixtureSet()
}

func GeneratedRelayProcessParity() (relayprocess.ParityReport, error) {
	set, err := relayprocess.GenerateFixtureSet()
	if err != nil {
		return relayprocess.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(relayprocess.Version), quote(p.ID), p.Seed, quote(relayprocess.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.TranscriptMode), quote(relayprocess.RecommendedNextMilestone), 3, 5, len(relayprocess.RequiredMisuseNames()), quote("structured_safe_metadata_only"), quoteSlice(relayprocess.RequiredMisuseNames()), quoteSlice([]string{"client_process", "relay_process", "supervisor_process"}), quoteSlice([]string{p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.TranscriptMode}))
	if err != nil {
		return nil, err
	}

	keyExchangePlanSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/keyexchangeplan"
)

const KeyExchangePlanSchemaVersion = %[1]s
const KeyExchangePlanGeneratedProfileID = %[2]s
const KeyExchangePlanGeneratedProfileSeed int64 = %[3]d
const KeyExchangePlanBackendVersion = %[4]s
const KeyExchangePlanTranscriptPolicy = %[5]s
const KeyExchangePlanNoncePolicy = %[6]s
const KeyExchangePlanCompatibilityPolicy = %[7]s
const KeyExchangePlanRecommendedNextMilestone = %[8]s
const KeyExchangePlanDesignCount = %[9]d
const KeyExchangePlanMisuseCount = %[10]d

var KeyExchangePlanControls = %[11]s
var KeyExchangePlanBoundComponents = %[12]s
var KeyExchangePlanGeneratedPolicyHints = %[13]s

func GeneratedKeyExchangePlanFixtureSet() (keyexchangeplan.FixtureSet, error) {
	return keyexchangeplan.GenerateFixtureSet()
}

func GeneratedKeyExchangePlanParity() (keyexchangeplan.ParityReport, error) {
	set, err := keyexchangeplan.GenerateFixtureSet()
	if err != nil {
		return keyexchangeplan.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(keyexchangeplan.Version), quote(p.ID), p.Seed, quote(keyexchangeplan.BackendVersion), quote(p.Security.TranscriptMode), quote(p.Security.NonceMode), quote(p.Security.CapabilityNegotiationPolicy+"/"+p.Security.DowngradePolicy), quote(keyexchangeplan.RecommendedNextMilestone), 10, len(keyexchangeplan.RequiredMisuseNames()), quoteSlice(keyexchangeplan.RequiredMisuseNames()), quoteSlice(keyexchangeplan.DefaultTranscriptBindingReport().BoundComponents), quoteSlice([]string{p.Security.TranscriptMode, p.Security.NonceMode, p.Security.ReplayPolicy, p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy}))
	if err != nil {
		return nil, err
	}

	relayAuthPlanSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/relayauthplan"
)

const RelayAuthPlanSchemaVersion = %[1]s
const RelayAuthPlanGeneratedProfileID = %[2]s
const RelayAuthPlanGeneratedProfileSeed int64 = %[3]d
const RelayAuthPlanBackendVersion = %[4]s
const RelayAuthPlanCompatibilityPolicy = %[5]s
const RelayAuthPlanRotationPolicy = %[6]s
const RelayAuthPlanFailurePolicy = %[7]s
const RelayAuthPlanRecommendedNextMilestone = %[8]s
const RelayAuthPlanInventoryCount = %[9]d
const RelayAuthPlanMisuseCount = %[10]d

var RelayAuthPlanControls = %[11]s
var RelayAuthPlanBoundComponents = %[12]s
var RelayAuthPlanGeneratedPolicyHints = %[13]s

func GeneratedRelayAuthPlanFixtureSet() (relayauthplan.FixtureSet, error) {
	return relayauthplan.GenerateFixtureSet()
}

func GeneratedRelayAuthPlanParity() (relayauthplan.ParityReport, error) {
	set, err := relayauthplan.GenerateFixtureSet()
	if err != nil {
		return relayauthplan.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(relayauthplan.Version), quote(p.ID), p.Seed, quote(relayauthplan.BackendVersion), quote(p.Security.CapabilityNegotiationPolicy+"/"+p.Security.DowngradePolicy+"/"+p.CarrierPolicy.CarrierFamily), quote("bounded_epoch_rotation_with_required_overlap_window"), quote("fail_closed_with_safe_bucketed_diagnostics"), quote(relayauthplan.RecommendedNextMilestone), 15, len(relayauthplan.RequiredMisuseNames()), quoteSlice(relayauthplan.RequiredMisuseNames()), quoteSlice(relayauthplan.DefaultIdentityBindingPolicyReport().BoundComponents), quoteSlice([]string{p.Security.CapabilityNegotiationPolicy, p.Security.DowngradePolicy, p.CarrierPolicy.CarrierFamily, p.AdapterPolicy.RuntimeMappingPolicy, p.Security.ReplayPolicy}))
	if err != nil {
		return nil, err
	}

	operationalHardeningSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/operationalhardening"
)

const OperationalHardeningSchemaVersion = %[1]s
const OperationalHardeningGeneratedProfileID = %[2]s
const OperationalHardeningGeneratedProfileSeed int64 = %[3]d
const OperationalHardeningBackendVersion = %[4]s
const OperationalHardeningResourcePolicy = %[5]s
const OperationalHardeningConfigPolicy = %[6]s
const OperationalHardeningLifecyclePolicy = %[7]s
const OperationalHardeningDiagnosticsPolicy = %[8]s
const OperationalHardeningRollbackPolicy = %[9]s
const OperationalHardeningHealthPolicy = %[10]s
const OperationalHardeningNextMilestone = %[11]s
const OperationalHardeningResourceBoundCount = %[12]d
const OperationalHardeningMisuseCount = %[13]d

var OperationalHardeningSafeErrorClasses = %[14]s
var OperationalHardeningControls = %[15]s
var OperationalHardeningGeneratedPolicyHints = %[16]s

func GeneratedOperationalHardeningFixtureSet() (operationalhardening.FixtureSet, error) {
	return operationalhardening.GenerateFixtureSet()
}

func GeneratedOperationalHardeningParity() (operationalhardening.ParityReport, error) {
	set, err := operationalhardening.GenerateFixtureSet()
	if err != nil {
		return operationalhardening.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(operationalhardening.Version), quote(p.ID), p.Seed, quote(operationalhardening.BackendVersion), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.ReplayPolicy), quote(p.Security.ConfigValidationPolicy+"/"+p.Security.ProfileCompatibilityPolicy), quote(p.Stream.ClosePolicy+"/"+p.Stream.ResetPolicy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote("structured_redacted_operational_status"), quote("fail_closed_profile_rotation_required"), quote("bucketed_redacted_operational_health"), quote(operationalhardening.RecommendedNextMilestone), len(operationalhardening.DefaultResourceLimitReport().Bounds), len(operationalhardening.RequiredMisuseNames()), quoteSlice(operationalhardening.DefaultConfigValidationReport().SafeErrorClasses), quoteSlice(operationalhardening.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.Security.ReplayPolicy, p.Security.DowngradePolicy, p.Security.ProfileCompatibilityPolicy}))
	if err != nil {
		return nil, err
	}

	androidReviewSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/androidreview"
)

const AndroidReviewSchemaVersion = %[1]s
const AndroidReviewGeneratedProfileID = %[2]s
const AndroidReviewGeneratedProfileSeed int64 = %[3]d
const AndroidReviewBackendVersion = %[4]s
const AndroidReviewDecision = %[5]s
const AndroidReviewRuntimePolicy = %[6]s
const AndroidReviewPermissionPolicy = %[7]s
const AndroidReviewDiagnosticsPolicy = %[8]s
const AndroidReviewKillSwitchPolicy = %[9]s
const AndroidReviewNextMilestone = %[10]s
const AndroidReviewUIStateCount = %[11]d
const AndroidReviewMisuseCount = %[12]d

var AndroidReviewUIStates = %[13]s
var AndroidReviewControls = %[14]s
var AndroidReviewGeneratedPolicyHints = %[15]s

func GeneratedAndroidReviewFixtureSet() (androidreview.FixtureSet, error) {
	return androidreview.GenerateFixtureSet()
}

func GeneratedAndroidReviewParity() (androidreview.ParityReport, error) {
	set, err := androidreview.GenerateFixtureSet()
	if err != nil {
		return androidreview.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(androidreview.Version), quote(p.ID), p.Seed, quote(androidreview.BackendVersion), quote(androidreview.DecisionReady), quote(p.AdapterPolicy.RuntimeMappingPolicy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.Security.ReplayPolicy), quote("platform_permission_first_foreground_service_bounded"), quote("local_user_export_only_redacted_diagnostic_bundle"), quote("fail_closed_on_profile_permission_runtime_or_carrier_invalid"), quote(androidreview.RecommendedNextMilestone), len(androidreview.DefaultUIStateReport().States), len(androidreview.RequiredMisuseNames()), quoteSlice(androidreview.DefaultUIStateReport().States), quoteSlice(androidreview.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidRuntimeSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/androidruntime"
)

const AndroidRuntimeSchemaVersion = %[1]s
const AndroidRuntimeGeneratedProfileID = %[2]s
const AndroidRuntimeGeneratedProfileSeed int64 = %[3]d
const AndroidRuntimeBackendVersion = %[4]s
const AndroidRuntimeDecision = %[5]s
const AndroidRuntimeInitializationPolicy = %[6]s
const AndroidRuntimeLifecyclePolicy = %[7]s
const AndroidRuntimeDiagnosticsPolicy = %[8]s
const AndroidRuntimeConcurrencyPolicy = %[9]s
const AndroidRuntimeCompatibilityPolicy = %[10]s
const AndroidRuntimeNextMilestone = %[11]s
const AndroidRuntimeLifecycleEventCount = %[12]d
const AndroidRuntimeMisuseCount = %[13]d

var AndroidRuntimeLifecycleEvents = %[14]s
var AndroidRuntimeControls = %[15]s
var AndroidRuntimeGeneratedPolicyHints = %[16]s

func GeneratedAndroidRuntimeFixtureSet() (androidruntime.FixtureSet, error) {
	return androidruntime.GenerateFixtureSet()
}

func GeneratedAndroidRuntimeParity() (androidruntime.ParityReport, error) {
	set, err := androidruntime.GenerateFixtureSet()
	if err != nil {
		return androidruntime.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(androidruntime.Version), quote(p.ID), p.Seed, quote(androidruntime.BackendVersion), quote(androidruntime.DecisionReady), quote(androidruntime.DefaultInitializationReport().Policy), quote(androidruntime.DefaultLifecycleReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidruntime.DefaultDiagnosticsReport().Policy), quote(androidruntime.DefaultConcurrencyReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(p.Security.ProfileCompatibilityPolicy+"/"+p.Security.CapabilityNegotiationPolicy+"/"+p.Security.ReplayPolicy), quote(androidruntime.RecommendedNextMilestone), len(androidruntime.DefaultLifecycleReport().Events), len(androidruntime.RequiredMisuseNames()), quoteSlice(androidruntime.DefaultLifecycleReport().Events), quoteSlice(androidruntime.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidVPNServiceSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/androidvpnservice"
)

const AndroidVpnServiceSchemaVersion = %[1]s
const AndroidVpnServiceGeneratedProfileID = %[2]s
const AndroidVpnServiceGeneratedProfileSeed int64 = %[3]d
const AndroidVpnServiceBackendVersion = %[4]s
const AndroidVpnServiceDecision = %[5]s
const AndroidVpnServicePermissionPolicy = %[6]s
const AndroidVpnServiceLifecyclePolicy = %[7]s
const AndroidVpnServicePacketFlowPolicy = %[8]s
const AndroidVpnServiceKillSwitchPolicy = %[9]s
const AndroidVpnServiceDiagnosticsPolicy = %[10]s
const AndroidVpnServiceReconnectPolicy = %[11]s
const AndroidVpnServiceIntegrationPolicy = %[12]s
const AndroidVpnServiceNextMilestone = %[13]s
const AndroidVpnServiceStateCount = %[14]d
const AndroidVpnServiceRuntimeStreamsMapped = %[15]d
const AndroidVpnServiceMisuseCount = %[16]d

var AndroidVpnServiceStates = %[17]s
var AndroidVpnServiceControls = %[18]s
var AndroidVpnServiceGeneratedPolicyHints = %[19]s

func GeneratedAndroidVpnServiceFixtureSet() (androidvpnservice.FixtureSet, error) {
	return androidvpnservice.GenerateFixtureSet()
}

func GeneratedAndroidVpnServiceParity() (androidvpnservice.ParityReport, error) {
	set, err := androidvpnservice.GenerateFixtureSet()
	if err != nil {
		return androidvpnservice.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(androidvpnservice.Version), quote(p.ID), p.Seed, quote(androidvpnservice.BackendVersion), quote(androidvpnservice.DecisionReady), quote(androidvpnservice.DefaultPermissionReport().Policy), quote(androidvpnservice.DefaultLifecycleReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidvpnservice.DefaultPacketFlowReport().Policy+"/"+p.Stream.IDEncodingMode), quote(androidvpnservice.DefaultKillSwitchReport().Policy), quote(androidvpnservice.DefaultDiagnosticsReport().Policy), quote(androidvpnservice.DefaultReconnectReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidvpnservice.DefaultIntegrationReport().Policy+"/"+p.Security.ProfileCompatibilityPolicy), quote(androidvpnservice.RecommendedNextMilestone), len(androidvpnservice.RequiredVpnStates()), androidvpnservice.DefaultPacketFlowReport().RuntimeStreamsMapped, len(androidvpnservice.RequiredMisuseNames()), quoteSlice(androidvpnservice.RequiredVpnStates()), quoteSlice(androidvpnservice.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Stream.IDEncodingMode, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	androidCarrierSource, err := renderGo(`package protocol

import (
	"kurdistan/internal/androidcarrier"
)

const AndroidCarrierSchemaVersion = %[1]s
const AndroidCarrierGeneratedProfileID = %[2]s
const AndroidCarrierGeneratedProfileSeed int64 = %[3]d
const AndroidCarrierBackendVersion = %[4]s
const AndroidCarrierDecision = %[5]s
const AndroidCarrierRuntimePathPolicy = %[6]s
const AndroidCarrierUIStatePolicy = %[7]s
const AndroidCarrierSelectionPolicy = %[8]s
const AndroidCarrierRelayCompatibilityPolicy = %[9]s
const AndroidCarrierFlowIntegrationPolicy = %[10]s
const AndroidCarrierReconnectPolicy = %[11]s
const AndroidCarrierProfileValidationPolicy = %[12]s
const AndroidCarrierNextMilestone = %[13]s
const AndroidCarrierUIStateCount = %[14]d
const AndroidCarrierRuntimeStreamsMapped = %[15]d
const AndroidCarrierCarrierEnvelopesMapped = %[16]d
const AndroidCarrierMisuseCount = %[17]d

var AndroidCarrierUIStates = %[18]s
var AndroidCarrierFailureClasses = %[19]s
var AndroidCarrierControls = %[20]s
var AndroidCarrierGeneratedPolicyHints = %[21]s

func GeneratedAndroidCarrierFixtureSet() (androidcarrier.FixtureSet, error) {
	return androidcarrier.GenerateFixtureSet()
}

func GeneratedAndroidCarrierParity() (androidcarrier.ParityReport, error) {
	set, err := androidcarrier.GenerateFixtureSet()
	if err != nil {
		return androidcarrier.ParityReport{}, err
	}
	return set.Parity, nil
}
`, quote(androidcarrier.Version), quote(p.ID), p.Seed, quote(androidcarrier.BackendVersion), quote(androidcarrier.DecisionReady), quote(androidcarrier.DefaultRuntimePathReport().Policy+"/"+p.AdapterPolicy.RuntimeMappingPolicy), quote(androidcarrier.DefaultUIStateReport().Policy), quote(androidcarrier.DefaultCarrierSelectionReport().Policy+"/"+p.CarrierPolicy.CarrierFamily+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidcarrier.DefaultRelayCompatibilityReport().Policy+"/"+p.Security.ProfileCompatibilityPolicy), quote(androidcarrier.DefaultFlowIntegrationReport().Policy+"/"+p.Stream.IDEncodingMode), quote(androidcarrier.DefaultReconnectFallbackReport().Policy+"/"+p.CarrierPolicy.BackpressurePolicy), quote(androidcarrier.DefaultProfileValidationReport().Policy+"/"+p.Security.CapabilityNegotiationPolicy), quote(androidcarrier.RecommendedNextMilestone), len(androidcarrier.RequiredUIStates()), androidcarrier.DefaultFlowIntegrationReport().RuntimeStreamsMapped, androidcarrier.DefaultFlowIntegrationReport().CarrierEnvelopesMapped, len(androidcarrier.RequiredMisuseNames()), quoteSlice(androidcarrier.RequiredUIStates()), quoteSlice(androidcarrier.DefaultFailureDiagnosticsReport().FailureClasses), quoteSlice(androidcarrier.RequiredMisuseNames()), quoteSlice([]string{p.AdapterPolicy.RuntimeMappingPolicy, p.CarrierPolicy.CarrierFamily, p.CarrierPolicy.BackpressurePolicy, p.Stream.IDEncodingMode, p.Security.ReplayPolicy, p.Security.ProfileCompatibilityPolicy, p.Security.CapabilityNegotiationPolicy}))
	if err != nil {
		return nil, err
	}

	scheduler, err := renderGo(`package protocol

import (
	"kurdistan/internal/protocol/scheduler"
)

const SchedulerMode = %[1]s
const SchedulerMaxBatchBytes = %[2]d
const SchedulerFlushIntervalMs = %[3]d
const SchedulerMaxInFlightFrames = %[4]d
const SchedulerPriorityMode = %[5]s

func PlanScheduler(items []scheduler.Item) []scheduler.Flush {
	return scheduler.Plan(StaticProfile().Scheduler, items)
}
`, quote(p.Scheduler.Mode), p.Scheduler.MaxBatchBytes, p.Scheduler.FlushIntervalMs, p.Scheduler.MaxInFlightFrames, quote(p.Scheduler.PriorityMode))
	if err != nil {
		return nil, err
	}

	invalid, err := renderGo(`package protocol

const InvalidUnknownFirstMessage = %[1]s
const InvalidMalformedFrame = %[2]s
const InvalidFailedAuth = %[3]s
const InvalidReplay = %[4]s
const InvalidDelayMsMin = %[5]d
const InvalidDelayMsMax = %[6]d

const MaxFrameBytes = %[7]d
const MaxPayloadBytes = %[8]d
const MaxStates = %[9]d
const MaxTransitions = %[10]d
const MaxSessionMillis = %[11]d

const ExternalNetworkingEnabled = false
const DeploymentEnabled = false
const PayloadLoggingEnabled = false
`, quote(p.InvalidInput.UnknownFirstMessage), quote(p.InvalidInput.MalformedFrame), quote(p.InvalidInput.FailedAuth), quote(p.InvalidInput.Replay), p.InvalidInput.DelayMsMin, p.InvalidInput.DelayMsMax, p.Limits.MaxFrameBytes, p.Limits.MaxPayloadBytes, p.Limits.MaxStates, p.Limits.MaxTransitions, p.Limits.MaxSessionMillis)
	if err != nil {
		return nil, err
	}

	auth, err := renderGo(`package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"kurdistan/internal/crypto/auth"
)

const AuthMode = %[1]s
const AuthKeyID = %[2]s
const AuthNonceBytes = %[3]d
const AuthProofMessage = %[4]s

func DerivedAuthTestKeyHex() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("test-only-key:%%s:%%d", ProfileID, ProfileSeed)))
	return hex.EncodeToString(sum[:])
}

func AuthKey() ([]byte, error) {
	return auth.Key(StaticProfile())
}
`, quote(p.Auth.Mode), quote(p.Auth.KeyID), p.Auth.NonceBytes, quote(p.Auth.ProofMessage))
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localproxyadapterreview"
)

func TestGeneratedLocalProxyAdapterReview(t *testing.T) {
	if LocalProxyAdapterReviewSchemaVersion != localproxyadapterreview.Version || LocalProxyAdapterReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated local proxy adapter review constants drifted")
	}
	set, err := GeneratedLocalProxyAdapterReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyadapterreview.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(LocalProxyAdapterReviewControls) < len(localproxyadapterreview.RequiredMisuseNames()) || len(LocalProxyAdapterReviewAcceptedProtocols) < 2 {
		t.Fatalf("generated local proxy adapter review constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLocalProxyAdapterReviewParity(t *testing.T) {
	parity, err := GeneratedLocalProxyAdapterReviewParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated local proxy adapter review parity failed: %%+v", parity)
	}
	if LocalProxyAdapterReviewRuntimePolicy == "" || LocalProxyAdapterReviewRecommendedNextMilestone == "" || LocalProxyAdapterReviewControlCount < 10 || LocalProxyAdapterReviewM49Decision == "" {
		t.Fatalf("local proxy adapter review generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyAdapterReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localproxyadapterreview"
)

func TestGeneratedLocalProxyAdapterReviewHygiene(t *testing.T) {
	set, err := GeneratedLocalProxyAdapterReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyadapterreview.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"exact_target_value": "synthetic"},
		map[string]string{"host_header_value": "synthetic"},
		map[string]bool{"payload_logged": true},
	}
	for _, tc := range unsafeCases {
		if err := localproxyadapterreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe local proxy adapter review metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyAdapterTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localproxyadapter"
)

func TestGeneratedLocalProxyAdapter(t *testing.T) {
	if LocalProxyAdapterSchemaVersion != localproxyadapter.Version || LocalProxyAdapterGeneratedProfileID != ProfileID {
		t.Fatalf("generated local proxy adapter constants drifted")
	}
	set, err := GeneratedLocalProxyAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyadapter.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(LocalProxyAdapterStreamClasses) < len(localproxyadapter.DefaultStreamClasses()) || len(LocalProxyAdapterControls) < len(localproxyadapter.RequiredMisuseNames()) {
		t.Fatalf("generated local proxy adapter constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyAdapterParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLocalProxyAdapterParity(t *testing.T) {
	parity, err := GeneratedLocalProxyAdapterParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated local proxy adapter parity failed: %%+v", parity)
	}
	if LocalProxyAdapterRuntimePolicy == "" || LocalProxyAdapterRecommendedNextMilestone == "" || LocalProxyAdapterControlCount < 10 || LocalProxyAdapterPayloadPolicy == "" {
		t.Fatalf("local proxy adapter generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyAdapterHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localproxyadapter"
)

func TestGeneratedLocalProxyAdapterHygiene(t *testing.T) {
	set, err := GeneratedLocalProxyAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyadapter.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_stream_bytes": "synthetic"},
		map[string]string{"exact_target_value": "synthetic"},
		map[string]bool{"payload_logged": true},
	}
	for _, tc := range unsafeCases {
		if err := localproxyadapter.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe local proxy adapter metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	vpnSemanticsTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/vpnsemantics"
)

func TestGeneratedPacketSemantics(t *testing.T) {
	if PacketSemanticsSchemaVersion != vpnsemantics.Version || PacketSemanticsGeneratedProfileID != ProfileID {
		t.Fatalf("generated packet semantics constants drifted")
	}
	set, err := GeneratedPacketSemanticsFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := vpnsemantics.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(PacketSemanticsFlowClasses) < 6 || len(PacketSemanticsControls) < len(vpnsemantics.RequiredMisuseNames()) {
		t.Fatalf("generated packet semantics constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	vpnSemanticsParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedPacketSemanticsParity(t *testing.T) {
	parity, err := GeneratedPacketSemanticsParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated packet semantics parity failed: %%+v", parity)
	}
	if PacketSemanticsRuntimePolicy == "" || PacketSemanticsRecommendedNextMilestone == "" || PacketSemanticsControlCount < 10 || PacketSemanticsM51Decision == "" {
		t.Fatalf("packet semantics generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	vpnSemanticsHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/vpnsemantics"
)

func TestGeneratedPacketSemanticsHygiene(t *testing.T) {
	set, err := GeneratedPacketSemanticsFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := vpnsemantics.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet_bytes": "synthetic"},
		map[string]string{"exact_endpoint_value": "synthetic"},
		map[string]bool{"android_vpnservice": true},
	}
	for _, tc := range unsafeCases {
		if err := vpnsemantics.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe packet semantics metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localVPNAdapterTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localvpnadapter"
)

func TestGeneratedPacketAdapter(t *testing.T) {
	if PacketAdapterSchemaVersion != localvpnadapter.Version || PacketAdapterGeneratedProfileID != ProfileID {
		t.Fatalf("generated packet adapter constants drifted")
	}
	set, err := GeneratedPacketAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localvpnadapter.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(PacketAdapterFlowClasses) < 7 || len(PacketAdapterControls) < len(localvpnadapter.RequiredMisuseNames()) {
		t.Fatalf("generated packet adapter constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localVPNAdapterParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedPacketAdapterParity(t *testing.T) {
	parity, err := GeneratedPacketAdapterParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated packet adapter parity failed: %%+v", parity)
	}
	if PacketAdapterRuntimePolicy == "" || PacketAdapterRecommendedNextMilestone == "" || PacketAdapterControlCount < 10 {
		t.Fatalf("packet adapter generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localVPNAdapterHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localvpnadapter"
)

func TestGeneratedPacketAdapterHygiene(t *testing.T) {
	set, err := GeneratedPacketAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localvpnadapter.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet_bytes": "synthetic"},
		map[string]string{"exact_endpoint_value": "synthetic"},
		map[string]bool{"allow_route_mutation": true},
	}
	for _, tc := range unsafeCases {
		if err := localvpnadapter.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe packet adapter metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayProcessTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relayprocess"
)

func TestGeneratedRelayProcess(t *testing.T) {
	if RelayProcessSchemaVersion != relayprocess.Version || RelayProcessGeneratedProfileID != ProfileID {
		t.Fatalf("generated relay process constants drifted")
	}
	set, err := GeneratedRelayProcessFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := relayprocess.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if RelayProcessRoleCount < 3 || RelayProcessLifecycleCount < 5 || len(RelayProcessControls) < len(relayprocess.RequiredMisuseNames()) {
		t.Fatalf("generated relay process constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayProcessParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedRelayProcessParity(t *testing.T) {
	parity, err := GeneratedRelayProcessParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated relay process parity failed: %%+v", parity)
	}
	if RelayProcessRuntimePolicy == "" || RelayProcessRecommendedNextMilestone == "" || RelayProcessMisuseCount < 10 || RelayProcessLoggingPolicy == "" {
		t.Fatalf("relay process generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayProcessHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relayprocess"
)

func TestGeneratedRelayProcessHygiene(t *testing.T) {
	set, err := GeneratedRelayProcessFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := relayprocess.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"packet_capture": "synthetic"},
		map[string]string{"secret_value": "synthetic"},
		map[string]bool{"public_observability_upload": true},
	}
	for _, tc := range unsafeCases {
		if err := relayprocess.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe relay process metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	keyExchangePlanTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/keyexchangeplan"
)

func TestGeneratedKeyExchangePlan(t *testing.T) {
	if KeyExchangePlanSchemaVersion != keyexchangeplan.Version || KeyExchangePlanGeneratedProfileID != ProfileID {
		t.Fatalf("generated key exchange constants drifted")
	}
	set, err := GeneratedKeyExchangePlanFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyexchangeplan.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if KeyExchangePlanDesignCount < 10 || len(KeyExchangePlanControls) < len(keyexchangeplan.RequiredMisuseNames()) || len(KeyExchangePlanBoundComponents) < 6 {
		t.Fatalf("generated key exchange constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	keyExchangePlanParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedKeyExchangePlanParity(t *testing.T) {
	parity, err := GeneratedKeyExchangePlanParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated key exchange parity failed: %%+v", parity)
	}
	if KeyExchangePlanTranscriptPolicy == "" || KeyExchangePlanNoncePolicy == "" || KeyExchangePlanCompatibilityPolicy == "" || KeyExchangePlanRecommendedNextMilestone == "" {
		t.Fatalf("key exchange generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	keyExchangePlanHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/keyexchangeplan"
)

func TestGeneratedKeyExchangePlanHygiene(t *testing.T) {
	set, err := GeneratedKeyExchangePlanFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := keyexchangeplan.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"secret_value": "synthetic"},
		map[string]string{"nonce_value": "synthetic"},
		map[string]string{"auth_tag": "synthetic"},
		map[string]string{"private_key": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := keyexchangeplan.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe key exchange metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	operationalHardeningTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/operationalhardening"
)

func TestGeneratedOperationalHardening(t *testing.T) {
	if OperationalHardeningSchemaVersion != operationalhardening.Version || OperationalHardeningGeneratedProfileID != ProfileID {
		t.Fatalf("generated operational hardening constants drifted")
	}
	set, err := GeneratedOperationalHardeningFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := operationalhardening.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if OperationalHardeningResourceBoundCount < 8 || OperationalHardeningMisuseCount < len(operationalhardening.RequiredMisuseNames()) || len(OperationalHardeningSafeErrorClasses) < 7 {
		t.Fatalf("generated operational hardening constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	operationalHardeningParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedOperationalHardeningParity(t *testing.T) {
	parity, err := GeneratedOperationalHardeningParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated operational hardening parity failed: %%+v", parity)
	}
	if OperationalHardeningResourcePolicy == "" || OperationalHardeningConfigPolicy == "" || OperationalHardeningLifecyclePolicy == "" || OperationalHardeningNextMilestone == "" {
		t.Fatalf("operational hardening generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	operationalHardeningHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/operationalhardening"
)

func TestGeneratedOperationalHardeningHygiene(t *testing.T) {
	set, err := GeneratedOperationalHardeningFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := operationalhardening.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"secret_value": "synthetic"},
		map[string]string{"key_material": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
		map[string]string{"destination_url": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := operationalhardening.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe operational hardening metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidreview"
)

func TestGeneratedAndroidReview(t *testing.T) {
	if AndroidReviewSchemaVersion != androidreview.Version || AndroidReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated Android review constants drifted")
	}
	set, err := GeneratedAndroidReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidreview.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if AndroidReviewUIStateCount < 14 || AndroidReviewMisuseCount < len(androidreview.RequiredMisuseNames()) || len(AndroidReviewUIStates) < 14 {
		t.Fatalf("generated Android review constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedAndroidReviewParity(t *testing.T) {
	parity, err := GeneratedAndroidReviewParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated Android review parity failed: %%+v", parity)
	}
	if AndroidReviewRuntimePolicy == "" || AndroidReviewPermissionPolicy == "" || AndroidReviewDiagnosticsPolicy == "" || AndroidReviewNextMilestone == "" {
		t.Fatalf("Android review generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidreview"
)

func TestGeneratedAndroidReviewHygiene(t *testing.T) {
	set, err := GeneratedAndroidReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidreview.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"dns_query": "synthetic"},
		map[string]string{"phone_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := androidreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android review metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidRuntimeTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidruntime"
)

func TestGeneratedAndroidRuntime(t *testing.T) {
	if AndroidRuntimeSchemaVersion != androidruntime.Version || AndroidRuntimeGeneratedProfileID != ProfileID {
		t.Fatalf("generated Android runtime constants drifted")
	}
	set, err := GeneratedAndroidRuntimeFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidruntime.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if AndroidRuntimeLifecycleEventCount < 10 || AndroidRuntimeMisuseCount < len(androidruntime.RequiredMisuseNames()) || len(AndroidRuntimeLifecycleEvents) < 10 {
		t.Fatalf("generated Android runtime constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidRuntimeParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedAndroidRuntimeParity(t *testing.T) {
	parity, err := GeneratedAndroidRuntimeParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated Android runtime parity failed: %%+v", parity)
	}
	if AndroidRuntimeInitializationPolicy == "" || AndroidRuntimeLifecyclePolicy == "" || AndroidRuntimeDiagnosticsPolicy == "" || AndroidRuntimeNextMilestone == "" {
		t.Fatalf("Android runtime generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidRuntimeHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidruntime"
)

func TestGeneratedAndroidRuntimeHygiene(t *testing.T) {
	set, err := GeneratedAndroidRuntimeFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidruntime.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"host_header": "synthetic"},
		map[string]string{"dns_query": "synthetic"},
		map[string]string{"phone_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := androidruntime.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android runtime metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidVPNServiceTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidvpnservice"
)

func TestGeneratedAndroidVpnService(t *testing.T) {
	if AndroidVpnServiceSchemaVersion != androidvpnservice.Version || AndroidVpnServiceGeneratedProfileID != ProfileID {
		t.Fatalf("generated Android VpnService constants drifted")
	}
	set, err := GeneratedAndroidVpnServiceFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidvpnservice.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if AndroidVpnServiceStateCount < len(androidvpnservice.RequiredVpnStates()) || AndroidVpnServiceMisuseCount < len(androidvpnservice.RequiredMisuseNames()) || len(AndroidVpnServiceStates) < len(androidvpnservice.RequiredVpnStates()) {
		t.Fatalf("generated Android VpnService constants incomplete")
	}
	if AndroidVpnServiceRuntimeStreamsMapped < 4 {
		t.Fatalf("runtime stream mapping count too low")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidVPNServiceParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedAndroidVpnServiceParity(t *testing.T) {
	parity, err := GeneratedAndroidVpnServiceParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated Android VpnService parity failed: %%+v", parity)
	}
	if AndroidVpnServicePermissionPolicy == "" || AndroidVpnServiceLifecyclePolicy == "" || AndroidVpnServicePacketFlowPolicy == "" || AndroidVpnServiceNextMilestone == "" {
		t.Fatalf("Android VpnService generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidVPNServiceHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidvpnservice"
)

func TestGeneratedAndroidVpnServiceHygiene(t *testing.T) {
	set, err := GeneratedAndroidVpnServiceFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidvpnservice.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet": "synthetic"},
		map[string]string{"packet_capture": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"host_header": "synthetic"},
		map[string]string{"dns_query": "synthetic"},
		map[string]string{"phone_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := androidvpnservice.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android VpnService metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidCarrierTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidcarrier"
)

func TestGeneratedAndroidCarrier(t *testing.T) {
	if AndroidCarrierSchemaVersion != androidcarrier.Version || AndroidCarrierGeneratedProfileID != ProfileID {
		t.Fatalf("generated Android carrier constants drifted")
	}
	set, err := GeneratedAndroidCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidcarrier.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if AndroidCarrierUIStateCount < len(androidcarrier.RequiredUIStates()) || AndroidCarrierMisuseCount < len(androidcarrier.RequiredMisuseNames()) || len(AndroidCarrierUIStates) < len(androidcarrier.RequiredUIStates()) {
		t.Fatalf("generated Android carrier constants incomplete")
	}
	if AndroidCarrierRuntimeStreamsMapped < 4 || AndroidCarrierCarrierEnvelopesMapped < 4 {
		t.Fatalf("generated Android carrier runtime mapping markers incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidCarrierParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedAndroidCarrierParity(t *testing.T) {
	parity, err := GeneratedAndroidCarrierParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated Android carrier parity failed: %%+v", parity)
	}
	if AndroidCarrierRuntimePathPolicy == "" || AndroidCarrierSelectionPolicy == "" || AndroidCarrierRelayCompatibilityPolicy == "" || AndroidCarrierNextMilestone == "" {
		t.Fatalf("Android carrier generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	androidCarrierHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/androidcarrier"
)

func TestGeneratedAndroidCarrierHygiene(t *testing.T) {
	set, err := GeneratedAndroidCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := androidcarrier.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_packet": "synthetic"},
		map[string]string{"packet_capture": "synthetic"},
		map[string]string{"visited_domain": "synthetic"},
		map[string]string{"host_header": "synthetic"},
		map[string]string{"dns_query": "synthetic"},
		map[string]string{"resolver_ip": "synthetic"},
		map[string]string{"phone_identifier": "synthetic"},
		map[string]string{"telemetry_upload_endpoint": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := androidcarrier.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe Android carrier metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayAuthPlanTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relayauthplan"
)

func TestGeneratedRelayAuthPlan(t *testing.T) {
	if RelayAuthPlanSchemaVersion != relayauthplan.Version || RelayAuthPlanGeneratedProfileID != ProfileID {
		t.Fatalf("generated relay auth constants drifted")
	}
	set, err := GeneratedRelayAuthPlanFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := relayauthplan.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if RelayAuthPlanInventoryCount < 15 || len(RelayAuthPlanControls) < len(relayauthplan.RequiredMisuseNames()) || len(RelayAuthPlanBoundComponents) < 6 {
		t.Fatalf("generated relay auth constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayAuthPlanParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedRelayAuthPlanParity(t *testing.T) {
	parity, err := GeneratedRelayAuthPlanParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || len(parity.UnexpectedDrift) != 0 {
		t.Fatalf("generated relay auth parity failed: %%+v", parity)
	}
	if RelayAuthPlanCompatibilityPolicy == "" || RelayAuthPlanRotationPolicy == "" || RelayAuthPlanFailurePolicy == "" || RelayAuthPlanRecommendedNextMilestone == "" {
		t.Fatalf("relay auth generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayAuthPlanHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relayauthplan"
)

func TestGeneratedRelayAuthPlanHygiene(t *testing.T) {
	set, err := GeneratedRelayAuthPlanFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := relayauthplan.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"secret_value": "synthetic"},
		map[string]string{"key_material_value": "synthetic"},
		map[string]string{"account_identifier": "synthetic"},
		map[string]string{"cloud_provider_metadata": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := relayauthplan.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe relay auth metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	protocol, err := renderGo(`package protocol

import (
	"context"
	"fmt"
	"net"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/observe/trace"
)

func ValidateProfile() error {
	return ir.Validate(StaticProfile())
}

func IsLoopbackAddress(addr string) bool {
	return relay.IsLoopbackAddress(addr)
}

func ListenLoopback(addr string) (net.Listener, error) {
	if !relay.IsLoopbackAddress(addr) {
		return nil, fmt.Errorf("listen address must be loopback")
	}
	return net.Listen("tcp", addr)
}

func OpenRecorder(path string) (*ktrace.Recorder, error) {
	return ktrace.OpenRecorder(path)
}

func ClientRoundTrip(ctx context.Context, server string, payload []byte, rec *ktrace.Recorder) ([]byte, error) {
	if !relay.IsLoopbackAddress(server) {
		return nil, fmt.Errorf("server address must be loopback")
	}
	return relay.ClientRoundTrip(ctx, StaticProfile(), server, payload, rec)
}

func Serve(ctx context.Context, ln net.Listener, target string, rec *ktrace.Recorder) error {
	return relay.Serve(ctx, ln, target, StaticProfile(), rec, nil)
}

func ServeEcho(ctx context.Context, ln net.Listener) error {
	return relay.ServeEcho(ctx, ln, nil)
}
`)
	if err != nil {
		return nil, err
	}

	testSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"kurdistan/internal/protocol/ir"
)

func TestStaticProfileValidates(t *testing.T) {
	p := StaticProfile()
	if p.ID != ProfileID || p.Seed != ProfileSeed {
		t.Fatalf("static profile identity mismatch")
	}
	if err := ValidateProfile(); err != nil {
		t.Fatalf("ValidateProfile() error = %%v", err)
	}
}

func TestEncodeDecodeData(t *testing.T) {
	payload := []byte("generated controlled test payload")
	frames, err := EncodeData(payload)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := DecodeFrames(frames)
	if err != nil {
		t.Fatal(err)
	}
	if op.Semantic != ir.SemanticData || !bytes.Equal(op.Payload, payload) {
		t.Fatalf("decoded operation mismatch")
	}
}

func TestGeneratedLoopbackRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() { _ = ServeEcho(ctx, echoLn) }()

	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()
	go func() { _ = Serve(ctx, serverLn, echoLn.Addr().String(), nil) }()

	payload := []byte("generated controlled loopback payload")
	echo, err := ClientRoundTrip(ctx, serverLn.Addr().String(), payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo mismatch")
	}
}
`)
	if err != nil {
		return nil, err
	}

	multiStreamTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/relay"
	"kurdistan/internal/streamadversary"
)

func TestGeneratedMultiStreamEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	count := StreamMaxConcurrentStreams
	if count > 4 {
		count = 4
	}
	if count < 2 {
		t.Fatalf("generated stream count too low: %%d", count)
	}
	result, events, err := MultiStreamDemo(ctx, count)
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenedStreams != count {
		t.Fatalf("opened streams = %%d, want %%d", result.OpenedStreams, count)
	}
	if len(events) == 0 {
		t.Fatalf("no stream events captured")
	}
}

func TestGeneratedMultiStreamResetAndLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	requests := []relay.MultiStreamRequest{
		{Label: "a", Priority: "interactive", Payload: []byte("generated stream a")},
		{Label: "b", Priority: "bulk", Payload: []byte("generated stream b"), ResetAfterOpen: true},
	}
	result, _, err := relay.SimulateMultiStreamEcho(ctx, StaticProfile(), requests)
	if err != nil {
		t.Fatal(err)
	}
	if result.ResetStreams != 1 || result.ClosedStreams != 1 {
		t.Fatalf("reset/close mismatch: %%+v", result)
	}
	tooMany := relay.DefaultMultiStreamDemoRequests(StreamMaxConcurrentStreams + 1)
	if _, _, err := relay.SimulateMultiStreamEcho(ctx, StaticProfile(), tooMany); err == nil {
		t.Fatalf("expected max concurrent stream limit")
	}
}

func TestGeneratedStreamAdversaryScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, kind := range []string{
		streamadversary.ScenarioBalancedInterleave,
		streamadversary.ScenarioBulkVsInteractive,
		streamadversary.ScenarioResetMidstream,
		streamadversary.ScenarioBlockedStream,
	} {
		t.Run(kind, func(t *testing.T) {
			run, err := streamadversary.RunScenario(ctx, StaticProfile(), streamadversary.DefaultScenario(kind))
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("scenario failed generated static profile checks: %%+v", run.Checks)
			}
			if len(run.Events) == 0 {
				t.Fatalf("scenario emitted no safe trace metadata")
			}
			raw, err := json.Marshal(run.Events)
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range streamadversary.ScenarioPayloadMarkers(run.Scenario) {
				if bytes.Contains(raw, []byte(marker)) {
					t.Fatalf("trace leaked payload marker %%q", marker)
				}
			}
		})
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxySemTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/proxyadversary"
)

func TestGeneratedProxySemDemo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := ProxySemDemo(ctx, "mixed", 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.Streams == 0 || len(events) == 0 {
		t.Fatalf("proxysem demo did not emit events: %%+v", result)
	}
	if len(result.TargetClasses) == 0 {
		t.Fatalf("proxysem demo exercised no target classes")
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range proxyadversary.ScenarioPayloadMarkers(proxyadversary.ScenarioMixedTargets) {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatalf("proxysem trace leaked payload marker %%q", marker)
		}
	}
}

func TestGeneratedProxySemConstants(t *testing.T) {
	if ProxyRelayIntentEncoding == "" || ProxyTargetDescriptorEncoding == "" || ProxyTargetClassMapping == "" {
		t.Fatalf("proxysem specialization constants missing")
	}
	if len(ProxyTargetClasses) == 0 || len(ProxySemanticWireSymbols) == 0 {
		t.Fatalf("proxysem target classes or wire symbols missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxySemAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/proxyadversary"
)

func TestGeneratedProxyAdversaryScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, kind := range []string{
		proxyadversary.ScenarioManySmallRequests,
		proxyadversary.ScenarioSlowTargetBackpressure,
		proxyadversary.ScenarioErrorTargetIsolation,
		proxyadversary.ScenarioTargetResetMidstream,
	} {
		t.Run(kind, func(t *testing.T) {
			run, err := proxyadversary.RunScenario(ctx, StaticProfile(), proxyadversary.DefaultScenario(kind))
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("generated proxy adversary scenario failed: %%+v", run.Checks)
			}
			if len(run.Events) == 0 {
				t.Fatalf("scenario emitted no proxy trace metadata")
			}
		})
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"
)

func TestGeneratedCarrierDemo(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := CarrierDemo(ctx, "mixed", 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.EnvelopeCount == 0 || result.SemanticMessages == 0 || len(events) == 0 {
		t.Fatalf("carrier demo did not emit safe metadata: %%+v", result)
	}
	if CarrierFamily == "" || CarrierEnvelopeEncoding == "" || CarrierFlushPolicy == "" {
		t.Fatalf("carrier specialization constants missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/carrieradversary"
)

func TestGeneratedCarrierAdversaryScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, kind := range []string{
		carrieradversary.ScenarioStreamVsMessageEquivalence,
		carrieradversary.ScenarioBatchingPressure,
		carrieradversary.ScenarioLossyRetryRecovery,
	} {
		t.Run(kind, func(t *testing.T) {
			run, err := carrieradversary.RunScenario(ctx, StaticProfile(), carrieradversary.DefaultScenario(kind))
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("generated carrier scenario failed: %%+v", run.Checks)
			}
			if len(run.Events) == 0 {
				t.Fatalf("carrier scenario emitted no trace metadata")
			}
		})
	}
}
`)
	if err != nil {
		return nil, err
	}

	securityTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/crypto/security"
)

func TestGeneratedSecurityTranscriptAndCapabilityParity(t *testing.T) {
	input, err := SecurityTranscriptInput()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := security.TranscriptHash(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := SecurityContext()
	if err != nil {
		t.Fatal(err)
	}
	if ctx.TranscriptHash != hash {
		t.Fatalf("generated transcript mismatch")
	}
	capabilityHash, err := (security.CapabilitySet{Features: RequiredCapabilities}).Hash()
	if err != nil {
		t.Fatal(err)
	}
	if ctx.CapabilityHash != capabilityHash {
		t.Fatalf("generated capability hash mismatch")
	}
	if SecurityVersion == "" || SecurityTranscriptMode == "" || SecurityNonceMode == "" {
		t.Fatalf("security specialization constants missing")
	}
}

func TestGeneratedSecurityEnvelopeRejectsReplayAndMismatch(t *testing.T) {
	ctx, err := SecurityContext()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := security.DeriveKeySchedule([]byte("generated-security-test-secret"), ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := security.NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	env, err := codec.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "target_response", CarrierFamily: CarrierFamily}, []byte("controlled generated security payload"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Open(env); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Open(env); err == nil {
		t.Fatalf("replayed envelope accepted")
	}
	mismatch := env
	mismatch.TranscriptHash = "different"
	fresh, err := security.NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Open(mismatch); err == nil {
		t.Fatalf("transcript mismatch accepted")
	}
}

func TestGeneratedSecurityTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := SecurityDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.EnvelopeCount == 0 || len(events) == 0 {
		t.Fatalf("security demo emitted no events")
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("generated-security-demo-secret"),
		[]byte("controlled generated security payload"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("security trace leaked forbidden material")
		}
	}
	for _, ev := range events {
		if ev.SecuritySuiteBucket == "" || ev.SecretHygieneResult == "" {
			t.Fatalf("security trace missing safe metadata: %%+v", ev)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	securityAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/crypto/security"
)

func TestGeneratedSecurityAdversaryRejectsDowngradeAndBadConfig(t *testing.T) {
	ctx, err := SecurityContext()
	if err != nil {
		t.Fatal(err)
	}
	if err := security.DetectSuiteDowngrade(ctx.Suite, security.Suite{KDF: "kdf_hkdf_sha1"}, ctx.TranscriptHash); err == nil {
		t.Fatalf("suite downgrade accepted")
	}
	cfg := security.SecurityConfig{
		ProfileID:       ProfileID,
		ProfileHash:     ctx.ProfileHash,
		InputSecret:     []byte("generated config secret"),
		Suite:           ctx.Suite,
		ReplayWindow:    SecurityReplayWindowSize,
		MaxEnvelopeBytes: CarrierMaxEnvelopeBytes,
		QueueDepth:      CarrierMaxQueueDepth,
		Capabilities:    RequiredCapabilities,
		TranscriptHash:  ctx.TranscriptHash,
		CapabilityHash:  ctx.CapabilityHash,
	}
	if err := security.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.InputSecret = make([]byte, len(cfg.InputSecret))
	if err := security.ValidateConfig(cfg); err == nil {
		t.Fatalf("unsafe generated config accepted")
	}
}

func TestGeneratedSecurityAdversaryTraceCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureSecurityTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || len(events) == 0 {
		t.Fatalf("security trace capture emitted no events")
	}
}
`)
	if err != nil {
		return nil, err
	}

	runtimeTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/proxyadversary"
	kruntime "kurdistan/internal/runtime"
)

func TestGeneratedRuntimeHappyPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := RuntimeDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.ClientState != "closed" || result.ServerState != "closed" || !result.TranscriptMatched || !result.CapabilityMatched {
		t.Fatalf("generated runtime summary mismatch: %%+v", result)
	}
	if len(events) == 0 {
		t.Fatalf("generated runtime emitted no trace metadata")
	}
}

func TestGeneratedRuntimeRejectsReplayAndProfileMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, _, err := kruntime.RunLocalHarness(ctx, StaticProfile(), kruntime.HarnessOptions{
		Scenario: proxyadversary.DefaultScenario(proxyadversary.ScenarioMixedTargets),
		ReplayInject: true,
		ClientSecret: []byte("generated-runtime-test-secret"),
		ServerSecret: []byte("generated-runtime-test-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ReplayRejected == 0 {
		t.Fatalf("generated runtime accepted replay")
	}
	mismatch := StaticProfile()
	mismatch.ID = mismatch.ID + "_mismatch"
	mismatch.GenerationHash = ""
	if _, _, err := kruntime.RunLocalHarness(ctx, StaticProfile(), kruntime.HarnessOptions{ProfileMismatch: mismatch}); err == nil {
		t.Fatalf("generated runtime accepted profile mismatch")
	}
}

func TestGeneratedRuntimeTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	secret := []byte("generated-runtime-hygiene-secret")
	result, events, err := kruntime.RunLocalHarness(ctx, StaticProfile(), kruntime.HarnessOptions{
		ClientSecret: secret,
		ServerSecret: secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if result.PayloadLogged || result.SecretLogged || bytes.Contains(raw, secret) || bytes.Contains(raw, []byte("runtime-local-bytes")) {
		t.Fatalf("generated runtime trace leaked forbidden material")
	}
}
`)
	if err != nil {
		return nil, err
	}

	runtimeAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/runtimeadversary"
)

func TestGeneratedRuntimeAdversaryScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, scenario := range runtimeadversary.QuickScenarios() {
		run := runtimeadversary.RunScenario(ctx, StaticProfile(), scenario)
		if !run.Correct {
			t.Fatalf("generated runtime adversary scenario failed: %%+v", run)
		}
	}
}

func TestGeneratedRuntimeTraceCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureRuntimeTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || len(events) == 0 {
		t.Fatalf("runtime trace capture emitted no events")
	}
}
`)
	if err != nil {
		return nil, err
	}

	hardeningTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/hardening"
	"kurdistan/internal/crypto/security"
)

func TestGeneratedHardeningDemoAndConstants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := HardeningDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.ProfileID != ProfileID || result.Generator != GeneratorVersion || result.ChecksRun == 0 || result.FailedChecks != 0 || len(events) == 0 {
		t.Fatalf("generated hardening summary mismatch: %%+v", result)
	}
	if HardeningProfileID != ProfileID || HardeningProfileHash != GenerationHash || HardeningMaxStreams != StreamMaxConcurrentStreams {
		t.Fatalf("generated hardening constants drifted")
	}
}

func TestGeneratedHardeningMisuseRejected(t *testing.T) {
	ctx, err := SecurityContext()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := security.DeriveKeySchedule(nil, ctx.TranscriptHash, ctx.Suite); err == nil {
		t.Fatalf("empty secret accepted")
	}
	if _, _, err := DecodeFrames([][]byte{{0xff, 0, 1}}); err == nil {
		t.Fatalf("malformed frame accepted")
	}
	mismatch := StaticProfile()
	mismatch.ID += "_mismatch"
	mismatch.GenerationHash = "mismatch"
	if mismatch.ID == ProfileID {
		t.Fatalf("profile mismatch fixture did not mutate")
	}
}

func TestGeneratedHardeningTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := HardeningDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.PayloadLogged || result.SecretLogged {
		t.Fatalf("generated hardening reported trace leak")
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		[]byte("generated-runtime-demo-secret"),
		[]byte("runtime-local-bytes"),
	} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("generated hardening trace leaked forbidden bytes")
		}
	}
	if report := hardening.ScanEvents(events); !report.Passed {
		t.Fatalf("generated trace hygiene failed: %%v", report.Findings)
	}
	if hardening.ScanJSON([]byte(` + "`" + `{"client_write_key":"x"}` + "`" + `)).Passed {
		t.Fatalf("secret marker accepted")
	}
}

func TestGeneratedHardeningTraceCapture(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureHardeningTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || summary.PayloadLogged || len(events) == 0 {
		t.Fatalf("hardening trace capture failed: %%+v", summary)
	}
}
`)
	if err != nil {
		return nil, err
	}

	adapterTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/adapter"
	"kurdistan/internal/adapteradversary"
)

func TestGeneratedAdapterConfigAndDemo(t *testing.T) {
	if AdapterGeneratedProfileID != ProfileID || AdapterMaxFlows <= 0 || AdapterMaxBufferedBytes <= 0 {
		t.Fatalf("adapter specialization constants missing")
	}
	if err := adapter.ValidateConfig(AdapterConfig()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := AdapterDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if result.FlowsOpened == 0 || result.RuntimeStreamsOpened == 0 || len(events) == 0 {
		t.Fatalf("adapter demo did not exercise runtime mapping: %%+v", result)
	}
	if result.PayloadLogged || result.SecretLogged {
		t.Fatalf("adapter demo reported trace leak")
	}
}

func TestGeneratedAdapterCapabilityAndInvalidFlowRejected(t *testing.T) {
	if err := adapter.RequireCapabilities(AdapterRequiredCapabilities, []string{adapter.CapabilityIngress}); err == nil {
		t.Fatalf("adapter capability downgrade accepted")
	}
	bad := adapter.FlowDescriptor{ID: "", Class: "synthetic", Direction: "bidirectional", RequestClass: "interactive", PriorityClass: "interactive", MaxReadBytes: 128, MaxWriteBytes: 128, MetadataPolicy: "bucketed"}
	if err := adapter.ValidateFlowDescriptor(bad); err == nil {
		t.Fatalf("invalid flow descriptor accepted")
	}
}

func TestGeneratedAdapterAdversaryScenarios(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, kind := range []string{
		adapteradversary.ScenarioSingleFlowHappyPath,
		adapteradversary.ScenarioLargeFlowBackpressure,
		adapteradversary.ScenarioFlowResetIsolation,
	} {
		run, err := AdapterAdversaryDemo(ctx, kind)
		if err != nil {
			t.Fatal(err)
		}
		if !run.Correct {
			t.Fatalf("generated adapter adversary scenario failed: %%+v", run)
		}
	}
}

func TestGeneratedAdapterTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureAdapterTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || summary.PayloadLogged || len(events) == 0 {
		t.Fatalf("adapter trace capture failed: %%+v", summary)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("generated-runtime-demo-secret"), []byte("runtime-local-bytes")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("adapter trace leaked forbidden bytes")
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	adapterAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/adapteradversary"
	"kurdistan/internal/protocol/ir"
)

func TestGeneratedAdapterAdversaryQuickCorpus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runs := adapteradversary.RunScenarioCorpus(ctx, []*ir.Profile{StaticProfile()}, adapteradversary.QuickScenarios())
	report := adapteradversary.AnalyzeRuns(runs, adapteradversary.DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("generated adapter adversary quick corpus failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localAdapterTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/localadapter"
)

func TestGeneratedLocalAdapterDemo(t *testing.T) {
	if LocalAdapterGeneratedProfileID != ProfileID || LocalAdapterMaxFlows <= 0 || LocalAdapterMaxChunkBytes <= 0 {
		t.Fatalf("local adapter specialization constants missing")
	}
	if err := localadapter.ValidateConfig(LocalAdapterConfig()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := LocalAdapterDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.RuntimeStreamsOpened == 0 || result.SinkChunks == 0 || len(events) == 0 {
		t.Fatalf("generated local adapter demo failed: %%+v", result)
	}
	if result.PayloadLogged || result.SecretLogged {
		t.Fatalf("local adapter trace leak reported")
	}
}

func TestGeneratedLocalAdapterInvalidSourceRejected(t *testing.T) {
	cfg := LocalAdapterConfig()
	chunk := localadapter.LocalSourceChunk{FlowID: "flow-1", Sequence: 0, ByteCount: 1}
	if err := localadapter.ValidateSourceChunk(chunk, cfg); err == nil {
		t.Fatalf("invalid source chunk accepted")
	}
}

func TestGeneratedLocalAdapterTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureLocalAdapterTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || summary.PayloadLogged || len(events) == 0 {
		t.Fatalf("local adapter trace capture failed: %%+v", summary)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("generated-runtime-demo-secret"), []byte("runtime-local-bytes")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("local adapter trace leaked forbidden bytes")
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localAdapterAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/localadapteradversary"
)

func TestGeneratedLocalAdapterAdversaryQuickCorpus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runs := localadapteradversary.RunScenarioCorpus(ctx, []*ir.Profile{StaticProfile()}, localadapteradversary.QuickScenarios())
	report := localadapteradversary.AnalyzeRuns(runs, localadapteradversary.DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("generated local adapter adversary quick corpus failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	byteTransportTestSource, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/observe/bytetransport"
)

func TestGeneratedByteTransportDemo(t *testing.T) {
	if ByteTransportGeneratedProfileID != ProfileID || ByteTransportMaxFrameBytes <= 0 || ByteTransportMaxPayloadBytes <= 0 {
		t.Fatalf("byte transport specialization constants missing")
	}
	if err := bytetransport.ValidateConfig(ByteTransportConfig()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, events, err := ByteTransportDemo(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.FramesEncoded == 0 || result.FramesDecoded == 0 || len(events) == 0 {
		t.Fatalf("generated byte transport demo failed: %%+v", result)
	}
	if result.PayloadLogged || result.SecretLogged {
		t.Fatalf("byte transport trace leak reported")
	}
}

func TestGeneratedByteTransportMalformedAndCorruptRejected(t *testing.T) {
	cfg := ByteTransportConfig()
	if _, err := bytetransport.DecodeFrameBytes(cfg, []byte{1, 2, 3}); err == nil {
		t.Fatalf("malformed byte frame accepted")
	}
	encoded, err := bytetransport.EncodeFrame(cfg, bytetransport.ByteFrame{SessionID: "generated-runtime", StreamID: 1, Sequence: 1, Kind: bytetransport.FrameData, ByteCount: 8})
	if err != nil {
		t.Fatal(err)
	}
	encoded.Bytes[8] ^= 0x44
	if _, err := bytetransport.DecodeFrameBytes(cfg, encoded.Bytes); err == nil {
		t.Fatalf("corrupted byte frame accepted")
	}
}

func TestGeneratedByteTransportTraceHygiene(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	events, summary, err := CaptureByteTransportTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || summary.PayloadLogged || len(events) == 0 {
		t.Fatalf("byte transport trace capture failed: %%+v", summary)
	}
	raw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("generated-runtime-demo-secret"), []byte("runtime-local-bytes")} {
		if bytes.Contains(raw, forbidden) {
			t.Fatalf("byte transport trace leaked forbidden bytes")
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	byteTransportAdversaryTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/bytetransportadversary"
	"kurdistan/internal/protocol/ir"
)

func TestGeneratedByteTransportAdversaryQuickCorpus(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runs := bytetransportadversary.RunScenarioCorpus(ctx, []*ir.Profile{StaticProfile()}, bytetransportadversary.QuickScenarios())
	report := bytetransportadversary.AnalyzeRuns(runs, bytetransportadversary.DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("generated byte transport adversary quick corpus failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	bytePathFixtureTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/fixtures"
)

func TestGeneratedBytePathFixtureManifest(t *testing.T) {
	if BytePathFixtureSchemaVersion != fixtures.SchemaVersion || BytePathFixtureGeneratedProfileID != ProfileID {
		t.Fatalf("generated bytepath fixture constants drifted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	manifest, err := fixtures.GenerateBytePathManifest(ctx, fixtures.ManifestOptions{
		FixtureSet: "generated-bytepath-fixture",
		Backend: fixtures.BackendGen,
		ProfileSeeds: []int{int(ProfileSeed)},
		ScenarioNames: []string{"byte_single_flow_echo", "byte_corruption_rejection", "byte_replay_rejection"},
		BackendVersion: GeneratorVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixtures.ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries) != 3 || manifest.PayloadLogged || manifest.SecretLogged {
		t.Fatalf("generated fixture manifest unsafe or incomplete: %%+v", manifest)
	}
	for _, tc := range fixtures.DefaultMalformedCorpus()[:3] {
		result := fixtures.RunMalformedCase(tc)
		if !result.Rejected || !result.SafeError {
			t.Fatalf("malformed case not safely rejected: %%+v", result)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	bytePathParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/byteparity"
)

func TestGeneratedBytePathParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	report, err := byteparity.Run(ctx, []int{int(ProfileSeed)}, []string{"byte_single_flow_echo", "byte_corruption_rejection", "byte_replay_rejection"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.ComparedPairs != 3 || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated bytepath parity failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	protocolCorpusTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/observe/protocorpus"
)

func TestGeneratedProtocolCorpusConstants(t *testing.T) {
	if ProtocolCorpusSchemaVersion != string(protocorpus.CorpusSchemaVersion) || ProtocolCorpusFeatureSchemaVersion != protocorpus.FeatureSchemaVersion {
		t.Fatalf("generated protocol corpus schema constants drifted")
	}
	if ProtocolCorpusGeneratedProfileID != ProfileID || len(GeneratedProtocolPhases) < 6 || len(GeneratedProtocolFieldKinds) < 12 {
		t.Fatalf("generated protocol corpus specialization missing")
	}
	corpus := GeneratedProtocolCorpus()
	if err := protocorpus.ValidateManifest(corpus); err != nil {
		t.Fatal(err)
	}
	if report := protocorpus.ValidateRedaction(corpus); !report.Passed {
		t.Fatalf("generated protocol corpus hygiene failed: %%v", report.Findings)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireFeaturesTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/wirefeatures"
)

func TestGeneratedWireFeatureExtraction(t *testing.T) {
	if WireFeatureSchemaVersion != wirefeatures.SchemaVersion || WireFeatureGeneratedProfileID != ProfileID {
		t.Fatalf("generated wirefeature constants drifted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseline, err := GeneratedWireFeatureBaseline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := wirefeatures.ValidateBaseline(baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.FeatureCount != 3 || baseline.PayloadLogged || baseline.SecretLogged {
		t.Fatalf("generated wirefeature baseline unsafe or incomplete: %%+v", baseline)
	}
}

func TestGeneratedWireFeatureCollapseScanner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vectors, err := GeneratedWireFeatureVectors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := wirefeatures.ScanCollapse(vectors)
	if report.FeatureVectors != len(vectors) || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated feature vectors unsafe or incomplete: %%+v", report)
	}
	collapsed := append([]wirefeatures.WireFeatureVector(nil), vectors...)
	for i := range collapsed {
		collapsed[i] = vectors[0]
		collapsed[i].ProfileID = vectors[i].ProfileID
	}
	if wirefeatures.ScanCollapse(collapsed).Conclusion != "failed" {
		t.Fatalf("collapsed wirefeature vectors not detected")
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireGenTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedWireShapePolicy(t *testing.T) {
	if WireGenPolicyVersion != "wiregen-policy-v1" || WireGenGeneratedProfileID != ProfileID {
		t.Fatalf("generated wiregen constants drifted")
	}
	if WireGenPolicyHash == "" || WireGenSelectedFamily == "" || len(WireGenFrameSizeBuckets) == 0 || len(WireGenPhaseSequence) == 0 {
		t.Fatalf("generated wiregen specialization missing")
	}
	if err := ValidateGeneratedWireShapePolicy(); err != nil {
		t.Fatal(err)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireGenParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/wiregencompare"
)

func TestGeneratedWireGenParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseline, err := GeneratedWireGenBaseline(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := wiregencompare.ValidateBaseline(baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.PolicyCount != 1 || baseline.FeatureCount != 3 || baseline.PayloadLogged || baseline.SecretLogged {
		t.Fatalf("generated wiregen baseline unsafe or incomplete: %%+v", baseline)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireGenFeaturesTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/wirefeatures"
	"kurdistan/internal/observe/wiregen"
	"kurdistan/internal/observe/wiregencompare"
)

func TestGeneratedWireGenFeatures(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	vectors, err := GeneratedWireGenVectors(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 3 {
		t.Fatalf("expected 3 generated wiregen vectors, got %%d", len(vectors))
	}
	for _, vector := range vectors {
		if err := wirefeatures.ValidateVector(vector); err != nil {
			t.Fatal(err)
		}
	}
	report := wiregencompare.ComparePoliciesToFeatures([]wiregen.WireShapePolicy{GeneratedWireShapePolicy()}, vectors)
	if report.Conclusion != "passed" {
		t.Fatalf("generated wiregen features do not match policy: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireEvalTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/wireeval"
)

func TestGeneratedWireEvalDataset(t *testing.T) {
	if WireEvalDatasetVersion != "wireeval-v1" || WireEvalGeneratedProfileID != ProfileID {
		t.Fatalf("generated wireeval constants drifted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := wireeval.ValidateDataset(dataset); err != nil {
		t.Fatal(err)
	}
	if dataset.Manifest.RecordCount == 0 || dataset.Manifest.PayloadLogged || dataset.Manifest.SecretLogged {
		t.Fatalf("generated wireeval dataset unsafe or empty: %%+v", dataset.Manifest)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireEvalExportTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/classifierdata"
)

func TestGeneratedWireEvalExports(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	csvRaw, err := GeneratedWireEvalCSV(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := classifierdata.ValidateCSV(csvRaw); err != nil {
		t.Fatal(err)
	}
	jsonlRaw, err := GeneratedWireEvalJSONL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := classifierdata.ValidateJSONL(jsonlRaw); err != nil {
		t.Fatal(err)
	}
}
`)
	if err != nil {
		return nil, err
	}

	wireEvalParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/wireeval"
)

func TestGeneratedWireEvalParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dataset, err := GeneratedWireEvalDataset(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := wireeval.ClassifierReadiness(dataset.Records, WireEvalRequiredColumns, []string{"csv", "jsonl"})
	if report.Conclusion != "passed" {
		t.Fatalf("generated wireeval readiness failed: %%+v", report)
	}
	diversity := wireeval.AnalyzeObservableDiversity(dataset.Records)
	if diversity.PayloadLogged || diversity.SecretLogged || diversity.ControlFailuresDetected == 0 {
		t.Fatalf("generated wireeval diversity unsafe or weak: %%+v", diversity)
	}
}
`)
	if err != nil {
		return nil, err
	}

	hostDetectTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/hostdetect"
)

func TestGeneratedHostDetectSummary(t *testing.T) {
	if HostDetectSchemaVersion != "hostdetect-v1" || HostDetectGeneratedProfileID != ProfileID {
		t.Fatalf("generated hostdetect constants drifted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary, err := GeneratedHostDetectSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := hostdetect.ValidateSummary(summary); err != nil {
		t.Fatal(err)
	}
	if summary.ObservationSet.ObservationCount == 0 || summary.PayloadLogged || summary.SecretLogged {
		t.Fatalf("generated hostdetect summary unsafe or empty: %%+v", summary.ObservationSet)
	}
}
`)
	if err != nil {
		return nil, err
	}

	hostDetectParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/observe/hostdetect"
)

func TestGeneratedHostDetectParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary, err := GeneratedHostDetectSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := hostdetect.CompareObservationSets(summary.ObservationSet, summary.ObservationSet)
	if report.Conclusion != "passed" || report.Changed != 0 || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated hostdetect self parity failed: %%+v", report)
	}
	if summary.Detection.ControlHostsFlagged == 0 || !summary.Resistance.ControlCollapseDetected {
		t.Fatalf("generated hostdetect controls not detected: %%+v", summary)
	}
}
`)
	if err != nil {
		return nil, err
	}

	hostDetectHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/observe/hostdetect"
)

func TestGeneratedHostDetectHygiene(t *testing.T) {
	if err := hostdetect.ScanForLeak(map[string]string{"synthetic_host_id": "host_1", "safe_bucket": "small"}); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "x"},
		{"encoded_bytes": "x"},
		{"destination_address": "127.0.0.1"},
		{"secret": "x"},
	}
	for _, tc := range unsafeCases {
		if err := hostdetect.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe hostdetect field accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayFleetTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/relayfleet"
)

func TestGeneratedRelayFleetSummary(t *testing.T) {
	if RelayFleetSchemaVersion != "relayfleet-v1" || RelayFleetGeneratedProfileID != ProfileID {
		t.Fatalf("generated relayfleet constants drifted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary, err := GeneratedRelayFleetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := relayfleet.ValidateSummary(summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.Fleet.Relays) == 0 || len(summary.ChurnEvents) == 0 || summary.PayloadLogged || summary.SecretLogged {
		t.Fatalf("generated relayfleet summary unsafe or empty: %%+v", summary)
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayFleetParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/relayfleet"
)

func TestGeneratedRelayFleetParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	summary, err := GeneratedRelayFleetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := relayfleet.CompareFleets(summary, summary)
	if report.Conclusion != "passed" || report.ComparedRelays == 0 || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated relayfleet parity failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayFleetHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relayfleet"
)

func TestGeneratedRelayFleetHygiene(t *testing.T) {
	if err := relayfleet.ScanForLeak(map[string]string{"relay_id": "relay_0001", "risk_bucket": "low"}); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "x"},
		{"cloud_provider": "x"},
		{"raw_payload": "x"},
		{"secret": "x"},
	}
	for _, tc := range unsafeCases {
		if err := relayfleet.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe relayfleet field accepted: %%v", tc)
		}
	}
	for _, marker := range RelayFleetForbiddenMarkers {
		if marker == "" {
			t.Fatalf("empty forbidden marker")
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyIngressTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyingress"
)

func TestGeneratedProxyIngressContract(t *testing.T) {
	if ProxyIngressSchemaVersion != string(proxyingress.Version) || ProxyIngressGeneratedProfileID != ProfileID {
		t.Fatalf("generated proxy ingress constants drifted")
	}
	contract := GeneratedProxyIngressContract()
	if err := proxyingress.ValidateContract(contract); err != nil {
		t.Fatal(err)
	}
	if len(ProxyIngressSupportedKinds) != len(contract.SupportedKinds) || len(ProxyIngressSupportedTargetKinds) != len(contract.SupportedTargetKinds) {
		t.Fatalf("generated proxy ingress kind markers drifted")
	}
	for _, target := range proxyingress.InvalidTargetDescriptors() {
		if err := proxyingress.ValidateTargetDescriptor(target, contract.Limits); err == nil {
			t.Fatalf("unsafe target descriptor accepted")
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyIngressParityTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyingressreview"
)

func TestGeneratedProxyIngressParity(t *testing.T) {
	review, err := GeneratedProxyIngressReview()
	if err != nil {
		t.Fatal(err)
	}
	if review.GoNoGoDecision != proxyingressreview.DecisionGo || review.PayloadLogged || review.SecretLogged {
		t.Fatalf("generated proxy ingress review failed: %%+v", review)
	}
	report := proxyingressreview.CompareParity(review, review, GeneratedProxyIngressContract(), GeneratedProxyIngressContract())
	if report.Conclusion != "passed" {
		t.Fatalf("generated proxy ingress parity failed: %%+v", report)
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyIngressHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyingress"
)

func TestGeneratedProxyIngressHygiene(t *testing.T) {
	if err := proxyingress.ScanForLeak(GeneratedProxyIngressContract()); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "x"},
		{"domain": "x"},
		{"payload": "x"},
		{"secret": "x"},
	}
	for _, tc := range unsafeCases {
		if err := proxyingress.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe proxy ingress metadata accepted: %%v", tc)
		}
	}
	if ProxyIngressFailureModeMatrixHash == "" {
		t.Fatalf("missing failure matrix hash")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingress"
)

func TestGeneratedLocalProxyIngressSummary(t *testing.T) {
	if LocalProxyIngressSchemaVersion != string(localproxyingress.Version) || LocalProxyIngressGeneratedProfileID != ProfileID {
		t.Fatalf("generated local proxy ingress constants drifted")
	}
	summary, err := GeneratedLocalProxyIngressSummary(context.Background(), localproxyingress.ScenarioSingleConnectEcho)
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingress.ValidateSummary(summary); err != nil {
		t.Fatal(err)
	}
	if summary.PayloadLogged || summary.SecretLogged || summary.AcceptedRequests == 0 {
		t.Fatalf("unsafe generated local proxy ingress summary: %%+v", summary)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingress"
)

func TestGeneratedLocalProxyIngressParity(t *testing.T) {
	set, err := GeneratedLocalProxyIngressFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingress.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if localproxyingress.CompareFixtureSets(set, set).Conclusion != "passed" {
		t.Fatalf("generated local proxy ingress parity failed")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyingress"
)

func TestGeneratedLocalProxyIngressHygiene(t *testing.T) {
	for _, marker := range LocalProxyIngressForbiddenFields {
		if marker == "" {
			t.Fatalf("empty forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "x"},
		{"dns_query": "x"},
		{"payload": "x"},
		{"secret": "x"},
	}
	for _, tc := range unsafeCases {
		if err := proxyingress.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe local proxy ingress metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingressadversary"
)

func TestGeneratedLocalProxyIngressAdversarialFixtureSet(t *testing.T) {
	if LocalProxyIngressAdversarialSchemaVersion != localproxyingressadversary.Version || LocalProxyIngressAdversarialGeneratedProfileID != ProfileID {
		t.Fatalf("generated local proxy ingress adversarial constants drifted")
	}
	set, err := GeneratedLocalProxyIngressAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingressadversary.ValidateAdversarialFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if set.Corpus.CorpusID != LocalProxyIngressAdversarialCorpusID || set.Corpus.ScenarioCount != len(LocalProxyIngressAdversarialScenarioClasses) {
		t.Fatalf("generated adversarial corpus metadata drifted")
	}
	if set.Readiness.GoNoGoDecision != LocalProxyIngressAdversarialReadinessDecision {
		t.Fatalf("generated readiness decision drifted: %%s", set.Readiness.GoNoGoDecision)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingressadversary"
)

func TestGeneratedLocalProxyIngressAdversarialParity(t *testing.T) {
	set, err := GeneratedLocalProxyIngressAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingressadversary.ValidateParityReport(set.Parity); err != nil {
		t.Fatal(err)
	}
	if localproxyingressadversary.CompareAdversarialFixtureSets(set, set).Conclusion != "passed" {
		t.Fatalf("generated local proxy ingress adversarial parity failed")
	}
	readiness, err := GeneratedLocalProxyIngressAdversarialReadiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingressadversary.ValidateReadinessReport(readiness); err != nil {
		t.Fatal(err)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProxyIngressAdvHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/localproxyingressadversary"
)

func TestGeneratedLocalProxyIngressAdversarialHygiene(t *testing.T) {
	set, err := GeneratedLocalProxyIngressAdversarialFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := localproxyingressadversary.ScanFixtureHygiene(set); err != nil {
		t.Fatal(err)
	}
	for _, marker := range LocalProxyIngressAdversarialForbiddenFields {
		if marker == "" {
			t.Fatalf("empty forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"payload": "synthetic"},
		{"raw_bytes": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := localproxyingressadversary.ScanFixtureHygiene(tc); err == nil {
			t.Fatalf("unsafe generated adversarial metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	adaptivePathTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
)

func TestGeneratedAdaptivePathFixtureSet(t *testing.T) {
	if AdaptivePathSchemaVersion != string(adaptivepath.Version) || AdaptivePathGeneratedProfileID != ProfileID {
		t.Fatalf("generated adaptive path constants drifted")
	}
	set, err := GeneratedAdaptivePathFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := adaptivepath.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(AdaptivePathCandidateFamilies) != len(set.Families) || len(AdaptivePathConditionClasses) != len(set.Conditions) {
		t.Fatalf("generated adaptive path taxonomy markers drifted")
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatalf("generated adaptive path fixture leaked sensitive flags")
	}
}
`)
	if err != nil {
		return nil, err
	}

	adaptivePathParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
)

func TestGeneratedAdaptivePathParity(t *testing.T) {
	report, err := GeneratedAdaptivePathParity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated adaptive path parity failed: %%+v", report)
	}
	set, err := GeneratedAdaptivePathFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if adaptivepath.CompareFixtureSets(set, set).Conclusion != "passed" {
		t.Fatalf("generated adaptive path fixture self-compare failed")
	}
}
`)
	if err != nil {
		return nil, err
	}

	adaptivePathHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/adaptivepath"
)

func TestGeneratedAdaptivePathHygiene(t *testing.T) {
	set, err := GeneratedAdaptivePathFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := adaptivepath.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	for _, marker := range AdaptivePathForbiddenFields {
		if marker == "" {
			t.Fatalf("empty adaptive path forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := adaptivepath.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe adaptive path metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	transportBundleTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transportbundle"
)

func TestGeneratedTransportBundleFixtureSet(t *testing.T) {
	if TransportBundleSchemaVersion != string(transportbundle.Version) || TransportBundleGeneratedProfileID != ProfileID {
		t.Fatalf("generated transport bundle constants drifted")
	}
	set, err := GeneratedTransportBundleFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := transportbundle.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(TransportBundleModes) != len(transportbundle.RequiredBundleModes()) || len(TransportBundleCandidateRoles) == 0 {
		t.Fatalf("generated transport bundle taxonomy markers drifted")
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatalf("generated transport bundle fixture leaked sensitive flags")
	}
}
`)
	if err != nil {
		return nil, err
	}

	transportBundleParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transportbundle"
)

func TestGeneratedTransportBundleParity(t *testing.T) {
	report, err := GeneratedTransportBundleParity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated transport bundle parity failed: %%+v", report)
	}
	set, err := GeneratedTransportBundleFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if transportbundle.CompareFixtureSets(set, set).Conclusion != "passed" {
		t.Fatalf("generated transport bundle fixture self-compare failed")
	}
}
`)
	if err != nil {
		return nil, err
	}

	transportBundleHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transportbundle"
)

func TestGeneratedTransportBundleHygiene(t *testing.T) {
	set, err := GeneratedTransportBundleFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := transportbundle.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	for _, marker := range TransportBundleForbiddenFields {
		if marker == "" {
			t.Fatalf("empty transport bundle forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := transportbundle.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe transport bundle metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathRaceTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/pathrace"
)

func TestGeneratedPathRaceFixtureSet(t *testing.T) {
	if PathRaceSchemaVersion != string(pathrace.Version) || PathRaceGeneratedProfileID != ProfileID {
		t.Fatalf("generated pathrace constants drifted")
	}
	set, err := GeneratedPathRaceFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := pathrace.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(PathRaceModes) == 0 || len(PathRaceEventKinds) == 0 || len(PathRaceStates) == 0 {
		t.Fatalf("generated pathrace taxonomy markers missing")
	}
	if set.PayloadLogged || set.SecretLogged {
		t.Fatalf("generated pathrace fixture leaked sensitive flags")
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathRaceParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
)

func TestGeneratedPathRaceParity(t *testing.T) {
	report, err := GeneratedPathRaceParity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated pathrace parity failed: %%+v", report)
	}
	misuse, err := GeneratedPathRaceMisuse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if misuse.Conclusion != "failed" || len(misuse.MisuseFindings) == 0 {
		t.Fatalf("generated pathrace misuse controls were not detected: %%+v", misuse)
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathRaceHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/pathrace"
)

func TestGeneratedPathRaceHygiene(t *testing.T) {
	set, err := GeneratedPathRaceFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := pathrace.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	for _, marker := range PathRaceForbiddenFields {
		if marker == "" {
			t.Fatalf("empty pathrace forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := pathrace.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe pathrace metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathHealthTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/pathhealth"
)

func TestGeneratedPathHealthFixtureSet(t *testing.T) {
	if PathHealthSchemaVersion != string(pathhealth.Version) || PathHealthGeneratedProfileID != ProfileID {
		t.Fatalf("generated pathhealth constants drifted")
	}
	set, err := GeneratedPathHealthFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Scenarios) == 0 || set.Parity.Conclusion != "passed" {
		t.Fatalf("generated pathhealth fixture failed: %%+v", set.Parity)
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathHealthParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
)

func TestGeneratedPathHealthParity(t *testing.T) {
	report, err := GeneratedPathHealthParity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		t.Fatalf("generated pathhealth parity failed: %%+v", report)
	}
	misuse, err := GeneratedPathHealthMisuse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if misuse.Conclusion != "failed" || len(misuse.MisuseFindings) == 0 {
		t.Fatalf("generated pathhealth misuse controls were not detected: %%+v", misuse)
	}
}
`)
	if err != nil {
		return nil, err
	}

	pathHealthHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/pathhealth"
)

func TestGeneratedPathHealthHygiene(t *testing.T) {
	set, err := GeneratedPathHealthFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := pathhealth.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	for _, marker := range PathHealthForbiddenFields {
		if marker == "" {
			t.Fatalf("empty pathhealth forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := pathhealth.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe pathhealth metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carrierreview"
)

func TestGeneratedCarrierReview(t *testing.T) {
	if CarrierReviewSchemaVersion != carrierreview.Version || CarrierReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated carrierreview constants drifted")
	}
	review, err := GeneratedCarrierReview()
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Descriptors) == 0 || review.Readiness.Conclusion != "passed" {
		t.Fatalf("generated carrier review failed: %%+v", review.Readiness)
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedCarrierReviewParity(t *testing.T) {
	review, err := GeneratedCarrierReview()
	if err != nil {
		t.Fatal(err)
	}
	if review.Parity.Conclusion != "passed" || review.PayloadLogged || review.SecretLogged {
		t.Fatalf("generated carrierreview parity failed: %%+v", review.Parity)
	}
	if review.Readiness.RecommendedNextMilestone != CarrierReviewRecommendedNextMilestone {
		t.Fatalf("carrierreview next milestone drifted")
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carrierreview"
)

func TestGeneratedCarrierReviewHygiene(t *testing.T) {
	review, err := GeneratedCarrierReview()
	if err != nil {
		t.Fatal(err)
	}
	if err := carrierreview.ScanForLeak(review); err != nil {
		t.Fatal(err)
	}
	for _, marker := range CarrierReviewForbiddenFields {
		if marker == "" {
			t.Fatalf("empty carrierreview forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
		{"claim": "guaranteed bypass"},
	}
	for _, tc := range unsafeCases {
		if err := carrierreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe carrierreview metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	measurementReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/measurementreview"
)

func TestGeneratedMeasurementReview(t *testing.T) {
	if MeasurementReviewSchemaVersion != measurementreview.Version || MeasurementReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated measurementreview constants drifted")
	}
	review, err := GeneratedMeasurementReview()
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Fields) == 0 || review.Readiness.Conclusion != "passed" {
		t.Fatalf("generated measurement review failed: %%+v", review.Readiness)
	}
	if len(MeasurementReviewObservationFields) == 0 || len(MeasurementReviewRedactionClasses) == 0 {
		t.Fatalf("generated measurement review taxonomy markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	measurementReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedMeasurementReviewParity(t *testing.T) {
	review, err := GeneratedMeasurementReview()
	if err != nil {
		t.Fatal(err)
	}
	if review.Parity.Conclusion != "passed" || review.PayloadLogged || review.SecretLogged {
		t.Fatalf("generated measurementreview parity failed: %%+v", review.Parity)
	}
	if review.Readiness.RecommendedNextMilestone != MeasurementReviewRecommendedNextMilestone {
		t.Fatalf("measurementreview next milestone drifted")
	}
}
`)
	if err != nil {
		return nil, err
	}

	measurementReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/measurementreview"
)

func TestGeneratedMeasurementReviewHygiene(t *testing.T) {
	review, err := GeneratedMeasurementReview()
	if err != nil {
		t.Fatal(err)
	}
	if err := measurementreview.ScanForLeak(review); err != nil {
		t.Fatal(err)
	}
	for _, marker := range MeasurementReviewForbiddenFields {
		if marker == "" {
			t.Fatalf("empty measurementreview forbidden marker")
		}
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "synthetic"},
		{"raw_packet": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"client_ip": "synthetic"},
		{"precise_location": "synthetic"},
		{"claim": "undetectable"},
	}
	for _, tc := range unsafeCases {
		if err := measurementreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe measurementreview metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyEgressTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyegress"
)

func TestGeneratedProxyEgress(t *testing.T) {
	if ProxyEgressSchemaVersion != proxyegress.Version || ProxyEgressGeneratedProfileID != ProfileID {
		t.Fatalf("generated proxyegress constants drifted")
	}
	set, err := GeneratedProxyEgressFixture()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(set.Targets) == 0 || len(ProxyEgressTargetClasses) == 0 {
		t.Fatalf("generated proxyegress fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyEgressParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedProxyEgressParity(t *testing.T) {
	parity, err := GeneratedProxyEgressParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated proxyegress parity failed: %%+v", parity)
	}
	if ProxyEgressRecommendedNextMilestone == "" || ProxyEgressMappingPolicy == "" {
		t.Fatalf("proxyegress generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	proxyEgressHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/proxyegress"
)

func TestGeneratedProxyEgressHygiene(t *testing.T) {
	set, err := GeneratedProxyEgressFixture()
	if err != nil {
		t.Fatal(err)
	}
	if err := proxyegress.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver": "synthetic"},
		{"url": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := proxyegress.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe proxyegress metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayBridgeTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relaybridge"
)

func TestGeneratedRelayBridge(t *testing.T) {
	if RelayBridgeSchemaVersion != relaybridge.Version || RelayBridgeGeneratedProfileID != ProfileID {
		t.Fatalf("generated relaybridge constants drifted")
	}
	set, err := GeneratedRelayBridgeFixture()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(set.Streams) == 0 || len(RelayBridgeStates) == 0 {
		t.Fatalf("generated relaybridge fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayBridgeParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedRelayBridgeParity(t *testing.T) {
	parity, err := GeneratedRelayBridgeParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated relaybridge parity failed: %%+v", parity)
	}
	if RelayBridgeRecommendedNextMilestone == "" || RelayBridgeMappingPolicy == "" {
		t.Fatalf("relaybridge generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	relayBridgeHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/relaybridge"
)

func TestGeneratedRelayBridgeHygiene(t *testing.T) {
	set, err := GeneratedRelayBridgeFixture()
	if err != nil {
		t.Fatal(err)
	}
	if err := relaybridge.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
		{"real_relay": "synthetic"},
		{"dial_real": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := relaybridge.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe relaybridge metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localPipelineTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localpipeline"
)

func TestGeneratedLocalPipeline(t *testing.T) {
	if LocalPipelineSchemaVersion != localpipeline.Version || LocalPipelineGeneratedProfileID != ProfileID {
		t.Fatalf("generated localpipeline constants drifted")
	}
	set, err := GeneratedLocalPipelineFixture()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(set.Runs) == 0 || len(LocalPipelineScenarioKinds) == 0 {
		t.Fatalf("generated localpipeline fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localPipelineParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLocalPipelineParity(t *testing.T) {
	parity, err := GeneratedLocalPipelineParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated localpipeline parity failed: %%+v", parity)
	}
	if LocalPipelineBoundaryPolicy == "" || LocalPipelineRecommendedNextMilestone == "" {
		t.Fatalf("localpipeline generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localPipelineHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localpipeline"
)

func TestGeneratedLocalPipelineHygiene(t *testing.T) {
	set, err := GeneratedLocalPipelineFixture()
	if err != nil {
		t.Fatal(err)
	}
	if err := localpipeline.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
		{"dns_query": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := localpipeline.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe localpipeline metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	productionReadinessTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/productionreadiness"
)

func TestGeneratedProductionReadiness(t *testing.T) {
	if ProductionReadinessSchemaVersion != productionreadiness.Version || ProductionReadinessGeneratedProfileID != ProfileID {
		t.Fatalf("generated productionreadiness constants drifted")
	}
	review, err := GeneratedProductionReadinessReview()
	if err != nil {
		t.Fatal(err)
	}
	if review.Conclusion != "passed" || len(review.Items) == 0 || len(ProductionReadinessContracts) == 0 {
		t.Fatalf("generated productionreadiness review failed: %%+v", review)
	}
}
`)
	if err != nil {
		return nil, err
	}

	productionReadinessParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedProductionReadinessParity(t *testing.T) {
	parity, err := GeneratedProductionReadinessParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated productionreadiness parity failed: %%+v", parity)
	}
	if ProductionReadinessBoundaryPolicy == "" || ProductionReadinessRecommendedNextMilestone == "" {
		t.Fatalf("productionreadiness generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	productionReadinessHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/productionreadiness"
)

func TestGeneratedProductionReadinessHygiene(t *testing.T) {
	review, err := GeneratedProductionReadinessReview()
	if err != nil {
		t.Fatal(err)
	}
	if err := productionreadiness.ScanForLeak(review); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"endpoint": "synthetic"},
		{"raw_payload": "synthetic"},
		{"secret": "synthetic"},
		{"deployment_token": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := productionreadiness.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe productionreadiness metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/concretelocaladapter"
)

func TestGeneratedConcreteLocalAdapter(t *testing.T) {
	if ConcreteLocalAdapterSchemaVersion != concretelocaladapter.Version || ConcreteLocalAdapterGeneratedProfileID != ProfileID {
		t.Fatalf("generated concrete local adapter constants drifted")
	}
	set, err := GeneratedConcreteLocalAdapterFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(ConcreteLocalAdapterScenarios) == 0 || ConcreteLocalAdapterBindClass == "" {
		t.Fatalf("generated concrete local adapter fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterParityTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"
)

func TestGeneratedConcreteLocalAdapterParity(t *testing.T) {
	parity, err := GeneratedConcreteLocalAdapterParity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated concrete local adapter parity failed: %%+v", parity)
	}
	if ConcreteLocalAdapterRuntimeMappingPolicy == "" || ConcreteLocalAdapterRecommendedNextMilestone == "" {
		t.Fatalf("concrete local adapter generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	concreteLocalAdapterHygieneTestSource, err := renderGo(`package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/concretelocaladapter"
)

func TestGeneratedConcreteLocalAdapterHygiene(t *testing.T) {
	set, err := GeneratedConcreteLocalAdapterFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := concretelocaladapter.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "unsafe"},
		{"encoded_bytes": "unsafe"},
		{"client_write_key": "unsafe"},
	}
	for _, tc := range unsafeCases {
		if err := concretelocaladapter.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe concrete local adapter metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localprotocoladapter"
)

func TestGeneratedLocalProtocolAdapter(t *testing.T) {
	if LocalProtocolAdapterSchemaVersion != localprotocoladapter.Version || LocalProtocolAdapterGeneratedProfileID != ProfileID {
		t.Fatalf("generated local protocol adapter constants drifted")
	}
	set, err := GeneratedLocalProtocolAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(LocalProtocolAdapterScenarios) == 0 || len(LocalProtocolAdapterFamilies) == 0 {
		t.Fatalf("generated local protocol adapter fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLocalProtocolAdapterParity(t *testing.T) {
	parity, err := GeneratedLocalProtocolAdapterParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated local protocol adapter parity failed: %%+v", parity)
	}
	if LocalProtocolAdapterRuntimeMappingPolicy == "" || LocalProtocolAdapterRecommendedNextMilestone == "" {
		t.Fatalf("local protocol adapter generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	localProtocolAdapterHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/localprotocoladapter"
)

func TestGeneratedLocalProtocolAdapterHygiene(t *testing.T) {
	set, err := GeneratedLocalProtocolAdapterFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := localprotocoladapter.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "synthetic"},
		{"raw_target": "synthetic"},
		{"secret": "synthetic"},
		{"resolved_address": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := localprotocoladapter.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe local protocol adapter metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	loopbackRelayTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/loopbackrelay"
)

func TestGeneratedLoopbackRelay(t *testing.T) {
	if LoopbackRelaySchemaVersion != loopbackrelay.Version || LoopbackRelayGeneratedProfileID != ProfileID {
		t.Fatalf("generated loopback relay constants drifted")
	}
	set, err := GeneratedLoopbackRelayFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(LoopbackRelayScenarios) == 0 || LoopbackRelayBindPolicy != loopbackrelay.BindPolicyLoopbackOnly {
		t.Fatalf("generated loopback relay fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	loopbackRelayParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLoopbackRelayParity(t *testing.T) {
	parity, err := GeneratedLoopbackRelayParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated loopback relay parity failed: %%+v", parity)
	}
	if LoopbackRelayRuntimePolicy == "" || LoopbackRelayRecommendedNextMilestone == "" {
		t.Fatalf("loopback relay generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	loopbackRelayHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/loopbackrelay"
)

func TestGeneratedLoopbackRelayHygiene(t *testing.T) {
	set, err := GeneratedLoopbackRelayFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := loopbackrelay.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "synthetic"},
		{"public_ip": "synthetic"},
		{"raw_secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := loopbackrelay.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe loopback relay metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	labEgressTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/labegress"
)

func TestGeneratedLabEgress(t *testing.T) {
	if LabEgressSchemaVersion != labegress.Version || LabEgressGeneratedProfileID != ProfileID {
		t.Fatalf("generated lab egress constants drifted")
	}
	set, err := GeneratedLabEgressFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || len(LabEgressScenarios) == 0 || LabEgressConnectorPolicy != labegress.ConnectorPolicyLoopbackAllowlist {
		t.Fatalf("generated lab egress fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	labEgressParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedLabEgressParity(t *testing.T) {
	parity, err := GeneratedLabEgressParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated lab egress parity failed: %%+v", parity)
	}
	if LabEgressRuntimePolicy == "" || LabEgressRecommendedNextMilestone == "" {
		t.Fatalf("lab egress generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	labEgressHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/labegress"
)

func TestGeneratedLabEgressHygiene(t *testing.T) {
	set, err := GeneratedLabEgressFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := labegress.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "synthetic"},
		{"public_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"raw_secret": "synthetic"},
	}
	for _, tc := range unsafeCases {
		if err := labegress.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe lab egress metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReadinessTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carrierreadiness"
)

func TestGeneratedCarrierReadiness(t *testing.T) {
	if CarrierReadinessSchemaVersion != carrierreadiness.Version || CarrierReadinessGeneratedProfileID != ProfileID {
		t.Fatalf("generated carrier readiness constants drifted")
	}
	set, err := GeneratedCarrierReadinessFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || CarrierReadinessDecision != carrierreadiness.DecisionReady || len(CarrierReadinessFutureMilestones) != 3 {
		t.Fatalf("generated carrier readiness fixture failed: %%+v", set)
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReadinessParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedCarrierReadinessParity(t *testing.T) {
	parity, err := GeneratedCarrierReadinessParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated carrier readiness parity failed: %%+v", parity)
	}
	if CarrierReadinessRuntimePolicy == "" || CarrierReadinessRecommendedNextMilestone == "" {
		t.Fatalf("carrier readiness generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierReadinessHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carrierreadiness"
)

func TestGeneratedCarrierReadinessHygiene(t *testing.T) {
	set, err := GeneratedCarrierReadinessFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := carrierreadiness.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []map[string]string{
		{"raw_payload": "synthetic"},
		{"raw_secret": "synthetic"},
		{"claim": "guaranteed bypass"},
	}
	for _, tc := range unsafeCases {
		if err := carrierreadiness.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe carrier readiness metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpscarrierreview"
)

func TestGeneratedHTTPSCarrierReview(t *testing.T) {
	if HTTPSCarrierReviewSchemaVersion != httpscarrierreview.Version || HTTPSCarrierReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated HTTPS carrier review constants drifted")
	}
	set, err := GeneratedHTTPSCarrierReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || HTTPSCarrierReviewDecision != httpscarrierreview.DecisionReady || len(HTTPSCarrierReviewBlockedBehaviors) < 10 {
		t.Fatalf("generated HTTPS carrier review fixture failed: %%+v", set)
	}
	if HTTPSCarrierReviewRequestShapeCount < 4 || HTTPSCarrierReviewResponseShapeCount < 4 {
		t.Fatalf("generated HTTPS carrier shape counts incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedHTTPSCarrierReviewParity(t *testing.T) {
	parity, err := GeneratedHTTPSCarrierReviewParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged {
		t.Fatalf("generated HTTPS carrier review parity failed: %%+v", parity)
	}
	if HTTPSCarrierReviewRuntimePolicy == "" || HTTPSCarrierReviewRecommendedNextMilestone == "" || len(HTTPSCarrierReviewM42Criteria) < 10 {
		t.Fatalf("HTTPS carrier review generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpscarrierreview"
)

func TestGeneratedHTTPSCarrierReviewHygiene(t *testing.T) {
	set, err := GeneratedHTTPSCarrierReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := httpscarrierreview.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"claim": "guaranteed bypass"},
		map[string]bool{"contains_sni": true},
		map[string]bool{"contains_host_header": true},
	}
	for _, tc := range unsafeCases {
		if err := httpscarrierreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe HTTPS carrier review metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpslikecarrier"
)

func TestGeneratedHTTPSLikeCarrier(t *testing.T) {
	if HTTPSLikeCarrierSchemaVersion != httpslikecarrier.Version || HTTPSLikeCarrierGeneratedProfileID != ProfileID {
		t.Fatalf("generated HTTPS-like carrier constants drifted")
	}
	set, err := GeneratedHTTPSLikeCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.BackendVersion != httpslikecarrier.BackendVersion {
		t.Fatalf("generated HTTPS-like carrier fixture failed: %%+v", set)
	}
	if HTTPSLikeCarrierMaxMarkerBytes <= 0 || HTTPSLikeCarrierRequestShapeCount < 4 || HTTPSLikeCarrierResponseShapeCount < 4 {
		t.Fatalf("generated HTTPS-like carrier shape constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedHTTPSLikeCarrierParity(t *testing.T) {
	parity, err := GeneratedHTTPSLikeCarrierParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated HTTPS-like carrier parity failed: %%+v", parity)
	}
	if HTTPSLikeCarrierRuntimePolicy == "" || HTTPSLikeCarrierRecommendedNextMilestone == "" || len(HTTPSLikeCarrierMisuseControls) < 20 {
		t.Fatalf("HTTPS-like carrier generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsLikeCarrierHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpslikecarrier"
)

func TestGeneratedHTTPSLikeCarrierHygiene(t *testing.T) {
	set, err := GeneratedHTTPSLikeCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := httpslikecarrier.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"claim": "real HTTPS carrier support"},
		map[string]bool{"contains_sni": true},
		map[string]bool{"contains_host_header": true},
		map[string]bool{"allow_public_network": true},
	}
	for _, tc := range unsafeCases {
		if err := httpslikecarrier.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe HTTPS-like carrier metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpscarrieradversary"
)

func TestGeneratedHTTPSCarrierAdversary(t *testing.T) {
	if HTTPSCarrierAdversarySchemaVersion != httpscarrieradversary.Version || HTTPSCarrierAdversaryGeneratedProfileID != ProfileID {
		t.Fatalf("generated HTTPS carrier adversary constants drifted")
	}
	set, err := GeneratedHTTPSCarrierAdversaryFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.BackendVersion != httpscarrieradversary.BackendVersion {
		t.Fatalf("generated HTTPS carrier adversary fixture failed: %%+v", set)
	}
	if HTTPSCarrierAdversaryCollapseControlCount < 4 || HTTPSCarrierAdversaryUnsafeFallbackControlCount < 8 || HTTPSCarrierAdversaryForbiddenControlCount < 20 {
		t.Fatalf("generated HTTPS carrier adversary controls incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedHTTPSCarrierAdversaryParity(t *testing.T) {
	parity, err := GeneratedHTTPSCarrierAdversaryParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated HTTPS carrier adversary parity failed: %%+v", parity)
	}
	if HTTPSCarrierAdversaryRuntimePolicy == "" || HTTPSCarrierAdversaryRecommendedNextMilestone == "" || len(HTTPSCarrierAdversaryForbiddenControls) < 20 {
		t.Fatalf("HTTPS carrier adversary generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	httpsCarrierAdversaryHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/httpscarrieradversary"
)

func TestGeneratedHTTPSCarrierAdversaryHygiene(t *testing.T) {
	set, err := GeneratedHTTPSCarrierAdversaryFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := httpscarrieradversary.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"claim": "guaranteed bypass"},
		map[string]bool{"contains_sni": true},
		map[string]bool{"contains_host_header": true},
	}
	for _, tc := range unsafeCases {
		if err := httpscarrieradversary.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe HTTPS carrier adversary metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/constrainedcarrierreview"
)

func TestGeneratedConstrainedCarrierReview(t *testing.T) {
	if ConstrainedCarrierReviewSchemaVersion != constrainedcarrierreview.Version || ConstrainedCarrierReviewGeneratedProfileID != ProfileID {
		t.Fatalf("generated constrained carrier review constants drifted")
	}
	set, err := GeneratedConstrainedCarrierReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.BackendVersion != constrainedcarrierreview.BackendVersion {
		t.Fatalf("generated constrained carrier review fixture failed: %%+v", set)
	}
	if ConstrainedCarrierReviewQueryShapeCount < 10 || ConstrainedCarrierReviewResponseShapeCount < 9 || ConstrainedCarrierReviewResolverBucketCount < 4 {
		t.Fatalf("generated constrained carrier review taxonomy constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedConstrainedCarrierReviewParity(t *testing.T) {
	parity, err := GeneratedConstrainedCarrierReviewParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated constrained carrier review parity failed: %%+v", parity)
	}
	if ConstrainedCarrierReviewRuntimePolicy == "" || ConstrainedCarrierReviewRecommendedNextMilestone == "" || len(ConstrainedCarrierReviewMisuseControls) < 20 {
		t.Fatalf("constrained carrier review generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierReviewHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/constrainedcarrierreview"
)

func TestGeneratedConstrainedCarrierReviewHygiene(t *testing.T) {
	set, err := GeneratedConstrainedCarrierReviewFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := constrainedcarrierreview.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"resolver_address_value": "synthetic"},
		map[string]string{"exact_query_value": "synthetic"},
		map[string]bool{"public_resolver_behavior": true},
	}
	for _, tc := range unsafeCases {
		if err := constrainedcarrierreview.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe constrained carrier review metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/constrainedcarrier"
)

func TestGeneratedConstrainedCarrier(t *testing.T) {
	if ConstrainedCarrierSchemaVersion != constrainedcarrier.Version || ConstrainedCarrierGeneratedProfileID != ProfileID {
		t.Fatalf("generated constrained carrier constants drifted")
	}
	set, err := GeneratedConstrainedCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" || set.BackendVersion != constrainedcarrier.BackendVersion {
		t.Fatalf("generated constrained carrier fixture failed: %%+v", set)
	}
	if ConstrainedCarrierQueryShapeCount < 8 || ConstrainedCarrierResponseShapeCount < 7 || ConstrainedCarrierCapacityBucketCount < 3 {
		t.Fatalf("generated constrained carrier taxonomy constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedConstrainedCarrierParity(t *testing.T) {
	parity, err := GeneratedConstrainedCarrierParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated constrained carrier parity failed: %%+v", parity)
	}
	if ConstrainedCarrierRuntimePolicy == "" || ConstrainedCarrierRecommendedNextMilestone == "" || len(ConstrainedCarrierMisuseControls) < 20 {
		t.Fatalf("constrained carrier generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	constrainedCarrierHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/constrainedcarrier"
)

func TestGeneratedConstrainedCarrierHygiene(t *testing.T) {
	set, err := GeneratedConstrainedCarrierFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := constrainedcarrier.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"resolver_address_value": "synthetic"},
		map[string]string{"exact_query_value": "synthetic"},
		map[string]bool{"allow_public_resolver": true},
	}
	for _, tc := range unsafeCases {
		if err := constrainedcarrier.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe constrained carrier metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/multicarrierselect"
)

func TestGeneratedMultiCarrierSelect(t *testing.T) {
	if MultiCarrierSelectSchemaVersion != multicarrierselect.Version || MultiCarrierSelectGeneratedProfileID != ProfileID {
		t.Fatalf("generated multi-carrier selection constants drifted")
	}
	set, err := GeneratedMultiCarrierSelectFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := multicarrierselect.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(MultiCarrierSelectFamilyClasses) < len(multicarrierselect.RequiredFamilyClasses()) || len(MultiCarrierSelectDecisionClasses) < len(multicarrierselect.RequiredDecisionClasses()) {
		t.Fatalf("generated multi-carrier taxonomy constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedMultiCarrierSelectParity(t *testing.T) {
	parity, err := GeneratedMultiCarrierSelectParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated multi-carrier selection parity failed: %%+v", parity)
	}
	if MultiCarrierSelectRuntimePolicy == "" || MultiCarrierSelectRecommendedNextMilestone == "" || len(MultiCarrierSelectMisuseControls) < 10 {
		t.Fatalf("multi-carrier selection generated specialization markers missing")
	}
	if GeneratedMultiCarrierSelectCandidate("default").Family == "" {
		t.Fatalf("generated multi-carrier selection candidate missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	multiCarrierSelectHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/multicarrierselect"
)

func TestGeneratedMultiCarrierSelectHygiene(t *testing.T) {
	set, err := GeneratedMultiCarrierSelectFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := multicarrierselect.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"resolver_ip": "synthetic"},
		map[string]string{"host_header": "synthetic"},
		map[string]bool{"allow_public_network": true},
	}
	for _, tc := range unsafeCases {
		if err := multicarrierselect.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe multi-carrier selection metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierCollapseTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carriercollapse"
)

func TestGeneratedCarrierCollapse(t *testing.T) {
	if CarrierCollapseSchemaVersion != carriercollapse.Version || CarrierCollapseGeneratedProfileID != ProfileID {
		t.Fatalf("generated carrier collapse constants drifted")
	}
	set, err := GeneratedCarrierCollapseFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := carriercollapse.ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if len(CarrierCollapseClasses) < len(carriercollapse.RequiredCollapseClasses()) || len(CarrierCollapseControls) < len(carriercollapse.RequiredMutationNames()) {
		t.Fatalf("generated carrier collapse constants incomplete")
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierCollapseParityTestSource, err := renderGo(`package protocol

import "testing"

func TestGeneratedCarrierCollapseParity(t *testing.T) {
	parity, err := GeneratedCarrierCollapseParity()
	if err != nil {
		t.Fatal(err)
	}
	if parity.Conclusion != "passed" || parity.PayloadLogged || parity.SecretLogged || len(parity.UnexpectedDifferences) != 0 {
		t.Fatalf("generated carrier collapse parity failed: %%+v", parity)
	}
	if CarrierCollapseRuntimePolicy == "" || CarrierCollapseRecommendedNextMilestone == "" || CarrierCollapseControlCount < 10 {
		t.Fatalf("carrier collapse generated specialization markers missing")
	}
}
`)
	if err != nil {
		return nil, err
	}

	carrierCollapseHygieneTestSource, err := renderGo(`package protocol

import (
	"testing"

	"kurdistan/internal/carriercollapse"
)

func TestGeneratedCarrierCollapseHygiene(t *testing.T) {
	set, err := GeneratedCarrierCollapseFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := carriercollapse.ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"resolver_ip": "synthetic"},
		map[string]string{"host_header_value": "synthetic"},
		map[string]bool{"payload_logged": true},
	}
	for _, tc := range unsafeCases {
		if err := carriercollapse.ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe carrier collapse metadata accepted: %%v", tc)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	benchSource, err := renderGo(`package protocol

import "testing"

func BenchmarkGeneratedEncodeDecode(b *testing.B) {
	payload := []byte("generated controlled benchmark payload")
	for i := 0; i < b.N; i++ {
		frames, err := EncodeData(payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := DecodeFrames(frames); err != nil {
			b.Fatal(err)
		}
	}
}
`)
	if err != nil {
		return nil, err
	}

	traceCapture, err := renderGo(`package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"

	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/observe/trace"
)

type TraceCaptureSummary struct {
	ProfileID         string ` + "`json:\"profile_id\"`" + `
	EchoBytes         int    ` + "`json:\"echo_bytes\"`" + `
	EventCount        int    ` + "`json:\"event_count\"`" + `
	FirstContactCount int    ` + "`json:\"first_contact_count\"`" + `
	DataEventCount    int    ` + "`json:\"data_event_count\"`" + `
	RelayReadyEvents  int    ` + "`json:\"relay_ready_events\"`" + `
	PayloadLogged     bool   ` + "`json:\"payload_logged\"`" + `
}

func CaptureLoopbackTrace(ctx context.Context, payload []byte) ([]ktrace.Event, TraceCaptureSummary, error) {
	echoCtx, stopEcho := context.WithCancel(ctx)
	defer stopEcho()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	defer echoLn.Close()
	go func() { _ = ServeEcho(echoCtx, echoLn) }()

	serverCtx, stopServer := context.WithCancel(ctx)
	defer stopServer()
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	defer serverLn.Close()
	var buf bytes.Buffer
	rec := ktrace.NewRecorder(&buf)
	go func() { _ = Serve(serverCtx, serverLn, echoLn.Addr().String(), rec) }()

	echo, err := ClientRoundTrip(ctx, serverLn.Addr().String(), payload, rec)
	stopServer()
	stopEcho()
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	if !bytes.Equal(echo, payload) {
		return nil, TraceCaptureSummary{}, fmt.Errorf("echo response mismatch")
	}
	events, err := ktrace.DecodeJSONL(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].TimeUnixNano == events[j].TimeUnixNano {
			return events[i].EventType < events[j].EventType
		}
		return events[i].TimeUnixNano < events[j].TimeUnixNano
	})
	summary := summarizeTraceCapture(events, len(echo), payload)
	return events, summary, nil
}

func CaptureGeneratedMultiStreamTrace(ctx context.Context, streamCount int) ([]ktrace.Event, TraceCaptureSummary, error) {
	events, result, err := CaptureMultiStreamTrace(ctx, streamCount)
	if err != nil {
		return nil, TraceCaptureSummary{}, err
	}
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].TimeUnixNano == events[j].TimeUnixNano {
			return events[i].EventType < events[j].EventType
		}
		return events[i].TimeUnixNano < events[j].TimeUnixNano
	})
	summary := TraceCaptureSummary{
		ProfileID:      ProfileID,
		EchoBytes:      totalEchoBytes(result),
		EventCount:     len(events),
		DataEventCount: result.OpenedStreams,
	}
	return events, summary, nil
}

func WriteTraceJSONL(path string, events []ktrace.Event) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, ev := range events {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}

func WriteTraceSummary(path string, summary TraceCaptureSummary) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func summarizeTraceCapture(events []ktrace.Event, echoBytes int, payload []byte) TraceCaptureSummary {
	summary := TraceCaptureSummary{ProfileID: ProfileID, EchoBytes: echoBytes, EventCount: len(events)}
	for _, ev := range events {
		if ev.EventType == "first_contact" {
			summary.FirstContactCount++
		}
		if ev.Semantic == "data" {
			summary.DataEventCount++
		}
		if ev.State == StaticProfile().FirstContact.RelayReadyState {
			summary.RelayReadyEvents++
		}
	}
	raw, _ := json.Marshal(events)
	summary.PayloadLogged = len(payload) > 0 && bytes.Contains(raw, payload)
	return summary
}

func totalEchoBytes(result relay.MultiStreamResult) int {
	total := 0
	for _, echo := range result.Echoes {
		total += len(echo)
	}
	return total
}
`)
	if err != nil {
		return nil, err
	}

	probeSource, err := renderGo(`package protocol

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"kurdistan/internal/relay"
)

func TestInvalidFirstContactRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- relay.HandleServerConn(ctx, serverConn, "127.0.0.1:1", StaticProfile(), nil)
	}()
	if _, err := clientConn.Write([]byte{3, 'b', 'a', 'd', 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err == nil {
		t.Fatalf("invalid first contact was accepted")
	}
}

func TestMalformedFrameRejected(t *testing.T) {
	if _, _, err := DecodeFrames([][]byte{{0xff, 0xff, 0xff}}); err == nil {
		t.Fatalf("malformed frame was accepted")
	}
}

func TestFailedAuthRejected(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	reader := bufio.NewReader(clientConn)
	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- relay.ServerHandshake(bufio.NewReader(serverConn), serverConn, StaticProfile(), nil)
	}()
	for _, step := range FirstContactSequence() {
		if step.Role == "server" {
			if _, err := readProbeContactPacket(reader); err != nil {
				t.Fatal(err)
			}
			continue
		}
		payload := make([]byte, step.PayloadSize)
		if step.Proof {
			payload = make([]byte, 32)
		}
		if err := writeProbeContactPacket(clientConn, step.WireSymbol, payload); err != nil {
			t.Fatal(err)
		}
		if step.Proof {
			break
		}
	}
	if err := <-errCh; err == nil {
		t.Fatalf("failed auth proof was accepted")
	}
}

func TestReplayPolicyRepresented(t *testing.T) {
	if InvalidReplay == "" {
		t.Fatalf("replay policy is not represented in generated constants")
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	frame := make([]byte, MaxFrameBytes+32)
	if _, _, err := DecodeFrames([][]byte{frame}); err == nil {
		t.Fatalf("oversized frame was accepted")
	}
}

func writeProbeContactPacket(w io.Writer, symbol string, payload []byte) error {
	if len(symbol) > 255 {
		return io.ErrShortWrite
	}
	packet := []byte{byte(len(symbol))}
	packet = append(packet, []byte(symbol)...)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	packet = append(packet, lenBuf[:]...)
	packet = append(packet, payload...)
	_, err := w.Write(packet)
	return err
}

func readProbeContactPacket(r *bufio.Reader) ([]byte, error) {
	symLen, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	packet := []byte{symLen}
	symbol := make([]byte, int(symLen))
	if _, err := io.ReadFull(r, symbol); err != nil {
		return nil, err
	}
	packet = append(packet, symbol...)
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	packet = append(packet, lenBuf[:]...)
	payload := make([]byte, int(binary.BigEndian.Uint16(lenBuf[:])))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	packet = append(packet, payload...)
	return packet, nil
}
`)
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
		return renderGo(`package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	%[1]s
)

func main() {
	server := flag.String("server", "", "loopback generated server address")
	message := flag.String("message", "", "message to send through the local generated protocol")
	tracePath := flag.String("trace", "", "optional payload-free trace JSONL path")
	multiStreamDemo := flag.Bool("multistream-demo", false, "run local generated multi-stream lab demo")
	proxySemDemo := flag.Bool("proxysem-demo", false, "run local generated proxy-semantics demo")
	carrierDemo := flag.Bool("carrier-demo", false, "run local generated carrier abstraction demo")
	securityDemo := flag.Bool("security-demo", false, "run local generated security demo")
	runtimeDemo := flag.Bool("runtime-demo", false, "run local generated runtime session demo")
	hardeningDemo := flag.Bool("hardening-demo", false, "run local generated hardening demo")
	adapterDemo := flag.Bool("adapter-demo", false, "run local generated adapter boundary demo")
	localAdapterDemo := flag.Bool("localadapter-demo", false, "run local generated deterministic local adapter demo")
	byteTransportDemo := flag.Bool("bytetransport-demo", false, "run local generated byte transport demo")
	targets := flag.String("targets", "mixed", "synthetic proxysem target set")
	carrierName := flag.String("carrier", "mixed", "abstract carrier model for carrier demo")
	streamCount := flag.Int("streams", 3, "logical streams for the local multi-stream demo")
	flowCount := flag.Int("flows", 0, "logical flows for the local adapter demo")
	flag.Parse()
	if *flowCount > 0 {
		*streamCount = *flowCount
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(protocol.MaxSessionMillis)*time.Millisecond)
	defer cancel()
	if *securityDemo {
		result, events, err := protocol.SecurityDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("security_envelopes=%%d transcript=%%s capability=%%s\n", result.EnvelopeCount, result.TranscriptHash[:12], result.CapabilityHash[:12])
		return
	}
	if *runtimeDemo {
		result, events, err := protocol.RuntimeDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("runtime_session=%%s streams=%%d replay_rejected=%%d backpressure_events=%%d\n", result.SessionID, result.StreamsOpened, result.ReplayRejected, result.BackpressureEvents)
		return
	}
	if *hardeningDemo {
		result, events, err := protocol.HardeningDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("hardening_checks=%%d failed=%%d\n", result.ChecksRun, result.FailedChecks)
		return
	}
	if *adapterDemo {
		result, events, err := protocol.AdapterDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("adapter_flows=%%d runtime_streams=%%d backpressure_events=%%d resets=%%d\n", result.FlowsOpened, result.RuntimeStreamsOpened, result.BackpressureEvents, result.FlowsReset)
		return
	}
	if *localAdapterDemo {
		result, events, err := protocol.LocalAdapterDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("local_adapter_flows=%%d source_chunks=%%d sink_chunks=%%d backpressure_events=%%d\n", result.FlowsOpened, result.SourceChunks, result.SinkChunks, result.BackpressureEvents)
		return
	}
	if *byteTransportDemo {
		result, events, err := protocol.ByteTransportDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("byte_transport_frames=%%d decoded=%%d fragments=%%d backpressure_events=%%d\n", result.FramesEncoded, result.FramesDecoded, result.FragmentsCreated, result.BackpressureEvents)
		return
	}
	if *carrierDemo {
		result, events, err := protocol.CarrierDemo(ctx, *carrierName, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("carrier=%%s envelopes=%%d semantic_messages=%%d backpressure_events=%%d reorder_events=%%d retry_events=%%d\n", result.Family, result.EnvelopeCount, result.SemanticMessages, result.BackpressureEvents, result.ReorderEvents, result.RetryEvents)
		return
	}
	if *proxySemDemo {
		result, events, err := protocol.ProxySemDemo(ctx, *targets, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("streams=%%d target_classes=%%d target_errors=%%d target_resets=%%d backpressure_events=%%d\n", result.Streams, len(result.TargetClasses), result.TargetErrors, result.TargetResets, result.BackpressureEvents)
		return
	}
	if *multiStreamDemo {
		result, events, err := protocol.MultiStreamDemo(ctx, *streamCount)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("streams=%%d closed=%%d reset=%%d echo_bytes=%%d\n", result.OpenedStreams, result.ClosedStreams, result.ResetStreams, sumEchoBytes(result.Echoes))
		return
	}
	if *server == "" {
		fmt.Fprintln(os.Stderr, "--server is required")
		os.Exit(2)
	}
	rec, err := protocol.OpenRecorder(*tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rec.Close()
	payload := []byte(*message)
	echo, err := protocol.ClientRoundTrip(ctx, *server, payload, rec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !bytes.Equal(echo, payload) {
		fmt.Fprintln(os.Stderr, "echo response mismatch")
		os.Exit(1)
	}
	fmt.Printf("echo_bytes=%%d\n", len(echo))
}

func sumEchoBytes(echoes map[string][]byte) int {
	total := 0
	for _, echo := range echoes {
		total += len(echo)
	}
	return total
}
`, quote(importPath))
	case "generated-server":
		return renderGo(`package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	%[1]s
)

func main() {
	listen := flag.String("listen", "", "loopback listen address")
	target := flag.String("target", "", "loopback echo target address")
	tracePath := flag.String("trace", "", "optional payload-free trace JSONL path")
	flag.Parse()
	if *listen == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "--listen and --target are required")
		os.Exit(2)
	}
	ln, err := protocol.ListenLoopback(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rec, err := protocol.OpenRecorder(*tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer rec.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := protocol.Serve(ctx, ln, *target, rec); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`, quote(importPath))
	case "generated-echo":
		return renderGo(`package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	%[1]s
)

func main() {
	listen := flag.String("listen", "", "loopback listen address")
	flag.Parse()
	if *listen == "" {
		fmt.Fprintln(os.Stderr, "--listen is required")
		os.Exit(2)
	}
	ln, err := protocol.ListenLoopback(*listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := protocol.ServeEcho(ctx, ln); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
`, quote(importPath))
	case "generated-trace":
		return renderGo(`package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	ktrace "kurdistan/internal/observe/trace"

	%[1]s
)

func main() {
	message := flag.String("message", "hello generated", "message for local generated trace capture")
	tracePath := flag.String("trace", "", "optional payload-free trace JSONL path")
	summaryPath := flag.String("summary", "", "optional trace summary JSON path")
	multiStream := flag.Bool("multistream", false, "capture local generated multi-stream trace")
	proxySem := flag.Bool("proxysem", false, "capture local generated proxy-semantics trace")
	carrierName := flag.String("carrier", "", "capture local generated carrier trace with the selected abstract carrier")
	securityTrace := flag.Bool("security", false, "capture local generated security trace")
	runtimeTrace := flag.Bool("runtime", false, "capture local generated runtime trace")
	hardeningTrace := flag.Bool("hardening", false, "capture local generated hardening trace")
	adapterTrace := flag.Bool("adapter", false, "capture local generated adapter trace")
	localAdapterTrace := flag.Bool("localadapter", false, "capture local generated deterministic local adapter trace")
	byteTransportTrace := flag.Bool("bytetransport", false, "capture local generated byte transport trace")
	targets := flag.String("targets", "mixed", "synthetic proxysem target set")
	streamCount := flag.Int("streams", 3, "logical streams for multi-stream trace capture")
	flowCount := flag.Int("flows", 0, "logical flows for adapter trace capture")
	flag.Parse()
	if *flowCount > 0 {
		*streamCount = *flowCount
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(protocol.MaxSessionMillis)*time.Millisecond)
	defer cancel()
	var events []ktrace.Event
	var summary protocol.TraceCaptureSummary
	var err error
	if *securityTrace {
		events, summary, err = protocol.CaptureSecurityTrace(ctx, *streamCount)
	} else if *runtimeTrace {
		events, summary, err = protocol.CaptureRuntimeTrace(ctx, *streamCount)
	} else if *hardeningTrace {
		events, summary, err = protocol.CaptureHardeningTrace(ctx, *streamCount)
	} else if *adapterTrace {
		events, summary, err = protocol.CaptureAdapterTrace(ctx, *streamCount)
	} else if *localAdapterTrace {
		events, summary, err = protocol.CaptureLocalAdapterTrace(ctx, *streamCount)
	} else if *byteTransportTrace {
		events, summary, err = protocol.CaptureByteTransportTrace(ctx, *streamCount)
	} else if *carrierName != "" {
		events, summary, err = protocol.CaptureCarrierTrace(ctx, *carrierName, *streamCount)
	} else if *proxySem {
		events, summary, err = protocol.CaptureProxySemTrace(ctx, *targets, *streamCount)
	} else if *multiStream {
		events, summary, err = protocol.CaptureGeneratedMultiStreamTrace(ctx, *streamCount)
	} else {
		events, summary, err = protocol.CaptureLoopbackTrace(ctx, []byte(*message))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := protocol.WriteTraceJSONL(*tracePath, events); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := protocol.WriteTraceSummary(*summaryPath, summary); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *summaryPath == "" {
		raw, _ := json.Marshal(summary)
		fmt.Println(string(raw))
	}
}
`, quote(importPath))
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

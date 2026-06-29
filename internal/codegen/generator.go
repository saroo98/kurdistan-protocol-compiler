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

	"kurdistan/internal/ir"
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

import "kurdistan/internal/ir"

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
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
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
	ktrace "kurdistan/internal/trace"
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
	ktrace "kurdistan/internal/trace"
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
	ktrace "kurdistan/internal/trace"
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

	"kurdistan/internal/security"
	ktrace "kurdistan/internal/trace"
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
	ktrace "kurdistan/internal/trace"
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

	"kurdistan/internal/ir"
	"kurdistan/internal/hardening"
	ktrace "kurdistan/internal/trace"
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
	ktrace "kurdistan/internal/trace"
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
	ktrace "kurdistan/internal/trace"
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

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/bytetransportadversary"
	ktrace "kurdistan/internal/trace"
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

import "kurdistan/internal/protocorpus"

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
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
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

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
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

	"kurdistan/internal/classifierdata"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
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

	scheduler, err := renderGo(`package protocol

import (
	"kurdistan/internal/scheduler"
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

	"kurdistan/internal/auth"
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

	protocol, err := renderGo(`package protocol

import (
	"context"
	"fmt"
	"net"

	"kurdistan/internal/ir"
	"kurdistan/internal/relay"
	ktrace "kurdistan/internal/trace"
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

	"kurdistan/internal/ir"
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

	"kurdistan/internal/security"
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

	"kurdistan/internal/security"
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
	"kurdistan/internal/security"
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
	"kurdistan/internal/ir"
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

	"kurdistan/internal/ir"
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

	"kurdistan/internal/bytetransport"
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
	"kurdistan/internal/ir"
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

	"kurdistan/internal/byteparity"
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

	"kurdistan/internal/protocorpus"
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

	"kurdistan/internal/wirefeatures"
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

	"kurdistan/internal/wiregencompare"
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

	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
	"kurdistan/internal/wiregencompare"
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

	"kurdistan/internal/wireeval"
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

	"kurdistan/internal/classifierdata"
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

	"kurdistan/internal/wireeval"
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
	ktrace "kurdistan/internal/trace"
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

	ktrace "kurdistan/internal/trace"

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

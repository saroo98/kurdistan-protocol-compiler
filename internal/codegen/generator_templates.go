// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package codegen

// Generated-code templates extracted from generator.go (Stage 4b).
// Each const holds the exact constant string expression previously inlined
// at a renderGo call site; values are unchanged (byte-identical output).

const genTmpl001 = `package protocol

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
`

const genTmpl002 = `package protocol

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
`

const genTmpl003 = `package protocol

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
`

const genTmpl004 = `package protocol

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
`

const genTmpl005 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/proxyadversary"
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
	Streams            int      ` + "`json:\"streams\"`" + `
	TargetClasses      []string ` + "`json:\"target_classes\"`" + `
	TargetErrors       int      ` + "`json:\"target_errors\"`" + `
	TargetResets       int      ` + "`json:\"target_resets\"`" + `
	BackpressureEvents int      ` + "`json:\"backpressure_events\"`" + `
	EventCount          int      ` + "`json:\"event_count\"`" + `
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
`

const genTmpl006 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/carrieradversary"
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
	Family             string ` + "`json:\"family\"`" + `
	Scenario           string ` + "`json:\"scenario\"`" + `
	EnvelopeCount      int    ` + "`json:\"envelope_count\"`" + `
	SemanticMessages    int    ` + "`json:\"semantic_messages\"`" + `
	BackpressureEvents int    ` + "`json:\"backpressure_events\"`" + `
	ReorderEvents      int    ` + "`json:\"reorder_events\"`" + `
	RetryEvents        int    ` + "`json:\"retry_events\"`" + `
	EventCount         int    ` + "`json:\"event_count\"`" + `
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
`

const genTmpl007 = `package protocol

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
`

const genTmpl008 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/proxyadversary"
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
`

const genTmpl009 = `package protocol

import (
	"context"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/lab/hardening"
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
	ProfileID      string ` + "`json:\"profile_id\"`" + `
	ChecksRun      int    ` + "`json:\"checks_run\"`" + `
	FailedChecks   int    ` + "`json:\"failed_checks\"`" + `
	PayloadLogged  bool   ` + "`json:\"payload_logged\"`" + `
	SecretLogged   bool   ` + "`json:\"secret_logged\"`" + `
	Generator      string ` + "`json:\"generator\"`" + `
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
`

const genTmpl010 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/adapter"
	"kurdistan/internal/lab/adapteradversary"
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
`

const genTmpl011 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/localadapter"
	"kurdistan/internal/lab/localadapteradversary"
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
`

const genTmpl012 = `package protocol

import (
	"context"

	"kurdistan/internal/observe/bytetransport"
	"kurdistan/internal/lab/bytetransportadversary"
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
`

const genTmpl013 = `package protocol

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
`

const genTmpl014 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/fixtures"
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
`

const genTmpl015 = `package protocol

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
`

const genTmpl016 = `package protocol

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
`

const genTmpl017 = `package protocol

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
`

const genTmpl018 = `package protocol

import (
	"context"

	"kurdistan/internal/operator/relayfleet"
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
`

const genTmpl019 = `package protocol

import (
	"kurdistan/internal/lab/proxyingress"
	"kurdistan/internal/contracts/proxy/proxyingressreview"
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
`

const genTmpl020 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/localproxyingress"
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
`

const genTmpl021 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/localproxyingressadversary"
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
`

const genTmpl022 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/adaptivepath"
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
`

const genTmpl023 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/transportbundle"
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
`

const genTmpl024 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/pathrace"
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
`

const genTmpl025 = `package protocol

import (
	"context"

	"kurdistan/internal/transport/pathhealth"
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
`

const genTmpl026 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/carrierreview"
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
`

const genTmpl027 = `package protocol

import (
	"kurdistan/internal/contracts/readiness/measurementreview"
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
`

const genTmpl028 = `package protocol

import (
	"kurdistan/internal/lab/proxyegress"
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
`

const genTmpl029 = `package protocol

import (
	"kurdistan/internal/operator/relaybridge"
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
`

const genTmpl030 = `package protocol

import (
	"kurdistan/internal/contracts/lab/localpipeline"
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
`

const genTmpl031 = `package protocol

import (
	"kurdistan/internal/contracts/readiness/productionreadiness"
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
`

const genTmpl032 = `package protocol

import (
	"context"

	"kurdistan/internal/lab/concretelocaladapter"
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
`

const genTmpl033 = `package protocol

import (
	"kurdistan/internal/lab/localprotocoladapter"
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
`

const genTmpl034 = `package protocol

import (
	"kurdistan/internal/contracts/lab/loopbackrelay"
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
`

const genTmpl035 = `package protocol

import (
	"kurdistan/internal/contracts/lab/labegress"
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
`

const genTmpl036 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/carrierreadiness"
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
`

const genTmpl037 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/httpscarrierreview"
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
`

const genTmpl038 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/httpslikecarrier"
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
`

const genTmpl039 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
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
`

const genTmpl040 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/constrainedcarrierreview"
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
`

const genTmpl041 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/constrainedcarrier"
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
`

const genTmpl042 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/multicarrierselect"
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
`

const genTmpl043 = `package protocol

import (
	"kurdistan/internal/contracts/carrier/carriercollapse"
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
`

const genTmpl044 = `package protocol

import (
	"kurdistan/internal/contracts/proxy/localproxyadapterreview"
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
`

const genTmpl045 = `package protocol

import (
	"kurdistan/internal/lab/localproxyadapter"
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
`

const genTmpl046 = `package protocol

import (
	"kurdistan/internal/contracts/vpn/vpnsemantics"
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
`

const genTmpl047 = `package protocol

import (
	"kurdistan/internal/contracts/vpn/localvpnadapter"
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
`

const genTmpl048 = `package protocol

import (
	"kurdistan/internal/operator/relayprocess"
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
`

const genTmpl049 = `package protocol

import (
	"kurdistan/internal/contracts/readiness/keyexchangeplan"
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
`

const genTmpl050 = `package protocol

import (
	"kurdistan/internal/operator/relayauthplan"
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
`

const genTmpl051 = `package protocol

import (
	"kurdistan/internal/contracts/readiness/operationalhardening"
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
`

const genTmpl052 = `package protocol

import (
	"kurdistan/internal/contracts/android/androidreview"
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
`

const genTmpl053 = `package protocol

import (
	"kurdistan/internal/contracts/android/androidruntime"
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
`

const genTmpl054 = `package protocol

import (
	"kurdistan/internal/contracts/android/androidvpnservice"
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
`

const genTmpl055 = `package protocol

import (
	"kurdistan/internal/contracts/android/androidcarrier"
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
`

const genTmpl056 = `package protocol

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
`

const genTmpl057 = `package protocol

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
`

const genTmpl058 = `package protocol

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
`

const genTmpl059 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/proxy/localproxyadapterreview"
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
`

const genTmpl060 = `package protocol

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
`

const genTmpl061 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/proxy/localproxyadapterreview"
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
`

const genTmpl062 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/localproxyadapter"
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
`

const genTmpl063 = `package protocol

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
`

const genTmpl064 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/localproxyadapter"
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
`

const genTmpl065 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/vpn/vpnsemantics"
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
`

const genTmpl066 = `package protocol

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
`

const genTmpl067 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/vpn/vpnsemantics"
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
`

const genTmpl068 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/vpn/localvpnadapter"
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
`

const genTmpl069 = `package protocol

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
`

const genTmpl070 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/vpn/localvpnadapter"
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
`

const genTmpl071 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relayprocess"
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
`

const genTmpl072 = `package protocol

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
`

const genTmpl073 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relayprocess"
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
`

const genTmpl074 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/keyexchangeplan"
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
`

const genTmpl075 = `package protocol

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
`

const genTmpl076 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/keyexchangeplan"
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
`

const genTmpl077 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/operationalhardening"
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
`

const genTmpl078 = `package protocol

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
`

const genTmpl079 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/operationalhardening"
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
`

const genTmpl080 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidreview"
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
`

const genTmpl081 = `package protocol

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
`

const genTmpl082 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidreview"
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
`

const genTmpl083 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidruntime"
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
`

const genTmpl084 = `package protocol

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
`

const genTmpl085 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidruntime"
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
`

const genTmpl086 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidvpnservice"
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
`

const genTmpl087 = `package protocol

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
`

const genTmpl088 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidvpnservice"
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
`

const genTmpl089 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidcarrier"
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
`

const genTmpl090 = `package protocol

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
`

const genTmpl091 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/android/androidcarrier"
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
`

const genTmpl092 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relayauthplan"
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
`

const genTmpl093 = `package protocol

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
`

const genTmpl094 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relayauthplan"
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
`

const genTmpl095 = `package protocol

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
`

const genTmpl096 = `package protocol

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
`

const genTmpl097 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/relay"
	"kurdistan/internal/lab/streamadversary"
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
`

const genTmpl098 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/transport/proxyadversary"
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
`

const genTmpl099 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/transport/proxyadversary"
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
`

const genTmpl100 = `package protocol

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
`

const genTmpl101 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/lab/carrieradversary"
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
`

const genTmpl102 = `package protocol

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
`

const genTmpl103 = `package protocol

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
`

const genTmpl104 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/transport/proxyadversary"
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
`

const genTmpl105 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/lab/runtimeadversary"
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
`

const genTmpl106 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/lab/hardening"
	"kurdistan/internal/crypto/security"
)

const generatedHardeningTestTimeout = 15 * time.Second

func TestGeneratedHardeningDemoAndConstants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), generatedHardeningTestTimeout)
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
	ctx, cancel := context.WithTimeout(context.Background(), generatedHardeningTestTimeout)
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
	ctx, cancel := context.WithTimeout(context.Background(), generatedHardeningTestTimeout)
	defer cancel()
	events, summary, err := CaptureHardeningTrace(ctx, 4)
	if err != nil {
		t.Fatal(err)
	}
	if summary.EventCount == 0 || summary.PayloadLogged || len(events) == 0 {
		t.Fatalf("hardening trace capture failed: %%+v", summary)
	}
}
`

const genTmpl107 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/transport/adapter"
	"kurdistan/internal/lab/adapteradversary"
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
`

const genTmpl108 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/lab/adapteradversary"
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
`

const genTmpl109 = `package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"kurdistan/internal/lab/localadapter"
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
`

const genTmpl110 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/lab/localadapteradversary"
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
`

const genTmpl111 = `package protocol

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
`

const genTmpl112 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/lab/bytetransportadversary"
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
`

const genTmpl113 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/lab/fixtures"
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
`

const genTmpl114 = `package protocol

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
`

const genTmpl115 = `package protocol

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
`

const genTmpl116 = `package protocol

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
`

const genTmpl117 = `package protocol

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
`

const genTmpl118 = `package protocol

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
`

const genTmpl119 = `package protocol

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
`

const genTmpl120 = `package protocol

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
`

const genTmpl121 = `package protocol

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
`

const genTmpl122 = `package protocol

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
`

const genTmpl123 = `package protocol

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
`

const genTmpl124 = `package protocol

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
`

const genTmpl125 = `package protocol

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
`

const genTmpl126 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/operator/relayfleet"
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
`

const genTmpl127 = `package protocol

import (
	"context"
	"testing"
	"time"

	"kurdistan/internal/operator/relayfleet"
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
`

const genTmpl128 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relayfleet"
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
`

const genTmpl129 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/proxyingress"
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
`

const genTmpl130 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/proxy/proxyingressreview"
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
`

const genTmpl131 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/proxyingress"
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
`

const genTmpl132 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/localproxyingress"
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
`

const genTmpl133 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/localproxyingress"
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
`

const genTmpl134 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/proxyingress"
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
`

const genTmpl135 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/localproxyingressadversary"
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
`

const genTmpl136 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/localproxyingressadversary"
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
`

const genTmpl137 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/localproxyingressadversary"
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
`

const genTmpl138 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/adaptivepath"
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
`

const genTmpl139 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/adaptivepath"
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
`

const genTmpl140 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/adaptivepath"
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
`

const genTmpl141 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/transportbundle"
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
`

const genTmpl142 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/transportbundle"
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
`

const genTmpl143 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/transportbundle"
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
`

const genTmpl144 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/pathrace"
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
`

const genTmpl145 = `package protocol

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
`

const genTmpl146 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/pathrace"
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
`

const genTmpl147 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/pathhealth"
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
`

const genTmpl148 = `package protocol

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
`

const genTmpl149 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/transport/pathhealth"
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
`

const genTmpl150 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
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
`

const genTmpl151 = `package protocol

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
`

const genTmpl152 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
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
`

const genTmpl153 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/measurementreview"
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
`

const genTmpl154 = `package protocol

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
`

const genTmpl155 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/measurementreview"
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
`

const genTmpl156 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/proxyegress"
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
`

const genTmpl157 = `package protocol

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
`

const genTmpl158 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/proxyegress"
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
`

const genTmpl159 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relaybridge"
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
`

const genTmpl160 = `package protocol

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
`

const genTmpl161 = `package protocol

import (
	"testing"

	"kurdistan/internal/operator/relaybridge"
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
`

const genTmpl162 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/localpipeline"
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
`

const genTmpl163 = `package protocol

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
`

const genTmpl164 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/localpipeline"
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
`

const genTmpl165 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/productionreadiness"
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
`

const genTmpl166 = `package protocol

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
`

const genTmpl167 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/readiness/productionreadiness"
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
`

const genTmpl168 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/concretelocaladapter"
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
`

const genTmpl169 = `package protocol

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
`

const genTmpl170 = `package protocol

import (
	"context"
	"testing"

	"kurdistan/internal/lab/concretelocaladapter"
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
`

const genTmpl171 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/localprotocoladapter"
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
`

const genTmpl172 = `package protocol

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
`

const genTmpl173 = `package protocol

import (
	"testing"

	"kurdistan/internal/lab/localprotocoladapter"
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
`

const genTmpl174 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/loopbackrelay"
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
`

const genTmpl175 = `package protocol

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
`

const genTmpl176 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/loopbackrelay"
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
`

const genTmpl177 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/labegress"
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
`

const genTmpl178 = `package protocol

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
`

const genTmpl179 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/lab/labegress"
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
`

const genTmpl180 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreadiness"
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
`

const genTmpl181 = `package protocol

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
`

const genTmpl182 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreadiness"
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
`

const genTmpl183 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpscarrierreview"
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
`

const genTmpl184 = `package protocol

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
`

const genTmpl185 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpscarrierreview"
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
`

const genTmpl186 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpslikecarrier"
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
`

const genTmpl187 = `package protocol

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
`

const genTmpl188 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpslikecarrier"
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
`

const genTmpl189 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
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
`

const genTmpl190 = `package protocol

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
`

const genTmpl191 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/httpscarrieradversary"
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
`

const genTmpl192 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/constrainedcarrierreview"
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
`

const genTmpl193 = `package protocol

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
`

const genTmpl194 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/constrainedcarrierreview"
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
`

const genTmpl195 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/constrainedcarrier"
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
`

const genTmpl196 = `package protocol

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
`

const genTmpl197 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/constrainedcarrier"
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
`

const genTmpl198 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/multicarrierselect"
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
`

const genTmpl199 = `package protocol

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
`

const genTmpl200 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/multicarrierselect"
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
`

const genTmpl201 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carriercollapse"
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
`

const genTmpl202 = `package protocol

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
`

const genTmpl203 = `package protocol

import (
	"testing"

	"kurdistan/internal/contracts/carrier/carriercollapse"
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
`

const genTmpl204 = `package protocol

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
`

const genTmpl205 = `package protocol

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
`

const genTmpl206 = `package protocol

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
`

const genTmpl207 = `package main

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
`

const genTmpl208 = `package main

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
`

const genTmpl209 = `package main

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
`

const genTmpl210 = `package main

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
`

func strictRuntimeTemplateV1() string {
	return `// Package strictv1 provides strictv1/runtime.go, the sole strict evidentiary surface; sibling protocol/** and cmd/** are legacy parity-only and non-evidentiary.
package strictv1

import (
	auth "kurdistan/internal/crypto/auth"
	kruntime "kurdistan/internal/runtime"
)

const (
	ProtocolSchemaVersion = "0.2.0-lab"
	SecurityVersion = "0.13.0-lab"
	RuntimeSecurityVersion = "0.13.0-lab"
	HandshakeVersion = "kurdistan-handshake-v1"
	PolicyEncodingVersion = "policy-v1"
	RecordVersion = "record-v1"
)

func NewStrictRuntimeV1(client, relay auth.Dependencies, clientRegistry kruntime.` + "ClientProfileAuthorization" + `RegistryV1, relayRegistry kruntime.` + "RelayProfileAuthorization" + `RegistryV1) (*kruntime.` + "Handshake" + `Runtime, error) {
	return kruntime.` + "NewStrictHandshake" + `RuntimeV1(client, relay, clientRegistry, relayRegistry)
}
`
}

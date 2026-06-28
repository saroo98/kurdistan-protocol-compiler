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
		{RelPath: "protocol/scheduler_generated.go", Content: scheduler, Go: true},
		{RelPath: "protocol/invalid_input_generated.go", Content: invalid, Go: true},
		{RelPath: "protocol/auth_generated.go", Content: auth, Go: true},
		{RelPath: "protocol/protocol.go", Content: protocol, Go: true},
		{RelPath: "protocol/trace_capture_generated.go", Content: traceCapture, Go: true},
		{RelPath: "protocol/protocol_test.go", Content: testSource, Go: true},
		{RelPath: "protocol/multistream_test.go", Content: multiStreamTestSource, Go: true},
		{RelPath: "protocol/proxysem_test.go", Content: proxySemTestSource, Go: true},
		{RelPath: "protocol/proxyadversary_test.go", Content: proxySemAdversaryTestSource, Go: true},
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
	targets := flag.String("targets", "mixed", "synthetic proxysem target set")
	streamCount := flag.Int("streams", 3, "logical streams for the local multi-stream demo")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(protocol.MaxSessionMillis)*time.Millisecond)
	defer cancel()
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
	targets := flag.String("targets", "mixed", "synthetic proxysem target set")
	streamCount := flag.Int("streams", 3, "logical streams for multi-stream trace capture")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(protocol.MaxSessionMillis)*time.Millisecond)
	defer cancel()
	var events []ktrace.Event
	var summary protocol.TraceCaptureSummary
	var err error
	if *proxySem {
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

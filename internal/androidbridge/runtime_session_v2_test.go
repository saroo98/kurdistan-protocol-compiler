// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
)

func TestRuntimeOpenRequestV2CanonicalRoundTrip(t *testing.T) {
	want := RuntimeOpenRequestV2{
		VerifyRequest:    []byte{1, 2, 3},
		ActivationRecord: []byte{4, 5},
		RecipientRequest: []byte{6, 7, 8},
		RecipientPrivate: []byte{9, 10},
		Policy: RuntimePolicyRequest{
			SelectionMode: RuntimeSelectionAutomatic,
			PerAppMode:    RuntimePerAppAllApps,
			Packages:      []string{},
			IPMode:        RuntimeIPV4Only,
			DNSMode:       RuntimeDNSInternal,
			MTU:           1280,
		},
	}
	encoded, err := EncodeRuntimeOpenRequestV2(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRuntimeOpenRequestV2(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip mismatch\n got=%+v\nwant=%+v", got, want)
	}
	for index := range encoded {
		mutated := append([]byte(nil), encoded...)
		mutated[index] ^= 1
		if _, err := DecodeRuntimeOpenRequestV2(mutated); err == nil && index < runtimeOpenV2HeaderBytes {
			t.Fatalf("accepted mutated header byte %d", index)
		}
	}
}

func TestRuntimeSessionSnapshotV2CanonicalRoundTrip(t *testing.T) {
	want := RuntimeSessionSnapshotV2{
		Generation: 7, PlanDigest: [32]byte{1}, ContentFingerprint: [16]byte{2}, StrategyFingerprint: [16]byte{3}, RelayFingerprint: [16]byte{4},
		SelectionMode: RuntimeSelectionAutomatic, PerAppMode: RuntimePerAppIncludeOnly, Packages: []string{"org.kurdistan.app"},
		IPMode: RuntimeIPDualStack, DNSMode: RuntimeDNSInternal, MTU: 1280, Metered: true,
		ClientIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: [4]byte{10, 89, 0, 1}, ClientIPv6: [16]byte{0xfd, 1}, DNSIPv6: [16]byte{0xfd, 2},
		Routes:           []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}, {Address: make([]byte, 16), PrefixLen: 0}},
		PayloadProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolICMP, runtimepolicy.PayloadProtocolTCP},
		MaxQueuePackets:  32, MaxIncompleteOps: 16, MaxReconnectAttempts: 3, DialTimeoutMillis: 5000, IdleTimeoutMillis: 30000,
	}
	encoded, err := EncodeRuntimeSessionSnapshotV2(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeRuntimeSessionSnapshotV2(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot round trip mismatch\n got=%+v\nwant=%+v", got, want)
	}
}

func TestRuntimeSessionV2EnforcesProtectedSocketAndTUNOrder(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan:    sessionplan.PlanV2{Digest: [32]byte{1}},
		factory: factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	defer registry.Free(handle)

	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodePolicyRejected {
		t.Fatalf("commit before prepare code=%v", code)
	}
	fd, code := RuntimeSocketPrepare(&registry, handle)
	if code != CodeOK || fd != 41 {
		t.Fatalf("prepare fd=%d code=%v", fd, code)
	}
	if got := factory.network.calls(); !reflect.DeepEqual(got, []string{"prepare"}) {
		t.Fatalf("prepare connected early: %v", got)
	}
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodePolicyRejected {
		t.Fatalf("double prepare code=%v", code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, false); code != CodePolicyRejected {
		t.Fatalf("unprotected commit code=%v", code)
	}
	if stateValue, code := RuntimeStatus(&registry, handle); code != CodeOK || stateValue != RuntimeStateClosed {
		t.Fatalf("failed protection did not close state=%v code=%v", stateValue, code)
	}
}

func TestRuntimeSessionV2RunsOnlyAfterAuthenticatedTUNAttach(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan:    sessionplan.PlanV2{Digest: [32]byte{1}},
		factory: factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	defer registry.Free(handle)
	if code := RuntimeTUNAttach(&registry, handle, 73); code != CodePolicyRejected {
		t.Fatalf("attach before auth code=%v", code)
	}
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatalf("prepare code=%v", code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodeOK {
		t.Fatalf("commit code=%v", code)
	}
	if current, code := RuntimeStatus(&registry, handle); code != CodeOK || current != RuntimeStateKurdAuthenticated {
		t.Fatalf("authenticated state=%v code=%v", current, code)
	}
	if code := RuntimeTUNAttach(&registry, handle, 73); code != CodeOK {
		t.Fatalf("attach code=%v", code)
	}
	if current, code := RuntimeStatus(&registry, handle); code != CodeOK || current != RuntimeStateRunning {
		t.Fatalf("running state=%v code=%v", current, code)
	}
	want := []string{"prepare", "connect", "tls", "kurd", "attach:73", "start"}
	if got := factory.network.calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls=%v want=%v", got, want)
	}
	if code := RuntimeTUNAttach(&registry, handle, 74); code != CodePolicyRejected {
		t.Fatalf("double attach code=%v", code)
	}
	if code := RuntimeStop(&registry, handle); code != CodeOK {
		t.Fatalf("stop code=%v", code)
	}
	if _, code := RuntimeStatus(&registry, handle); code != CodeAlreadyClosed {
		t.Fatalf("status after stop code=%v", code)
	}
}

func TestRuntimeSessionV2ReportsOnlyBoundedAggregateNetworkDiagnostics(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	factory.network.diagnostics = RuntimeNetworkDiagnosticsV1{
		TUNPacketsRead:          1,
		OutboundPacketsAccepted: 2,
		CarrierRecordsWritten:   3,
		CarrierRecordsRead:      4,
		AuthenticatedOperations: 5,
		InnerPacketsAccepted:    6,
		InnerPacketsRejected:    7,
		TUNWriteAttempts:        8,
		TUNWriteFailures:        9,
		TUNWriteFailureCode:     10,
		TUNWriteErrno:           11,
		TUNPacketsWritten:       12,
		RejectedTUNPackets:      13,
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateRunning,
		plan:    sessionplan.PlanV2{Digest: [32]byte{1}},
		factory: factory,
		network: &factory.network,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatalf("open code=%v", code)
	}
	defer registry.Free(handle)

	got, code := RuntimeNetworkDiagnostics(&registry, handle)
	if code != CodeOK {
		t.Fatalf("diagnostics code=%v", code)
	}
	if !reflect.DeepEqual(got, factory.network.diagnostics) {
		t.Fatalf("diagnostics=%+v want=%+v", got, factory.network.diagnostics)
	}
}

func TestRuntimeSessionV2ReportsAsynchronousNetworkFailure(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan:    sessionplan.PlanV2{Digest: [32]byte{1}},
		factory: factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}
	defer registry.Free(handle)
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatal(code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodeOK {
		t.Fatal(code)
	}
	if code := RuntimeTUNAttach(&registry, handle, 73); code != CodeOK {
		t.Fatal(code)
	}
	factory.network.setStatus(CodeTUNIOFailed)

	if current, code := RuntimeStatus(&registry, handle); code != CodeTUNIOFailed || current != RuntimeStateClosed {
		t.Fatalf("asynchronous failure state=%v code=%v", current, code)
	}
	if !factory.network.closed() {
		t.Fatal("asynchronous failure did not close network")
	}
}

func TestRuntimeSessionV2CancelClosesNetwork(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan:    sessionplan.PlanV2{Digest: [32]byte{1}},
		factory: factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatal(code)
	}
	if code := registry.Cancel(handle); code != CodeOK {
		t.Fatal(code)
	}
	deadline := time.Now().Add(time.Second)
	for !factory.network.closed() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !factory.network.closed() {
		t.Fatal("cancel did not close network")
	}
	if code := registry.Free(handle); code != CodeOK {
		t.Fatal(code)
	}
}

func TestRuntimeStopRetiresHandleWhenNetworkCleanupFails(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	factory.network.closeCode = CodeTUNIOFailed
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateRunning,
		plan: sessionplan.PlanV2{Digest: [32]byte{1}}, factory: factory, network: &factory.network,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}

	if code := RuntimeStop(&registry, handle); code != CodeTUNIOFailed {
		t.Fatalf("stop code=%v", code)
	}
	if factory.network.closeCount() != 1 {
		t.Fatalf("close count=%d want=1", factory.network.closeCount())
	}
	if _, code := RuntimeStatus(&registry, handle); code != CodeAlreadyClosed {
		t.Fatalf("status after failed cleanup code=%v", code)
	}
	if code := RuntimeStop(&registry, handle); code != CodeAlreadyClosed {
		t.Fatalf("duplicate stop code=%v", code)
	}
	if code := registry.Free(handle); code != CodeAlreadyClosed {
		t.Fatalf("free after stop code=%v", code)
	}
}

func TestRuntimeCancellationRetainsCleanupFailureUntilHandleRelease(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	factory.network.closeCode = CodeInternalFailure
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateSocketPrepared,
		plan: sessionplan.PlanV2{Digest: [32]byte{1}}, factory: factory, network: &factory.network,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}

	if code := registry.Cancel(handle); code != CodeInternalFailure {
		t.Fatalf("cancel code=%v", code)
	}
	if code := registry.Free(handle); code != CodeInternalFailure {
		t.Fatalf("free code=%v", code)
	}
	if factory.network.closeCount() != 1 {
		t.Fatalf("close count=%d want=1", factory.network.closeCount())
	}
	if _, code := RuntimeStatus(&registry, handle); code != CodeAlreadyClosed {
		t.Fatalf("status after cancellation code=%v", code)
	}
}

func TestRuntimeStopConcurrentCleanupFailureClosesOnce(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	factory.network.closeCode = CodeTUNIOFailed
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateRunning,
		plan: sessionplan.PlanV2{Digest: [32]byte{1}}, factory: factory, network: &factory.network,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}

	results := make(chan ErrorCode, 8)
	var wait sync.WaitGroup
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- RuntimeStop(&registry, handle)
		}()
	}
	wait.Wait()
	close(results)
	cleanupFailures, alreadyClosed := 0, 0
	for result := range results {
		switch result {
		case CodeTUNIOFailed:
			cleanupFailures++
		case CodeAlreadyClosed:
			alreadyClosed++
		default:
			t.Fatalf("concurrent stop code=%v", result)
		}
	}
	if cleanupFailures != 1 || alreadyClosed != 7 {
		t.Fatalf("cleanup failures=%d already closed=%d", cleanupFailures, alreadyClosed)
	}
	if factory.network.closeCount() != 1 {
		t.Fatalf("close count=%d want=1", factory.network.closeCount())
	}
}

func TestRuntimeSocketPrepareCleanupFailurePreventsReuse(t *testing.T) {
	factory := &recordingRuntimeNetworkFactory{}
	factory.network.socketCode = CodeInternalFailure
	factory.network.closeCode = CodeTUNIOFailed
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan: sessionplan.PlanV2{Digest: [32]byte{1}}, factory: factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}

	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeTUNIOFailed {
		t.Fatalf("prepare cleanup code=%v", code)
	}
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodePolicyRejected {
		t.Fatalf("prepare after uncertain cleanup code=%v", code)
	}
	if current, code := RuntimeStatus(&registry, handle); code != CodeOK || current != RuntimeStateClosed {
		t.Fatalf("state after uncertain cleanup=%v code=%v", current, code)
	}
	if code := RuntimeStop(&registry, handle); code != CodeTUNIOFailed {
		t.Fatalf("stop after uncertain cleanup code=%v", code)
	}
}

func TestRuntimeSessionV2ThousandCancellationPointsFailClosed(t *testing.T) {
	stages := []string{"prepare", "connect", "tls", "kurd", "tun-attach", "tun-start"}
	for iteration := 0; iteration < 1000; iteration++ {
		stage := stages[iteration%len(stages)]
		ctx, cancel := context.WithCancel(context.Background())
		factory := &cancellationRuntimeNetworkFactory{cancelAt: stage, cancel: cancel}
		state := &runtimeSessionV2Handle{
			ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
			plan: sessionplan.PlanV2{Digest: [32]byte{1}}, maxFallbackAttempts: 1, factory: factory,
		}
		registry := HandleRegistry{}
		handle, code := registry.Open(HandleRuntimeSession, state)
		if code != CodeOK {
			t.Fatalf("iteration %d stage %s open=%v", iteration, stage, code)
		}
		_, prepareCode := RuntimeSocketPrepare(&registry, handle)
		if stage == "prepare" {
			if prepareCode != CodeCancelled {
				t.Fatalf("iteration %d prepare=%v", iteration, prepareCode)
			}
		} else {
			if prepareCode != CodeOK {
				t.Fatalf("iteration %d stage %s prepare=%v", iteration, stage, prepareCode)
			}
			commitCode := RuntimeSocketCommitProtected(&registry, handle, true)
			if stage == "connect" || stage == "tls" || stage == "kurd" {
				if commitCode != CodeCancelled {
					t.Fatalf("iteration %d stage %s commit=%v", iteration, stage, commitCode)
				}
			} else {
				if commitCode != CodeOK {
					t.Fatalf("iteration %d stage %s commit=%v", iteration, stage, commitCode)
				}
				if attachCode := RuntimeTUNAttach(&registry, handle, 73); attachCode != CodeCancelled {
					t.Fatalf("iteration %d stage %s attach=%v", iteration, stage, attachCode)
				}
			}
		}
		if factory.network == nil || !factory.network.closed() {
			t.Fatalf("iteration %d stage %s retained network", iteration, stage)
		}
		if current, statusCode := RuntimeStatus(&registry, handle); statusCode != CodeOK || current != RuntimeStateClosed {
			t.Fatalf("iteration %d stage %s state=%v code=%v", iteration, stage, current, statusCode)
		}
		if freeCode := registry.Free(handle); freeCode != CodeOK {
			t.Fatalf("iteration %d stage %s free=%v", iteration, stage, freeCode)
		}
	}
}

func TestRuntimeSessionV2FallsBackOnlyAfterFreshProtectedSocket(t *testing.T) {
	factory := &fallbackRuntimeNetworkFactory{connectCodes: []ErrorCode{CodeEndpointUnavailable, CodeOK}}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan: sessionplan.PlanV2{
			Digest: [32]byte{1},
			Endpoints: []runtimepolicy.EndpointV2{
				{Family: 4, Address: []byte{192, 0, 2, 1}, Port: 443},
				{Family: 4, Address: []byte{192, 0, 2, 2}, Port: 443},
			},
		},
		maxFallbackAttempts: 2,
		factory:             factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}
	defer registry.Free(handle)

	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatalf("first prepare code=%v", code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodeEndpointUnavailable {
		t.Fatalf("first commit code=%v", code)
	}
	if current, code := RuntimeStatus(&registry, handle); code != CodeOK || current != RuntimeStateVerified {
		t.Fatalf("fallback state=%v code=%v", current, code)
	}
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatalf("second prepare code=%v", code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodeOK {
		t.Fatalf("second commit code=%v", code)
	}
	if got := factory.indexes(); !reflect.DeepEqual(got, []uint8{0, 1}) {
		t.Fatalf("endpoint indexes=%v", got)
	}
	if got := factory.closed(); !reflect.DeepEqual(got, []bool{true, false}) {
		t.Fatalf("network close state=%v", got)
	}
}

func TestRuntimeSessionV2ExhaustedFallbackFailsClosed(t *testing.T) {
	factory := &fallbackRuntimeNetworkFactory{connectCodes: []ErrorCode{CodeEndpointUnavailable}}
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified,
		plan: sessionplan.PlanV2{Digest: [32]byte{1}, Endpoints: []runtimepolicy.EndpointV2{
			{Family: 4, Address: []byte{192, 0, 2, 1}, Port: 443},
		}},
		maxFallbackAttempts: 1,
		factory:             factory,
	}
	registry := HandleRegistry{}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		t.Fatal(code)
	}
	defer registry.Free(handle)
	if _, code := RuntimeSocketPrepare(&registry, handle); code != CodeOK {
		t.Fatal(code)
	}
	if code := RuntimeSocketCommitProtected(&registry, handle, true); code != CodeFallbackExhausted {
		t.Fatalf("commit code=%v", code)
	}
	if current, code := RuntimeStatus(&registry, handle); code != CodeOK || current != RuntimeStateClosed {
		t.Fatalf("exhausted state=%v code=%v", current, code)
	}
}

func TestNormalizeRuntimeNetworkCodePreservesActionableFailures(t *testing.T) {
	for _, code := range []ErrorCode{
		CodeEndpointUnavailable,
		CodeTLSRejected,
		CodeKurdAuthRejected,
		CodeTUNIOFailed,
		CodeDNSUnavailable,
		CodeNetworkLost,
		CodeFallbackExhausted,
		CodeNodeDrained,
		CodeDeploymentDisabled,
		CodeResourceLimit,
		CodeStateCorrupt,
	} {
		if got := normalizeRuntimeNetworkCode(code); got != code {
			t.Fatalf("code=%v normalized=%v", code, got)
		}
	}
}

type recordingRuntimeNetworkFactory struct{ network recordingRuntimeNetwork }

type cancellationRuntimeNetworkFactory struct {
	cancelAt string
	cancel   context.CancelFunc
	network  *cancellationRuntimeNetwork
}

func (factory *cancellationRuntimeNetworkFactory) Prepare(_ context.Context, _ sessionplan.PlanV2, seed []byte, _ uint8) (RuntimeNetworkSession, ErrorCode) {
	clear(seed)
	factory.network = &cancellationRuntimeNetwork{cancelAt: factory.cancelAt, cancel: factory.cancel}
	if factory.cancelAt == "prepare" {
		factory.cancel()
	}
	return factory.network, CodeOK
}

type cancellationRuntimeNetwork struct {
	mu       sync.Mutex
	cancelAt string
	cancel   context.CancelFunc
	isClosed bool
}

func (*cancellationRuntimeNetwork) SocketFD() (int, ErrorCode) { return 41, CodeOK }
func (network *cancellationRuntimeNetwork) ConnectProtected(context.Context) ErrorCode {
	network.cancelIf("connect")
	return CodeOK
}
func (network *cancellationRuntimeNetwork) AuthenticateTLS(context.Context) ErrorCode {
	network.cancelIf("tls")
	return CodeOK
}
func (network *cancellationRuntimeNetwork) AuthenticateKurd(context.Context) ErrorCode {
	network.cancelIf("kurd")
	return CodeOK
}
func (network *cancellationRuntimeNetwork) AttachTUN(context.Context, int) ErrorCode {
	network.cancelIf("tun-attach")
	return CodeOK
}
func (network *cancellationRuntimeNetwork) Start(context.Context) ErrorCode {
	network.cancelIf("tun-start")
	return CodeOK
}
func (*cancellationRuntimeNetwork) Status() ErrorCode { return CodeOK }
func (network *cancellationRuntimeNetwork) Close() ErrorCode {
	network.mu.Lock()
	network.isClosed = true
	network.mu.Unlock()
	return CodeOK
}
func (network *cancellationRuntimeNetwork) closed() bool {
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.isClosed
}
func (network *cancellationRuntimeNetwork) cancelIf(stage string) {
	if network.cancelAt == stage {
		network.cancel()
	}
}

func (factory *recordingRuntimeNetworkFactory) Prepare(_ context.Context, _ sessionplan.PlanV2, seed []byte, _ uint8) (RuntimeNetworkSession, ErrorCode) {
	clear(seed)
	factory.network.add("prepare")
	return &factory.network, CodeOK
}

type fallbackRuntimeNetworkFactory struct {
	mu           sync.Mutex
	connectCodes []ErrorCode
	endpointIDs  []uint8
	networks     []*fallbackRuntimeNetwork
}

func (factory *fallbackRuntimeNetworkFactory) Prepare(_ context.Context, _ sessionplan.PlanV2, seed []byte, endpointIndex uint8) (RuntimeNetworkSession, ErrorCode) {
	clear(seed)
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if len(factory.connectCodes) == 0 {
		return nil, CodeInternalFailure
	}
	code := factory.connectCodes[0]
	factory.connectCodes = factory.connectCodes[1:]
	network := &fallbackRuntimeNetwork{connectCode: code}
	factory.endpointIDs = append(factory.endpointIDs, endpointIndex)
	factory.networks = append(factory.networks, network)
	return network, CodeOK
}

func (factory *fallbackRuntimeNetworkFactory) indexes() []uint8 {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return append([]uint8(nil), factory.endpointIDs...)
}

func (factory *fallbackRuntimeNetworkFactory) closed() []bool {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	result := make([]bool, len(factory.networks))
	for index, network := range factory.networks {
		result[index] = network.isClosed
	}
	return result
}

type fallbackRuntimeNetwork struct {
	connectCode ErrorCode
	isClosed    bool
}

func (*fallbackRuntimeNetwork) SocketFD() (int, ErrorCode) { return 41, CodeOK }
func (network *fallbackRuntimeNetwork) ConnectProtected(context.Context) ErrorCode {
	return network.connectCode
}
func (*fallbackRuntimeNetwork) AuthenticateTLS(context.Context) ErrorCode  { return CodeOK }
func (*fallbackRuntimeNetwork) AuthenticateKurd(context.Context) ErrorCode { return CodeOK }
func (*fallbackRuntimeNetwork) AttachTUN(context.Context, int) ErrorCode   { return CodeOK }
func (*fallbackRuntimeNetwork) Start(context.Context) ErrorCode            { return CodeOK }
func (*fallbackRuntimeNetwork) Status() ErrorCode                          { return CodeOK }
func (network *fallbackRuntimeNetwork) Close() ErrorCode                   { network.isClosed = true; return CodeOK }

type recordingRuntimeNetwork struct {
	mu           sync.Mutex
	history      []string
	isClose      bool
	closeCountV  int
	closeCode    ErrorCode
	socketCode   ErrorCode
	terminalCode ErrorCode
	diagnostics  RuntimeNetworkDiagnosticsV1
}

func (network *recordingRuntimeNetwork) SocketFD() (int, ErrorCode) {
	return 41, network.socketCode
}
func (network *recordingRuntimeNetwork) ConnectProtected(context.Context) ErrorCode {
	network.add("connect")
	return CodeOK
}
func (network *recordingRuntimeNetwork) AuthenticateTLS(context.Context) ErrorCode {
	network.add("tls")
	return CodeOK
}
func (network *recordingRuntimeNetwork) AuthenticateKurd(context.Context) ErrorCode {
	network.add("kurd")
	return CodeOK
}
func (network *recordingRuntimeNetwork) AttachTUN(_ context.Context, fd int) ErrorCode {
	network.add("attach:" + strconv.Itoa(fd))
	return CodeOK
}
func (network *recordingRuntimeNetwork) Start(context.Context) ErrorCode {
	network.add("start")
	return CodeOK
}
func (network *recordingRuntimeNetwork) Status() ErrorCode {
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.terminalCode
}
func (network *recordingRuntimeNetwork) RuntimeNetworkDiagnosticsV1() RuntimeNetworkDiagnosticsV1 {
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.diagnostics
}
func (network *recordingRuntimeNetwork) Close() ErrorCode {
	network.mu.Lock()
	defer network.mu.Unlock()
	network.isClose = true
	network.closeCountV++
	return network.closeCode
}
func (network *recordingRuntimeNetwork) add(value string) {
	network.mu.Lock()
	defer network.mu.Unlock()
	network.history = append(network.history, value)
}
func (network *recordingRuntimeNetwork) calls() []string {
	network.mu.Lock()
	defer network.mu.Unlock()
	return append([]string(nil), network.history...)
}
func (network *recordingRuntimeNetwork) closed() bool {
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.isClose
}
func (network *recordingRuntimeNetwork) closeCount() int {
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.closeCountV
}
func (network *recordingRuntimeNetwork) setStatus(code ErrorCode) {
	network.mu.Lock()
	defer network.mu.Unlock()
	network.terminalCode = code
}

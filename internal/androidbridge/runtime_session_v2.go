// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"sync"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
)

const (
	runtimeOpenV2Magic       = "KRV2"
	runtimeOpenV2Version     = byte(2)
	runtimeOpenV2HeaderBytes = 24
	runtimeSnapshotV2Magic   = "KSV2"
	runtimeSnapshotV2Bytes   = 157
	MaxRuntimeOpenV2Bytes    = MaxVerifyRequestBytes + MaxBridgeResultBytes + enrollment.MaxRequestBytes + enrollment.MaxPrivateBundleBytes + 32*1024
)

type RuntimeOpenRequestV2 struct {
	VerifyRequest    []byte
	ActivationRecord []byte
	RecipientRequest []byte
	RecipientPrivate []byte
	Policy           RuntimePolicyRequest
}

type RuntimeSessionState uint8

const (
	RuntimeStateVerified RuntimeSessionState = iota + 1
	RuntimeStateSocketPrepared
	RuntimeStateSocketProtectedCommitted
	RuntimeStateTLSAuthenticated
	RuntimeStateKurdAuthenticated
	RuntimeStateTUNAttached
	RuntimeStateRunning
	RuntimeStateStopping
	RuntimeStateClosed
)

type RuntimeSessionSnapshotV2 struct {
	Generation           uint64
	PlanDigest           [32]byte
	ContentFingerprint   [16]byte
	StrategyFingerprint  [16]byte
	RelayFingerprint     [16]byte
	SelectionMode        RuntimeSelectionMode
	PerAppMode           RuntimePerAppMode
	Packages             []string
	IPMode               RuntimeIPMode
	DNSMode              RuntimeDNSMode
	MTU                  uint16
	Metered              bool
	ClientIPv4           [4]byte
	DNSIPv4              [4]byte
	ClientIPv6           [16]byte
	DNSIPv6              [16]byte
	Routes               []runtimepolicy.PrefixV2
	PayloadProtocols     []runtimepolicy.PayloadProtocolV2
	MaxQueuePackets      uint16
	MaxIncompleteOps     uint16
	MaxReconnectAttempts uint8
	DialTimeoutMillis    uint32
	IdleTimeoutMillis    uint32
}

type RuntimeNetworkFactory interface {
	Prepare(context.Context, sessionplan.PlanV2, []byte, uint8) (RuntimeNetworkSession, ErrorCode)
}

type RuntimeNetworkSession interface {
	SocketFD() (int, ErrorCode)
	ConnectProtected(context.Context) ErrorCode
	AuthenticateTLS(context.Context) ErrorCode
	AuthenticateKurd(context.Context) ErrorCode
	AttachTUN(context.Context, int) ErrorCode
	Start(context.Context) ErrorCode
	Status() ErrorCode
	Close() ErrorCode
}

// RuntimeNetworkDiagnosticsV1 contains only bounded aggregate packet-pump
// counters. It intentionally excludes addresses, payloads, profile material,
// credentials, and stable session identifiers.
type RuntimeNetworkDiagnosticsV1 struct {
	TUNPacketsRead          uint64
	OutboundPacketsAccepted uint64
	CarrierRecordsWritten   uint64
	CarrierRecordsRead      uint64
	AuthenticatedOperations uint64
	InnerPacketsAccepted    uint64
	InnerPacketsRejected    uint64
	TUNWriteAttempts        uint64
	TUNWriteFailures        uint64
	TUNWriteFailureCode     uint32
	TUNWriteErrno           uint32
	TUNPacketsWritten       uint64
	RejectedTUNPackets      uint64
	RejectedTUNPacketCode   uint32
}

type runtimeNetworkDiagnosticsProviderV1 interface {
	RuntimeNetworkDiagnosticsV1() RuntimeNetworkDiagnosticsV1
}

type runtimeSessionV2Handle struct {
	mu                  sync.Mutex
	ctx                 context.Context
	cancel              context.CancelFunc
	state               RuntimeSessionState
	snapshot            RuntimeSessionSnapshotV2
	plan                sessionplan.PlanV2
	credentials         RecipientCredentials
	factory             RuntimeNetworkFactory
	network             RuntimeNetworkSession
	nextEndpoint        uint8
	attemptCount        uint8
	maxFallbackAttempts uint8
	stopOnce            sync.Once
	destroyOnce         sync.Once
	cleanupCode         ErrorCode
}

func EncodeRuntimeSessionSnapshotV2(snapshot RuntimeSessionSnapshotV2) ([]byte, error) {
	if snapshot.Generation == 0 || snapshot.PlanDigest == ([32]byte{}) || snapshot.MTU != 1280 ||
		len(snapshot.Packages) > maxRuntimePackages || len(snapshot.Routes) == 0 || len(snapshot.Routes) > 2 ||
		len(snapshot.PayloadProtocols) == 0 || len(snapshot.PayloadProtocols) > 4 ||
		snapshot.MaxQueuePackets == 0 || snapshot.MaxIncompleteOps == 0 || snapshot.MaxReconnectAttempts == 0 ||
		snapshot.DialTimeoutMillis == 0 || snapshot.IdleTimeoutMillis == 0 {
		return nil, errors.New("androidbridge: invalid runtime v2 snapshot")
	}
	size := runtimeSnapshotV2Bytes
	for _, value := range snapshot.Packages {
		if !validRuntimePackage(value) {
			return nil, errors.New("androidbridge: invalid runtime v2 package")
		}
		size += 2 + len(value)
	}
	for _, prefix := range snapshot.Routes {
		if len(prefix.Address) != 4 && len(prefix.Address) != 16 {
			return nil, errors.New("androidbridge: invalid runtime v2 route")
		}
		size += 2 + len(prefix.Address)
	}
	size += len(snapshot.PayloadProtocols)
	if size > MaxRuntimeSnapshotBytes {
		return nil, errors.New("androidbridge: runtime v2 snapshot too large")
	}
	out := make([]byte, size)
	copy(out[:4], runtimeSnapshotV2Magic)
	out[4] = runtimeOpenV2Version
	if snapshot.Metered {
		out[5] = 1
	}
	out[6], out[7], out[8], out[9] = byte(snapshot.SelectionMode), byte(snapshot.PerAppMode), byte(snapshot.IPMode), byte(snapshot.DNSMode)
	binary.BigEndian.PutUint16(out[10:12], snapshot.MTU)
	binary.BigEndian.PutUint64(out[12:20], snapshot.Generation)
	copy(out[20:52], snapshot.PlanDigest[:])
	copy(out[52:68], snapshot.ContentFingerprint[:])
	copy(out[68:84], snapshot.StrategyFingerprint[:])
	copy(out[84:100], snapshot.RelayFingerprint[:])
	copy(out[100:104], snapshot.ClientIPv4[:])
	copy(out[104:108], snapshot.DNSIPv4[:])
	copy(out[108:124], snapshot.ClientIPv6[:])
	copy(out[124:140], snapshot.DNSIPv6[:])
	binary.BigEndian.PutUint16(out[140:142], snapshot.MaxQueuePackets)
	binary.BigEndian.PutUint16(out[142:144], snapshot.MaxIncompleteOps)
	out[144] = snapshot.MaxReconnectAttempts
	binary.BigEndian.PutUint16(out[145:147], uint16(len(snapshot.Packages)))
	out[147] = byte(len(snapshot.Routes))
	out[148] = byte(len(snapshot.PayloadProtocols))
	binary.BigEndian.PutUint32(out[149:153], snapshot.DialTimeoutMillis)
	binary.BigEndian.PutUint32(out[153:157], snapshot.IdleTimeoutMillis)
	offset := runtimeSnapshotV2Bytes
	for _, value := range snapshot.Packages {
		binary.BigEndian.PutUint16(out[offset:offset+2], uint16(len(value)))
		offset += 2
		copy(out[offset:], value)
		offset += len(value)
	}
	for _, prefix := range snapshot.Routes {
		out[offset], out[offset+1] = byte(len(prefix.Address)), prefix.PrefixLen
		offset += 2
		copy(out[offset:], prefix.Address)
		offset += len(prefix.Address)
	}
	for _, protocol := range snapshot.PayloadProtocols {
		value, ok := encodePayloadProtocolV2(protocol)
		if !ok {
			return nil, errors.New("androidbridge: invalid runtime v2 protocol")
		}
		out[offset] = value
		offset++
	}
	return out, nil
}

func DecodeRuntimeSessionSnapshotV2(encoded []byte) (RuntimeSessionSnapshotV2, error) {
	if len(encoded) < runtimeSnapshotV2Bytes || len(encoded) > MaxRuntimeSnapshotBytes || string(encoded[:4]) != runtimeSnapshotV2Magic ||
		encoded[4] != runtimeOpenV2Version || encoded[5]&^byte(1) != 0 {
		return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: invalid runtime v2 snapshot header")
	}
	packageCount, routeCount, protocolCount := int(binary.BigEndian.Uint16(encoded[145:147])), int(encoded[147]), int(encoded[148])
	if packageCount > maxRuntimePackages || routeCount == 0 || routeCount > 2 || protocolCount == 0 || protocolCount > 4 {
		return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: invalid runtime v2 snapshot counts")
	}
	snapshot := RuntimeSessionSnapshotV2{
		SelectionMode: RuntimeSelectionMode(encoded[6]), PerAppMode: RuntimePerAppMode(encoded[7]), IPMode: RuntimeIPMode(encoded[8]), DNSMode: RuntimeDNSMode(encoded[9]),
		MTU: binary.BigEndian.Uint16(encoded[10:12]), Generation: binary.BigEndian.Uint64(encoded[12:20]), Metered: encoded[5]&1 != 0,
		MaxQueuePackets: binary.BigEndian.Uint16(encoded[140:142]), MaxIncompleteOps: binary.BigEndian.Uint16(encoded[142:144]),
		MaxReconnectAttempts: encoded[144], DialTimeoutMillis: binary.BigEndian.Uint32(encoded[149:153]), IdleTimeoutMillis: binary.BigEndian.Uint32(encoded[153:157]),
	}
	copy(snapshot.PlanDigest[:], encoded[20:52])
	copy(snapshot.ContentFingerprint[:], encoded[52:68])
	copy(snapshot.StrategyFingerprint[:], encoded[68:84])
	copy(snapshot.RelayFingerprint[:], encoded[84:100])
	copy(snapshot.ClientIPv4[:], encoded[100:104])
	copy(snapshot.DNSIPv4[:], encoded[104:108])
	copy(snapshot.ClientIPv6[:], encoded[108:124])
	copy(snapshot.DNSIPv6[:], encoded[124:140])
	offset := runtimeSnapshotV2Bytes
	snapshot.Packages = make([]string, packageCount)
	for index := range snapshot.Packages {
		if offset+2 > len(encoded) {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: truncated runtime v2 package")
		}
		length := int(binary.BigEndian.Uint16(encoded[offset : offset+2]))
		offset += 2
		if length == 0 || length > maxRuntimePackageBytes || offset+length > len(encoded) {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: invalid runtime v2 package length")
		}
		snapshot.Packages[index] = string(encoded[offset : offset+length])
		offset += length
	}
	snapshot.Routes = make([]runtimepolicy.PrefixV2, routeCount)
	for index := range snapshot.Routes {
		if offset+2 > len(encoded) {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: truncated runtime v2 route")
		}
		length, prefix := int(encoded[offset]), encoded[offset+1]
		offset += 2
		if length != 4 && length != 16 || offset+length > len(encoded) {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: invalid runtime v2 route length")
		}
		snapshot.Routes[index] = runtimepolicy.PrefixV2{Address: bytes.Clone(encoded[offset : offset+length]), PrefixLen: prefix}
		offset += length
	}
	snapshot.PayloadProtocols = make([]runtimepolicy.PayloadProtocolV2, protocolCount)
	for index := range snapshot.PayloadProtocols {
		if offset >= len(encoded) {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: truncated runtime v2 protocol")
		}
		protocol, ok := decodePayloadProtocolV2(encoded[offset])
		if !ok {
			return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: invalid runtime v2 protocol")
		}
		snapshot.PayloadProtocols[index] = protocol
		offset++
	}
	if offset != len(encoded) {
		return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: trailing runtime v2 snapshot")
	}
	reencoded, err := EncodeRuntimeSessionSnapshotV2(snapshot)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		clear(reencoded)
		return RuntimeSessionSnapshotV2{}, errors.New("androidbridge: non-canonical runtime v2 snapshot")
	}
	clear(reencoded)
	return snapshot, nil
}

func EncodeRuntimeOpenRequestV2(request RuntimeOpenRequestV2) ([]byte, error) {
	policyBytes, err := encodeRuntimePolicyOnly(request.Policy)
	if err != nil || len(policyBytes) > 1<<16-1 || !runtimeOpenV2LengthsValid(request) {
		return nil, errors.New("androidbridge: invalid runtime v2 open request")
	}
	size := runtimeOpenV2HeaderBytes + len(policyBytes) + len(request.VerifyRequest) + len(request.ActivationRecord) + len(request.RecipientRequest) + len(request.RecipientPrivate)
	if size > MaxRuntimeOpenV2Bytes {
		return nil, errors.New("androidbridge: runtime v2 open request too large")
	}
	out := make([]byte, size)
	copy(out[:4], runtimeOpenV2Magic)
	out[4] = runtimeOpenV2Version
	binary.BigEndian.PutUint16(out[6:8], uint16(len(policyBytes)))
	binary.BigEndian.PutUint32(out[8:12], uint32(len(request.VerifyRequest)))
	binary.BigEndian.PutUint32(out[12:16], uint32(len(request.ActivationRecord)))
	binary.BigEndian.PutUint16(out[16:18], uint16(len(request.RecipientRequest)))
	binary.BigEndian.PutUint16(out[18:20], uint16(len(request.RecipientPrivate)))
	binary.BigEndian.PutUint32(out[20:24], uint32(size))
	offset := runtimeOpenV2HeaderBytes
	for _, value := range [][]byte{policyBytes, request.VerifyRequest, request.ActivationRecord, request.RecipientRequest, request.RecipientPrivate} {
		copy(out[offset:], value)
		offset += len(value)
	}
	clear(policyBytes)
	return out, nil
}

func DecodeRuntimeOpenRequestV2(encoded []byte) (RuntimeOpenRequestV2, error) {
	if len(encoded) < runtimeOpenV2HeaderBytes || len(encoded) > MaxRuntimeOpenV2Bytes ||
		string(encoded[:4]) != runtimeOpenV2Magic || encoded[4] != runtimeOpenV2Version || encoded[5] != 0 ||
		binary.BigEndian.Uint32(encoded[20:24]) != uint32(len(encoded)) {
		return RuntimeOpenRequestV2{}, errors.New("androidbridge: invalid runtime v2 header")
	}
	lengths := []int{
		int(binary.BigEndian.Uint16(encoded[6:8])),
		int(binary.BigEndian.Uint32(encoded[8:12])),
		int(binary.BigEndian.Uint32(encoded[12:16])),
		int(binary.BigEndian.Uint16(encoded[16:18])),
		int(binary.BigEndian.Uint16(encoded[18:20])),
	}
	offset := runtimeOpenV2HeaderBytes
	parts := make([][]byte, len(lengths))
	for index, length := range lengths {
		if length <= 0 || offset+length < offset || offset+length > len(encoded) {
			return RuntimeOpenRequestV2{}, errors.New("androidbridge: invalid runtime v2 lengths")
		}
		parts[index] = bytes.Clone(encoded[offset : offset+length])
		offset += length
	}
	if offset != len(encoded) {
		return RuntimeOpenRequestV2{}, errors.New("androidbridge: trailing runtime v2 data")
	}
	policyRequest, err := DecodeRuntimeOpenRequest(parts[0])
	if err != nil || len(policyRequest.VerifyRequest) != 1 || policyRequest.VerifyRequest[0] != 1 ||
		len(policyRequest.ActivationRecord) != 1 || policyRequest.ActivationRecord[0] != 1 {
		clearRuntimeV2Parts(parts)
		return RuntimeOpenRequestV2{}, errors.New("androidbridge: invalid runtime v2 policy")
	}
	request := RuntimeOpenRequestV2{
		VerifyRequest: parts[1], ActivationRecord: parts[2], RecipientRequest: parts[3], RecipientPrivate: parts[4],
		Policy: policyRequest.Policy,
	}
	clear(parts[0])
	if !runtimeOpenV2LengthsValid(request) {
		clearRuntimeOpenRequestV2(&request)
		return RuntimeOpenRequestV2{}, errors.New("androidbridge: invalid runtime v2 request")
	}
	reencoded, err := EncodeRuntimeOpenRequestV2(request)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		clear(reencoded)
		clearRuntimeOpenRequestV2(&request)
		return RuntimeOpenRequestV2{}, errors.New("androidbridge: non-canonical runtime v2 request")
	}
	clear(reencoded)
	return request, nil
}

func OpenRuntimeSessionV2(registry *HandleRegistry, encoded []byte, environment RecipientVerificationEnvironment, factory RuntimeNetworkFactory, now time.Time) (Handle, RuntimeSessionSnapshotV2, ErrorCode) {
	if registry == nil || environment == nil || factory == nil || now.IsZero() {
		return 0, RuntimeSessionSnapshotV2{}, CodeTrustUnavailable
	}
	request, err := DecodeRuntimeOpenRequestV2(encoded)
	if err != nil {
		return 0, RuntimeSessionSnapshotV2{}, CodeInvalidArgument
	}
	defer clearRuntimeOpenRequestV2(&request)
	preview, code := VerifyAndPreviewWithRecipient(request.VerifyRequest, request.RecipientRequest, request.RecipientPrivate, environment)
	if code != CodeOK {
		return 0, RuntimeSessionSnapshotV2{}, code
	}
	defer preview.Destroy()
	record, err := DecodeActivationRecord(request.ActivationRecord)
	if err != nil || !runtimeRecordMatches(preview, record) || preview.recipient == nil {
		return 0, RuntimeSessionSnapshotV2{}, CodePolicyRejected
	}
	policy, err := runtimepolicy.DecodeV2At(record.Profile.Policy, now)
	if err != nil || !runtimeRecipientMatchesPolicy(*preview.recipient, policy) {
		return 0, RuntimeSessionSnapshotV2{}, CodePolicyRejected
	}
	narrowing, err := runtimeNarrowingV2(request.Policy)
	if err != nil {
		return 0, RuntimeSessionSnapshotV2{}, CodePolicyRejected
	}
	plan, err := sessionplan.BuildV2At(sessionplan.RequestV2{
		Profile: record.Profile, ActivationReceipt: record.State.Receipt, RuntimePolicy: policy, Requested: narrowing,
	}, now)
	if err != nil {
		return 0, RuntimeSessionSnapshotV2{}, CodePolicyRejected
	}
	credentials := *preview.recipient
	preview.recipient = nil
	snapshot := runtimeSnapshotV2(preview, request.Policy, plan)
	ctx, cancel := context.WithCancel(context.Background())
	state := &runtimeSessionV2Handle{
		ctx: ctx, cancel: cancel, state: RuntimeStateVerified, snapshot: snapshot,
		plan: plan, credentials: credentials, factory: factory,
		maxFallbackAttempts: runtimeFallbackAttemptsV2(plan, policy),
	}
	handle, code := registry.Open(HandleRuntimeSession, state)
	if code != CodeOK {
		state.Destroy()
		return 0, RuntimeSessionSnapshotV2{}, code
	}
	return handle, cloneRuntimeSnapshotV2(snapshot), CodeOK
}

func RuntimeSocketPrepare(registry *HandleRegistry, handle Handle) (int, ErrorCode) {
	state, code := runtimeV2State(registry, handle)
	if code != CodeOK {
		return -1, code
	}
	state.mu.Lock()
	if state.state != RuntimeStateVerified || state.factory == nil || state.ctx == nil || state.ctx.Err() != nil {
		state.mu.Unlock()
		return -1, CodePolicyRejected
	}
	if state.maxFallbackAttempts == 0 {
		state.maxFallbackAttempts = 1
	}
	if state.attemptCount >= state.maxFallbackAttempts || len(state.plan.Endpoints) > 0 && int(state.nextEndpoint) >= len(state.plan.Endpoints) {
		state.mu.Unlock()
		return -1, CodeFallbackExhausted
	}
	factory, ctx, plan, endpointIndex := state.factory, state.ctx, state.plan.Clone(), state.nextEndpoint
	seed := bytes.Clone(state.credentials.Private.ClientAuthSeed)
	state.mu.Unlock()
	network, code := factory.Prepare(ctx, plan, seed, endpointIndex)
	clear(seed)
	plan.Destroy()
	if code != CodeOK || network == nil {
		if network != nil {
			if cleanupCode := runtimeCloseNetwork(network); cleanupCode != CodeOK {
				state.recordCleanupFailure(cleanupCode)
				state.Cancel()
				return -1, cleanupCode
			}
		}
		return -1, normalizeRuntimeNetworkCode(code)
	}
	fd, fdCode := network.SocketFD()
	if fdCode != CodeOK || fd < 0 {
		if cleanupCode := runtimeCloseNetwork(network); cleanupCode != CodeOK {
			state.recordCleanupFailure(cleanupCode)
			state.Cancel()
			return -1, cleanupCode
		}
		return -1, normalizeRuntimeNetworkCode(fdCode)
	}
	state.mu.Lock()
	if state.state != RuntimeStateVerified || state.ctx.Err() != nil {
		state.mu.Unlock()
		cleanupCode := runtimeCloseNetwork(network)
		if cleanupCode != CodeOK {
			state.recordCleanupFailure(cleanupCode)
		}
		state.Cancel()
		if cleanupCode != CodeOK {
			return -1, cleanupCode
		}
		return -1, CodeCancelled
	}
	state.network = network
	state.state = RuntimeStateSocketPrepared
	state.attemptCount++
	state.nextEndpoint++
	state.mu.Unlock()
	return fd, CodeOK
}

func RuntimeSocketCommitProtected(registry *HandleRegistry, handle Handle, protected bool) ErrorCode {
	state, code := runtimeV2State(registry, handle)
	if code != CodeOK {
		return code
	}
	state.mu.Lock()
	if state.state != RuntimeStateSocketPrepared || state.network == nil || state.ctx == nil || state.ctx.Err() != nil {
		state.mu.Unlock()
		return CodePolicyRejected
	}
	if !protected {
		state.mu.Unlock()
		state.Cancel()
		return CodePolicyRejected
	}
	network, ctx := state.network, state.ctx
	state.mu.Unlock()
	steps := []struct {
		state RuntimeSessionState
		run   func(context.Context) ErrorCode
	}{
		{RuntimeStateSocketProtectedCommitted, network.ConnectProtected},
		{RuntimeStateTLSAuthenticated, network.AuthenticateTLS},
		{RuntimeStateKurdAuthenticated, network.AuthenticateKurd},
	}
	for _, step := range steps {
		if result := step.run(ctx); result != CodeOK {
			normalized := normalizeRuntimeNetworkCode(result)
			if step.state == RuntimeStateSocketProtectedCommitted && normalized == CodeEndpointUnavailable {
				state.mu.Lock()
				canRetry := state.attemptCount < state.maxFallbackAttempts &&
					(len(state.plan.Endpoints) == 0 || int(state.nextEndpoint) < len(state.plan.Endpoints)) &&
					state.ctx.Err() == nil
				if state.network == network {
					state.network = nil
				}
				if canRetry {
					state.state = RuntimeStateVerified
				}
				state.mu.Unlock()
				cleanupCode := runtimeCloseNetwork(network)
				if cleanupCode != CodeOK {
					state.recordCleanupFailure(cleanupCode)
					state.Cancel()
					return cleanupCode
				}
				if canRetry {
					return CodeEndpointUnavailable
				}
				state.Cancel()
				return CodeFallbackExhausted
			}
			state.Cancel()
			return normalized
		}
		state.mu.Lock()
		if state.ctx.Err() != nil || state.state == RuntimeStateClosed {
			state.mu.Unlock()
			state.Cancel()
			return CodeCancelled
		}
		state.state = step.state
		state.mu.Unlock()
	}
	return CodeOK
}

func runtimeFallbackAttemptsV2(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2) uint8 {
	count := int(policy.Fallback.TotalAttempts)
	if count > len(plan.Endpoints) {
		count = len(plan.Endpoints)
	}
	if count > int(plan.MaxReconnectAttempts) {
		count = int(plan.MaxReconnectAttempts)
	}
	if count <= 0 || count > int(^uint8(0)) {
		return 0
	}
	return uint8(count)
}

func RuntimeTUNAttach(registry *HandleRegistry, handle Handle, fd int) ErrorCode {
	if fd < 0 {
		return CodeInvalidArgument
	}
	state, code := runtimeV2State(registry, handle)
	if code != CodeOK {
		return code
	}
	state.mu.Lock()
	if state.state != RuntimeStateKurdAuthenticated {
		state.mu.Unlock()
		return CodePolicyRejected
	}
	if state.network == nil {
		state.mu.Unlock()
		return CodeEndpointUnavailable
	}
	if state.ctx == nil {
		state.mu.Unlock()
		return CodeStateCorrupt
	}
	if state.ctx.Err() != nil {
		state.mu.Unlock()
		return CodeCancelled
	}
	network, ctx := state.network, state.ctx
	state.mu.Unlock()
	if code := network.AttachTUN(ctx, fd); code != CodeOK {
		return normalizeRuntimeNetworkCode(code)
	}
	state.mu.Lock()
	if state.state != RuntimeStateKurdAuthenticated || state.ctx.Err() != nil {
		state.mu.Unlock()
		state.Cancel()
		return CodeCancelled
	}
	state.state = RuntimeStateTUNAttached
	state.mu.Unlock()
	if code := network.Start(ctx); code != CodeOK {
		if cleanupCode := state.Cancel(); cleanupCode != CodeOK {
			return cleanupCode
		}
		return normalizeRuntimeNetworkCode(code)
	}
	state.mu.Lock()
	if state.state != RuntimeStateTUNAttached || state.ctx.Err() != nil {
		state.mu.Unlock()
		state.Cancel()
		return CodeCancelled
	}
	state.state = RuntimeStateRunning
	state.mu.Unlock()
	return CodeOK
}

func RuntimeStatus(registry *HandleRegistry, handle Handle) (RuntimeSessionState, ErrorCode) {
	state, code := runtimeV2State(registry, handle)
	if code != CodeOK {
		return 0, code
	}
	state.mu.Lock()
	current, network := state.state, state.network
	state.mu.Unlock()
	if current != RuntimeStateRunning || network == nil {
		return current, CodeOK
	}
	if networkCode := normalizeRuntimeNetworkCode(network.Status()); networkCode != CodeOK {
		state.Cancel()
		return RuntimeStateClosed, networkCode
	}
	return current, CodeOK
}

func RuntimeNetworkDiagnostics(registry *HandleRegistry, handle Handle) (RuntimeNetworkDiagnosticsV1, ErrorCode) {
	state, code := runtimeV2State(registry, handle)
	if code != CodeOK {
		return RuntimeNetworkDiagnosticsV1{}, code
	}
	state.mu.Lock()
	network := state.network
	state.mu.Unlock()
	if network == nil {
		return RuntimeNetworkDiagnosticsV1{}, CodeEndpointUnavailable
	}
	provider, ok := network.(runtimeNetworkDiagnosticsProviderV1)
	if !ok || provider == nil {
		return RuntimeNetworkDiagnosticsV1{}, CodeInternalFailure
	}
	return provider.RuntimeNetworkDiagnosticsV1(), CodeOK
}

func RuntimeStop(registry *HandleRegistry, handle Handle) ErrorCode {
	_, _, kind, ok := decodeHandle(handle)
	if !ok {
		return CodeInvalidHandle
	}
	if kind != HandleRuntimeSession {
		return CodeWrongHandleType
	}
	return registry.Free(handle)
}

func (state *runtimeSessionV2Handle) Cancel() ErrorCode {
	if state == nil {
		return CodeOK
	}
	state.stopOnce.Do(func() {
		state.mu.Lock()
		state.state = RuntimeStateStopping
		cancel, network := state.cancel, state.network
		state.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		cleanupCode := runtimeCloseNetwork(network)
		state.mu.Lock()
		if state.cleanupCode == CodeOK {
			state.cleanupCode = cleanupCode
		}
		state.network = nil
		state.state = RuntimeStateClosed
		state.mu.Unlock()
	})
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.cleanupCode
}

func (state *runtimeSessionV2Handle) recordCleanupFailure(code ErrorCode) {
	if state == nil || code == CodeOK {
		return
	}
	state.mu.Lock()
	if state.cleanupCode == CodeOK {
		state.cleanupCode = code
	}
	state.mu.Unlock()
}

func (state *runtimeSessionV2Handle) Destroy() {
	_ = state.DestroyResult()
}

func (state *runtimeSessionV2Handle) DestroyResult() ErrorCode {
	if state == nil {
		return CodeOK
	}
	cleanupCode := state.Cancel()
	state.destroyOnce.Do(func() {
		state.mu.Lock()
		state.credentials.Destroy()
		state.plan.Destroy()
		clearRuntimeSnapshotV2(&state.snapshot)
		state.factory = nil
		state.ctx = nil
		state.cancel = nil
		state.mu.Unlock()
	})
	return cleanupCode
}

func runtimeCloseNetwork(network RuntimeNetworkSession) ErrorCode {
	if network == nil {
		return CodeOK
	}
	return normalizeRuntimeNetworkCode(network.Close())
}

func runtimeV2State(registry *HandleRegistry, handle Handle) (*runtimeSessionV2Handle, ErrorCode) {
	if registry == nil {
		return nil, CodeInvalidHandle
	}
	value, code := registry.Get(handle, HandleRuntimeSession)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*runtimeSessionV2Handle)
	if !ok || state == nil {
		return nil, CodeWrongHandleType
	}
	return state, CodeOK
}

func runtimeOpenV2LengthsValid(request RuntimeOpenRequestV2) bool {
	return len(request.VerifyRequest) > 0 && len(request.VerifyRequest) <= MaxVerifyRequestBytes &&
		len(request.ActivationRecord) > 0 && len(request.ActivationRecord) <= MaxBridgeResultBytes &&
		len(request.RecipientRequest) > 0 && len(request.RecipientRequest) <= enrollment.MaxRequestBytes &&
		len(request.RecipientPrivate) > 0 && len(request.RecipientPrivate) <= enrollment.MaxPrivateBundleBytes
}

func runtimeRecipientMatchesPolicy(credentials RecipientCredentials, policy runtimepolicy.PolicyV2) bool {
	if len(credentials.Private.ClientAuthSeed) != ed25519.SeedSize || credentials.Request.ClientAuthKeyID != policy.ClientAuthKeyID ||
		!bytes.Equal(credentials.Request.ClientAuthPublic, policy.ClientAuthPublic[:]) {
		return false
	}
	private := ed25519.NewKeyFromSeed(credentials.Private.ClientAuthSeed)
	defer clear(private)
	return bytes.Equal(private.Public().(ed25519.PublicKey), policy.ClientAuthPublic[:])
}

func runtimeNarrowingV2(request RuntimePolicyRequest) (sessionplan.NarrowingRequestV2, error) {
	policy, err := normalizeRuntimePolicy(request)
	if err != nil {
		return sessionplan.NarrowingRequestV2{}, err
	}
	narrowing := sessionplan.NarrowingRequestV2{MTU: policy.MTU, AllowLAN: policy.AllowLAN}
	if policy.SelectionMode == RuntimeSelectionManual {
		narrowing.StrategyID = policy.ManualStrategyID
	}
	switch policy.IPMode {
	case RuntimeIPAuto:
	case RuntimeIPV4Only:
		narrowing.IPMode = runtimepolicy.IPModeIPv4Only
	case RuntimeIPV6Only:
		narrowing.IPMode = runtimepolicy.IPModeIPv6Only
	case RuntimeIPDualStack:
		narrowing.IPMode = runtimepolicy.IPModeDualStack
	default:
		return sessionplan.NarrowingRequestV2{}, errors.New("androidbridge: invalid runtime IP mode")
	}
	if policy.DNSMode == RuntimeDNSCustom {
		parsed := net.ParseIP(policy.CustomDNS)
		if parsed == nil {
			return sessionplan.NarrowingRequestV2{}, errors.New("androidbridge: invalid runtime DNS")
		}
		if value := parsed.To4(); value != nil {
			narrowing.DNSServers = [][]byte{bytes.Clone(value)}
		} else {
			narrowing.DNSServers = [][]byte{bytes.Clone(parsed.To16())}
		}
	}
	return narrowing, nil
}

func runtimeSnapshotV2(preview VerifyPreview, requested RuntimePolicyRequest, plan sessionplan.PlanV2) RuntimeSessionSnapshotV2 {
	content := sha256.Sum256([]byte(preview.Inspection.ContentSHA256))
	strategy := sha256.Sum256([]byte(plan.StrategyID))
	relay := sha256.Sum256([]byte(plan.RelayKeyID))
	snapshot := RuntimeSessionSnapshotV2{
		Generation: plan.ProfileGeneration, PlanDigest: plan.Digest,
		SelectionMode: requested.SelectionMode, PerAppMode: requested.PerAppMode, Packages: slices.Clone(requested.Packages),
		IPMode: requested.IPMode, DNSMode: requested.DNSMode, MTU: plan.MTU, Metered: requested.Metered,
		ClientIPv4: plan.ClientIPv4, DNSIPv4: plan.DNSIPv4, ClientIPv6: plan.ClientIPv6, DNSIPv6: plan.DNSIPv6,
		Routes: cloneRuntimePrefixesV2(plan.Routes), PayloadProtocols: slices.Clone(plan.PayloadProtocols),
		MaxQueuePackets: plan.MaxQueuePackets, MaxIncompleteOps: plan.MaxIncompleteOps, MaxReconnectAttempts: plan.MaxReconnectAttempts,
		DialTimeoutMillis: boundedDurationMillisV2(plan.DialTimeout), IdleTimeoutMillis: boundedDurationMillisV2(plan.IdleTimeout),
	}
	copy(snapshot.ContentFingerprint[:], content[:16])
	copy(snapshot.StrategyFingerprint[:], strategy[:16])
	copy(snapshot.RelayFingerprint[:], relay[:16])
	return snapshot
}

func cloneRuntimeSnapshotV2(snapshot RuntimeSessionSnapshotV2) RuntimeSessionSnapshotV2 {
	snapshot.Packages = slices.Clone(snapshot.Packages)
	snapshot.Routes = cloneRuntimePrefixesV2(snapshot.Routes)
	snapshot.PayloadProtocols = slices.Clone(snapshot.PayloadProtocols)
	return snapshot
}

func clearRuntimeSnapshotV2(snapshot *RuntimeSessionSnapshotV2) {
	if snapshot == nil {
		return
	}
	for index := range snapshot.Routes {
		clear(snapshot.Routes[index].Address)
	}
	*snapshot = RuntimeSessionSnapshotV2{}
}

func cloneRuntimePrefixesV2(values []runtimepolicy.PrefixV2) []runtimepolicy.PrefixV2 {
	result := make([]runtimepolicy.PrefixV2, len(values))
	for index := range values {
		result[index] = runtimepolicy.PrefixV2{Address: bytes.Clone(values[index].Address), PrefixLen: values[index].PrefixLen}
	}
	return result
}

func boundedDurationMillisV2(value time.Duration) uint32 {
	millis := value.Milliseconds()
	if millis <= 0 || millis > int64(^uint32(0)) {
		return 0
	}
	return uint32(millis)
}

func normalizeRuntimeNetworkCode(code ErrorCode) ErrorCode {
	switch code {
	case CodeOK, CodeInvalidArgument, CodeSizeLimit, CodeCancelled, CodeVerificationRejected, CodePolicyRejected,
		CodeIncompatible, CodeInternalFailure, CodeEndpointUnavailable, CodeTLSRejected, CodeKurdAuthRejected,
		CodeTUNIOFailed, CodeDNSUnavailable, CodeNetworkLost, CodeFallbackExhausted, CodeNodeDrained,
		CodeDeploymentDisabled, CodeResourceLimit, CodeStateCorrupt:
		return code
	default:
		return CodeInternalFailure
	}
}

func clearRuntimeOpenRequestV2(request *RuntimeOpenRequestV2) {
	if request == nil {
		return
	}
	clear(request.VerifyRequest)
	clear(request.ActivationRecord)
	clear(request.RecipientRequest)
	clear(request.RecipientPrivate)
	*request = RuntimeOpenRequestV2{}
}

func clearRuntimeV2Parts(parts [][]byte) {
	for _, part := range parts {
		clear(part)
	}
}

func encodePayloadProtocolV2(protocol runtimepolicy.PayloadProtocolV2) (byte, bool) {
	switch protocol {
	case runtimepolicy.PayloadProtocolICMP:
		return 1, true
	case runtimepolicy.PayloadProtocolICMPv6:
		return 2, true
	case runtimepolicy.PayloadProtocolTCP:
		return 3, true
	case runtimepolicy.PayloadProtocolUDP:
		return 4, true
	default:
		return 0, false
	}
}

func decodePayloadProtocolV2(value byte) (runtimepolicy.PayloadProtocolV2, bool) {
	switch value {
	case 1:
		return runtimepolicy.PayloadProtocolICMP, true
	case 2:
		return runtimepolicy.PayloadProtocolICMPv6, true
	case 3:
		return runtimepolicy.PayloadProtocolTCP, true
	case 4:
		return runtimepolicy.PayloadProtocolUDP, true
	default:
		return "", false
	}
}

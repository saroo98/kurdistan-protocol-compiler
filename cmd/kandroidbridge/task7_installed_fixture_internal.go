//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"kurdistan/internal/protocol/wirev1"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const task7RelayEndpointV1 = "127.0.0.1:28471"

var task7NativeV1 struct {
	sync.Mutex
	relay     *task7RelayV1
	pressure  task7PressureV1
	starting  bool
	cancelled bool
}

//export kvpn_task7_issue_v1
func kvpn_task7_issue_v1(directory *C.char, request *C.uint8_t, length C.uint32_t, output *C.uint8_t, capacity C.uint32_t, written *C.uint32_t) C.int32_t {
	if directory == nil || request == nil || length == 0 || length > 65536 || output == nil || capacity != 1052763 || written == nil {
		return 1
	}
	*written = 0
	dst := unsafe.Slice((*byte)(unsafe.Pointer(output)), int(capacity))
	clear(dst)
	artifact, err := task7IssueForEnrollmentV1(C.GoString(directory), unsafe.Slice((*byte)(unsafe.Pointer(request)), int(length)))
	if err != nil {
		return 2
	}
	defer clear(artifact)
	if len(artifact) == 0 || len(artifact) > len(dst) {
		return 2
	}
	copy(dst, artifact)
	*written = C.uint32_t(len(artifact))
	return 0
}

//export kvpn_task7_start_v1
func kvpn_task7_start_v1(directory *C.char, level C.int32_t, fixtureMode C.int32_t) C.int32_t {
	if directory == nil {
		return 1
	}
	dir := C.GoString(directory)
	if !task7RelayModeValidV1(dir, int(level), int(fixtureMode)) {
		return 1
	}
	task7NativeV1.Lock()
	if task7NativeV1.starting || task7NativeV1.relay != nil {
		task7NativeV1.Unlock()
		return 3
	}
	task7NativeV1.starting = true
	task7NativeV1.cancelled = false
	task7NativeV1.Unlock()
	if !task7NativeV1.pressure.acquire(int(level)) {
		task7NativeV1.Lock()
		task7NativeV1.starting = false
		task7NativeV1.Unlock()
		return 1
	}
	relay, err := task7StartRelayModeV1(context.Background(), dir, int(fixtureMode))
	task7NativeV1.Lock()
	defer task7NativeV1.Unlock()
	task7NativeV1.starting = false
	if err != nil {
		task7NativeV1.pressure.release()
		return 2
	}
	task7NativeV1.relay = relay
	if task7NativeV1.cancelled {
		relay.close()
	}
	return 0
}

//export kvpn_task7_snapshot_v1
func kvpn_task7_snapshot_v1(out *C.uint64_t, capacity C.uint32_t) C.int32_t {
	if out == nil || capacity != 16 {
		return 1
	}
	values := unsafe.Slice((*uint64)(unsafe.Pointer(out)), 16)
	clear(values)
	p := task7NativeV1.pressure.snapshot()
	copy(values, p[:])
	task7NativeV1.Lock()
	r := task7NativeV1.relay
	task7NativeV1.Unlock()
	if r != nil {
		values[9] = r.accepted.Load()
		values[10] = r.targetAccepted.Load()
		values[13] = r.targetReadFailures.Load()
		values[14] = r.targetReadMillis.Load()
		values[15] = r.targetWriteFailures.Load()
		select {
		case <-r.done:
			if r.joined.Load() {
				values[11] = 1
			}
		default:
		}
		select {
		case <-r.ready:
			values[12] = 1
		default:
		}
	}
	return 0
}

//export kvpn_task7_cancel_v1
func kvpn_task7_cancel_v1() C.int32_t {
	task7NativeV1.Lock()
	r := task7NativeV1.relay
	task7NativeV1.cancelled = true
	task7NativeV1.Unlock()
	if r != nil {
		r.close()
	}
	return 0
}

//export kvpn_task7_finish_v1
func kvpn_task7_finish_v1() C.int32_t {
	task7NativeV1.Lock()
	defer task7NativeV1.Unlock()
	if task7NativeV1.starting {
		return 3
	}
	r := task7NativeV1.relay
	if r == nil {
		return 1
	}
	select {
	case <-r.done:
	default:
		return 3
	}
	if !r.joined.Load() {
		return 2
	}
	task7NativeV1.relay = nil
	task7NativeV1.pressure.release()
	return 0
}

type task7RelayV1 struct {
	mode                int
	mu                  sync.Mutex
	cancel              context.CancelFunc
	listener            net.Listener
	target              net.Listener
	raw                 net.Conn
	port                *kruntime.PacketPortV1
	done                chan struct{}
	ready               chan struct{}
	accepted            atomic.Uint64
	targetAccepted      atomic.Uint64
	targetReadFailures  atomic.Uint64
	targetReadMillis    atomic.Uint64
	targetWriteFailures atomic.Uint64
	joined              atomic.Bool
	stopped             bool
	closeDone           chan struct{}
	tunDone             chan struct{}
	tunError            error
}

var task7RatesV1 struct {
	sync.Once
	rates *kruntime.ProbeRateRegistryV1
	err   error
}

type task7RelayNetworkV1 struct{ endpoint string }

func (n task7RelayNetworkV1) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	return 0, kruntime.ServiceDestinationDeniedV1
}
func (n task7RelayNetworkV1) DialTCP(ctx context.Context, address netip.AddrPort) (kruntime.ServiceTCPConnV1, error) {
	if address != netip.MustParseAddrPort("8.8.8.8:443") {
		return nil, kruntime.ServiceDestinationDeniedV1
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", n.endpoint)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func task7StartRelayV1(parent context.Context, dir string) (*task7RelayV1, error) {
	return task7StartRelayModeV1(parent, dir, 0)
}

func task7RelayModeValidV1(dir string, level, mode int) bool {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return false
	}
	if mode == 0 {
		return (filepath.Base(dir) == "task7-installed-v1" || filepath.Base(dir) == "task12-installed-proxy-v1") && (level == 0 || level == 16 || level == 32 || level == 64)
	}
	return (mode == 1 || mode == 2) && level == 0 && filepath.Base(dir) == "task7-installed-update-v2"
}

func task7StartRelayModeV1(parent context.Context, dir string, mode int) (*task7RelayV1, error) {
	if !task7RelayModeValidV1(dir, 0, mode) {
		return nil, errors.New("fixture directory rejected")
	}
	snapshot, err := selfhost.OpenRelayRuntimeSnapshotV1(filepath.Join(dir, "node"), time.Now())
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", task7RelayEndpointV1)
	if err != nil {
		snapshot.Close()
		return nil, err
	}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		snapshot.Close()
		return nil, err
	}
	ctx, cancel := context.WithTimeout(parent, 40*time.Second)
	r := &task7RelayV1{mode: mode, cancel: cancel, listener: listener, target: target, done: make(chan struct{}), ready: make(chan struct{}), closeDone: make(chan struct{})}
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for i := 0; i < 10; i++ {
			c, e := target.Accept()
			if e != nil {
				return
			}
			r.targetAccepted.Add(1)
			if filepath.Base(dir) == "task12-installed-proxy-v1" {
				c.SetDeadline(time.Now().Add(2 * time.Second))
				var payload [16]byte
				started := time.Now()
				_, readErr := io.ReadFull(c, payload[:])
				r.targetReadMillis.Store(uint64(time.Since(started).Milliseconds()))
				if readErr == nil {
					if _, err := c.Write(payload[:]); err != nil {
						r.targetWriteFailures.Add(1)
					}
				} else {
					r.targetReadFailures.Add(1)
				}
				clear(payload[:])
			}
			c.Close()
		}
	}()
	go func() {
		defer close(r.done)
		defer snapshot.Close()
		watchDone := make(chan struct{})
		go func() { defer close(watchDone); <-ctx.Done(); r.close() }()
		_ = r.serve(ctx, snapshot)
		r.close()
		<-watchDone
		<-targetDone
		r.joined.Store(true)
	}()
	return r, nil
}

// Cancellation closes actual blocking I/O; the worker alone publishes joined.
func (r *task7RelayV1) close() {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		<-r.closeDone
		return
	}
	r.stopped = true
	raw, port := r.raw, r.port
	r.mu.Unlock()
	defer close(r.closeDone)
	r.cancel()
	r.listener.Close()
	r.target.Close()
	if raw != nil {
		raw.Close()
	}
	if port != nil {
		port.Close()
	}
}

func (r *task7RelayV1) serve(ctx context.Context, snapshot *selfhost.RelayRuntimeSnapshotV1) error {
	raw, err := r.listener.Accept()
	if err != nil {
		return err
	}
	r.accepted.Add(1)
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		raw.Close()
		return context.Canceled
	}
	r.raw = raw
	r.mu.Unlock()
	defer raw.Close()
	if deadline, ok := ctx.Deadline(); ok {
		raw.SetDeadline(deadline)
	}
	preface, err := sessionplan.ReadRelayAdmissionPrefaceV1(raw)
	if err != nil {
		return err
	}
	a, ok := snapshot.AdmissionByProfileV1(preface.ProfileContentID, preface.ProfileGeneration)
	if !ok {
		return errors.New("fixture admission rejected")
	}
	plan, err := sessionplan.BuildRelayV2At(sessionplan.RelayAuthorityV2{ProfileContentID: a.ContentID, ProfileGeneration: a.Generation,
		ValidFrom: a.ValidFrom, ValidUntil: a.ValidUntil, RuntimePolicy: a.RuntimePolicy, StrategyIDs: a.StrategyIDs, RelayIDs: a.RelayIDs}, preface, time.Now())
	if err != nil {
		return err
	}
	program, err := liveprogram.DecodeV1(a.RuntimePolicy.LiveProgram)
	if err != nil {
		return err
	}
	config, err := snapshot.ServerTLSConfigV1()
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range config.Certificates {
			if k, ok := c.PrivateKey.(ed25519.PrivateKey); ok {
				clear(k)
			}
		}
	}()
	carrier, err := tlstcp.Server(ctx, raw, config, plan.Digest, uint32(program.Limits.MaxFrameBytes))
	if err != nil {
		return err
	}
	defer carrier.Close()
	projected, err := auth.NewProjectedProcessHandshakeConfigV1(a.ClientAuthKeyID, a.RuntimePolicy.RelayAuthKeyID, program, "tls13-tcp")
	if err != nil {
		return err
	}
	cache, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		return err
	}
	handshake, err := kruntime.NewProcessWireRelayHandshakeV1(projected, auth.Dependencies{Identity: snapshot, Trust: snapshot}, cache, plan.Digest)
	if err != nil {
		return err
	}
	defer handshake.Close()
	receive := func() ([]byte, error) {
		f, e := carrier.Receive(ctx)
		if e != nil {
			return nil, e
		}
		defer clear(f.Payload)
		return wirev1.Encode(f)
	}
	send := func(b []byte) error {
		defer clear(b)
		f, e := wirev1.Decode(b)
		if e != nil {
			return e
		}
		defer clear(f.Payload)
		return carrier.Send(ctx, f)
	}
	ch, err := receive()
	if err != nil {
		return err
	}
	sh, err := handshake.AcceptClientHello(ch)
	clear(ch)
	if err != nil {
		return err
	}
	if err = send(sh); err != nil {
		return err
	}
	cf, err := receive()
	if err != nil {
		return err
	}
	sf, result, err := handshake.AcceptClientFinish(cf)
	clear(cf)
	if err != nil {
		return err
	}
	defer result.Close()
	if err = send(sf); err != nil {
		return err
	}
	exporter, err := carrier.CarrierBinding()
	if err != nil {
		return err
	}
	stream, err := carrier.SelectRecordStreamV3(ctx, time.Minute)
	if err != nil {
		return err
	}
	port, err := kruntime.NewPacketPortV1(int(plan.MTU))
	if err != nil {
		return err
	}
	defer port.Close()
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return context.Canceled
	}
	r.port = port
	r.tunDone = make(chan struct{})
	r.mu.Unlock()
	var pump *kruntime.ServicePumpV1
	go func() {
		defer close(r.tunDone)
		var err error
		if r.mode == 0 {
			err = task7RunTunResponderV1(ctx, port, plan.ClientIPv4, plan.DNSIPv4, int(plan.MTU))
		} else {
			err = task7RunMaintenanceDNSResponderV1(ctx, port, plan.ClientIPv4, plan.DNSIPv4, int(plan.MTU), uint8(r.mode))
		}
		r.mu.Lock()
		r.tunError = err
		r.mu.Unlock()
		// A malformed/duplicate/bound-exhausting fixture stream is terminal.
		if ctx.Err() == nil {
			r.close()
		}
	}()
	defer func() {
		port.Close()
		<-r.tunDone
		if pump != nil {
			pump.Close()
		}
	}()
	scope, err := kruntime.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: a.ProviderID, LineageID: a.LineageID, ProfileID: a.ProfileID})
	if err != nil {
		return err
	}
	// The signed scope's history survives serial fixture relay reopenings in this process.
	task7RatesV1.Do(func() { task7RatesV1.rates, task7RatesV1.err = kruntime.NewProbeRateRegistryV1(64) })
	if task7RatesV1.err != nil {
		return task7RatesV1.err
	}
	var streamLimit uint8
	var streamQueue uint32
	bufferBudget := uint64(64 << 20)
	if a.RuntimePolicy.Services != nil && a.RuntimePolicy.Services.Proxy != nil {
		streamLimit = min(4, a.RuntimePolicy.Services.Proxy.MaxConcurrentStreams)
		streamQueue = min(16384, a.RuntimePolicy.Services.Proxy.MaxQueuedBytesPerDirection)
		bufferBudget = min(bufferBudget, uint64(a.RuntimePolicy.Services.Proxy.MaxBufferBytes))
	}
	pump, err = kruntime.NewRelayServicePumpV1(result, plan, kruntime.ServicePumpConfigV1{PacketIO: port, Carrier: stream,
		StreamLimit: streamLimit, StreamQueueBytes: streamQueue,
		CarrierOwnedBytes: 1 << 20, PacketOwnedBytes: 65536, PacketQueuedBytes: uint64(2 * plan.MTU), ProbeLimit: 1, BufferBudget: bufferBudget,
		MaxRecordBytes: uint32(program.Limits.MaxFrameBytes), Generation: 1, AuthorityDeadline: time.Unix(a.ValidUntil, 0), Now: time.Now,
		CheckAuthority: func(at time.Time) error {
			if _, ok := snapshot.AdmissionByProfileV1(plan.ProfileContentID, plan.ProfileGeneration); !ok || at.Unix() >= a.ValidUntil {
				return kruntime.ServiceAuthorityExpiredV1
			}
			return nil
		},
		ProbeScope: scope, ProbeRates: task7RatesV1.rates, RelayNetwork: task7RelayNetworkV1{r.target.Addr().String()}, NetworkOperationBytes: 8192})
	if err != nil {
		return err
	}
	if err = pump.BindV1(ctx, exporter); err != nil {
		return err
	}
	close(r.ready)
	return pump.Run(ctx)
}

// Default-process preparation only. The public request is real enrollment output;
// no private recipient, activation, currentness or settings input is accepted.
func task7IssueForEnrollmentV1(dir string, request []byte) ([]byte, error) {
	leaf := filepath.Base(dir)
	if (leaf != "task7-installed-v1" && leaf != "task7-installed-update-v2" && leaf != "task12-installed-proxy-v1") || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errors.New("fixture directory rejected")
	}
	if _, err := enrollment.DecodeRequestV1(request); err != nil {
		return nil, errors.New("fixture enrollment rejected")
	}
	// Exclusive creation refuses existing, partial or previously prepared state.
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, errors.New("fixture state exists or unavailable")
	}
	now := time.Now().UTC().Truncate(time.Second)
	pass := []byte("synthetic local recovery only")
	defer clear(pass)
	node, recovery := filepath.Join(dir, "node"), filepath.Join(dir, "recovery")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: node, DeploymentName: "task7-installed-fixture",
		Endpoint: task7RelayEndpointV1, RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)}); err != nil {
		return nil, err
	}
	if err := selfhost.ConfirmRecovery(node, recovery, pass, now.Add(-time.Minute)); err != nil {
		return nil, err
	}
	model, err := compiler.Generate(71)
	if err != nil {
		return nil, err
	}
	features := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model,
		ClientMandatoryFeatures: features[:2], RelayMandatoryFeatures: features[:2], SelectedFeatures: features})
	if err != nil {
		return nil, err
	}
	wire, err := liveprogram.EncodeV1(program)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	services := &runtimepolicy.ServicesV1{Version: 1, Probes: &runtimepolicy.ProbesV1{
		Targets:                 []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}},
		MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
	if leaf == "task7-installed-update-v2" {
		services.Update = &runtimepolicy.UpdateV1{URL: "https://updates.example/profile",
			MaxArtifactBytes: 65536, TimeoutMillis: 30000, MinCheckIntervalSeconds: 60}
	}
	if leaf == "task12-installed-proxy-v1" {
		services.Proxy = &runtimepolicy.ProxyV1{AddressKinds: []uint8{1},
			DestinationCIDRs:     []runtimepolicy.PrefixV2{{Address: []byte{8, 8, 8, 8}, PrefixLen: 32}},
			DestinationPorts:     []runtimepolicy.PortRangeV1{{First: 443, Last: 443}},
			MaxConcurrentStreams: 4, MaxBufferBytes: 32 << 20, ConnectTimeoutMillis: 1000,
			IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 16384}
	}
	issued, err := selfhost.CreateProfile(node, selfhost.CreateProfileOptions{Name: "task7-installed", ValidFor: 12 * time.Hour,
		Now: now, RecipientRequest: request, LiveProgram: wire, RegistryDir: filepath.Join(dir, "registry"), Services: services})
	if err != nil {
		return nil, err
	}
	return issued.Artifact, nil
}

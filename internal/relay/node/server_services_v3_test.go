// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"kurdistan/internal/relay/tun"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
)

type healthTunnelV3 struct {
	*memoryTunnelV1
	failure chan struct{}
}

func (t *healthTunnelV3) PreparePacketWriteV3(context.Context) error { return nil }
func (t *healthTunnelV3) WriteFailureV3() <-chan struct{}            { return t.failure }
func (t *healthTunnelV3) WritePacketContextV3(ctx context.Context, p []byte) (int, error) {
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return t.Write(p)
}

type authenticatedFixtureV3 struct {
	dir, recovery string
	pass          []byte
	admission     selfhost.RelayAdmissionV1
	plan          sessionplan.PlanV2
	program       liveprogram.ProgramV1
	private       ed25519.PrivateKey
}

func authenticatedServerFixtureV3(t *testing.T) authenticatedFixtureV3 {
	t.Helper()
	f := authenticatedFixtureV3{dir: filepath.Join(t.TempDir(), "state"), recovery: filepath.Join(t.TempDir(), "recovery"), pass: []byte("local V3 adapter test recovery passphrase")}
	now := time.Now().UTC()
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: f.dir, DeploymentName: "adapter-v3", Endpoint: "203.0.113.7:443", RecoveryPath: f.recovery, RecoveryPassphrase: f.pass, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(f.dir, f.recovery, f.pass, now); err != nil {
		t.Fatal(err)
	}
	return issueAuthenticatedFixtureV3(t, f)
}

func issueAuthenticatedFixtureV3(t *testing.T, f authenticatedFixtureV3) authenticatedFixtureV3 {
	t.Helper()
	now := time.Now().UTC()
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private.RecipientPrivate)
	defer clear(private.ClientAuthSeed)
	f.private = ed25519.NewKeyFromSeed(private.ClientAuthSeed)
	t.Cleanup(func() { clear(f.private); clear(f.pass) })
	wire, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	model, err := compiler.Generate(1701)
	if err != nil {
		t.Fatal(err)
	}
	caps := ir.SecurityCapabilities()
	f.program, err = liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model, ClientMandatoryFeatures: append([]string(nil), caps[:2]...), RelayMandatoryFeatures: append([]string(nil), caps[:2]...), SelectedFeatures: append([]string(nil), caps...)})
	if err != nil {
		t.Fatal(err)
	}
	program, err := liveprogram.EncodeV1(f.program)
	if err != nil {
		t.Fatal(err)
	}
	services := &runtimepolicy.ServicesV1{Version: 1, Proxy: &runtimepolicy.ProxyV1{AddressKinds: []uint8{1, 2}, DestinationCIDRs: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DestinationPorts: []runtimepolicy.PortRangeV1{{First: 443, Last: 443}}, MaxConcurrentStreams: 2, MaxBufferBytes: 64 << 20, ConnectTimeoutMillis: 1000, IdleTimeoutSeconds: 30, MaxQueuedBytesPerDirection: 1024}, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 2, MaxOperationMillis: 1000}}
	name := "adapter"
	if f.admission.ProfileID != "" {
		name = "adapter-extra"
	}
	issued, err := selfhost.CreateProfile(f.dir, selfhost.CreateProfileOptions{Name: name, ValidFor: 24 * time.Hour, Now: now, RecipientRequest: wire, LiveProgram: program, RegistryDir: filepath.Join(filepath.Dir(f.dir), "registry"), Services: services})
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := selfhost.VerifyLiveBundleForRecipient(issued.Artifact, now, 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimepolicy.DecodeV3At(verified.Profile.Policy, now)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(issued.Artifact)
	receipt := lifecycle.VerifiedReceipt{ContentID: issued.ContentID, ProviderID: verified.Profile.ProviderID, LineageID: verified.Profile.LineageID, RootEpoch: verified.Profile.RootEpoch, RevocationEpoch: verified.Profile.RevocationEpoch, RecipientEpoch: 1, AuthenticatedArtifactSHA256: hex.EncodeToString(digest[:])}
	f.plan, err = sessionplan.BuildV2At(sessionplan.RequestV2{Profile: verified.Profile, RuntimePolicy: policy, ActivationReceipt: receipt, Requested: sessionplan.NarrowingRequestV2{MaxQueuePackets: 2}}, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := selfhost.OpenRelayRuntimeSnapshotV1(f.dir, now)
	if err != nil {
		t.Fatal(err)
	}
	var ok bool
	f.admission, ok = snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation)
	snapshot.Close()
	if !ok {
		t.Fatal("issued admission missing")
	}
	return f
}

type clientKeysV3 struct{ f authenticatedFixtureV3 }

func (k clientKeysV3) Local(id string) (ed25519.PrivateKey, error) {
	if id != k.f.admission.ClientAuthKeyID {
		return nil, ErrServerSession
	}
	return append(ed25519.PrivateKey(nil), k.f.private...), nil
}
func (k clientKeysV3) Peer(id string) (ed25519.PublicKey, error) {
	if id != k.f.plan.RelayKeyID {
		return nil, ErrServerSession
	}
	return append(ed25519.PublicKey(nil), k.f.admission.RuntimePolicy.RelayAuthPublic[:]...), nil
}

func startAuthenticatedClientV3(t *testing.T, f authenticatedFixtureV3, ctx context.Context, raw net.Conn) (*kruntime.ServicePumpV1, *kruntime.PacketPortV1) {
	pump, port, binding := newAuthenticatedClientV3(t, f, ctx, raw)
	if err := pump.BindV1(ctx, binding); err != nil {
		t.Fatal(err)
	}
	return pump, port
}

func newAuthenticatedClientV3(t *testing.T, f authenticatedFixtureV3, ctx context.Context, raw net.Conn) (*kruntime.ServicePumpV1, *kruntime.PacketPortV1, [32]byte) {
	t.Helper()
	pump, port, binding, err := tryAuthenticatedClientV3(t, f, ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	return pump, port, binding
}

func tryAuthenticatedClientV3(t *testing.T, f authenticatedFixtureV3, ctx context.Context, raw net.Conn) (*kruntime.ServicePumpV1, *kruntime.PacketPortV1, [32]byte, error) {
	t.Helper()
	preface, err := sessionplan.NewRelayAdmissionPrefaceV1(f.plan)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if err = sessionplan.WriteRelayAdmissionPrefaceV1(raw, preface); err != nil {
		return nil, nil, [32]byte{}, err
	}
	cert, err := x509.ParseCertificate(f.admission.RuntimePolicy.TLSLeafDER)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	carrier, err := tlstcp.Client(ctx, raw, &tls.Config{ServerName: f.admission.RuntimePolicy.TLSServerName, RootCAs: roots}, f.plan.Digest, uint32(f.program.Limits.MaxFrameBytes))
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	t.Cleanup(func() { carrier.Close() })
	config, err := auth.NewProjectedProcessHandshakeConfigV1(f.admission.ClientAuthKeyID, f.plan.RelayKeyID, f.program, "tls13-tcp")
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	keys := clientKeysV3{f}
	h, err := kruntime.NewProcessWireClientHandshakeV1(config, auth.Dependencies{Identity: keys, Trust: keys}, f.plan.Digest)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	defer h.Close()
	hello, err := h.Start()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if err = sendProcessFrameV1(ctx, carrier, hello); err != nil {
		return nil, nil, [32]byte{}, err
	}
	clear(hello)
	hello, err = receiveProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	finish, err := h.AcceptServerHello(hello)
	clear(hello)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	if err = sendProcessFrameV1(ctx, carrier, finish); err != nil {
		return nil, nil, [32]byte{}, err
	}
	clear(finish)
	finish, err = receiveProcessFrameV1(ctx, carrier)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	result, err := h.AcceptServerFinish(finish)
	clear(finish)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	defer result.Close()
	stream, err := carrier.SelectRecordStreamV3(ctx, 5*time.Second)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	port, err := kruntime.NewPacketPortV1(int(f.plan.MTU))
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	scope, err := kruntime.NewAuthenticatedProbeScopeV1(envelope.CanonicalProfileV1{ProviderID: f.admission.ProviderID, LineageID: f.admission.LineageID, ProfileID: f.admission.ProfileID})
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	rates, err := kruntime.NewProbeRateRegistryV1(1)
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	pump, err := kruntime.NewClientServicePumpV1(result, f.plan, kruntime.ServicePumpConfigV1{PacketIO: port, Carrier: stream, CarrierOwnedBytes: stream.BoundsV3().OwnedBytes, StreamLimit: 2, StreamQueueBytes: 1024, ProbeLimit: 1, ProbeScope: scope, ProbeRates: rates, BufferBudget: 64 << 20, MaxRecordBytes: stream.BoundsV3().MaxRecordBytes, Generation: f.admission.Generation, AuthorityDeadline: f.admission.ServiceAuthorityDeadlineV3, Now: time.Now, CheckAuthority: func(time.Time) error { return nil }})
	if err != nil {
		port.Close()
		return nil, nil, [32]byte{}, err
	}
	t.Cleanup(func() { pump.Close(); waitDeviceV3(t, pump.Done()) })
	binding, err := carrier.CarrierBinding()
	if err != nil {
		return nil, nil, [32]byte{}, err
	}
	return pump, port, binding, nil
}

type slowRetiringReadV3 struct {
	net.Conn
	armed            atomic.Bool
	entered, release chan struct{}
}

func (c *slowRetiringReadV3) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if e != nil && c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.release
	}
	return n, e
}

type signalReadV3 struct {
	net.Conn
	armed   atomic.Bool
	started chan struct{}
}

func (c *signalReadV3) Read(p []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.started)
	}
	return c.Conn.Read(p)
}

func TestServerAuthenticatedV3SelectsDirectIngressOwner(t *testing.T) {
	f := authenticatedServerFixtureV3(t)
	r, tunnel, _, _ := deviceFixtureV3(t, 1)
	config := DefaultConfig(f.dir, 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.SessionBufferBudget = 64 << 20
	ready := make(chan struct{}, 1)
	config.SessionProgress = func(stage SessionStageCodeV1) {
		if stage == SessionStagePumpReadyV1 {
			ready <- struct{}{}
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	control, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer control.Close()
	config.MaxSessions = 1
	config.MaxHandshakeWorkers = 1
	server, e := NewServerV1(config, listener, r.tun, control, func(net.Conn) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	r = server.registry
	defer r.Close()
	target, e := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	var dials atomic.Int32
	server.socketsV3.dial = func(call context.Context, network, address string, local net.Addr) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp4" || address != "8.8.8.8:443" || local.String() != "10.77.0.1:0" {
			t.Error("mixed operation escaped numeric target/source binding")
		}
		return new(net.Dialer).DialContext(call, "tcp4", target.Addr().String())
	}
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		for i := 0; i < 2; i++ {
			conn, err := target.AcceptTCP()
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			if i == 0 {
				body, err := io.ReadAll(conn)
				if err != nil || !bytes.Equal(body, []byte("request")) {
					t.Error("real target did not receive request and FIN")
				}
				conn.Write([]byte("reply"))
				conn.CloseWrite()
			}
			conn.Close()
		}
	}()
	t.Cleanup(func() { target.Close(); waitDeviceV3(t, targetDone) })
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	defer server.shutdownV1()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, relay := net.Pipe()
	defer client.Close()
	clientRead := &signalReadV3{Conn: client, started: make(chan struct{})}
	slow := &slowRetiringReadV3{Conn: relay, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(func() {
		select {
		case <-slow.release:
		default:
			close(slow.release)
		}
	})
	done := make(chan error, 1)
	go func() { done <- server.handleSessionV1(ctx, slow) }()
	t.Cleanup(func() {
		cancel()
		client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("handler did not join")
		}
	})
	pump, port := startAuthenticatedClientV3(t, f, ctx, clientRead)
	defer pump.Close()
	waitDeviceV3(t, ready)
	r.mu.RLock()
	var d *SessionDeviceV3
	for _, record := range r.sessions {
		d = record.v3
	}
	r.mu.RUnlock()
	if d == nil {
		t.Fatal("authenticated V3 selected legacy packet device")
	}
	relayPump, ok := d.owner.(*kruntime.ServicePumpV1)
	if !ok {
		t.Fatal("registry owner is not actual service pump")
	}
	t.Logf("authenticated relay pump owned=%d queued=%d device=%d budget=%d", relayPump.BoundsV1().OwnedBytes, relayPump.BoundsV1().QueuedBytes, d.BoundsV3().OwnedBytes, config.SessionBufferBudget)
	clientRead.armed.Store(true)
	runDone := make(chan error, 1)
	go func() { runDone <- pump.Run(ctx) }()
	t.Cleanup(func() {
		pump.Close()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("client Run not joined")
		}
	})
	waitDeviceV3(t, clientRead.started)
	streamID, err := pump.OpenStream(ctx, kruntime.ProxyRequestV1{Kind: 1, Address: []byte{8, 8, 8, 8}, Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := pump.WriteStream(ctx, streamID, []byte("request")); err != nil || n != 7 {
		t.Fatal("proxy write failed")
	}
	if err = pump.CloseWrite(ctx, streamID); err != nil {
		t.Fatal(err)
	}
	var reply [32]byte
	token, n, err := pump.ReceiveStream(ctx, streamID, reply[:])
	if err != nil || string(reply[:n]) != "reply" {
		t.Fatalf("proxy return failed: %v", err)
	}
	if err = pump.ConfirmStreamDelivery(streamID, token, n); err != nil {
		t.Fatal(err)
	}
	handle, err := pump.StartProbe(ctx, kruntime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000, Samples: 1})
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := pump.AwaitProbe(ctx, handle)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.Path != kruntime.ProbeActiveRelayEndToEndV1 || aggregate.Attempted != 1 || !aggregate.HasLatency || aggregate.LossPermille != 0 {
		t.Fatal("real successful connect did not produce an active end-to-end probe outcome")
	}
	waitDeviceV3(t, targetDone)
	if dials.Load() != 2 {
		t.Fatal("numeric proxy/probe unexpectedly used DNS or another socket")
	}
	writeEntered, writeRelease := make(chan struct{}), make(chan struct{})
	tunnel.write = func(call context.Context, p []byte) (int, error) {
		close(writeEntered)
		select {
		case <-writeRelease:
			return len(p), nil
		case <-call.Done():
			return 0, call.Err()
		}
	}
	packet := testIPv4PacketV1(f.plan.ClientIPv4, [4]byte{8, 8, 8, 8}, 17, []byte{1})
	if err = port.Submit(ctx, packet); err != nil {
		t.Fatal(err)
	}
	waitDeviceV3(t, writeEntered)
	if relayPump.BoundsV1().PacketsProcessed != 0 {
		t.Fatal("packet committed before destination write")
	}
	close(writeRelease)
	limit := time.Now().Add(time.Second)
	for relayPump.BoundsV1().PacketsProcessed == 0 && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if relayPump.BoundsV1().PacketsProcessed != 1 {
		t.Fatal("full current packet did not commit")
	}
	// Actual pump reader is held after underlying Close, with no ingress/write
	// reference left. Only the handler's retirement fence can keep it counted.
	slow.armed.Store(true)
	spec := d.record.spec
	d.Close()
	waitDeviceV3(t, slow.entered)
	select {
	case <-relayPump.Done():
		t.Fatal("test did not hold real pump retirement")
	default:
	}
	for i := 0; i < 20; i++ {
		select {
		case <-d.Done():
			t.Fatal("PacketIO.Close retired capacity ahead of Pump.Done")
		default:
		}
		if _, err = r.Register(spec); !errors.Is(err, ErrSessionLimit) {
			t.Fatal("slow pump allowed legacy churn")
		}
	}
	close(slow.release)
	waitDeviceV3(t, relayPump.Done())
	waitDeviceV3(t, d.Done())
	select {
	case <-tunnel.closed:
		t.Fatal("session cancellation closed shared TUN")
	default:
	}
}

func TestServerAuthenticatedV3CancellationDuringPrepareAndBind(t *testing.T) {
	for _, prepare := range []bool{true, false} {
		t.Run(map[bool]string{true: "prepare", false: "private-bind"}[prepare], func(t *testing.T) {
			f := authenticatedServerFixtureV3(t)
			_, tunnel, _, _ := deviceFixtureV3(t, 1)
			entered := make(chan struct{})
			if prepare {
				tunnel.prepare = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			control, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			config := DefaultConfig(f.dir, 443)
			config.MaxSessions = 1
			config.MaxHandshakeWorkers = 1
			config.SessionBufferBudget = 64 << 20
			config.DNSReady = func(context.Context) bool { return true }
			var ready atomic.Int32
			config.SessionProgress = func(stage SessionStageCodeV1) {
				if stage == SessionStageKurdReadyV1 || stage == SessionStagePumpReadyV1 {
					ready.Add(1)
				}
			}
			s, err := NewServerV1(config, listener, tunnel, control, func(net.Conn) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.shutdownV1()
			defer s.registry.Close()
			if err = s.Reload(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, relay := net.Pipe()
			defer client.Close()
			done := make(chan struct{})
			go func() { defer close(done); _ = s.handleSessionV1(ctx, relay) }()
			t.Cleanup(func() { cancel(); client.Close(); waitDeviceV3(t, done) })
			pump, _, binding := newAuthenticatedClientV3(t, f, ctx, client)
			var d *SessionDeviceV3
			if prepare {
				waitDeviceV3(t, entered)
			} else {
				limit := time.Now().Add(time.Second)
				for time.Now().Before(limit) {
					s.registry.mu.RLock()
					for _, record := range s.registry.sessions {
						if record.v3 != nil && record.v3.attached {
							d = record.v3
						}
					}
					s.registry.mu.RUnlock()
					if d != nil {
						break
					}
					time.Sleep(time.Millisecond)
				}
				if d == nil {
					t.Fatal("real pump did not enter private Bind")
				}
			}
			if s.stopProfileV1(f.admission.ProfileID) == 0 {
				t.Fatal("stop missed preparing/attached exact attempt")
			}
			waitDeviceV3(t, done)
			if err = pump.BindV1(ctx, binding); err == nil {
				t.Fatal("stopped construction published a bound client")
			}
			if ready.Load() != 0 {
				t.Fatal("uncompleted Bind emitted ready/success")
			}
			if d != nil {
				waitDeviceV3(t, d.Done())
				if !errors.Is(d.checkAuthorityV3(time.Now()), kruntime.ServiceCancelledV1) {
					t.Fatal("generic owner stop fabricated another terminal category")
				}
			}
			s.registry.mu.RLock()
			active, pending, draining := len(s.registry.sessions), s.registry.preparingV3, s.registry.drainingV3
			s.registry.mu.RUnlock()
			if active != 0 || pending != 0 || draining != 0 {
				t.Fatal("canceled handoff retained capacity after handler joined")
			}
			select {
			case <-tunnel.closed:
				t.Fatal("session cancellation closed shared TUN")
			default:
			}
		})
	}
}

type negativeSnapshotV3 struct {
	RelaySnapshotV1
	status selfhost.RelayRuntimeStatusV1
	view   *selfhost.RelayRevocationViewV3
}

// These use real signed authority and the real TLS/process/pump handshake.
// Equal display status must not hide revocation or a root replacement.
func TestServerAuthenticatedV3SameStatusAuthorityFence(t *testing.T) {
	for _, mode := range []string{"readmission", "captured", "prepare", "unaffected", "different-root"} {
		t.Run(mode, func(t *testing.T) {
			f := authenticatedServerFixtureV3(t)
			other := f
			if mode == "unaffected" {
				other = issueAuthenticatedFixtureV3(t, f)
			}
			old, err := selfhost.OpenRelayRuntimeSnapshotV1(f.dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			status, _ := old.StatusV1()
			if mode == "different-root" {
				other = authenticatedServerFixtureV3(t)
			} else if err = selfhost.RevokeProfile(other.dir, selfhost.RevokeProfileOptions{ProfileID: other.admission.ProfileID, RecoveryPath: other.recovery, RecoveryPassphrase: other.pass, Now: time.Now()}); err != nil {
				t.Fatal(err)
			}
			candidate, err := selfhost.OpenRelayRuntimeSnapshotV1(other.dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			view := candidate.VerifiedRevocationsV3()
			if mode != "unaffected" && mode != "different-root" && !view.RevokesV3(f.admission.RevocationSubjectV3, time.Now()) {
				t.Fatal("missing signed revocation")
			}
			_, tunnel, _, _ := deviceFixtureV3(t, 1)
			entered, release := make(chan struct{}), make(chan struct{})
			if mode == "prepare" {
				tunnel.prepare = func(context.Context) error { close(entered); <-release; return nil }
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			control, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer control.Close()
			config := DefaultConfig(f.dir, 443)
			config.MaxSessions, config.MaxHandshakeWorkers = 1, 1
			config.SessionBufferBudget = 64 << 20
			config.DNSReady = func(context.Context) bool { return true }
			loads := 0
			config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
				loads++
				if loads == 1 {
					return old, nil
				}
				return &negativeSnapshotV3{RelaySnapshotV1: candidate, status: status, view: view}, nil
			}
			var ready, destinations atomic.Int32
			config.SessionProgress = func(stage SessionStageCodeV1) {
				if mode == "captured" && stage == SessionStageAuthorityReadyV1 {
					close(entered)
					<-release
				}
				if stage == SessionStageKurdReadyV1 || stage == SessionStagePumpReadyV1 {
					ready.Add(1)
				}
			}
			s, err := NewServerV1(config, listener, tunnel, control, func(net.Conn) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer s.shutdownV1()
			defer s.registry.Close()
			s.socketsV3.dial = func(context.Context, string, string, net.Addr) (net.Conn, error) {
				destinations.Add(1)
				return nil, errors.New("unexpected destination")
			}
			if err = s.Reload(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := func() (net.Conn, <-chan struct{}) {
				client, relay := net.Pipe()
				done := make(chan struct{})
				go func() { defer close(done); _ = s.handleSessionV1(ctx, relay) }()
				t.Cleanup(func() { client.Close(); waitDeviceV3(t, done) })
				return client, done
			}
			if mode == "captured" {
				client, done := start()
				reloaded := make(chan error, 1)
				go func() { <-entered; reloaded <- s.Reload(); close(release) }()
				pump, _, binding, attemptErr := tryAuthenticatedClientV3(t, f, ctx, client)
				if attemptErr == nil {
					attemptErr = pump.BindV1(ctx, binding)
				}
				if err = <-reloaded; err != nil {
					t.Fatal(err)
				}
				client.Close()
				waitDeviceV3(t, done)
				if attemptErr == nil {
					t.Error("captured revoked admission became bound")
				}
			} else if mode == "prepare" {
				client, done := start()
				pump, _, binding := newAuthenticatedClientV3(t, f, ctx, client)
				waitDeviceV3(t, entered)
				if err = s.Reload(); err != nil {
					t.Fatal(err)
				}
				close(release)
				err = pump.BindV1(ctx, binding)
				client.Close()
				waitDeviceV3(t, done)
				if err == nil {
					t.Error("Prepare crossing accepted revocation became bound")
				}
			} else {
				client, done := start()
				pump, _ := startAuthenticatedClientV3(t, f, ctx, client)
				s.registry.mu.RLock()
				var d *SessionDeviceV3
				for _, record := range s.registry.sessions {
					d = record.v3
				}
				s.registry.mu.RUnlock()
				if d == nil {
					t.Fatal("authenticated owner missing")
				}
				if err = s.Reload(); err != nil {
					t.Fatal(err)
				}
				if mode == "unaffected" {
					select {
					case <-d.Done():
						t.Error("unaffected same-root session retired")
					default:
					}
				} else {
					select {
					case <-d.Done():
					default:
						t.Error("affected owner not retired")
					}
					want := kruntime.ServiceAuthorityRevokedV1
					if mode == "different-root" {
						want = kruntime.ServiceCancelledV1
					}
					if !errors.Is(d.checkAuthorityV3(time.Now()), want) {
						t.Error("incorrect first terminal category")
					}
				}
				pump.Close()
				client.Close()
				waitDeviceV3(t, done)
				waitDeviceV3(t, d.Done())
				ready.Store(0)
				client, done = start()
				pump, _, binding, attemptErr := tryAuthenticatedClientV3(t, f, ctx, client)
				if attemptErr == nil {
					attemptErr = pump.BindV1(ctx, binding)
				}
				if mode != "unaffected" && attemptErr == nil {
					t.Error("retired authority authenticated again after old owner Done")
				}
				if mode == "unaffected" && attemptErr != nil {
					t.Errorf("unaffected admission refused: %v", attemptErr)
				}
				client.Close()
				waitDeviceV3(t, done)
			}
			if (mode == "captured" || mode == "prepare" || mode == "readmission") && ready.Load() != 0 {
				t.Error("revoked attempt emitted ready")
			}
			if destinations.Load() != 0 {
				t.Error("authority test performed destination I/O")
			}
			s.registry.mu.RLock()
			retained := len(s.registry.sessions) + s.registry.preparingV3 + s.registry.drainingV3
			s.registry.mu.RUnlock()
			if retained != 0 {
				t.Error("joined handler retained registry capacity")
			}
		})
	}
}

func (s *negativeSnapshotV3) StatusV1() (selfhost.RelayRuntimeStatusV1, bool)        { return s.status, true }
func (s *negativeSnapshotV3) VerifiedRevocationsV3() *selfhost.RelayRevocationViewV3 { return s.view }

func TestServerReloadV3VerifiedReasonPrecedesCancellationAndReentry(t *testing.T) {
	for _, badDNS := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-status", true: "failed-DNS"}[badDNS], func(t *testing.T) {
			f := authenticatedServerFixtureV3(t)
			old, err := selfhost.OpenRelayRuntimeSnapshotV1(f.dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			status, _ := old.StatusV1()
			if err = selfhost.RevokeProfile(f.dir, selfhost.RevokeProfileOptions{ProfileID: f.admission.ProfileID, RecoveryPath: f.recovery, RecoveryPassphrase: f.pass, Now: time.Now()}); err != nil {
				t.Fatal(err)
			}
			candidate, err := selfhost.OpenRelayRuntimeSnapshotV1(f.dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			view := candidate.VerifiedRevocationsV3()
			if !view.RevokesV3(f.admission.RevocationSubjectV3, time.Now()) {
				t.Fatal("signed test evidence does not revoke subject")
			}
			r, _, spec, c := deviceFixtureV3(t, 1)
			spec.ProfileID = f.admission.ProfileID
			c.subjectV3 = f.admission.RevocationSubjectV3
			loads := 0
			dnsReady := true
			config := DefaultConfig(f.dir, 443)
			config.DNSReady = func(context.Context) bool { return dnsReady }
			config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
				loads++
				if loads == 1 {
					return old, nil
				}
				return &negativeSnapshotV3{RelaySnapshotV1: candidate, status: status, view: view}, nil
			}
			s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true, stopActionsV3: make([]serviceStopActionV3, 1)}
			if err = s.Reload(); err != nil {
				t.Fatal(err)
			}
			d, err := r.RegisterV3(spec, c)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			if err = d.AttachReturnIngressV3(&ingressOwnerV3{cancel: func(reason error) {
				calls++
				if !errors.Is(reason, kruntime.ServiceAuthorityRevokedV1) || !errors.Is(d.checkAuthorityV3(time.Now()), reason) {
					t.Error("verified reason was not staged first")
				}
				if calls == 1 && d.ctx.Err() != nil {
					t.Error("generic cancellation won before reason dispatch")
				}
				if err := s.Reload(); !errors.Is(err, ErrServerReload) {
					t.Error("synchronous reentrant reload not rejected")
				}
				if loads != 2 {
					t.Error("reentrant reload performed another load")
				}
			}}); err != nil {
				t.Fatal(err)
			}
			dnsReady = !badDNS
			err = s.Reload()
			if badDNS && !errors.Is(err, ErrServerState) || !badDNS && err != nil {
				t.Fatalf("wrong reload result %v", err)
			}
			waitDeviceV3(t, d.Done())
			if calls == 0 {
				t.Fatal("reason not delivered")
			}
			if !errors.Is(d.checkAuthorityV3(time.Now()), kruntime.ServiceAuthorityRevokedV1) {
				t.Fatal("terminal reason overwritten")
			}
			// The transaction ownership is released after off-lock joined cleanup.
			config.LoadSnapshot = nil
			s.config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) { return nil, selfhost.ErrDrained }
			if err = s.Reload(); err != nil {
				t.Fatal("later reload remained busy")
			}
			s.shutdownV1()
		})
	}
}

func TestServerReloadV3CannotPublishAfterShutdown(t *testing.T) {
	r, _, _, _ := deviceFixtureV3(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	candidate := &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) { close(entered); <-release; return candidate, nil }
	config.DNSReady = func(context.Context) bool { return true }
	s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true}
	done := make(chan error, 1)
	go func() { done <- s.Reload() }()
	waitDeviceV3(t, entered)
	s.shutdownV1()
	close(release)
	if err := <-done; !errors.Is(err, ErrServerReload) {
		t.Fatal("shutdown did not fence completing reload")
	}
	if s.snapshot != nil || s.health.Snapshot().AcceptingSessions {
		t.Fatal("reload revived stopped server")
	}
}

func TestServerReloadV3AuthorityGenerationNeverWraps(t *testing.T) {
	r, _, _, _ := deviceFixtureV3(t, 1)
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true, authorityGenerationV3: ^uint64(0) - 1}
	defer s.shutdownV1()
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.authorityGenerationV3 != ^uint64(0) {
		t.Fatal("generation did not reach exhausted sentinel")
	}
	s.config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(2)}, nil
	}
	if err := s.Reload(); err != nil {
		t.Fatal("V2 reload changed on V3 exhaustion", err)
	}
	if s.authorityGenerationV3 != ^uint64(0) {
		t.Fatal("generation wrapped and could reuse captured authority")
	}
	a := selfhost.RelayAdmissionV1{ServiceAuthorityDeadlineV3: time.Now().Add(time.Hour)}
	for _, generation := range []uint64{0, ^uint64(0) - 1, ^uint64(0)} {
		if s.admissionCurrentLockedV3(a, generation) {
			t.Fatal("exhausted generation admitted V3 authority")
		}
	}
}

func TestServerReloadV3DoesNotWaitForAlreadyDetachedDevice(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.holdAttemptV3(); err != nil {
		t.Fatal(err)
	}
	defer d.releaseAttemptV3()
	d.Close()
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(2)}, nil
	}
	config.DNSReady = func(context.Context) bool { return true }
	s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true}
	done := make(chan error, 1)
	go func() { done <- s.Reload() }()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		d.releaseAttemptV3()
		<-done
		t.Fatal("reload waited on a nonexistent whole-view borrower")
	}
	select {
	case <-d.Done():
		t.Fatal("reload released detached handler capacity")
	default:
	}
	if _, err = r.Register(spec); !errors.Is(err, ErrSessionLimit) {
		t.Fatal("detached pump was no longer counted")
	}
	d.releaseAttemptV3()
	waitDeviceV3(t, d.Done())
	next, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	waitDeviceV3(t, next.Done())
	s.shutdownV1()
}

func TestServerServicesV3PreparationResidualAndCategory(t *testing.T) {
	f := authenticatedServerFixtureV3(t)
	s := f.admission.RuntimePolicy.Services
	preparation, err := kruntime.ServicePreparationBoundsForPlanV1(f.plan, true)
	if err != nil {
		t.Fatal(err)
	}
	if serviceConstructionBudgetV3(f.plan, s, 16<<20, 1, 1) || serviceConstructionBudgetV3(f.plan, s, preparation.OwnedBytes+2, 1, 1) {
		t.Fatal("scratch shortfall accepted")
	}
	if !serviceConstructionBudgetV3(f.plan, s, 64<<20, 1024, 1024) || serviceConstructionBudgetV3(f.plan, s, 64<<20, ^uint64(0), 1) {
		t.Fatal("residual did not preserve signed cap/checked subtraction")
	}
	if servicePumpRejectCategoryV3(kruntime.ServiceResourceLimitV1) != SessionRejectCapacityV1 || servicePumpRejectCategoryV3(kruntime.ServiceNotAdmittedV1) != SessionRejectPacketPumpV1 {
		t.Fatal("resource refusal category drift")
	}
}

func TestServerServicesV3PreservesExistingBudgetSelection(t *testing.T) {
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	services := &runtimepolicy.ServicesV1{Proxy: &runtimepolicy.ProxyV1{MaxBufferBytes: 64 << 20}}
	if config.SessionBufferBudget != 8<<20 || serviceBudgetV3(services, config.SessionBufferBudget) {
		t.Fatal("default V2 budget reinterpreted for V3 proxy")
	}
	if !serviceBudgetV3(services, 64<<20) || serviceBudgetV3(services, 65<<20) || serviceBudgetV3(nil, 64<<20) {
		t.Fatal("signed service budget widened")
	}
}

func TestServerReloadV3CompetingTransactionDoesNotLoadOrWait(t *testing.T) {
	r, _, _, _ := deviceFixtureV3(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	var loads atomic.Int32
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		if loads.Add(1) == 1 {
			close(entered)
			<-release
		}
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	config.DNSReady = func(context.Context) bool { return true }
	s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true}
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { first <- s.Reload() }()
	waitDeviceV3(t, entered)
	go func() { second <- s.Reload() }()
	early := false
	select {
	case err := <-second:
		early = true
		if !errors.Is(err, ErrServerReload) {
			t.Error("competing reload not rejected")
		}
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !early {
		<-second
		t.Fatal("competing reload waited on transaction")
	}
	if loads.Load() != 1 {
		t.Fatal("rejected transaction performed load")
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	s.shutdownV1()
}

func TestServerReloadV3DoesNotHoldStateDuringReadiness(t *testing.T) {
	r, _, _, _ := deviceFixtureV3(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	config.DNSReady = func(context.Context) bool { close(entered); <-release; return true }
	s := &ServerV1{config: config, registry: r, health: NewHealthMachine(), listenerReady: true, tunnelReady: true}
	done := make(chan error, 1)
	go func() { done <- s.Reload() }()
	waitDeviceV3(t, entered)
	available := s.stateMu.TryRLock()
	if available {
		s.stateMu.RUnlock()
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.shutdownV1()
	if !available {
		t.Fatal("readiness I/O held state authority fence")
	}
}

func TestServerStopProfileV3PublishesReasonOutsideStateAndRegistryLocks(t *testing.T) {
	r, _, spec, c := deviceFixtureV3(t, 1)
	d, err := r.RegisterV3(spec, c)
	if err != nil {
		t.Fatal(err)
	}
	s := &ServerV1{registry: r, config: Config{Now: time.Now}}
	called := false
	if err = d.AttachReturnIngressV3(&ingressOwnerV3{cancel: func(reason error) {
		called = true
		if !errors.Is(reason, kruntime.ServiceCancelledV1) {
			t.Error("owner stop fabricated revocation")
		}
		if !s.stateMu.TryLock() {
			t.Error("owner callback under state lock")
		} else {
			s.stateMu.Unlock()
		}
		if !r.mu.TryLock() {
			t.Error("owner callback under registry lock")
		} else {
			r.mu.Unlock()
		}
	}}); err != nil {
		t.Fatal(err)
	}
	s.stopProfileV1(spec.ProfileID)
	waitDeviceV3(t, d.Done())
	if !called {
		t.Fatal("owner reason not delivered")
	}
}

func TestServerWriteHealthV3ClosesAndJoinsOwnedRuntime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	control, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), uint16(listener.Addr().(*net.TCPAddr).Port))
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	tunnel := &healthTunnelV3{memoryTunnelV1: newMemoryTunnelV1(), failure: make(chan struct{})}
	server, err := NewServerV1(config, listener, tunnel, control, func(net.Conn) error { return nil })
	if err != nil {
		listener.Close()
		control.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	limit := time.Now().Add(time.Second)
	for !server.health.Snapshot().AcceptingSessions && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if !server.health.Snapshot().AcceptingSessions {
		cancel()
		<-done
		t.Fatal("server did not become ready")
	}
	close(tunnel.failure)
	select {
	case err = <-done:
		if !errors.Is(err, ErrServerRegistry) || !errors.Is(err, tun.ErrWriteHealthV3) {
			t.Fatalf("wrong health result %v", err)
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("latched TUN health did not stop server")
	}
	select {
	case <-tunnel.closed:
	default:
		t.Fatal("server did not close shared TUN")
	}
	if server.health.Snapshot().AcceptingSessions {
		t.Fatal("fault left admission open")
	}
	if server.readyRequirementsV1().Tunnel {
		t.Fatal("latched fault can regain readiness")
	}
}

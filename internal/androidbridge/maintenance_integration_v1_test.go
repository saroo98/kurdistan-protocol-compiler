// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/dns/dnsmessage"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

// All authority, issuance, activation, verification, DNS parsing, filtering and
// TLS are real. Only a private numeric route maps validated destinations to
// local sockets. It is not exposed by a release constructor or request.
type maintenanceSignedFixture struct {
	now                   time.Time
	current               MaintenanceCurrentInputV1
	artifact, replacement []byte
	record                profile.ActivationRecord
}

func newMaintenanceSignedFixture(t *testing.T) maintenanceSignedFixture {
	return newMaintenanceSignedFixtureWithCandidateLifetime(t, 12*time.Hour)
}

func newMaintenanceSignedFixtureWithCandidateLifetime(t *testing.T, lifetime time.Duration) maintenanceSignedFixture {
	t.Helper()
	base := t.TempDir()
	dir, recovery := filepath.Join(base, "node"), filepath.Join(base, "recovery")
	now := time.Unix(1780000062, 0).UTC()
	pass := []byte("local maintenance integration recovery phrase")
	if _, e := selfhost.Initialize(selfhost.InitOptions{DataDir: dir, DeploymentName: "maintenance-host", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(-2 * time.Minute)}); e != nil {
		t.Fatal("initialize", e)
	}
	if e := selfhost.ConfirmRecovery(dir, recovery, pass, now.Add(-time.Minute)); e != nil {
		t.Fatal("confirm", e)
	}
	model, e := compiler.Generate(71)
	if e != nil {
		t.Fatal(e)
	}
	features := ir.SecurityCapabilities()
	program, e := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: model, ClientMandatoryFeatures: features[:2], RelayMandatoryFeatures: features[:2], SelectedFeatures: features})
	if e != nil {
		t.Fatal(e)
	}
	wireProgram, e := liveprogram.EncodeV1(program)
	if e != nil {
		t.Fatal(e)
	}
	request, private, e := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	requestWire, e := enrollment.EncodeRequestV1(request)
	if e != nil {
		t.Fatal(e)
	}
	privateWire, e := enrollment.EncodePrivateBundleV1(private)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(privateWire); clear(private.RecipientPrivate); clear(private.ClientAuthSeed) })
	services := &runtimepolicy.ServicesV1{Version: 1, Update: &runtimepolicy.UpdateV1{URL: "https://example.com/exact", MaxArtifactBytes: 65536, TimeoutMillis: 30000, MinCheckIntervalSeconds: 60}, Probes: &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1, 2}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 10, MaxOperationMillis: 30000}}
	issued, e := selfhost.CreateProfile(dir, selfhost.CreateProfileOptions{Name: "host-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestWire, LiveProgram: wireProgram, RegistryDir: filepath.Join(base, "registry"), Services: services})
	if e != nil {
		t.Fatal("create", e)
	}
	session, e := selfhost.NewAndroidLiveActivationSessionForRecipient(issued.Artifact, now, lifecycle.VerifiedState{}, request, private)
	if e != nil {
		t.Fatal("activation", e)
	}
	defer session.Destroy()
	var staged profile.ActivationRecord
	for {
		command, ok := session.Next()
		if !ok {
			break
		}
		result := profile.ActivationCommandResult{}
		if command.Kind == profile.ActivationCommandStageCandidate {
			staged = command.Record
		}
		if command.Kind == profile.ActivationCommandReopenCandidate {
			result.Record = staged
		}
		if e = session.Submit(command, result); e != nil {
			t.Fatal(e)
		}
	}
	record, e := session.Result()
	if e != nil {
		t.Fatal(e)
	}
	recordWire, e := EncodeActivationRecord(record)
	if e != nil {
		t.Fatal(e)
	}
	verifyWire, e := EncodeVerifyRequest(VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if e != nil {
		t.Fatal(e)
	}
	next, e := selfhost.RotateProfile(dir, selfhost.RotateProfileOptions{ProfileID: issued.ProfileID, RecoveryPath: recovery, RecoveryPassphrase: pass, Now: now.Add(time.Minute), ValidFor: lifetime, LiveProgram: wireProgram, RegistryDir: filepath.Join(base, "registry")})
	if e != nil {
		t.Fatal("rotate", e)
	}
	return maintenanceSignedFixture{now: now.Add(time.Minute), current: MaintenanceCurrentInputV1{VerifyRequest: verifyWire, ActivationRecord: recordWire, RecipientRequest: requestWire, RecipientPrivate: privateWire}, artifact: issued.Artifact, replacement: next.Artifact, record: record}
}

type maintenanceRealVerifier struct{}

func (maintenanceRealVerifier) VerifyWithRecipientAt(artifact []byte, class envelope.ArtifactClass, c RecipientCredentials, at time.Time, limits selfhost.LiveMaintenanceLimits) (profile.OfflineVerifiedArtifact, selfhost.LiveMaintenanceBounds, error) {
	defer c.Destroy()
	return selfhost.VerifyLiveMaintenanceCurrentForRecipient(artifact, at, 1, c.Request, c.Private, limits)
}

type maintenanceIntegrationPlatform struct {
	invalidate   func() ErrorCode
	publications atomic.Int32
	afterAcquire func()
}

func (p *maintenanceIntegrationPlatform) Register(_ uint64, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	p.invalidate = invalidate
	return p, CodeOK
}
func (*maintenanceIntegrationPlatform) Revalidate(context.Context) MaintenanceResultV1 {
	return MaintenanceSuccess
}
func (p *maintenanceIntegrationPlatform) AcquirePublication(context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	p.publications.Add(1)
	if p.afterAcquire != nil {
		p.afterAcquire()
	}
	return maintenanceClockLease{}, MaintenanceSuccess
}
func (*maintenanceIntegrationPlatform) Close() ErrorCode { return CodeOK }
func (f maintenanceSignedFixture) open(t *testing.T, e MaintenanceTransportEnvironmentV1, clock func() time.Time) (*HandleRegistry, Handle, *maintenanceAuthorityV1, *maintenanceIntegrationPlatform) {
	t.Helper()
	r := new(HandleRegistry)
	rates, _ := NewMaintenanceUpdateRateRegistryV1(1)
	platform := new(maintenanceIntegrationPlatform)
	h, result := OpenMaintenanceV1(r, f.current, maintenanceRealVerifier{}, platform, MaintenanceConfigV1{Now: clock, OwnedBudgetBytes: 128 << 20, Limits: selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}, Transport: e, UpdateRates: rates})
	if result != MaintenanceSuccess {
		t.Fatal("open", result)
	}
	t.Cleanup(func() { r.Free(h) })
	p, result := maintenanceParentV1(r, h)
	if result != MaintenanceSuccess {
		t.Fatal(result)
	}
	return r, h, p, platform
}
func maintenanceIntegrationRoots(server *httptest.Server) []byte {
	der := server.Certificate().Raw
	out := make([]byte, 7+len(der))
	out[0] = 1
	binary.BigEndian.PutUint16(out[1:], 1)
	binary.BigEndian.PutUint32(out[3:], uint32(len(der)))
	copy(out[7:], der)
	return out
}

func maintenanceLocalDNS(t *testing.T, stage func(), answers []netip.Addr, truncated ...bool) (netip.AddrPort, *atomic.Int32) {
	t.Helper()
	socket, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	calls := new(atomic.Int32)
	go func() {
		defer close(done)
		var buf [4096]byte
		for {
			n, peer, e := socket.ReadFromUDP(buf[:])
			if e != nil {
				return
			}
			calls.Add(1)
			if stage != nil {
				stage()
			}
			var parser dnsmessage.Parser
			header, e := parser.Start(buf[:n])
			if e != nil {
				return
			}
			q, e := parser.Question()
			if e != nil {
				return
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionAvailable: true, Truncated: len(truncated) > 0 && truncated[0]})
			builder.EnableCompression()
			if e = builder.StartQuestions(); e != nil {
				return
			}
			if e = builder.Question(q); e != nil {
				return
			}
			if e = builder.StartAnswers(); e != nil {
				return
			}
			for _, a := range answers {
				if a.Is4() && q.Type == dnsmessage.TypeA {
					e = builder.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: a.As4()})
				} else if a.Is6() && q.Type == dnsmessage.TypeAAAA {
					e = builder.AAAAResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AAAAResource{AAAA: a.As16()})
				}
				if e != nil {
					return
				}
			}
			reply, e := builder.Finish()
			if e != nil {
				return
			}
			if _, e = socket.WriteToUDP(reply, peer); e != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { socket.Close(); <-done })
	return socket.LocalAddr().(*net.UDPAddr).AddrPort(), calls
}

func TestMaintenanceSignedFetchOrchestration(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	for _, scenario := range []string{"replacement", "no-change", "corrupt", "private-only"} {
		t.Run(scenario, func(t *testing.T) {
			body := f.replacement
			if scenario == "no-change" {
				body = f.artifact
			}
			if scenario == "corrupt" {
				body = []byte{0xff}
			}
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Host != "example.com" || r.URL.RequestURI() != "/exact" || r.UserAgent() != "" {
					t.Error("signed request changed")
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(body)
			}))
			defer server.Close()
			answers := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("8.8.8.8")}
			if scenario == "private-only" {
				answers = answers[:1]
			}
			dns, calls := maintenanceLocalDNS(t, nil, answers)
			network := newMaintenanceTestNetwork()
			r, h, p, platform := f.open(t, &maintenanceTestEnvironment{network: network, roots: maintenanceIntegrationRoots(server)}, func() time.Time { return f.now })
			tcp := server.Listener.Addr().(*net.TCPAddr).AddrPort()
			route := func(kind string, dst netip.AddrPort) netip.AddrPort {
				if kind == "udp" && dst == netip.MustParseAddrPort("127.0.0.1:53") {
					return dns
				}
				if kind == "tcp" && dst == netip.MustParseAddrPort("8.8.8.8:443") {
					return tcp
				}
				t.Errorf("unexpected unvalidated destination %s %v", kind, dst)
				return netip.AddrPort{}
			}
			got := checkSameDeploymentUpdateV1(r, h, 10000, route)
			want := MaintenanceSuccess
			switch scenario {
			case "no-change":
				want = MaintenanceNoChange
			case "corrupt":
				want = MaintenanceInvalidRequest
			case "private-only":
				want = MaintenanceDestinationDenied
			}
			if got.Result != want {
				t.Fatalf("result=%v want=%v", got.Result, want)
			}
			if scenario == "replacement" {
				if got.Candidate == 0 || got.Preview.Generation != 2 || p.candidate == nil || platform.publications.Load() < 2 {
					t.Fatal("fetched replacement not published", got)
				}
				materialized := make([]byte, len(f.replacement))
				n, result := MaterializeMaintenanceCandidateV1(r, h, got.Candidate, materialized)
				if result != MaintenanceSuccess || n != len(f.replacement) || !bytes.Equal(materialized, f.replacement) {
					t.Fatal("fetched authenticated bytes changed", result, n)
				}
				clear(materialized)
			} else if got.Candidate != 0 || got.Preview != (selfhost.LiveMaintenancePreviewV1{}) || p.candidate != nil {
				t.Fatal("noncandidate result leaked metadata", got)
			}
			if calls.Load() != 1 {
				t.Fatal("signed IPv4-only policy repeated or widened DNS", calls.Load())
			}
			wantRequests := int32(1)
			if scenario == "private-only" {
				wantRequests = 0
			}
			if requests.Load() != wantRequests {
				t.Fatal("filter/retry boundary", requests.Load())
			}
		})
	}
}

func TestMaintenanceSignedFetchClockChangeBeforeDNSFallbackSocket(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	for _, change := range []time.Duration{20 * time.Second, -time.Second} {
		t.Run(change.String(), func(t *testing.T) {
			var clock atomic.Int64
			clock.Store(f.now.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()) }
			var requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write(f.replacement) }))
			defer server.Close()
			dns, calls := maintenanceLocalDNS(t, func() { clock.Store(f.now.Add(change).UnixNano()) }, nil, true)
			fallback, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer fallback.Close()
			network := newMaintenanceTestNetwork()
			r, h, _, _ := f.open(t, &maintenanceTestEnvironment{network: network, roots: maintenanceIntegrationRoots(server)}, now)
			route := func(kind string, dst netip.AddrPort) netip.AddrPort {
				if dst != netip.MustParseAddrPort("127.0.0.1:53") {
					t.Errorf("unexpected destination %s %v", kind, dst)
					return netip.AddrPort{}
				}
				if kind == "udp" {
					return dns
				}
				return fallback.Addr().(*net.TCPAddr).AddrPort()
			}
			got := checkSameDeploymentUpdateV1(r, h, 10000, route)
			want := MaintenanceTimeout
			if change < 0 {
				want = MaintenanceExpired
			}
			if got.Result != want || got.Candidate != 0 || got.Preview != (selfhost.LiveMaintenancePreviewV1{}) || network.binds.Load() != 1 || calls.Load() != 1 || requests.Load() != 0 {
				t.Fatal("stale original update reached fallback bind or publication", got, network.binds.Load(), calls.Load(), requests.Load())
			}
		})
	}
}

func TestMaintenanceSignedFetchBlockedStagesFenceLifecycle(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	for _, stage := range []string{"dns-cancel", "tls-free", "header-revision", "body-expiry"} {
		t.Run(stage, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var enterOnce, releaseOnce sync.Once
			signal := func() { enterOnce.Do(func() { close(entered) }) }
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			// Registered before any fixture can block. Later cleanup also unblocks
			// before closing/joining servers, including every assertion failure.
			t.Cleanup(unblock)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				if stage == "header-revision" {
					signal()
					<-release
				}
				if stage == "body-expiry" {
					w.Header().Set("Content-Length", fmt.Sprint(len(f.replacement)))
					w.WriteHeader(200)
					_, _ = w.Write(f.replacement[:1])
					w.(http.Flusher).Flush()
					signal()
					<-release
					_, _ = w.Write(f.replacement[1:])
					return
				}
				_, _ = w.Write(f.replacement)
			}))
			t.Cleanup(func() { unblock(); server.Close() })
			var dnsStage func()
			if stage == "dns-cancel" {
				dnsStage = func() { signal(); <-release }
			}
			dns, _ := maintenanceLocalDNS(t, dnsStage, []netip.Addr{netip.MustParseAddr("8.8.8.8")})
			t.Cleanup(unblock)
			tcp := server.Listener.Addr().(*net.TCPAddr).AddrPort()
			if stage == "tls-free" {
				listener, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if e != nil {
					t.Fatal(e)
				}
				tcp = listener.Addr().(*net.TCPAddr).AddrPort()
				peerDone := make(chan struct{})
				var peerMu sync.Mutex
				var peer net.Conn
				peerClosing := false
				go func() {
					defer close(peerDone)
					c, e := listener.Accept()
					if e != nil {
						return
					}
					peerMu.Lock()
					if peerClosing {
						peerMu.Unlock()
						c.Close()
						return
					}
					peer = c
					peerMu.Unlock()
					defer c.Close()
					var header [5]byte
					if _, e = io.ReadFull(c, header[:]); e == nil {
						signal()
					}
					_, _ = io.Copy(io.Discard, c)
				}()
				t.Cleanup(func() {
					listener.Close()
					peerMu.Lock()
					peerClosing = true
					if peer != nil {
						peer.Close()
					}
					peerMu.Unlock()
					<-peerDone
				})
			}
			network := newMaintenanceTestNetwork()
			r, h, p, platform := f.open(t, &maintenanceTestEnvironment{network: network, roots: maintenanceIntegrationRoots(server)}, func() time.Time { return f.now })
			route := func(kind string, dst netip.AddrPort) netip.AddrPort {
				if kind == "udp" && dst == netip.MustParseAddrPort("127.0.0.1:53") {
					return dns
				}
				if kind == "tcp" && dst == netip.MustParseAddrPort("8.8.8.8:443") {
					return tcp
				}
				t.Errorf("unexpected destination %s %v", kind, dst)
				return netip.AddrPort{}
			}
			done := make(chan struct{})
			var got MaintenanceCandidateResultV1
			go func() { defer close(done); got = checkSameDeploymentUpdateV1(r, h, 10000, route) }()
			t.Cleanup(func() { unblock(); r.Cancel(h); <-done })
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("stage not entered")
			}
			want := MaintenanceCancelled
			switch stage {
			case "dns-cancel":
				if code := r.Cancel(h); code != CodeOK {
					t.Fatal(code)
				}
			case "tls-free":
				if code := r.Free(h); code != CodeOK {
					t.Fatal(code)
				}
			case "header-revision":
				if code := platform.invalidate(); code != CodeOK {
					t.Fatal(code)
				}
			case "body-expiry":
				want = MaintenanceExpired
				p.mu.Lock()
				p.parentTimerAt = time.Now().Add(-time.Second)
				p.armTimerAtLocked(p.parentTimerAt, maintenanceTimerParent)
				p.mu.Unlock()
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("blocked stage operation did not join")
			}
			if got.Result != want || got.Candidate != 0 || got.Preview != (selfhost.LiveMaintenancePreviewV1{}) {
				t.Fatal("late stage publication", got)
			}
			p.mu.Lock()
			retained := p.candidate != nil
			p.mu.Unlock()
			if retained {
				t.Fatal("failed stage retained candidate")
			}
			if platform.publications.Load() != 1 {
				t.Fatal("failed stage reached publication lease", platform.publications.Load())
			}
		})
	}
}

type maintenanceHandshakeIdentity struct {
	id  string
	key ed25519.PrivateKey
}

func (i maintenanceHandshakeIdentity) Local(id string) (ed25519.PrivateKey, error) {
	if id != i.id {
		return nil, errors.New("fixture identity")
	}
	return bytes.Clone(i.key), nil
}

type maintenanceHandshakeTrust struct {
	id  string
	key ed25519.PublicKey
}

func (i maintenanceHandshakeTrust) Peer(id string) (ed25519.PublicKey, error) {
	if id != i.id {
		return nil, errors.New("fixture peer")
	}
	return bytes.Clone(i.key), nil
}

type maintenancePumpCarrier struct {
	net.Conn
	armed   atomic.Bool
	once    sync.Once
	reading chan struct{}
}

func (c *maintenancePumpCarrier) Read(dst []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.reading) })
	}
	return c.Conn.Read(dst)
}

func maintenanceConcretePumpPair(t *testing.T, f maintenanceSignedFixture, network runtime.RelayServiceNetworkV1) (*runtime.ServicePumpV1, *runtime.ServicePumpV1) {
	t.Helper()
	policy, e := runtimepolicy.DecodeRuntimeAt(f.record.Profile.Policy, f.now)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := sessionplan.BuildV2At(sessionplan.RequestV2{Profile: f.record.Profile, ActivationReceipt: f.record.State.Receipt, RuntimePolicy: policy, Requested: sessionplan.NarrowingRequestV2{MaxQueuePackets: 1}}, f.now)
	if e != nil {
		t.Fatal(e)
	}
	program, e := liveprogram.DecodeV1(policy.LiveProgram)
	if e != nil {
		t.Fatal(e)
	}
	cp, ck, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { clear(ck); clear(rk) })
	hc, e := auth.NewProjectedProcessHandshakeConfigV1("host-client", "host-relay", program, "tls13-tcp")
	if e != nil {
		t.Fatal(e)
	}
	cache, e := auth.NewHandshakeReplayCache(64)
	if e != nil {
		t.Fatal(e)
	}
	ch, e := runtime.NewProcessWireClientHandshakeV1(hc, auth.Dependencies{Identity: maintenanceHandshakeIdentity{"host-client", ck}, Trust: maintenanceHandshakeTrust{"host-relay", rp}}, [32]byte{9})
	if e != nil {
		t.Fatal(e)
	}
	defer ch.Close()
	rh, e := runtime.NewProcessWireRelayHandshakeV1(hc, auth.Dependencies{Identity: maintenanceHandshakeIdentity{"host-relay", rk}, Trust: maintenanceHandshakeTrust{"host-client", cp}}, cache, [32]byte{9})
	if e != nil {
		t.Fatal(e)
	}
	defer rh.Close()
	hello, e := ch.Start()
	if e != nil {
		t.Fatal(e)
	}
	response, e := rh.AcceptClientHello(hello)
	if e != nil {
		t.Fatal(e)
	}
	finish, e := ch.AcceptServerHello(response)
	if e != nil {
		t.Fatal(e)
	}
	last, rr, e := rh.AcceptClientFinish(finish)
	if e != nil {
		t.Fatal(e)
	}
	cr, e := ch.AcceptServerFinish(last)
	if e != nil {
		t.Fatal(e)
	}
	defer cr.Close()
	defer rr.Close()
	a, b := net.Pipe()
	ca := &maintenancePumpCarrier{Conn: a, reading: make(chan struct{})}
	ra := &maintenancePumpCarrier{Conn: b, reading: make(chan struct{})}
	cport, e := runtime.NewPacketPortV1(int(plan.MTU))
	if e != nil {
		t.Fatal(e)
	}
	rport, e := runtime.NewPacketPortV1(int(plan.MTU))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ca.Close(); ra.Close(); cport.Close(); rport.Close() })
	scope, e := runtime.NewAuthenticatedProbeScopeV1(f.record.Profile)
	if e != nil {
		t.Fatal(e)
	}
	rates, e := runtime.NewProbeRateRegistryV1(1)
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	now := func() time.Time { return f.now.Add(time.Since(start)) }
	cfg := runtime.ServicePumpConfigV1{PacketIO: cport, Carrier: ca, CarrierOwnedBytes: uint64(unsafe.Sizeof(*ca)), ProbeLimit: 1, BufferBudget: 64 << 20, MaxRecordBytes: 1 << 20, Generation: f.record.Profile.Generation, AuthorityDeadline: f.now.Add(time.Minute), Now: now, CheckAuthority: func(time.Time) error { return nil }, ProbeScope: scope, ProbeRates: rates}
	client, e := runtime.NewClientServicePumpV1(cr, plan, cfg)
	if e != nil {
		t.Fatal("client", e)
	}
	cfg.PacketIO = rport
	cfg.Carrier = ra
	cfg.CarrierOwnedBytes = uint64(unsafe.Sizeof(*ra))
	cfg.PacketOwnedBytes = 65536
	cfg.PacketQueuedBytes = uint64(2 * plan.MTU)
	cfg.NetworkOperationBytes = 8192
	cfg.RelayNetwork = network
	cfg.ProbeRates, _ = runtime.NewProbeRateRegistryV1(1)
	relay, e := runtime.NewRelayServicePumpV1(rr, plan, cfg)
	if e != nil {
		client.Close()
		t.Fatal("relay", e)
	}
	t.Cleanup(func() {
		client.Close()
		relay.Close()
		select {
		case <-client.Done():
		case <-time.After(2 * time.Second):
			t.Error("client pump not joined")
		}
		select {
		case <-relay.Done():
		case <-time.After(2 * time.Second):
			t.Error("relay pump not joined")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bound := make(chan error, 1)
	go func() { bound <- relay.BindV1(ctx, [32]byte{1}) }()
	if e = client.BindV1(ctx, [32]byte{1}); e != nil {
		client.Close()
		relay.Close()
		<-bound
		t.Fatal(e)
	}
	if e = <-bound; e != nil {
		t.Fatal(e)
	}
	ca.armed.Store(true)
	ra.armed.Store(true)
	clientDone, relayDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(clientDone); _ = client.Run(context.Background()) }()
	go func() { defer close(relayDone); _ = relay.Run(context.Background()) }()
	t.Cleanup(func() { client.Close(); relay.Close(); <-clientDone; <-relayDone })
	for _, ready := range []chan struct{}{ca.reading, ra.reading} {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("pump Run did not enter I/O")
		}
	}
	return client, relay
}

type maintenanceConcreteProbeOwner struct {
	mu    sync.Mutex
	pump  *runtime.ServicePumpV1
	epoch uint64
	scope runtime.AuthenticatedProbeScopeV1
	calls int
	valid bool
}

func (o *maintenanceConcreteProbeOwner) CurrentPump(epoch uint64, scope runtime.AuthenticatedProbeScopeV1) (*runtime.ServicePumpV1, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	return o.pump, o.valid && epoch == o.epoch && scope == o.scope
}

type maintenanceRelayProbeNetwork struct {
	address                     netip.AddrPort
	entered, cancelled, release chan struct{}
	gate                        bool
	calls                       atomic.Int32
}

func (*maintenanceRelayProbeNetwork) ResolveProxy(context.Context, []byte, *[16]netip.Addr) (int, error) {
	return 0, runtime.ServiceDestinationDeniedV1
}
func (n *maintenanceRelayProbeNetwork) DialTCP(ctx context.Context, dst netip.AddrPort) (runtime.ServiceTCPConnV1, error) {
	n.calls.Add(1)
	if dst != netip.MustParseAddrPort("8.8.8.8:443") {
		return nil, runtime.ServiceDestinationDeniedV1
	}
	if n.entered != nil {
		close(n.entered)
	}
	if n.gate {
		<-ctx.Done()
		close(n.cancelled)
		<-n.release
		return nil, ctx.Err()
	}
	d := net.Dialer{}
	return d.DialTCP(ctx, "tcp", netip.AddrPort{}, n.address)
}

func TestMaintenanceConcreteActivePumpConsumer(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	for _, scenario := range []string{"success", "wrong-scope", "changed-pump", "cancel-reset"} {
		t.Run(scenario, func(t *testing.T) {
			listener, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if e != nil {
				t.Fatal(e)
			}
			defer listener.Close()
			network := &maintenanceRelayProbeNetwork{address: listener.Addr().(*net.TCPAddr).AddrPort(), entered: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{}), gate: scenario == "cancel-reset"}
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(network.release) }) }
			t.Cleanup(unblock)
			client, relay := maintenanceConcretePumpPair(t, f, network)
			t.Cleanup(unblock)
			lease := newMaintenanceTestNetwork()
			lease.mode = runtime.ProbeActiveRelayV1
			r, h, p, platform := f.open(t, &maintenanceTestEnvironment{network: lease}, func() time.Time { return f.now })
			owner := &maintenanceConcreteProbeOwner{pump: client, epoch: p.parentEpoch, scope: p.probeScope, valid: true}
			p.activeProbes = owner
			if scenario == "wrong-scope" {
				owner.scope = runtime.AuthenticatedProbeScopeV1{}
			}
			if scenario == "changed-pump" {
				platform.afterAcquire = func() { owner.mu.Lock(); owner.pump = relay; owner.mu.Unlock() }
			}
			type answer struct {
				out runtime.ProbeAggregateV1
				r   MaintenanceResultV1
			}
			result := make(chan answer, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				out, code := RunMaintenanceProbeV1(r, h, runtime.ProbeRequestV1{TargetID: 1, Method: 1, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 5000, Samples: 1})
				result <- answer{out, code}
			}()
			t.Cleanup(func() { unblock(); r.Cancel(h); <-joined })
			if scenario == "cancel-reset" {
				select {
				case <-network.entered:
				case <-time.After(time.Second):
					t.Fatal("relay target dial not entered")
				}
				if code := r.Cancel(h); code != CodeOK {
					t.Fatal(code)
				}
				select {
				case <-network.cancelled:
				case <-time.After(time.Second):
					t.Fatal("authenticated RESET did not cancel relay worker")
				}
				select {
				case <-relay.Done():
					t.Fatal("maintenance falsely closed pump")
				default:
				}
				if relay.BoundsV1().OwnedBytes == 0 {
					t.Fatal("blocked relay borrower charge released")
				}
			}
			var got answer
			select {
			case got = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("active maintenance not joined")
			}
			want := MaintenanceSuccess
			if scenario == "wrong-scope" || scenario == "changed-pump" {
				want = MaintenanceNetworkUnavailable
			}
			if scenario == "cancel-reset" {
				want = MaintenanceCancelled
			}
			if got.r != want {
				t.Fatal("active result", got.r, want)
			}
			if scenario == "success" && (got.out.Path != runtime.ProbeActiveRelayEndToEndV1 || got.out.Attempted != 1 || !got.out.HasLatency || got.out.LossPermille != 0) {
				t.Fatal("real active aggregate", got.out)
			}
			if scenario == "wrong-scope" && network.calls.Load() != 0 {
				t.Fatal("wrong scope reached relay")
			}
			if lease.binds.Load() != 0 {
				t.Fatal("active probe opened maintenance socket")
			}
			if scenario == "cancel-reset" {
				unblock()
				relay.Close()
				client.Close()
				select {
				case <-relay.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("pump owner failed joined cleanup")
				}
			}
		})
	}
}

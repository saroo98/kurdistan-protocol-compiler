// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/selfhost"
)

func TestServerReloadV1ReplacesAuthorityAndTerminatesExistingSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	first := &fakeRelaySnapshotV1{status: selfhost.RelayRuntimeStatusV1{Revision: 1, Generation: 1, RelayEpoch: 1, TLSEpoch: 1, RelayKeyID: "relay.1111111111111111", TLSKeyID: "tls.1111111111111111", RelayPublic: [32]byte{1}}}
	second := &fakeRelaySnapshotV1{status: selfhost.RelayRuntimeStatusV1{Revision: 2, Generation: 2, RelayEpoch: 2, TLSEpoch: 1, RelayKeyID: "relay.2222222222222222", TLSKeyID: "tls.1111111111111111", RelayPublic: [32]byte{2}}}
	loads := []RelaySnapshotV1{first, second}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.Now = func() time.Time { return now }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		if len(loads) == 0 {
			return nil, errors.New("unexpected load")
		}
		loaded := loads[0]
		loads = loads[1:]
		return loaded, nil
	}
	registry, err := NewSessionRegistry(newMemoryTunnelV1(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
	if err := server.Reload(); err != nil || server.health.Snapshot().State != HealthReady {
		t.Fatalf("initial reload err=%v health=%+v", err, server.health.Snapshot())
	}
	if _, err := registry.Register(SessionSpec{ID: "session-1", ProfileID: "profile-1", ClientKeyID: "client-1", AssignedIPv4: [4]byte{10, 77, 0, 2}}); err != nil {
		t.Fatal(err)
	}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	if !first.closed || second.closed || registry.Snapshot().ActiveSessions != 0 || server.health.Snapshot().State != HealthReady {
		t.Fatalf("first.closed=%v second.closed=%v registry=%+v health=%+v", first.closed, second.closed, registry.Snapshot(), server.health.Snapshot())
	}
}

func TestSessionRejectPacketPumpStageV1IsBoundedAndCategorical(t *testing.T) {
	for _, test := range []struct {
		stage kruntime.PacketPumpStageV1
		want  SessionRejectCodeV1
	}{
		{kruntime.PacketPumpStageTUNReadV1, SessionRejectPumpTUNV1},
		{kruntime.PacketPumpStageCarrierWriteV1, SessionRejectPumpCarrierV1},
		{kruntime.PacketPumpStageRecordOpenV1, SessionRejectPumpRecordV1},
		{kruntime.PacketPumpStageOutboundQueueV1, SessionRejectPumpQueueV1},
		{kruntime.PacketPumpStageIdleV1, SessionRejectPumpIdleV1},
		{"unknown", SessionRejectPacketPumpV1},
	} {
		if got := sessionRejectPacketPumpStageV1(test.stage); got != test.want {
			t.Fatalf("stage=%q code=%q want=%q", test.stage, got, test.want)
		}
	}
}

func TestSessionRejectHandshakeV1IsBoundedAndCategorical(t *testing.T) {
	for _, test := range []struct {
		err  error
		want SessionRejectCodeV1
	}{
		{&auth.HandshakeError{Code: auth.FailureUnknownIdentity}, SessionRejectAuthUnknownIdentityV1},
		{&auth.HandshakeError{Code: auth.FailureUntrustedIdentity}, SessionRejectAuthUntrustedIdentityV1},
		{&auth.HandshakeError{Code: auth.FailureInternalLimit}, SessionRejectAuthLimitV1},
		{errors.New("other"), SessionRejectAuthCredentialsV1},
	} {
		if got := sessionRejectHandshakeV1(test.err); got != test.want {
			t.Fatalf("err=%v code=%q want=%q", test.err, got, test.want)
		}
	}
}

func TestSessionRejectAuthConfigV1IsBoundedAndCategorical(t *testing.T) {
	for _, test := range []struct {
		err  error
		want SessionRejectCodeV1
	}{
		{&auth.HandshakeError{Code: auth.FailureProfileMismatch}, SessionRejectAuthConfigProfileV1},
		{&auth.HandshakeError{Code: auth.FailurePolicyMismatch}, SessionRejectAuthConfigPolicyV1},
		{&auth.HandshakeError{Code: auth.FailurePolicyFloorRejected}, SessionRejectAuthConfigFloorV1},
		{errors.New("other"), SessionRejectAuthConfigV1},
	} {
		if got := sessionRejectAuthConfigV1(test.err); got != test.want {
			t.Fatalf("err=%v code=%q want=%q", test.err, got, test.want)
		}
	}
}

func TestSessionRejectRegistryV1IsBoundedAndCategorical(t *testing.T) {
	for _, test := range []struct {
		err  error
		want SessionRejectCodeV1
	}{
		{ErrSessionLimit, SessionRejectCapacityV1},
		{ErrSessionConflict, SessionRejectAdmissionV1},
		{errors.New("other"), SessionRejectAdmissionV1},
	} {
		if got := sessionRejectRegistryV1(test.err); got != test.want {
			t.Fatalf("error=%v got=%q want=%q", test.err, got, test.want)
		}
	}
}

func TestAcceptLoopV1ReportsFailClosedPreAcceptReason(t *testing.T) {
	for _, test := range []struct {
		name          string
		healthReady   bool
		closeLimiter  bool
		wantRejection SessionRejectCodeV1
	}{
		{name: "health unavailable", wantRejection: SessionRejectHealthV1},
		{name: "source limiter denied", healthReady: true, closeLimiter: true, wantRejection: SessionRejectSourceLimitV1},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			limiter, err := NewSourceLimiterV1(make([]byte, 32), 4, 2, time.Minute, func() time.Time {
				return time.Unix(1_800_000_000, 0).UTC()
			})
			if err != nil {
				listener.Close()
				t.Fatal(err)
			}
			if test.closeLimiter {
				limiter.Close()
			} else {
				defer limiter.Close()
			}
			health := NewHealthMachine()
			if test.healthReady {
				health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true})
			}
			rejected := make(chan SessionRejectCodeV1, 1)
			server := &ServerV1{
				config: Config{SessionRejected: func(code SessionRejectCodeV1) { rejected <- code }},
				health: health, listener: listener, limiter: limiter, workers: make(chan struct{}, 1),
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- server.acceptLoopV1(ctx) }()

			connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
			if err != nil {
				cancel()
				listener.Close()
				t.Fatal(err)
			}
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				connection.Close()
				cancel()
				listener.Close()
				t.Fatal(err)
			}
			if count, readErr := connection.Read(make([]byte, 1)); count != 0 || readErr == nil {
				connection.Close()
				cancel()
				listener.Close()
				t.Fatalf("pre-accept rejection did not close connection: count=%d err=%v", count, readErr)
			}
			connection.Close()
			select {
			case got := <-rejected:
				if got != test.wantRejection {
					cancel()
					listener.Close()
					t.Fatalf("rejection=%q want=%q", got, test.wantRejection)
				}
			case <-time.After(time.Second):
				cancel()
				listener.Close()
				t.Fatal("pre-accept rejection was not reported")
			}
			cancel()
			listener.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("accept loop stop err=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("accept loop did not stop")
			}
		})
	}
}

func TestSessionTerminationCodeV1IsBoundedAndCategorical(t *testing.T) {
	for _, test := range []struct {
		pumpErr, contextErr error
		stopCode            SessionStopCodeV1
		want                SessionTerminationCodeV1
	}{
		{contextErr: context.DeadlineExceeded, want: SessionTerminationLifetimeV1},
		{contextErr: context.Canceled, stopCode: SessionStopQueueV1, want: SessionTerminationQueueV1},
		{contextErr: context.Canceled, stopCode: SessionStopProfileV1, want: SessionTerminationProfileV1},
		{contextErr: context.Canceled, stopCode: SessionStopAllV1, want: SessionTerminationAuthorityV1},
		{contextErr: context.Canceled, stopCode: SessionStopRegistryV1, want: SessionTerminationRegistryV1},
		{contextErr: context.Canceled, want: SessionTerminationCancelledV1},
		{want: SessionTerminationCompleteV1},
	} {
		if got := sessionTerminationCodeV1(test.pumpErr, test.contextErr, test.stopCode); got != test.want {
			t.Fatalf("context=%v stop=%q code=%q want=%q", test.contextErr, test.stopCode, got, test.want)
		}
	}
}

func TestServerReloadV1ClearsTemporaryTLSIdentity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	snapshot := &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.Now = func() time.Time { return now }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) { return snapshot, nil }
	registry, err := NewSessionRegistry(newMemoryTunnelV1(), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, value := range snapshot.lastTLSPrivate {
		if value != 0 {
			t.Fatal("reload retained a temporary TLS private-key copy")
		}
	}
	for _, value := range snapshot.lastTLSCertificate {
		if value != 0 {
			t.Fatal("reload retained a temporary TLS certificate copy")
		}
	}
}

func TestServerReloadV1FailsClosedAcrossAdministrativeAndCorruptState(t *testing.T) {
	for _, test := range []struct {
		failure error
		want    HealthState
		wantErr bool
	}{
		{failure: selfhost.ErrDrained, want: HealthDraining},
		{failure: selfhost.ErrRelayRuntimeUnavailable, want: HealthDisabled},
		{failure: selfhost.ErrStateCorrupt, want: HealthDegraded, wantErr: true},
	} {
		t.Run(test.failure.Error(), func(t *testing.T) {
			config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
			config.DNSReady = func(context.Context) bool { return true }
			config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) { return nil, test.failure }
			registry, err := NewSessionRegistry(newMemoryTunnelV1(), 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			if _, err := registry.Register(SessionSpec{ID: "session-1", ProfileID: "profile-1", ClientKeyID: "client-1", AssignedIPv4: [4]byte{10, 77, 0, 2}}); err != nil {
				t.Fatal(err)
			}
			server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
			err = server.Reload()
			if (err != nil) != test.wantErr || registry.Snapshot().ActiveSessions != 0 {
				t.Fatalf("reload err=%v registry=%+v", err, registry.Snapshot())
			}
			if got := server.health.Snapshot().State; got != test.want {
				t.Fatalf("health=%s want=%s", got, test.want)
			}
		})
	}
}

func TestServerReloadV1AppliesAdministrativeFailClosedStatesWithoutStoppingControl(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		want    HealthState
	}{
		{name: "drained", failure: selfhost.ErrDrained, want: HealthDraining},
		{name: "disabled", failure: selfhost.ErrRelayRuntimeUnavailable, want: HealthDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
			config.DNSReady = func(context.Context) bool { return true }
			config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) { return nil, test.failure }
			registry, err := NewSessionRegistry(newMemoryTunnelV1(), 1, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			if _, err := registry.Register(SessionSpec{ID: "session-1", ProfileID: "profile-1", ClientKeyID: "client-1", AssignedIPv4: [4]byte{10, 77, 0, 2}}); err != nil {
				t.Fatal(err)
			}
			server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
			if err := server.Reload(); err != nil {
				t.Fatalf("administrative transition returned error: %v", err)
			}
			if registry.Snapshot().ActiveSessions != 0 || server.health.Snapshot().State != test.want {
				t.Fatalf("registry=%+v health=%+v", registry.Snapshot(), server.health.Snapshot())
			}
		})
	}
}

func TestServerReloadV1CancelsInFlightHandshakeBeforeReplacingAuthority(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	first := &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}
	second := &fakeRelaySnapshotV1{status: validRelayStatusV1(2)}
	loads := []RelaySnapshotV1{first, second}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.Now = func() time.Time { return now }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		loaded := loads[0]
		loads = loads[1:]
		return loaded, nil
	}
	registry, err := NewSessionRegistry(newMemoryTunnelV1(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	token, ok := server.trackTransientV1("session-in-flight", "profile-in-flight", cancel)
	if !ok {
		t.Fatal("failed to track in-flight handshake")
	}
	if err := server.Reload(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("authority replacement did not cancel in-flight handshake")
	}
	server.releaseTransientV1("session-in-flight", token)
}

func TestServerStopProfileV1CancelsEstablishedAndInFlightSessions(t *testing.T) {
	registry, err := NewSessionRegistry(newMemoryTunnelV1(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if _, err := registry.Register(SessionSpec{
		ID: "session-established", ProfileID: "profile-target", ClientKeyID: "client-established",
		AssignedIPv4: [4]byte{10, 77, 0, 2},
	}); err != nil {
		t.Fatal(err)
	}
	server := &ServerV1{registry: registry}
	inFlight, cancel := context.WithCancel(context.Background())
	if _, ok := server.trackTransientV1("session-in-flight", "profile-target", cancel); !ok {
		t.Fatal("failed to track in-flight session")
	}
	if stopped := server.stopProfileV1("profile-target"); stopped != 2 {
		t.Fatalf("stopped=%d", stopped)
	}
	select {
	case <-inFlight.Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight session was not cancelled")
	}
	if registry.Snapshot().ActiveSessions != 0 {
		t.Fatal("established session was not stopped")
	}
}

func TestServerTransientReleaseCannotDeleteAReplacementSession(t *testing.T) {
	server := &ServerV1{}
	firstContext, firstCancel := context.WithCancel(context.Background())
	firstToken, ok := server.trackTransientV1("session-reused", "profile-first", firstCancel)
	if !ok {
		t.Fatal("failed to track first session")
	}
	if stopped := server.stopAllTransientsV1(); stopped != 1 {
		t.Fatalf("stopped=%d", stopped)
	}
	<-firstContext.Done()
	secondContext, secondCancel := context.WithCancel(context.Background())
	if _, ok := server.trackTransientV1("session-reused", "profile-second", secondCancel); !ok {
		t.Fatal("failed to track replacement session")
	}
	server.releaseTransientV1("session-reused", firstToken)
	if stopped := server.stopAllTransientsV1(); stopped != 1 {
		t.Fatalf("replacement removed by stale release: stopped=%d", stopped)
	}
	select {
	case <-secondContext.Done():
	case <-time.After(time.Second):
		t.Fatal("replacement session was not cancelled")
	}
}

func TestServerRunV1InitialStateFailureClosesOwnedResources(t *testing.T) {
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return nil, selfhost.ErrStateCorrupt
	}
	relayListener := newCloseTrackingListenerV1()
	controlListener := newCloseTrackingListenerV1()
	tunnel := newMemoryTunnelV1()
	server, err := NewServerV1(config, relayListener, tunnel, controlListener, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Run(context.Background()); !errors.Is(err, ErrServerState) {
		t.Fatalf("run err=%v", err)
	}
	if !relayListener.isClosed() || !controlListener.isClosed() {
		t.Fatal("initial state failure leaked a listener")
	}
	select {
	case <-tunnel.closed:
	default:
		t.Fatal("initial state failure leaked the TUN")
	}
	if err := server.Run(context.Background()); !errors.Is(err, ErrServerConfig) {
		t.Fatalf("consumed server ran twice: %v", err)
	}
}

func TestServerRunV1ClassifiesRegistryFailure(t *testing.T) {
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		relayListener.Close()
		t.Fatal(err)
	}
	tunnel := newMemoryTunnelV1()
	if err := tunnel.Close(); err != nil {
		relayListener.Close()
		controlListener.Close()
		t.Fatal(err)
	}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), uint16(relayListener.Addr().(*net.TCPAddr).Port))
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	server, err := NewServerV1(config, relayListener, tunnel, controlListener, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Run(context.Background()); !errors.Is(err, ErrServerRegistry) {
		t.Fatalf("run err=%v", err)
	}
}

func TestServerRunV1RejectsMalformedPrefaceAndStopsCleanly(t *testing.T) {
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		relayListener.Close()
		t.Fatal(err)
	}
	port := uint16(relayListener.Addr().(*net.TCPAddr).Port)
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), port)
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	var stagesMu sync.Mutex
	var stages []SessionStageCodeV1
	config.SessionProgress = func(stage SessionStageCodeV1) {
		stagesMu.Lock()
		defer stagesMu.Unlock()
		stages = append(stages, stage)
	}
	server, err := NewServerV1(config, relayListener, newMemoryTunnelV1(), controlListener, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for !server.health.Snapshot().AcceptingSessions && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.health.Snapshot().AcceptingSessions {
		cancel()
		t.Fatal("server did not become ready")
	}
	connection, err := net.DialTimeout("tcp", relayListener.Addr().String(), time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte{0, 0, 0, 1, 0xff}); err != nil {
		connection.Close()
		cancel()
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		connection.Close()
		cancel()
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if count, err := connection.Read(buffer); count != 0 || err == nil {
		connection.Close()
		cancel()
		t.Fatalf("malformed preface was not rejected: count=%d err=%v", count, err)
	}
	connection.Close()
	stagesMu.Lock()
	if len(stages) != 1 || stages[0] != SessionStageAcceptedV1 {
		stagesMu.Unlock()
		cancel()
		t.Fatalf("stages=%v", stages)
	}
	stagesMu.Unlock()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run err=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerRunV1CancellationClosesConnectionBlockedBeforePreface(t *testing.T) {
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		relayListener.Close()
		t.Fatal(err)
	}
	port := uint16(relayListener.Addr().(*net.TCPAddr).Port)
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), port)
	config.HandshakeTimeout = 30 * time.Second
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	accepted := make(chan struct{}, 1)
	config.SessionProgress = func(stage SessionStageCodeV1) {
		if stage == SessionStageAcceptedV1 {
			select {
			case accepted <- struct{}{}:
			default:
			}
		}
	}
	server, err := NewServerV1(config, relayListener, newMemoryTunnelV1(), controlListener, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for !server.health.Snapshot().AcceptingSessions && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.health.Snapshot().AcceptingSessions {
		cancel()
		t.Fatal("server did not become ready")
	}
	connection, err := net.DialTimeout("tcp", relayListener.Addr().String(), time.Second)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer connection.Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("server did not accept blocked preface connection")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run err=%v", err)
		}
	case <-time.After(500 * time.Millisecond):
		connection.Close()
		<-done
		t.Fatal("server cancellation waited for the handshake deadline")
	}
}

func TestDestroyTLSConfigV1ClearsSessionOwnedIdentity(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificate := []byte{1, 2, 3}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: private}}}
	destroyTLSConfigV1(config)
	if len(config.Certificates) != 0 {
		t.Fatal("TLS certificate remained reachable")
	}
	for _, value := range private {
		if value != 0 {
			t.Fatal("TLS private-key copy was not cleared")
		}
	}
	for _, value := range certificate {
		if value != 0 {
			t.Fatal("TLS certificate copy was not cleared")
		}
	}
}

type fakeRelaySnapshotV1 struct {
	status             selfhost.RelayRuntimeStatusV1
	closed             bool
	lastTLSPrivate     ed25519.PrivateKey
	lastTLSCertificate []byte
}

func (snapshot *fakeRelaySnapshotV1) StatusV1() (selfhost.RelayRuntimeStatusV1, bool) {
	return snapshot.status, !snapshot.closed
}
func (*fakeRelaySnapshotV1) AdmissionByProfileV1(string, uint64) (selfhost.RelayAdmissionV1, bool) {
	return selfhost.RelayAdmissionV1{}, false
}
func (*fakeRelaySnapshotV1) Local(string) (ed25519.PrivateKey, error) {
	return nil, errors.New("not configured")
}
func (*fakeRelaySnapshotV1) Peer(string) (ed25519.PublicKey, error) {
	return nil, errors.New("not configured")
}
func (snapshot *fakeRelaySnapshotV1) ServerTLSConfigV1() (*tls.Config, error) {
	if snapshot.closed {
		return nil, errors.New("closed")
	}
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	certificate := []byte{1}
	snapshot.lastTLSPrivate = private
	snapshot.lastTLSCertificate = certificate
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"kurd/1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: private}},
	}, nil
}
func (snapshot *fakeRelaySnapshotV1) Close() { snapshot.closed = true }

func validRelayStatusV1(revision uint64) selfhost.RelayRuntimeStatusV1 {
	return selfhost.RelayRuntimeStatusV1{
		Revision: revision, Generation: revision, RelayEpoch: revision, TLSEpoch: 1,
		RelayKeyID: "relay.1111111111111111", TLSKeyID: "tls.1111111111111111", RelayPublic: [32]byte{byte(revision)},
	}
}

type closeTrackingListenerV1 struct {
	mu     sync.Mutex
	closed bool
}

func newCloseTrackingListenerV1() *closeTrackingListenerV1 { return &closeTrackingListenerV1{} }

func (listener *closeTrackingListenerV1) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (listener *closeTrackingListenerV1) Close() error {
	listener.mu.Lock()
	listener.closed = true
	listener.mu.Unlock()
	return nil
}

func (*closeTrackingListenerV1) Addr() net.Addr { return &net.TCPAddr{} }

func (listener *closeTrackingListenerV1) isClosed() bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	return listener.closed
}

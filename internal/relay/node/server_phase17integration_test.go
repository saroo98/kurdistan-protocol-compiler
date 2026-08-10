// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build linux && phase17integration

package node

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

// TestPhase17IntegrationRelayFailsClosedAcrossReloadStates keeps the namespace
// proof bound to the production relay authority transitions. A live packet
// pump may not outlive drain, disable, corruption, or authority replacement.
func TestPhase17IntegrationRelayFailsClosedAcrossReloadStates(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure error
		state   HealthState
		wantErr bool
	}{
		{name: "drain", failure: selfhost.ErrDrained, state: HealthDraining},
		{name: "disable", failure: selfhost.ErrRelayRuntimeUnavailable, state: HealthDisabled},
		{name: "corrupt", failure: selfhost.ErrStateCorrupt, state: HealthDegraded, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig(filepath.Join(t.TempDir(), "node"), 443)
			config.DNSReady = func(context.Context) bool { return true }
			loads := 0
			config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
				loads++
				if loads == 1 {
					return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
				}
				return nil, test.failure
			}
			registry, err := NewSessionRegistry(newMemoryTunnelV1(), 2, 2)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			server := &ServerV1{config: config, health: NewHealthMachine(), registry: registry, listenerReady: true, tunnelReady: true}
			if err := server.Reload(); err != nil {
				t.Fatal(err)
			}
			cancelled, cancel := context.WithCancel(context.Background())
			if _, ok := server.trackTransientV1("phase17-inflight", "phase17-profile", cancel); !ok {
				t.Fatal("track in-flight session")
			}
			if _, err := registry.Register(SessionSpec{ID: "phase17-established", ProfileID: "phase17-profile", ClientKeyID: "client-1", AssignedIPv4: [4]byte{10, 77, 0, 2}, DNSIPv4: [4]byte{10, 77, 0, 1}}); err != nil {
				t.Fatal(err)
			}
			err = server.Reload()
			if (err != nil) != test.wantErr {
				t.Fatalf("reload err=%v wantErr=%v", err, test.wantErr)
			}
			select {
			case <-cancelled.Done():
			case <-time.After(time.Second):
				t.Fatal("reload did not terminate in-flight session")
			}
			if registry.Snapshot().ActiveSessions != 0 || server.health.Snapshot().State != test.state {
				t.Fatalf("registry=%+v health=%+v", registry.Snapshot(), server.health.Snapshot())
			}
		})
	}
}

// TestPhase17IntegrationMalformedAdmissionFloodRemainsBounded proves the
// production accept loop rejects unauthenticated work without creating a live
// relay session or leaking a running server.
func TestPhase17IntegrationMalformedAdmissionFloodRemainsBounded(t *testing.T) {
	relayListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		relayListener.Close()
		t.Fatal(err)
	}
	config := DefaultConfig(filepath.Join(t.TempDir(), "node"), uint16(relayListener.Addr().(*net.TCPAddr).Port))
	config.MaxHandshakeWorkers = 2
	config.MaxSourceAttempts = 4
	config.DNSReady = func(context.Context) bool { return true }
	config.LoadSnapshot = func(string, time.Time) (RelaySnapshotV1, error) {
		return &fakeRelaySnapshotV1{status: validRelayStatusV1(1)}, nil
	}
	server, err := NewServerV1(config, relayListener, newMemoryTunnelV1(), controlListener, func(net.Conn) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for !server.health.Snapshot().AcceptingSessions && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for index := 0; index < 32; index++ {
		connection, dialErr := net.DialTimeout("tcp", relayListener.Addr().String(), 100*time.Millisecond)
		if dialErr == nil {
			_, _ = connection.Write([]byte{0xff, 0x00, byte(index)})
			_ = connection.Close()
		}
	}
	time.Sleep(100 * time.Millisecond)
	if server.registry.Snapshot().ActiveSessions != 0 {
		cancel()
		t.Fatal("unauthenticated flood created a relay session")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after malformed admission flood")
	}
}

// TestPhase17IntegrationMultiClientIsolationAndSourcePolicy binds the live
// namespace proof to the shared relay registry's two-client isolation rules.
// A session may emit only its assigned source, return packets route only to the
// exact assigned destination, and private/reserved destinations remain denied.
func TestPhase17IntegrationMultiClientIsolationAndSourcePolicy(t *testing.T) {
	tunnel := newMemoryTunnelV1()
	registry, err := NewSessionRegistry(tunnel, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	firstAddress := [4]byte{10, 89, 0, 2}
	secondAddress := [4]byte{10, 89, 0, 3}
	first, err := registry.Register(SessionSpec{ID: "phase17-one", ProfileID: "phase17-profile-one", ClientKeyID: "phase17-client-one", AssignedIPv4: firstAddress, DNSIPv4: [4]byte{10, 77, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := registry.Register(SessionSpec{ID: "phase17-two", ProfileID: "phase17-profile-two", ClientKeyID: "phase17-client-two", AssignedIPv4: secondAddress, DNSIPv4: [4]byte{10, 77, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}

	publicDestination := [4]byte{1, 1, 1, 1}
	if count, err := first.Write(testIPv4PacketV1(secondAddress, publicDestination, 17, []byte{1})); count != 0 || !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("cross-client source accepted: count=%d err=%v", count, err)
	}
	if count, err := first.Write(testIPv4PacketV1(firstAddress, [4]byte{10, 0, 0, 1}, 17, []byte{2})); count != 0 || !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("private destination accepted: count=%d err=%v", count, err)
	}

	firstReturn := testIPv4PacketV1(publicDestination, firstAddress, 17, []byte{3})
	secondReturn := testIPv4PacketV1(publicDestination, secondAddress, 17, []byte{4})
	if err := registry.RouteReturnPacket(firstReturn); err != nil {
		t.Fatal(err)
	}
	if err := registry.RouteReturnPacket(secondReturn); err != nil {
		t.Fatal(err)
	}
	if got := readPacketV1(t, first); string(got) != string(firstReturn) {
		t.Fatal("first return packet crossed session authority")
	}
	if got := readPacketV1(t, second); string(got) != string(secondReturn) {
		t.Fatal("second return packet crossed session authority")
	}
	unknown := testIPv4PacketV1(publicDestination, [4]byte{10, 89, 0, 9}, 17, []byte{5})
	if err := registry.RouteReturnPacket(unknown); !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("unknown return destination err=%v", err)
	}
	if snapshot := registry.Snapshot(); snapshot.ActiveSessions != 2 || snapshot.UnknownDestinations != 1 {
		t.Fatalf("unexpected registry snapshot: %+v", snapshot)
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestControlProtocolV1IsBoundedCanonicalAndRejectsMalformedInput(t *testing.T) {
	request, err := EncodeControlRequestV1(ControlRequestV1{Command: ControlStopProfileV1, ProfileID: "profile-7"})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeControlRequestV1(request)
	if err != nil || decoded.Command != ControlStopProfileV1 || decoded.ProfileID != "profile-7" {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	for _, mutation := range [][]byte{
		nil,
		request[:len(request)-1],
		append(append([]byte(nil), request...), 0),
		append([]byte("NOT-CTL1"), request[8:]...),
		append(request[:8], 0xff, 0),
	} {
		if _, err := DecodeControlRequestV1(mutation); !errors.Is(err, ErrControlProtocol) {
			t.Fatalf("mutation accepted: %x err=%v", mutation, err)
		}
	}
	if _, err := EncodeControlRequestV1(ControlRequestV1{Command: ControlStatusV1, ProfileID: "unexpected"}); !errors.Is(err, ErrControlProtocol) {
		t.Fatalf("status profile accepted: %v", err)
	}
	if _, err := EncodeControlRequestV1(ControlRequestV1{Command: ControlStopProfileV1, ProfileID: string(bytes.Repeat([]byte{'p'}, 129))}); !errors.Is(err, ErrControlProtocol) {
		t.Fatalf("oversized profile accepted: %v", err)
	}
}

func TestControlActionsV1MutateOnlyAuthorizedLocalState(t *testing.T) {
	tunnel := &controlMemoryTUN{}
	registry, err := NewSessionRegistry(tunnel, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	device, err := registry.Register(SessionSpec{ID: "session-1", ProfileID: "profile-1", ClientKeyID: "client-1", AssignedIPv4: [4]byte{10, 77, 0, 2}})
	if err != nil {
		t.Fatal(err)
	}
	defer device.Close()

	health := NewHealthMachine()
	health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true})
	reloads := 0
	actions := ControlActionsV1{Health: health, Registry: registry, Reload: func() error {
		reloads++
		health.SetDrain(false)
		return nil
	}}

	for _, test := range []struct {
		request ControlRequestV1
		state   HealthState
		stopped uint16
	}{
		{request: ControlRequestV1{Command: ControlStatusV1}, state: HealthReady},
		{request: ControlRequestV1{Command: ControlDrainV1}, state: HealthDraining},
		{request: ControlRequestV1{Command: ControlResumeV1}, state: HealthReady},
		{request: ControlRequestV1{Command: ControlReloadV1}, state: HealthReady},
		{request: ControlRequestV1{Command: ControlStopProfileV1, ProfileID: "profile-1"}, state: HealthReady, stopped: 1},
	} {
		response, err := actions.Execute(test.request)
		if err != nil {
			t.Fatalf("request=%+v err=%v", test.request, err)
		}
		if !response.OK || response.Health.State != test.state || response.Stopped != test.stopped {
			t.Fatalf("request=%+v response=%+v", test.request, response)
		}
		wire, err := EncodeControlResponseV1(response)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeControlResponseV1(wire)
		if err != nil || decoded != response {
			t.Fatalf("response round trip decoded=%+v want=%+v err=%v", decoded, response, err)
		}
	}
	if reloads != 2 || registry.Snapshot().ActiveSessions != 0 {
		t.Fatalf("reloads=%d registry=%+v", reloads, registry.Snapshot())
	}
}

func TestControlResumeV1FailsClosedUntilReloadRestoresHealthyState(t *testing.T) {
	health := NewHealthMachine()
	health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true})
	health.SetDrain(true)
	actions := ControlActionsV1{
		Health: health,
		Reload: func() error { return errors.New("state remains unavailable") },
	}
	response, err := actions.Execute(ControlRequestV1{Command: ControlResumeV1})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Code != ControlCodeReloadFailedV1 || response.Health.State != HealthDraining || response.Health.AcceptingSessions {
		t.Fatalf("resume response=%+v", response)
	}
}

func TestExchangeControlV1RoundTripsOneBoundedRequest(t *testing.T) {
	client, server := net.Pipe()
	health := NewHealthMachine()
	health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true})
	go handleControlConnectionV1(server, func(net.Conn) error { return nil }, ControlActionsV1{Health: health}, time.Second)

	response, err := ExchangeControlV1(context.Background(), client, ControlRequestV1{Command: ControlStatusV1}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.Code != ControlCodeOKV1 || response.Health.State != HealthReady || !response.Health.AcceptingSessions {
		t.Fatalf("response=%+v", response)
	}
}

func TestExchangeControlV1RejectsTruncatedResponse(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		request := make([]byte, 10)
		_, _ = io.ReadFull(server, request)
		_, _ = server.Write([]byte("truncated"))
	}()
	if _, err := ExchangeControlV1(context.Background(), client, ControlRequestV1{Command: ControlStatusV1}, time.Second); !errors.Is(err, ErrControlProtocol) {
		t.Fatalf("truncated response err=%v", err)
	}
}

func TestControlReloadFailureIsCategoricalAndSecretFree(t *testing.T) {
	secret := "secret-canary.example"
	actions := ControlActionsV1{
		Health: NewHealthMachine(),
		Reload: func() error { return errors.New(secret) },
	}
	response, err := actions.Execute(ControlRequestV1{Command: ControlReloadV1})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Code != ControlCodeReloadFailedV1 {
		t.Fatalf("response=%+v", response)
	}
	wire, err := EncodeControlResponseV1(response)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(secret)) {
		t.Fatal("control response leaked underlying error")
	}
}

func TestControlPeerAuthorizationV1AllowsOnlyRootOrProcessOwner(t *testing.T) {
	for _, test := range []struct {
		owner, peer uint32
		ok          bool
	}{
		{owner: 1001, peer: 0, ok: true},
		{owner: 1001, peer: 1001, ok: true},
		{owner: 1001, peer: 1002},
	} {
		err := validateControlPeerUIDV1(test.owner, test.peer)
		if test.ok && err != nil {
			t.Fatalf("owner=%d peer=%d err=%v", test.owner, test.peer, err)
		}
		if !test.ok && !errors.Is(err, ErrControlUnauthorized) {
			t.Fatalf("owner=%d peer=%d err=%v", test.owner, test.peer, err)
		}
	}
}

func TestControlSocketPathV1IsAbsoluteBoundedAndExact(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
	valid := filepath.Join(root, "run", "control.sock")
	if err := validateControlSocketPathV1(valid); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"control.sock",
		filepath.Join(root, "run", "admin.sock"),
		filepath.Join(root, strings.Repeat("x", 110), "control.sock"),
	} {
		if err := validateControlSocketPathV1(path); !errors.Is(err, ErrControlConfig) {
			t.Fatalf("path=%q err=%v", path, err)
		}
	}
}

func TestControlServerV1BoundsConnectionsAndStopsWithContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	health := NewHealthMachine()
	health.Update(HealthRequirements{Listener: true, Tunnel: true, VerifiedState: true, TLSIdentity: true, RelayIdentity: true, DNS: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- ServeControlV1(ctx, listener, func(net.Conn) error { return nil }, ControlActionsV1{Health: health}, time.Second, 2)
	}()

	request, err := EncodeControlRequestV1(ControlRequestV1{Command: ControlDrainV1})
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(request); err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, controlResponseSizeV1)
	if _, err := io.ReadFull(connection, wire); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	response, err := DecodeControlResponseV1(wire)
	if err != nil || response.Health.State != HealthDraining {
		t.Fatalf("response=%+v err=%v", response, err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve stopped with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("control server did not stop")
	}
}

type controlMemoryTUN struct{ bytes.Buffer }

func (*controlMemoryTUN) Read([]byte) (int, error) { return 0, io.EOF }
func (*controlMemoryTUN) Close() error             { return nil }

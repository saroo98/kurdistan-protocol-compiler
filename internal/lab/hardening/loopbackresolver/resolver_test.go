// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package loopbackresolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"kurdistan/internal/product/livecarrier"
	"kurdistan/internal/product/sessionplan"
)

func testPlan() sessionplan.Plan {
	return sessionplan.Plan{
		Version: sessionplan.Version, StrategyFamily: "https_like_tcp",
		CarrierFamily: livecarrier.FamilyKurdTLS13TCP, LoopbackOnly: true,
		EndpointReference: "relayref:test-node", DialTimeoutMs: 500, MaxFrameBytes: 64 << 10,
		Digest: [32]byte{1},
	}
}

func TestRegistryRejectsNonLoopbackAndAmbiguousEndpoints(t *testing.T) {
	invalid := []Entry{
		{},
		{Reference: "relayref:test", Address: "localhost:443", ServerName: "test"},
		{Reference: "relayref:test", Address: "192.168.1.1:443", ServerName: "test"},
		{Reference: "relayref:test", Address: "0.0.0.0:443", ServerName: "test"},
		{Reference: "relayref:test", Address: "127.0.0.1:0", ServerName: "test"},
		{Reference: "https://test", Address: "127.0.0.1:443", ServerName: "test"},
		{Reference: "relayref:test", Address: "127.0.0.1:443", ServerName: ""},
	}
	for index, entry := range invalid {
		if registry, err := New([]Entry{entry}); !errors.Is(err, ErrResolution) || registry != nil {
			t.Fatalf("case=%d registry=%v err=%v", index, registry, err)
		}
	}
	entry := Entry{Reference: "relayref:test", Address: "127.0.0.1:443", ServerName: "test"}
	if registry, err := New([]Entry{entry, entry}); !errors.Is(err, ErrResolution) || registry != nil {
		t.Fatalf("duplicate registry=%v err=%v", registry, err)
	}
}

func TestResolveRequiresExactImmutablePlan(t *testing.T) {
	entry := Entry{Reference: "relayref:test-node", Address: "127.0.0.1:443", ServerName: "phase11.test"}
	registry, err := New([]Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	plan := testPlan()
	if got, err := registry.Resolve(plan); err != nil || got != entry {
		t.Fatalf("entry=%+v err=%v", got, err)
	}
	for _, mutate := range []func(*sessionplan.Plan){
		func(value *sessionplan.Plan) { value.Version = "future" },
		func(value *sessionplan.Plan) { value.Digest = [32]byte{} },
		func(value *sessionplan.Plan) { value.LoopbackOnly = false },
		func(value *sessionplan.Plan) { value.CarrierFamily = "other" },
		func(value *sessionplan.Plan) { value.EndpointReference = "relayref:other" },
	} {
		candidate := plan
		mutate(&candidate)
		if got, err := registry.Resolve(candidate); !errors.Is(err, ErrResolution) || got != (Entry{}) {
			t.Fatalf("candidate=%+v entry=%+v err=%v", candidate, got, err)
		}
	}
}

func TestDialContextUsesExactLoopbackRegistryEntry(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	registry, err := New([]Entry{{
		Reference: "relayref:test-node", Address: listener.Addr().String(), ServerName: "phase11.test",
	}})
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		accepted <- connection
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	connection, serverName, err := registry.DialContext(ctx, testPlan())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	peer := <-accepted
	defer peer.Close()
	if serverName != "phase11.test" || connection.RemoteAddr().String() != listener.Addr().String() {
		t.Fatalf("server=%q remote=%q", serverName, connection.RemoteAddr())
	}
	if connection, name, err := registry.DialContext(context.Background(), testPlan()); !errors.Is(err, ErrResolution) || connection != nil || name != "" {
		t.Fatalf("unbounded connection=%v name=%q err=%v", connection, name, err)
	}
}

//go:build phase17campaign

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"errors"
	gort "runtime"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
)

func TestPhase17TenThousandConnectAuthPacketCloseCyclesRemainBounded(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	config, err := auth.NewProcessHandshakeConfigV1(fixture.input.Client, fixture.input.Server, fixture.input.SelectedPolicy, fixture.input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	program := testDuplexProgramV1()
	var digest [32]byte
	copy(digest[:], []byte("phase17-endurance-plan-v1"))
	exporter := [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}

	gort.GC()
	startGoroutines := gort.NumGoroutine()
	var startMemory gort.MemStats
	gort.ReadMemStats(&startMemory)

	for cycle := 0; cycle < 10_000; cycle++ {
		replay, replayErr := auth.NewHandshakeReplayCache(64)
		if replayErr != nil {
			t.Fatalf("cycle %d replay cache: %v", cycle, replayErr)
		}
		clientHandshake, clientErr := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
		if clientErr != nil {
			t.Fatalf("cycle %d client handshake: %v", cycle, clientErr)
		}
		relayHandshake, relayErr := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
		if relayErr != nil {
			clientHandshake.Close()
			t.Fatalf("cycle %d relay handshake: %v", cycle, relayErr)
		}

		clientHello, startErr := clientHandshake.Start()
		serverHello, acceptClientErr := relayHandshake.AcceptClientHello(clientHello)
		clientFinish, acceptServerErr := clientHandshake.AcceptServerHello(serverHello)
		serverFinish, relayResult, finishRelayErr := relayHandshake.AcceptClientFinish(clientFinish)
		clientResult, finishClientErr := clientHandshake.AcceptServerFinish(serverFinish)
		clientHandshake.Close()
		relayHandshake.Close()
		if startErr != nil || acceptClientErr != nil || acceptServerErr != nil || finishRelayErr != nil || finishClientErr != nil {
			t.Fatalf("cycle %d handshake: start=%v client=%v server=%v relay-finish=%v client-finish=%v", cycle, startErr, acceptClientErr, acceptServerErr, finishRelayErr, finishClientErr)
		}

		client, clientEndpointErr := NewProcessClientDuplexEndpointV1(clientResult, digest, program)
		relay, relayEndpointErr := NewProcessRelayDuplexEndpointV1(relayResult, digest, program)
		if clientEndpointErr != nil || relayEndpointErr != nil {
			if client != nil {
				client.Abort()
			}
			if relay != nil {
				relay.Abort()
			}
			t.Fatalf("cycle %d endpoints: client=%v relay=%v", cycle, clientEndpointErr, relayEndpointErr)
		}
		bind, bindErr := client.ProfileBind(exporter)
		ready, readyErr := relay.AcceptProfileBind(bind, exporter)
		acceptReadyErr := client.AcceptEngineReady(ready)
		if bindErr != nil || readyErr != nil || acceptReadyErr != nil {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d bind: client=%v relay=%v ready=%v", cycle, bindErr, readyErr, acceptReadyErr)
		}

		records, sealErr := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 1, Sequence: 1, Payload: []byte{0x17}}, int64(cycle+1))
		if sealErr != nil || len(records) != 1 {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d seal: records=%d err=%v", cycle, len(records), sealErr)
		}
		pending, openErr := relay.OpenFrame(records[0])
		if openErr != nil || pending == nil || len(pending.Operation().Payload) != 1 || pending.Operation().Payload[0] != 0x17 {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d packet: pending=%v err=%v", cycle, pending != nil, openErr)
		}
		if commitErr := pending.Commit(); commitErr != nil {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d commit: %v", cycle, commitErr)
		}
		closeRecord, closeErr := client.SealClose(CloseCodeTerminalV1)
		if closeErr != nil {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d close seal: %v", cycle, closeErr)
		}
		if _, remoteCloseErr := relay.OpenFrame(closeRecord); !errors.Is(remoteCloseErr, ErrLinkClosed) {
			client.Abort()
			relay.Abort()
			t.Fatalf("cycle %d close open: %v", cycle, remoteCloseErr)
		}
		client.Abort()
		relay.Abort()
	}

	gort.GC()
	var finalMemory gort.MemStats
	gort.ReadMemStats(&finalMemory)
	if finalGoroutines := gort.NumGoroutine(); finalGoroutines > startGoroutines+2 {
		t.Fatalf("goroutine growth start=%d final=%d", startGoroutines, finalGoroutines)
	}
	const maximumRetainedHeapGrowth = 32 << 20
	if finalMemory.Alloc > startMemory.Alloc+maximumRetainedHeapGrowth {
		t.Fatalf("retained heap growth start=%d final=%d limit=%d", startMemory.Alloc, finalMemory.Alloc, maximumRetainedHeapGrowth)
	}
}

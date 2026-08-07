// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/wirev1"
)

func TestProcessDuplexRecordV1RoundTripAndDeferredReplayCommit(t *testing.T) {
	client, relay, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, client, relay, exporter)

	op := framing.Operation{Semantic: "data", StreamID: 7, Sequence: 11, Payload: bytes.Repeat([]byte{0x42}, 1536)}
	records, err := client.SealOperation(op, 19)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("records=%d, want one atomic authenticated operation", len(records))
	}
	pending, err := relay.OpenFrame(records[0])
	if err != nil {
		t.Fatal(err)
	}
	got := pending.Operation()
	if got.StreamID != op.StreamID || got.Sequence != op.Sequence || !bytes.Equal(got.Payload, op.Payload) {
		t.Fatalf("operation mismatch: %#v", got)
	}
	got.Payload[0] ^= 0xff
	if pending.Operation().Payload[0] != op.Payload[0] {
		t.Fatal("Operation returned retained payload")
	}
	if pending.StreamID() != op.StreamID || pending.Sequence() == 0 {
		t.Fatalf("binding stream=%d sequence=%d", pending.StreamID(), pending.Sequence())
	}
	if err := pending.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := pending.Commit(); !errors.Is(err, ErrAuthenticatedFrameState) {
		t.Fatalf("second commit=%v", err)
	}
	if _, err := relay.OpenFrame(records[0]); !errors.Is(err, security.ErrReplayDuplicate) {
		t.Fatalf("replay=%v", err)
	}
}

func TestProcessDuplexRecordV1DiscardPoisonsSession(t *testing.T) {
	client, relay, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, client, relay, exporter)
	records, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 1, Payload: []byte("discard")}, 1)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := relay.OpenFrame(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := relay.OpenFrame(records[0]); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("discarded endpoint remained usable: %v", err)
	}
	if pending.Operation().Payload != nil {
		t.Fatal("terminal frame still exposed operation")
	}
}

func TestProcessDuplexRecordV1BidirectionalKeepaliveAndClose(t *testing.T) {
	client, relay, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, client, relay, exporter)
	keepalive, err := relay.SealKeepalive(1)
	if err != nil {
		t.Fatal(err)
	}
	if frame, err := client.OpenFrame(keepalive); err != nil || frame != nil {
		t.Fatalf("keepalive frame=%v err=%v", frame, err)
	}
	records, err := relay.SealOperation(framing.Operation{Semantic: "data", StreamID: 8, Sequence: 2, Payload: []byte("return")}, 2)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := client.OpenFrame(records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := pending.Commit(); err != nil {
		t.Fatal(err)
	}
	closeRecord, err := relay.SealClose(CloseCodeTerminalV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenFrame(closeRecord); !errors.Is(err, ErrLinkClosed) {
		t.Fatalf("close=%v", err)
	}
}

func TestProcessDuplexRecordV1ZeroValueFailsClosed(t *testing.T) {
	var client ProcessClientDuplexEndpointV1
	var relay ProcessRelayDuplexEndpointV1
	operation := framing.Operation{Semantic: "data", StreamID: 1, Sequence: 1, Payload: []byte("x")}

	if _, err := client.ProfileBind([32]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client ProfileBind error=%v", err)
	}
	if err := client.AcceptEngineReady([]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client AcceptEngineReady error=%v", err)
	}
	if _, err := relay.AcceptProfileBind([]byte{1}, [32]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay AcceptProfileBind error=%v", err)
	}
	if _, err := client.SealOperation(operation, 1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client SealOperation error=%v", err)
	}
	if _, err := relay.SealOperation(operation, 1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay SealOperation error=%v", err)
	}
	if _, err := client.OpenFrame([]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client OpenFrame error=%v", err)
	}
	if _, err := relay.OpenFrame([]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay OpenFrame error=%v", err)
	}
	if _, err := client.SealKeepalive(1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client SealKeepalive error=%v", err)
	}
	if _, err := relay.SealKeepalive(1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay SealKeepalive error=%v", err)
	}
	if _, err := client.SealClose(CloseCodeTerminalV1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client SealClose error=%v", err)
	}
	if _, err := relay.SealClose(CloseCodeTerminalV1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay SealClose error=%v", err)
	}
	client.Abort()
	relay.Abort()
}

func TestProcessDuplexRecordV1RoundTripsAllAdmittedFramingModes(t *testing.T) {
	fragmentationModes := []string{"no_fragmentation_for_small_payloads", "fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks"}
	schedulerModes := []string{"max_speed", "balanced", "interactive_first", "bulk_first"}
	for _, fragmentationMode := range fragmentationModes {
		for _, schedulerMode := range schedulerModes {
			t.Run(fragmentationMode+"/"+schedulerMode, func(t *testing.T) {
				program := testDuplexProgramV1()
				program.Frame.FragmentationMode = fragmentationMode
				program.Scheduler.Mode = schedulerMode
				program.Scheduler.MaxBatchBytes = 256
				program.Limits.MaxFrameBytes = 1024
				client, relay, exporter := newProcessDuplexPairWithProgramV1(t, program)
				bindProcessDuplexPairV1(t, client, relay, exporter)
				operation := framing.Operation{Semantic: "data", StreamID: 11, Sequence: 19, Payload: bytes.Repeat([]byte{0x5a}, 1536)}
				records, err := client.SealOperation(operation, 37)
				if err != nil {
					t.Fatal(err)
				}
				if len(records) != 1 {
					t.Fatalf("records=%d", len(records))
				}
				pending, err := relay.OpenFrame(records[0])
				if err != nil {
					t.Fatal(err)
				}
				if got := pending.Operation(); got.StreamID != operation.StreamID || got.Sequence != operation.Sequence || !bytes.Equal(got.Payload, operation.Payload) {
					t.Fatal("round trip changed the operation")
				}
				if err := pending.Commit(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestProcessDuplexRecordV1RejectsOrderingAndInnerOuterBindingViolations(t *testing.T) {
	t.Run("reordered outer sequence", func(t *testing.T) {
		client, relay, exporter := newProcessDuplexPairV1(t)
		bindProcessDuplexPairV1(t, client, relay, exporter)
		first, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 1, Payload: []byte("first")}, 1)
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 3, Sequence: 2, Payload: []byte("second")}, 2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := relay.OpenFrame(second[0]); !errors.Is(err, security.ErrReplayOutOfOrder) {
			t.Fatalf("reordered record error=%v", err)
		}
		if _, err := relay.OpenFrame(first[0]); !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("endpoint survived ordered replay violation: %v", err)
		}
	})

	for _, test := range []struct {
		name        string
		outerStream uint32
		slot        uint16
		innerStream uint32
	}{
		{name: "wrong envelope slot", outerStream: 2, slot: 3, innerStream: 2},
		{name: "inner outer stream mismatch", outerStream: 2, slot: 2, innerStream: 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, relay, exporter := newProcessDuplexPairV1(t)
			bindProcessDuplexPairV1(t, client, relay, exporter)
			frames, err := framing.EncodeLiveOperation(testDuplexProgramV1(), framing.Operation{Semantic: "data", StreamID: test.innerStream, Sequence: 1, Payload: []byte("binding")}, 1)
			if err != nil {
				t.Fatal(err)
			}
			body, err := encodeDuplexOperationBodyV1(frames)
			clearFrameSetV1(frames)
			if err != nil {
				t.Fatal(err)
			}
			record := sealDuplexTestBodyV1(t, client.state, wirev1.TypeReliableData, test.outerStream, test.slot, body)
			clear(body)
			if _, err := relay.OpenFrame(record); !errors.Is(err, ErrRecordInvalid) {
				t.Fatalf("binding violation error=%v", err)
			}
		})
	}
}

func TestProcessDuplexRecordV1RejectsIncompleteDuplicateAndMixedOperations(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func([][]byte, [][]byte) [][]byte
	}{
		{name: "missing fragment", mutate: func(first, _ [][]byte) [][]byte { return first[:len(first)-1] }},
		{name: "duplicate fragment", mutate: func(first, _ [][]byte) [][]byte { return [][]byte{first[0], first[0]} }},
		{name: "mixed operation", mutate: func(first, second [][]byte) [][]byte { return [][]byte{first[0], second[1]} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			program := testDuplexProgramV1()
			program.Frame.FragmentationMode = "fixed_size_chunks"
			program.Scheduler.MaxBatchBytes = 64
			program.Limits.MaxFrameBytes = 1024
			client, relay, exporter := newProcessDuplexPairWithProgramV1(t, program)
			bindProcessDuplexPairV1(t, client, relay, exporter)
			first, err := framing.EncodeLiveOperation(program, framing.Operation{Semantic: "data", StreamID: 9, Sequence: 1, Payload: bytes.Repeat([]byte{1}, 220)}, 1)
			if err != nil || len(first) < 2 {
				t.Fatalf("first fragments=%d err=%v", len(first), err)
			}
			second, err := framing.EncodeLiveOperation(program, framing.Operation{Semantic: "data", StreamID: 9, Sequence: 2, Payload: bytes.Repeat([]byte{2}, 220)}, 2)
			if err != nil || len(second) < 2 {
				t.Fatalf("second fragments=%d err=%v", len(second), err)
			}
			mutated := test.mutate(first, second)
			body, err := encodeDuplexOperationBodyV1(mutated)
			if err != nil {
				t.Fatal(err)
			}
			record := sealDuplexTestBodyV1(t, client.state, wirev1.TypeReliableData, 9, 9, body)
			clear(body)
			clearFrameSetV1(first)
			clearFrameSetV1(second)
			if _, err := relay.OpenFrame(record); !errors.Is(err, ErrRecordInvalid) {
				t.Fatalf("fragment violation error=%v", err)
			}
		})
	}
}

func TestProcessDuplexRecordV1MessageLimitAndConcurrentCloseFailClosed(t *testing.T) {
	client, relay, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, client, relay, exporter)
	client.state.mu.Lock()
	client.state.maxMessages = client.state.sendCount + 1
	client.state.mu.Unlock()
	if _, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 1, Payload: []byte("last")}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SealKeepalive(2); !errors.Is(err, ErrSessionMessageLimit) {
		t.Fatalf("message limit error=%v", err)
	}
	if _, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 2, Sequence: 2, Payload: []byte("after")}, 2); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("endpoint survived message exhaustion: %v", err)
	}

	concurrentClient, concurrentRelay, concurrentExporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, concurrentClient, concurrentRelay, concurrentExporter)
	results := make(chan error, 16)
	var group sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := concurrentClient.SealClose(CloseCodeTerminalV1)
			results <- err
		}()
	}
	group.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("concurrent close error=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful closes=%d, want 1", successes)
	}
}

func newProcessDuplexPairV1(t *testing.T) (*ProcessClientDuplexEndpointV1, *ProcessRelayDuplexEndpointV1, [32]byte) {
	return newProcessDuplexPairWithProgramV1(t, testDuplexProgramV1())
}

func newProcessDuplexPairWithProgramV1(t *testing.T, program liveprogram.ProgramV1) (*ProcessClientDuplexEndpointV1, *ProcessRelayDuplexEndpointV1, [32]byte) {
	t.Helper()
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	config, err := auth.NewProcessHandshakeConfigV1(fixture.input.Client, fixture.input.Server, fixture.input.SelectedPolicy, fixture.input.SelectedCapabilities)
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("phase17-duplex-record-plan-v1"))
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	clientHandshake, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	relayHandshake, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	clientHello, _ := clientHandshake.Start()
	serverHello, err := relayHandshake.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	clientFinish, err := clientHandshake.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	serverFinish, relayResult, err := relayHandshake.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := clientHandshake.AcceptServerFinish(serverFinish)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewProcessClientDuplexEndpointV1(clientResult, digest, program)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewProcessRelayDuplexEndpointV1(relayResult, digest, program)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Abort)
	t.Cleanup(relay.Abort)
	return client, relay, [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}
}

func sealDuplexTestBodyV1(t *testing.T, state *processDuplexStateV1, frameType uint8, outerStream uint32, slot uint16, body []byte) []byte {
	t.Helper()
	state.mu.Lock()
	defer state.mu.Unlock()
	record, err := state.sealBodyLockedV1(frameType, outerStream, slot, body)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func bindProcessDuplexPairV1(t *testing.T, client *ProcessClientDuplexEndpointV1, relay *ProcessRelayDuplexEndpointV1, exporter [32]byte) {
	t.Helper()
	bind, err := client.ProfileBind(exporter)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := relay.AcceptProfileBind(bind, exporter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptEngineReady(ready); err != nil {
		t.Fatal(err)
	}
}

func testDuplexProgramV1() liveprogram.ProgramV1 {
	var source [32]byte
	for index := range source {
		source[index] = byte(index + 1)
	}
	digest := sha256.Sum256(append([]byte("kurd-live-program-v1\x00"), source[:]...))
	var id [16]byte
	copy(id[:], digest[:16])
	return liveprogram.ProgramV1{
		Schema: liveprogram.SchemaV1, ProgramID: id, SourceSchemaVersion: "0.2.0-lab", SourceGenerationHash: source,
		Messages: []liveprogram.MessageV1{
			{Semantic: "data", WireSymbol: "data", Direction: "bidirectional", MinPayloadBytes: 0, MaxPayloadBytes: 4096},
			{Semantic: "padding", WireSymbol: "padding", Direction: "bidirectional", MinPayloadBytes: 0, MaxPayloadBytes: 4096},
		},
		Frame:     liveprogram.FrameV1{LengthMode: "varint_prefix", TypeMode: "explicit_generated_tag", HeaderOrder: []string{"length", "type", "stream", "flags"}, FragmentationMode: "bounded_variable_chunks", ChecksumMode: "crc32", PaddingPlacement: "suffix", Compiled: liveprogram.CompiledFramingV1{DataTypeTag: []byte("data"), PaddingTypeTag: []byte("padding"), ProfileXORStreamMask: 1, TableStreamMask: 2, CRC32PrefixState: 3}},
		Stream:    liveprogram.StreamV1{IDEncodingMode: "fixed32_be", MaxConcurrentStreams: 16},
		Scheduler: liveprogram.SchedulerV1{Mode: "balanced", MaxBatchBytes: 4096, FlushIntervalMs: 10, MaxInFlightFrames: 4, PriorityMode: "fifo"},
		Padding:   liveprogram.PaddingV1{Mode: "bounded", MinPaddingBytes: 1, MaxPaddingBytes: 8, Probability: 1},
		Security:  liveprogram.SecurityV1{CompilerSecurityVersion: "0.13.0-lab", MinimumRuntimeVersion: "0.13.0-lab", Policy: liveprogram.SecurityPolicyV1{SecurityVersion: "0.13.0-lab", TranscriptMode: "canonical_v1", KDFSuite: "kdf_hkdf_sha256", AEADSuite: "aead_aes_256_gcm", MACSuite: "mac_hmac_sha256", NonceMode: "counter_xor_base", ReplayPolicy: "ordered_only", ReplayWindowSize: 64, DowngradePolicy: "strict_capabilities", CapabilityNegotiationPolicy: "strict_required", ProfileCompatibilityPolicy: "strict_schema", KeyRotationPolicy: "session_only", ConfigValidationPolicy: "strict_required", SecureEnvelopeMode: "metadata_authenticated", MaxSessionMessages: 1024, MaxKeyLifetimeMessages: 512}, ClientMandatoryCapabilities: []string{"multi_stream"}, RelayMandatoryCapabilities: []string{"multi_stream"}, SelectedCapabilities: []string{"multi_stream"}},
		Limits:    liveprogram.LimitsV1{MaxFrameBytes: 8192, MaxPayloadBytes: 4096, MaxSessionMillis: 30000, MaxSessionMessages: 1024, MaxKeyLifetimeMessages: 512},
	}
}

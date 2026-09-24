// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/framing"
)

func newTestPacketPortV1(t *testing.T, maximum int) *PacketPortV1 {
	t.Helper()
	p, err := NewPacketPortV1(maximum)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

type packetPortResultV1 struct {
	n   int
	err error
}

func packetPortWriteV1(p *PacketPortV1, input []byte) <-chan packetPortResultV1 {
	done := make(chan packetPortResultV1, 1)
	go func() {
		n, err := p.Write(input)
		done <- packetPortResultV1{n, err}
	}()
	return done
}

func awaitPacketPortResultV1(t *testing.T, done <-chan packetPortResultV1, wantN int, wantErr error) {
	t.Helper()
	select {
	case got := <-done:
		if got.n != wantN || !errors.Is(got.err, wantErr) {
			t.Fatalf("operation count=%d error=%v, want count=%d error=%v", got.n, got.err, wantN, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("packet-port operation did not finish")
	}
}

func assertPacketPortBlockedV1(t *testing.T, done <-chan packetPortResultV1) {
	t.Helper()
	synctest.Wait()
	select {
	case result := <-done:
		t.Fatalf("operation completed prematurely: count=%d error=%v", result.n, result.err)
	default:
	}
}

func TestPacketPortConstructorLimits(t *testing.T) {
	for _, maximum := range []int{-1, 0, 39, 65536, math.MaxInt} {
		if p, err := NewPacketPortV1(maximum); p != nil || !errors.Is(err, ErrPacketPortConfig) {
			t.Fatalf("maximum=%d accepted", maximum)
		}
	}
	for _, maximum := range []int{40, 1280, 65535} {
		p := newTestPacketPortV1(t, maximum)
		var _ io.ReadWriteCloser = p
		if err := p.Submit(context.Background(), make([]byte, maximum)); err != nil {
			t.Fatal(err)
		}
		if n, err := p.Read(make([]byte, maximum)); n != maximum || err != nil {
			t.Fatalf("maximum packet: count=%d error=%v", n, err)
		}
	}
}

func TestPacketPortSubmitCopiesAndReadPreservesBoundaries(t *testing.T) {
	p := newTestPacketPortV1(t, 40)
	input := []byte{1, 2, 3}
	if err := p.Submit(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	clear(input)
	output := bytes.Repeat([]byte{9}, 10)
	if n, err := p.Read(output[:2]); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("short read: count=%d error=%v", n, err)
	}
	if !bytes.Equal(output, bytes.Repeat([]byte{9}, 10)) {
		t.Fatal("short read changed output")
	}
	if n, err := p.Read(output); n != 3 || err != nil || !bytes.Equal(output[:3], []byte{1, 2, 3}) || output[3] != 9 {
		t.Fatalf("read did not preserve exact owned packet: count=%d error=%v", n, err)
	}
	if err := p.Submit(context.Background(), []byte{4}); err != nil {
		t.Fatal(err)
	}
	if n, err := p.Read(output); n != 1 || err != nil || output[0] != 4 {
		t.Fatalf("second packet: count=%d error=%v", n, err)
	}
}

func TestPacketPortRejectsEmptyOversizedAndEmptyOutput(t *testing.T) {
	p := newTestPacketPortV1(t, 40)
	for _, input := range [][]byte{nil, {}, make([]byte, 41)} {
		if err := p.Submit(context.Background(), input); !errors.Is(err, ErrPacketPortPacket) {
			t.Fatalf("invalid submit: %v", err)
		}
		if n, err := p.Write(input); n != 0 || !errors.Is(err, ErrPacketPortPacket) {
			t.Fatalf("invalid write: count=%d error=%v", n, err)
		}
	}
	if n, err := p.Read(nil); n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("empty read: count=%d error=%v", n, err)
	}
	if token, n, err := p.Receive(context.Background(), nil); token != 0 || n != 0 || !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("empty receive: count=%d error=%v", n, err)
	}
}

func TestPacketPortWriteWaitsForExactAcknowledgment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 40)
		ctx := context.Background()
		done := packetPortWriteV1(p, []byte{1, 2, 3})
		assertPacketPortBlockedV1(t, done)
		output := bytes.Repeat([]byte{9}, 5)
		if token, n, err := p.Receive(ctx, output[:2]); token != 0 || n != 0 || !errors.Is(err, io.ErrShortBuffer) {
			t.Fatalf("short receive: count=%d error=%v", n, err)
		}
		if !bytes.Equal(output, bytes.Repeat([]byte{9}, 5)) {
			t.Fatal("short receive changed output")
		}
		token, n, err := p.Receive(ctx, output)
		if token == 0 || n != 3 || err != nil || !bytes.Equal(output[:3], []byte{1, 2, 3}) || output[3] != 9 {
			t.Fatalf("receive: count=%d error=%v", n, err)
		}
		clear(output)
		assertPacketPortBlockedV1(t, done)
		if _, _, err := p.Receive(ctx, output); !errors.Is(err, ErrPacketPortBusy) {
			t.Fatalf("second receive before acknowledgment=%v", err)
		}
		if n, err := p.Write([]byte{4}); n != 0 || !errors.Is(err, ErrPacketPortBusy) {
			t.Fatalf("concurrent write: count=%d error=%v", n, err)
		}
		if err := p.Acknowledge(ctx, token, 3, nil); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, done, 3, nil)
		if !bytes.Equal(output, make([]byte, len(output))) {
			t.Fatal("acknowledgment retained or changed receive buffer")
		}
	})
}

func TestPacketPortRejectsDuplicateStaleCrossPortAndUnissuedTokens(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 40)
		other := newTestPacketPortV1(t, 40)
		ctx := context.Background()
		one := packetPortWriteV1(p, []byte{1})
		token, _, err := p.Receive(ctx, make([]byte, 40))
		if err != nil {
			t.Fatal(err)
		}
		two := packetPortWriteV1(other, []byte{2})
		otherToken, _, err := other.Receive(ctx, make([]byte, 40))
		if err != nil {
			t.Fatal(err)
		}
		if token == otherToken {
			t.Fatal("cross-port token collision")
		}
		for _, bad := range []PacketDeliveryTokenV1{0, otherToken, PacketDeliveryTokenV1(math.MaxUint64)} {
			if err := p.Acknowledge(ctx, bad, 1, nil); !errors.Is(err, ErrPacketPortToken) {
				t.Fatalf("invalid token=%v", err)
			}
		}
		assertPacketPortBlockedV1(t, one)
		if err := p.Acknowledge(ctx, token, 1, nil); err != nil {
			t.Fatal(err)
		}
		if err := p.Acknowledge(ctx, token, 1, nil); !errors.Is(err, ErrPacketPortToken) {
			t.Fatalf("duplicate=%v", err)
		}
		awaitPacketPortResultV1(t, one, 1, nil)
		one = packetPortWriteV1(p, []byte{3, 4})
		nextToken, n, err := p.Receive(ctx, make([]byte, 40))
		if err != nil || n != 2 || nextToken == token {
			t.Fatalf("next delivery: count=%d error=%v", n, err)
		}
		if err := p.Acknowledge(ctx, token, 2, nil); !errors.Is(err, ErrPacketPortToken) {
			t.Fatalf("stale=%v", err)
		}
		assertPacketPortBlockedV1(t, one)
		if err := p.Acknowledge(ctx, nextToken, 2, nil); err != nil {
			t.Fatal(err)
		}
		if err := other.Acknowledge(ctx, otherToken, 1, nil); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, one, 2, nil)
		awaitPacketPortResultV1(t, two, 1, nil)
	})
}

func TestPacketPortFailedAcknowledgmentClosesAndFailsWrite(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count int
		err   error
	}{
		{"short", 2, nil}, {"oversized", 4, nil}, {"negative", -1, nil}, {"failed", 3, errors.New("external-detail-must-not-escape")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newTestPacketPortV1(t, 40)
				done := packetPortWriteV1(p, []byte{1, 2, 3})
				token, _, err := p.Receive(context.Background(), make([]byte, 40))
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Acknowledge(context.Background(), token, tc.count, tc.err); err != ErrPacketPortDelivery {
					t.Fatalf("ack error=%v", err)
				}
				awaitPacketPortResultV1(t, done, 0, ErrPacketPortDelivery)
				if err := p.Submit(context.Background(), []byte{1}); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("submit after failure=%v", err)
				}
			})
		})
	}
}

func TestPacketPortBoundedSubmitCancellationAndReadConcurrency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 40)
		ctx := context.Background()
		if err := p.Submit(ctx, []byte{1}); err != nil {
			t.Fatal(err)
		}
		for range 100 {
			cancelCtx, cancel := context.WithCancel(ctx)
			done := make(chan packetPortResultV1, 1)
			go func() { done <- packetPortResultV1{err: p.Submit(cancelCtx, []byte{2})} }()
			assertPacketPortBlockedV1(t, done)
			if err := p.Submit(ctx, []byte{3}); !errors.Is(err, ErrPacketPortBusy) {
				t.Fatalf("overlapping submit=%v", err)
			}
			cancel()
			awaitPacketPortResultV1(t, done, 0, context.Canceled)
		}
		out := make([]byte, 40)
		if n, err := p.Read(out); n != 1 || err != nil || out[0] != 1 {
			t.Fatalf("queued packet lost: count=%d error=%v", n, err)
		}
		done := make(chan packetPortResultV1, 1)
		go func() { n, err := p.Read(out); done <- packetPortResultV1{n, err} }()
		assertPacketPortBlockedV1(t, done)
		if n, err := p.Read(make([]byte, 40)); n != 0 || !errors.Is(err, ErrPacketPortBusy) {
			t.Fatalf("overlapping read: count=%d error=%v", n, err)
		}
		if err := p.Submit(ctx, []byte{4, 5}); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, done, 2, nil)
		if !bytes.Equal(out[:2], []byte{4, 5}) {
			t.Fatal("read returned wrong packet")
		}
	})
}

func TestPacketPortReceiveCancellationDoesNotDropDelivery(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 40)
		for range 100 {
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan packetPortResultV1, 1)
			go func() { _, n, err := p.Receive(ctx, make([]byte, 40)); done <- packetPortResultV1{n, err} }()
			assertPacketPortBlockedV1(t, done)
			if _, _, err := p.Receive(context.Background(), make([]byte, 40)); !errors.Is(err, ErrPacketPortBusy) {
				t.Fatalf("overlapping receive=%v", err)
			}
			cancel()
			awaitPacketPortResultV1(t, done, 0, context.Canceled)
		}
		done := packetPortWriteV1(p, []byte{1, 2})
		assertPacketPortBlockedV1(t, done)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if token, n, err := p.Receive(ctx, make([]byte, 40)); token != 0 || n != 0 || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled receive: count=%d error=%v", n, err)
		}
		token, n, err := p.Receive(context.Background(), make([]byte, 40))
		if n != 2 || err != nil {
			t.Fatalf("preserved delivery: count=%d error=%v", n, err)
		}
		if err := p.Acknowledge(context.Background(), token, n, nil); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, done, 2, nil)
	})
}

func TestPacketPortCanceledSubmitAndAcknowledgment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 40)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.Submit(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
			t.Fatalf("submit=%v", err)
		}
		done := packetPortWriteV1(p, []byte{1})
		token, _, err := p.Receive(context.Background(), make([]byte, 40))
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Acknowledge(ctx, token, 1, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("ack=%v", err)
		}
		awaitPacketPortResultV1(t, done, 0, io.ErrClosedPipe)
	})
}

func TestPacketPortCloseWakesAllBlockedOperations(t *testing.T) {
	for _, operation := range []string{"read", "write", "delivered-write", "submit", "receive"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				p := newTestPacketPortV1(t, 40)
				done := make(chan packetPortResultV1, 1)
				switch operation {
				case "read":
					go func() { n, err := p.Read(make([]byte, 40)); done <- packetPortResultV1{n, err} }()
				case "write", "delivered-write":
					go func() { n, err := p.Write([]byte{1}); done <- packetPortResultV1{n, err} }()
					if operation == "delivered-write" {
						if _, _, err := p.Receive(context.Background(), make([]byte, 40)); err != nil {
							t.Fatal(err)
						}
					}
				case "submit":
					if err := p.Submit(context.Background(), []byte{1}); err != nil {
						t.Fatal(err)
					}
					go func() { done <- packetPortResultV1{err: p.Submit(context.Background(), []byte{2})} }()
				case "receive":
					go func() {
						_, n, err := p.Receive(context.Background(), make([]byte, 40))
						done <- packetPortResultV1{n, err}
					}()
				}
				assertPacketPortBlockedV1(t, done)
				var wg sync.WaitGroup
				for range 20 {
					wg.Go(func() {
						if err := p.Close(); err != nil {
							t.Error(err)
						}
					})
				}
				wg.Wait()
				awaitPacketPortResultV1(t, done, 0, io.ErrClosedPipe)
			})
		})
	}
}

func TestPacketPortOperationsAfterClose(t *testing.T) {
	p := newTestPacketPortV1(t, 40)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if n, err := p.Read(make([]byte, 40)); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("read: count=%d error=%v", n, err)
	}
	if n, err := p.Write([]byte{1}); n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write: count=%d error=%v", n, err)
	}
	if err := p.Submit(context.Background(), []byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("submit=%v", err)
	}
	if token, n, err := p.Receive(context.Background(), make([]byte, 40)); token != 0 || n != 0 || !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("receive: count=%d error=%v", n, err)
	}
	if err := p.Acknowledge(context.Background(), 1, 1, nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("ack=%v", err)
	}
}

func TestPacketPortTokenAllocatorNeverWraps(t *testing.T) {
	var counter atomic.Uint64
	counter.Store(math.MaxUint64 - 1)
	if token, err := nextPacketPortTokenV1(&counter); token != PacketDeliveryTokenV1(math.MaxUint64) || err != nil {
		t.Fatalf("last token error=%v", err)
	}
	for range 3 {
		if token, err := nextPacketPortTokenV1(&counter); token != 0 || !errors.Is(err, ErrPacketPortTokenExhausted) {
			t.Fatalf("token allocator wrapped: error=%v", err)
		}
	}
}

func TestPacketPortFullDuplexCapacityAndOwnedBufferClearing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := newTestPacketPortV1(t, 65535)
		ctx := context.Background()
		// Retain test-only aliases to observe zeroization, including after Close
		// drops the port's references. No alias is accessed during an active copy.
		outboundStorage, inboundStorage := p.outbound, p.inbound
		first := bytes.Repeat([]byte{1}, 65535)
		if err := p.Submit(ctx, first); err != nil {
			t.Fatal(err)
		}
		second := []byte{2, 3}
		submitted := make(chan packetPortResultV1, 1)
		go func() { submitted <- packetPortResultV1{err: p.Submit(ctx, second)} }()
		assertPacketPortBlockedV1(t, submitted)
		written := packetPortWriteV1(p, bytes.Repeat([]byte{4}, 65535))
		token, n, err := p.Receive(ctx, make([]byte, 65535))
		if token == 0 || n != 65535 || err != nil {
			t.Fatalf("maximum inbound: count=%d error=%v", n, err)
		}
		readOutput := make([]byte, 65535)
		if n, err := p.Read(readOutput); n != 65535 || err != nil || !bytes.Equal(readOutput, first) {
			t.Fatalf("maximum outbound: count=%d error=%v", n, err)
		}
		awaitPacketPortResultV1(t, submitted, 0, nil)
		clear(second)
		if n, err := p.Read(readOutput); n != 2 || err != nil || !bytes.Equal(readOutput[:2], []byte{2, 3}) {
			t.Fatalf("unblocked submit: count=%d error=%v", n, err)
		}
		if !bytes.Equal(outboundStorage, make([]byte, 65535)) {
			t.Fatal("Read did not clear owned outbound copy")
		}
		if err := p.Acknowledge(ctx, token, 65535, nil); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, written, 65535, nil)
		if !bytes.Equal(inboundStorage, make([]byte, 65535)) {
			t.Fatal("acknowledgment did not clear owned inbound copy")
		}
		if err := p.Submit(ctx, []byte{5}); err != nil {
			t.Fatal(err)
		}
		written = packetPortWriteV1(p, []byte{6})
		assertPacketPortBlockedV1(t, written)
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		awaitPacketPortResultV1(t, written, 0, io.ErrClosedPipe)
		if !bytes.Equal(outboundStorage, make([]byte, 65535)) || !bytes.Equal(inboundStorage, make([]byte, 65535)) {
			t.Fatal("Close did not clear both owned packet copies")
		}
	})
}

func TestPacketPortConcurrentAcknowledgmentAndCloseLinearize(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		for range 100 {
			p := newTestPacketPortV1(t, 40)
			written := packetPortWriteV1(p, []byte{1})
			token, _, err := p.Receive(context.Background(), make([]byte, 40))
			if err != nil {
				t.Fatal(err)
			}
			ackResults := make(chan error, 8)
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() { ackResults <- p.Acknowledge(context.Background(), token, 1, nil) })
			}
			wg.Go(func() { _ = p.Close() })
			wg.Wait()
			close(ackResults)
			successes := 0
			for err := range ackResults {
				if err == nil {
					successes++
				} else if !errors.Is(err, ErrPacketPortToken) && !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("concurrent acknowledgment=%v", err)
				}
			}
			if successes > 1 {
				t.Fatal("multiple acknowledgments succeeded")
			}
			if successes == 1 {
				awaitPacketPortResultV1(t, written, 1, nil)
			} else {
				awaitPacketPortResultV1(t, written, 0, io.ErrClosedPipe)
			}
		}
	})
}

func TestPacketPortPumpReplayCommitFollowsAcknowledgment(t *testing.T) {
	for _, successful := range []bool{true, false} {
		name := "failed-destination"
		if successful {
			name = "exact-destination"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client, relay, exporter := newProcessDuplexPairV1(t)
				bindProcessDuplexPairV1(t, client, relay, exporter)
				assigned := [4]byte{10, 89, 0, 2}
				packet := testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{1, 2, 3})
				records, err := client.SealOperation(framing.Operation{Semantic: "data", StreamID: 7, Sequence: 1, Payload: packet}, 1)
				if err != nil || len(records) != 1 {
					t.Fatalf("fixture sealing: records=%d error=%v", len(records), err)
				}
				pending, err := relay.OpenFrame(records[0])
				if err != nil || pending == nil {
					t.Fatalf("fixture open=%v", err)
				}
				port := newTestPacketPortV1(t, 1280)
				pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: port, Carrier: newMemoryPacketDeviceV1(), Endpoint: relay, Program: testDuplexProgramV1(), Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 16384, IdleTimeout: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				defer pump.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				input := make(chan authenticatedPacketV1, 1)
				completed := make(chan error, 1)
				failures := make(chan error, 1)
				workerDone := make(chan struct{})
				input <- authenticatedPacketV1{frame: pending, completed: completed}
				go func() { defer close(workerDone); pump.writeTUNV1(ctx, input, failures) }()
				token, n, err := port.Receive(ctx, make([]byte, 1280))
				if n != len(packet) || err != nil {
					t.Fatalf("delivery: count=%d error=%v", n, err)
				}
				synctest.Wait()
				if !bytes.Equal(pending.Operation().Payload, packet) || pump.SnapshotV1().TUNPacketsWritten != 0 {
					t.Fatal("authenticated frame committed before destination acknowledgment")
				}
				select {
				case <-completed:
					t.Fatal("pump completed before acknowledgment")
				default:
				}
				count := n
				if !successful {
					count--
				}
				err = port.Acknowledge(ctx, token, count, nil)
				if successful && err != nil || !successful && !errors.Is(err, ErrPacketPortDelivery) {
					t.Fatalf("ack=%v", err)
				}
				select {
				case err := <-completed:
					if successful && err != nil || !successful && !errors.Is(err, ErrPacketPumpIO) {
						t.Fatalf("pump completion=%v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("pump did not finish delivery")
				}
				wantReplay := security.ErrReplayDuplicate
				if !successful {
					wantReplay = ErrSecureChannel
				}
				if _, err := relay.OpenFrame(records[0]); !errors.Is(err, wantReplay) {
					t.Fatalf("post-delivery replay state=%v", err)
				}
				cancel()
				select {
				case <-workerDone:
				case <-time.After(time.Second):
					t.Fatal("pump writer did not stop")
				}
			})
		})
	}
}

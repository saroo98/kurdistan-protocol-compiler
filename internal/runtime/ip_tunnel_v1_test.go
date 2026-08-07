// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPacketPumpV1CarriesPacketsBothDirections(t *testing.T) {
	clientEndpoint, relayEndpoint, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, clientEndpoint, relayEndpoint, exporter)
	clientCarrier, relayCarrier := net.Pipe()
	clientTUN := newMemoryPacketDeviceV1()
	relayTUN := newMemoryPacketDeviceV1()
	assigned := [4]byte{10, 89, 0, 2}
	program := testDuplexProgramV1()
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientResults := make(chan error, 1)
	relayResults := make(chan error, 1)
	go func() { clientResults <- clientPump.Run(ctx) }()
	go func() { relayResults <- relayPump.Run(ctx) }()

	outbound := testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{1, 2, 3})
	clientTUN.injectV1(t, outbound)
	if got := receivePacketOrFailureV1(t, relayTUN, clientResults, relayResults); string(got) != string(outbound) {
		t.Fatalf("relay packet mismatch")
	}
	response := testIPv4PacketV1([4]byte{1, 1, 1, 1}, assigned, 17, []byte{4, 5})
	relayTUN.injectV1(t, response)
	if got := receivePacketOrFailureV1(t, clientTUN, clientResults, relayResults); string(got) != string(response) {
		t.Fatalf("client packet mismatch")
	}

	cancel()
	_ = clientPump.Close()
	_ = relayPump.Close()
	for _, results := range []<-chan error{clientResults, relayResults} {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("pump=%v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pump did not stop")
		}
	}
}

func receivePacketOrFailureV1(t *testing.T, device *memoryPacketDeviceV1, clientResults, relayResults <-chan error) []byte {
	t.Helper()
	select {
	case packet := <-device.writes:
		return packet
	case err := <-clientResults:
		t.Fatalf("client pump failed before delivery: %v", err)
		return nil
	case err := <-relayResults:
		t.Fatalf("relay pump failed before delivery: %v", err)
		return nil
	case <-time.After(2 * time.Second):
		t.Fatal("receive timeout")
		return nil
	}
}

func TestPacketPumpV1RejectsUnsafeBoundsAndShortTUNWrite(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, _ := net.Pipe()
	if _, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, QueuePackets: 0, IncompleteOps: 1, BufferBudget: 1, IdleTimeout: time.Second}); !errors.Is(err, ErrPacketPumpConfig) {
		t.Fatalf("unsafe config=%v", err)
	}
}

func TestPacketPumpV1ShortTUNWriteDiscardsPendingAndTerminates(t *testing.T) {
	clientEndpoint, relayEndpoint, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, clientEndpoint, relayEndpoint, exporter)
	clientCarrier, relayCarrier := net.Pipe()
	clientTUN := newMemoryPacketDeviceV1()
	relayTUN := &shortWritePacketDeviceV1{memoryPacketDeviceV1: newMemoryPacketDeviceV1()}
	assigned := [4]byte{10, 89, 0, 2}
	program := testDuplexProgramV1()
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientResults := make(chan error, 1)
	relayResults := make(chan error, 1)
	go func() { clientResults <- clientPump.Run(ctx) }()
	go func() { relayResults <- relayPump.Run(ctx) }()

	clientTUN.injectV1(t, testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{1}))
	select {
	case err := <-relayResults:
		if !errors.Is(err, ErrPacketPumpIO) {
			t.Fatalf("relay result=%v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("short TUN write did not terminate the relay pump")
	}
	if _, err := relayEndpoint.SealKeepalive(1); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay endpoint survived discarded pending packet: %v", err)
	}
	_ = clientPump.Close()
	_ = relayPump.Close()
	select {
	case <-clientResults:
	case <-time.After(2 * time.Second):
		t.Fatal("client pump did not stop")
	}
}

func TestPacketPumpV1OutboundQueueFullFailsClosed(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	carrier, peer := net.Pipe()
	defer peer.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: carrier, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	output := make(chan []byte, 1)
	output <- []byte{1}
	failures := make(chan error, 1)
	device.injectV1(t, testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 17, []byte{1}))
	pump.readTUNV1(context.Background(), output, failures)
	if err := <-failures; !errors.Is(err, ErrPacketQueueFull) {
		t.Fatalf("queue result=%v", err)
	}
	_ = pump.Close()
}

func TestPacketPumpV1IdleTimeoutIsTerminal(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, two := net.Pipe()
	defer two.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := pump.Run(context.Background()); !errors.Is(err, ErrLinkFailure) {
		t.Fatalf("idle result=%v", err)
	}
}

type memoryPacketDeviceV1 struct {
	read   chan []byte
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

type shortWritePacketDeviceV1 struct{ *memoryPacketDeviceV1 }

func (device *shortWritePacketDeviceV1) Write(packet []byte) (int, error) {
	if len(packet) == 0 {
		return 0, nil
	}
	return len(packet) - 1, nil
}

func newMemoryPacketDeviceV1() *memoryPacketDeviceV1 {
	return &memoryPacketDeviceV1{read: make(chan []byte, 4), writes: make(chan []byte, 4), closed: make(chan struct{})}
}

func (device *memoryPacketDeviceV1) Read(buffer []byte) (int, error) {
	select {
	case packet := <-device.read:
		if len(packet) > len(buffer) {
			return 0, io.ErrShortBuffer
		}
		return copy(buffer, packet), nil
	case <-device.closed:
		return 0, io.EOF
	}
}

func (device *memoryPacketDeviceV1) Write(packet []byte) (int, error) {
	owned := append([]byte(nil), packet...)
	select {
	case device.writes <- owned:
		return len(packet), nil
	case <-device.closed:
		clear(owned)
		return 0, io.ErrClosedPipe
	}
}

func (device *memoryPacketDeviceV1) Close() error {
	device.once.Do(func() { close(device.closed) })
	return nil
}

func (device *memoryPacketDeviceV1) injectV1(t *testing.T, packet []byte) {
	t.Helper()
	select {
	case device.read <- append([]byte(nil), packet...):
	case <-time.After(time.Second):
		t.Fatal("inject timeout")
	}
}

func (device *memoryPacketDeviceV1) receiveV1(t *testing.T) []byte {
	t.Helper()
	select {
	case packet := <-device.writes:
		return packet
	case <-time.After(2 * time.Second):
		t.Fatal("receive timeout")
		return nil
	}
}

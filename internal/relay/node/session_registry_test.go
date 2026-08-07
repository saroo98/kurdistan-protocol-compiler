// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestSessionRegistryRoutesExactReturnAddressesWithoutCrossDelivery(t *testing.T) {
	tunnel := newMemoryTunnelV1()
	registry, err := NewSessionRegistry(tunnel, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- registry.Run(ctx) }()

	first4 := [4]byte{10, 89, 0, 2}
	second4 := [4]byte{10, 89, 0, 3}
	first6 := [16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	second6 := [16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3}
	one, err := registry.Register(SessionSpec{ID: "session-one", ProfileID: "profile-one", ClientKeyID: "client-one", AssignedIPv4: first4, AssignedIPv6: first6})
	if err != nil {
		t.Fatal(err)
	}
	two, err := registry.Register(SessionSpec{ID: "session-two", ProfileID: "profile-two", ClientKeyID: "client-two", AssignedIPv4: second4, AssignedIPv6: second6})
	if err != nil {
		t.Fatal(err)
	}

	firstPacket := testIPv4PacketV1([4]byte{1, 1, 1, 1}, first4, 17, []byte{1})
	secondPacket := testIPv6PacketV1([16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, second6, 6, []byte{2})
	tunnel.inject(firstPacket)
	tunnel.inject(secondPacket)
	if got := readPacketV1(t, one); string(got) != string(firstPacket) {
		t.Fatal("first return packet reached the wrong session")
	}
	if got := readPacketV1(t, two); string(got) != string(secondPacket) {
		t.Fatal("second return packet reached the wrong session")
	}
	assertNoPacketV1(t, one)
	assertNoPacketV1(t, two)

	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, ErrRegistryClosed) {
			t.Fatalf("registry run err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("registry did not stop")
	}
}

func TestSessionRegistryRejectsDuplicateAuthorityAndSpoofedSource(t *testing.T) {
	tunnel := newMemoryTunnelV1()
	registry, err := NewSessionRegistry(tunnel, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	assigned := [4]byte{10, 89, 0, 2}
	device, err := registry.Register(SessionSpec{ID: "session-one", ProfileID: "profile-one", ClientKeyID: "client-one", AssignedIPv4: assigned})
	if err != nil {
		t.Fatal(err)
	}
	for name, spec := range map[string]SessionSpec{
		"session": {ID: "session-one", ProfileID: "profile-two", ClientKeyID: "client-two", AssignedIPv4: [4]byte{10, 89, 0, 3}},
		"profile": {ID: "session-two", ProfileID: "profile-one", ClientKeyID: "client-two", AssignedIPv4: [4]byte{10, 89, 0, 3}},
		"client":  {ID: "session-two", ProfileID: "profile-two", ClientKeyID: "client-one", AssignedIPv4: [4]byte{10, 89, 0, 3}},
		"address": {ID: "session-two", ProfileID: "profile-two", ClientKeyID: "client-two", AssignedIPv4: assigned},
	} {
		t.Run(name, func(t *testing.T) {
			if duplicate, err := registry.Register(spec); duplicate != nil || !errors.Is(err, ErrSessionConflict) {
				t.Fatalf("duplicate authority accepted: device=%v err=%v", duplicate, err)
			}
		})
	}
	spoofed := testIPv4PacketV1([4]byte{10, 89, 0, 9}, [4]byte{1, 1, 1, 1}, 17, []byte{3})
	if count, err := device.Write(spoofed); count != 0 || !errors.Is(err, ErrPacketRejected) {
		t.Fatalf("spoofed packet accepted: count=%d err=%v", count, err)
	}
	valid := testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{4})
	if count, err := device.Write(valid); err != nil || count != len(valid) {
		t.Fatalf("valid packet rejected: count=%d err=%v", count, err)
	}
	if got := tunnel.writtenPacket(t); string(got) != string(valid) {
		t.Fatal("valid packet was not delivered to the shared TUN")
	}
}

func TestSessionRegistryQueuePressureAndProfileStopFailClosed(t *testing.T) {
	tunnel := newMemoryTunnelV1()
	registry, err := NewSessionRegistry(tunnel, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	assigned := [4]byte{10, 89, 0, 2}
	device, err := registry.Register(SessionSpec{ID: "session-one", ProfileID: "profile-one", ClientKeyID: "client-one", AssignedIPv4: assigned})
	if err != nil {
		t.Fatal(err)
	}
	packet := testIPv4PacketV1([4]byte{1, 1, 1, 1}, assigned, 17, []byte{1})
	if err := registry.RouteReturnPacket(packet); err != nil {
		t.Fatal(err)
	}
	if err := registry.RouteReturnPacket(packet); !errors.Is(err, ErrSessionQueueFull) {
		t.Fatalf("queue pressure err=%v", err)
	}
	if stopped := registry.StopProfile("profile-one"); stopped != 0 {
		t.Fatalf("stopped=%d", stopped)
	}
	buffer := make([]byte, 1500)
	if count, err := device.Read(buffer); count != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("stopped device remained readable: count=%d err=%v", count, err)
	}
	if snapshot := registry.Snapshot(); snapshot.ActiveSessions != 0 || snapshot.QueueDrops != 1 || snapshot.StoppedSessions != 1 {
		t.Fatalf("unexpected registry snapshot: %+v", snapshot)
	}
}

func TestSessionRegistryStopAllTerminatesEveryAssignment(t *testing.T) {
	registry, err := NewSessionRegistry(newMemoryTunnelV1(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	for index, spec := range []SessionSpec{
		{ID: "session-one", ProfileID: "profile-one", ClientKeyID: "client-one", AssignedIPv4: [4]byte{10, 89, 0, 2}},
		{ID: "session-two", ProfileID: "profile-two", ClientKeyID: "client-two", AssignedIPv4: [4]byte{10, 89, 0, 3}},
	} {
		if _, err := registry.Register(spec); err != nil {
			t.Fatalf("register %d: %v", index, err)
		}
	}
	if stopped := registry.StopAll(); stopped != 2 {
		t.Fatalf("stopped=%d", stopped)
	}
	if snapshot := registry.Snapshot(); snapshot.ActiveSessions != 0 || snapshot.StoppedSessions != 2 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestSessionRegistryStopProfileIsNotBlockedByStalledTunnelWrite(t *testing.T) {
	tunnel := newBlockingWriteTunnelV1()
	t.Cleanup(tunnel.release)
	registry, err := NewSessionRegistry(tunnel, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		tunnel.release()
		_ = registry.Close()
	})
	assigned := [4]byte{10, 89, 0, 2}
	device, err := registry.Register(SessionSpec{ID: "session-one", ProfileID: "profile-one", ClientKeyID: "client-one", AssignedIPv4: assigned})
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan struct{})
	go func() {
		_, _ = device.Write(testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{4}))
		close(writeDone)
	}()
	select {
	case <-tunnel.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("TUN write did not start")
	}
	stopped := make(chan int, 1)
	go func() { stopped <- registry.StopProfile("profile-one") }()
	select {
	case count := <-stopped:
		if count != 1 {
			t.Fatalf("stopped=%d", count)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("profile stop waited for a stalled TUN write")
	}
	tunnel.release()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("TUN write did not exit")
	}
}

type memoryTunnelV1 struct {
	read      chan []byte
	writes    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

type blockingWriteTunnelV1 struct {
	*memoryTunnelV1
	writeStarted chan struct{}
	releaseWrite chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
}

func (tunnel *blockingWriteTunnelV1) release() {
	tunnel.releaseOnce.Do(func() { close(tunnel.releaseWrite) })
}

func newBlockingWriteTunnelV1() *blockingWriteTunnelV1 {
	return &blockingWriteTunnelV1{
		memoryTunnelV1: newMemoryTunnelV1(), writeStarted: make(chan struct{}), releaseWrite: make(chan struct{}),
	}
}

func (tunnel *blockingWriteTunnelV1) Write(packet []byte) (int, error) {
	tunnel.startOnce.Do(func() { close(tunnel.writeStarted) })
	select {
	case <-tunnel.releaseWrite:
		return len(packet), nil
	case <-tunnel.closed:
		return 0, io.EOF
	}
}

func newMemoryTunnelV1() *memoryTunnelV1 {
	return &memoryTunnelV1{read: make(chan []byte, 8), writes: make(chan []byte, 8), closed: make(chan struct{})}
}

func (tunnel *memoryTunnelV1) Read(buffer []byte) (int, error) {
	select {
	case packet := <-tunnel.read:
		return copy(buffer, packet), nil
	case <-tunnel.closed:
		return 0, io.EOF
	}
}

func (tunnel *memoryTunnelV1) Write(packet []byte) (int, error) {
	copyPacket := append([]byte(nil), packet...)
	select {
	case tunnel.writes <- copyPacket:
		return len(packet), nil
	case <-tunnel.closed:
		return 0, io.EOF
	}
}

func (tunnel *memoryTunnelV1) Close() error {
	tunnel.closeOnce.Do(func() { close(tunnel.closed) })
	return nil
}

func (tunnel *memoryTunnelV1) inject(packet []byte) { tunnel.read <- append([]byte(nil), packet...) }

func (tunnel *memoryTunnelV1) writtenPacket(t *testing.T) []byte {
	t.Helper()
	select {
	case packet := <-tunnel.writes:
		return packet
	case <-time.After(time.Second):
		t.Fatal("shared TUN did not receive packet")
		return nil
	}
}

func readPacketV1(t *testing.T, device io.Reader) []byte {
	t.Helper()
	result := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 65535)
		count, err := device.Read(buffer)
		if err != nil {
			result <- nil
			return
		}
		result <- append([]byte(nil), buffer[:count]...)
	}()
	select {
	case packet := <-result:
		return packet
	case <-time.After(time.Second):
		t.Fatal("session packet not routed")
		return nil
	}
}

func assertNoPacketV1(t *testing.T, device io.Reader) {
	t.Helper()
	result := make(chan struct{}, 1)
	go func() {
		buffer := make([]byte, 65535)
		if count, _ := device.Read(buffer); count > 0 {
			result <- struct{}{}
		}
	}()
	select {
	case <-result:
		t.Fatal("cross-session packet delivered")
	case <-time.After(30 * time.Millisecond):
	}
}

func testIPv4PacketV1(source, destination [4]byte, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4ChecksumV1(packet[:20]))
	return packet
}

func testIPv6PacketV1(source, destination [16]byte, next byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = next
	packet[7] = 64
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	copy(packet[40:], payload)
	return packet
}

func ipv4ChecksumV1(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var testTunnelDNSIPv4V1 = [4]byte{10, 89, 0, 1}

func TestClassifyRelayTransportV1ReportsOnlyBoundedDNSAndChecksumCategories(t *testing.T) {
	assigned := [4]byte{10, 77, 1, 2}
	gateway := [4]byte{10, 77, 0, 1}

	valid := testIPv4UDPPacketV1(assigned, gateway, 40000, 53, []byte{0, 1, 0, 0})
	classification := classifyRelayTransportV1(valid, gateway, [16]byte{})
	if classification.Version != 4 || classification.Protocol != 17 || !classification.GatewayDNS || !classification.ChecksumValid || classification.Malformed {
		t.Fatalf("valid DNS classification=%+v", classification)
	}

	invalidChecksum := append([]byte(nil), valid...)
	invalidChecksum[len(invalidChecksum)-1] ^= 1
	classification = classifyRelayTransportV1(invalidChecksum, gateway, [16]byte{})
	if !classification.GatewayDNS || classification.ChecksumValid || classification.Malformed {
		t.Fatalf("invalid-checksum DNS classification=%+v", classification)
	}

	nonDNS := testIPv4UDPPacketV1(assigned, [4]byte{1, 1, 1, 1}, 40000, 443, []byte{1})
	classification = classifyRelayTransportV1(nonDNS, gateway, [16]byte{})
	if classification.GatewayDNS || !classification.ChecksumValid || classification.Malformed {
		t.Fatalf("public UDP classification=%+v", classification)
	}

	malformed := testIPv4PacketV1(assigned, gateway, 17, []byte{1, 2, 3})
	classification = classifyRelayTransportV1(malformed, gateway, [16]byte{})
	if !classification.Malformed || classification.ChecksumValid {
		t.Fatalf("malformed UDP classification=%+v", classification)
	}
}

func TestPacketPumpCloseReleasesTUNBeforePotentiallyBlockingRemoteTeardown(t *testing.T) {
	carrierCloseStarted := make(chan struct{})
	releaseCarrierClose := make(chan struct{})
	tunClosed := make(chan struct{})
	pump := &PacketPumpV1{
		config: PacketPumpConfigV1{
			TUN: &closeSignalPacketDeviceV1{closed: tunClosed},
			Carrier: &blockingClosePacketDeviceV1{
				started: carrierCloseStarted,
				release: releaseCarrierClose,
			},
			Endpoint: closeOrderEndpointV1{},
		},
		closed: make(chan struct{}),
	}

	done := make(chan error, 1)
	go func() { done <- pump.Close() }()
	defer func() {
		close(releaseCarrierClose)
		<-done
	}()

	select {
	case <-carrierCloseStarted:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not start")
	}
	select {
	case <-tunClosed:
	default:
		t.Fatal("TUN remained open while remote carrier teardown was blocked")
	}
}

func TestClassifyRelayReturnTransportV1ReportsOnlyBoundedTCPAndChecksumCategories(t *testing.T) {
	assigned := [4]byte{10, 89, 1, 2}
	remote := [4]byte{198, 51, 100, 8}

	synACK := testIPv4TCPPacketV1(remote, assigned, 443, 40000, 0x12, nil)
	classification := classifyRelayReturnTransportV1(synACK)
	if classification.Version != 4 || classification.Protocol != 6 || !classification.TCP ||
		!classification.SYN || !classification.ACK || classification.RST || classification.FIN ||
		!classification.ChecksumValid || classification.Malformed || classification.PacketBytes != len(synACK) {
		t.Fatalf("valid TCP classification=%+v", classification)
	}

	invalidChecksum := append([]byte(nil), synACK...)
	invalidChecksum[36] ^= 1
	classification = classifyRelayReturnTransportV1(invalidChecksum)
	if !classification.TCP || classification.ChecksumValid || classification.Malformed {
		t.Fatalf("invalid-checksum TCP classification=%+v", classification)
	}

	malformed := testIPv4PacketV1(remote, assigned, 6, []byte{1, 2, 3})
	classification = classifyRelayReturnTransportV1(malformed)
	if !classification.TCP || !classification.Malformed || classification.ChecksumValid {
		t.Fatalf("malformed TCP classification=%+v", classification)
	}
}

func testIPv4UDPPacketV1(source, destination [4]byte, sourcePort, destinationPort uint16, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	packet := testIPv4PacketV1(source, destination, 17, udp)
	checksumInput := make([]byte, 12+len(udp)+(len(udp)%2))
	copy(checksumInput[0:4], source[:])
	copy(checksumInput[4:8], destination[:])
	checksumInput[9] = 17
	binary.BigEndian.PutUint16(checksumInput[10:12], uint16(len(udp)))
	copy(checksumInput[12:], udp)
	checksum := testTransportChecksumV1(checksumInput)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[26:28], checksum)
	clear(checksumInput)
	return packet
}

func testIPv4TCPPacketV1(source, destination [4]byte, sourcePort, destinationPort uint16, flags byte, payload []byte) []byte {
	tcp := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], destinationPort)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(tcp[20:], payload)
	packet := testIPv4PacketV1(source, destination, 6, tcp)
	checksumInput := make([]byte, 12+len(tcp)+(len(tcp)%2))
	copy(checksumInput[0:4], source[:])
	copy(checksumInput[4:8], destination[:])
	checksumInput[9] = 6
	binary.BigEndian.PutUint16(checksumInput[10:12], uint16(len(tcp)))
	copy(checksumInput[12:], tcp)
	checksum := testTransportChecksumV1(checksumInput)
	binary.BigEndian.PutUint16(packet[36:38], checksum)
	clear(checksumInput)
	return packet
}

func testTransportChecksumV1(input []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(input); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(input[index : index+2]))
	}
	if len(input)%2 != 0 {
		sum += uint32(input[len(input)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func TestPacketPumpV1CarriesPacketsBothDirections(t *testing.T) {
	clientEndpoint, relayEndpoint, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, clientEndpoint, relayEndpoint, exporter)
	clientCarrier, relayCarrier := net.Pipe()
	clientTUN := newMemoryPacketDeviceV1()
	relayTUN := newMemoryPacketDeviceV1()
	assigned := [4]byte{10, 89, 0, 2}
	program := testDuplexProgramV1()
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
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

	var snapshots map[string]PacketPumpSnapshotV1
	deadline := time.Now().Add(time.Second)
	for {
		snapshots = map[string]PacketPumpSnapshotV1{
			"client": clientPump.SnapshotV1(),
			"relay":  relayPump.SnapshotV1(),
		}
		if snapshots["client"].CarrierRecordsWritten > 0 && snapshots["relay"].CarrierRecordsWritten > 0 &&
			snapshots["client"].TUNPacketsWritten == 1 && snapshots["relay"].TUNPacketsWritten == 1 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	for name, snapshot := range snapshots {
		if snapshot.TUNPacketsRead != 1 || snapshot.OutboundPacketsAccepted != 1 || snapshot.CarrierRecordsWritten == 0 ||
			snapshot.CarrierRecordsRead == 0 || snapshot.AuthenticatedOperations != 1 || snapshot.InnerPacketsAccepted != 1 ||
			snapshot.InnerPacketsRejected != 0 || snapshot.TUNWriteAttempts != 1 || snapshot.TUNWriteFailures != 0 ||
			snapshot.TUNPacketsWritten != 1 || snapshot.RejectedTUNPackets != 0 {
			t.Fatalf("%s packet-pump snapshot=%+v", name, snapshot)
		}
	}
	for name, results := range map[string]<-chan error{"client": clientResults, "relay": relayResults} {
		select {
		case err := <-results:
			t.Fatalf("%s pump stopped before cancellation: %v", name, err)
		default:
		}
	}

	cancel()
	for name, results := range map[string]<-chan error{"client": clientResults, "relay": relayResults} {
		select {
		case err := <-results:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Fatalf("%s pump=%v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("pump did not stop")
		}
	}
}

func TestPacketPumpV1CarriesAssignedTunnelDNSGatewayToRelayTUN(t *testing.T) {
	clientEndpoint, relayEndpoint, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, clientEndpoint, relayEndpoint, exporter)
	clientCarrier, relayCarrier := net.Pipe()
	clientTUN := newMemoryPacketDeviceV1()
	relayTUN := newMemoryPacketDeviceV1()
	assigned := [4]byte{10, 89, 1, 2}
	program := testDuplexProgramV1()
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer clientPump.Close()
	defer relayPump.Close()
	clientResults := make(chan error, 1)
	relayResults := make(chan error, 1)
	go func() { clientResults <- clientPump.Run(ctx) }()
	go func() { relayResults <- relayPump.Run(ctx) }()

	query := testIPv4UDPPacketV1(assigned, testTunnelDNSIPv4V1, 40000, 53, []byte{0, 1, 0, 0})
	clientTUN.injectV1(t, query)
	if got := receivePacketOrFailureV1(t, relayTUN, clientResults, relayResults); string(got) != string(query) {
		t.Fatal("relay DNS packet mismatch")
	}
	snapshot := relayPump.SnapshotV1()
	if snapshot.RelayGatewayDNSPackets != 1 || snapshot.RelayGatewayDNSChecksumFailures != 0 || snapshot.RelayTransportMalformedPackets != 0 {
		t.Fatalf("relay DNS classification snapshot=%+v", snapshot)
	}
}

func TestRelayPacketPumpSnapshotCountsOnlyAggregateReturnTCPMetadata(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	carrier, peer := net.Pipe()
	defer peer.Close()
	assigned := [4]byte{10, 89, 0, 2}
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{
		TUN: device, Carrier: carrier, Endpoint: clientEndpoint, Program: testDuplexProgramV1(),
		Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 1,
		BufferBudget: 12288, IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pump.Close()
	output := make(chan []byte, 1)
	failures := make(chan error, 1)
	go pump.readTUNV1(ctx, output, failures)
	packet := testIPv4TCPPacketV1([4]byte{198, 51, 100, 8}, assigned, 443, 40000, 0x12, nil)
	device.injectV1(t, packet)
	select {
	case got := <-output:
		clear(got)
	case err := <-failures:
		t.Fatalf("return packet failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("return packet was not read")
	}
	snapshot := pump.SnapshotV1()
	if snapshot.RelayReturnTCPPackets != 1 || snapshot.RelayReturnTCPSYNPackets != 1 ||
		snapshot.RelayReturnTCPACKPackets != 1 || snapshot.RelayReturnTCPRSTPackets != 0 ||
		snapshot.RelayReturnTCPFINPackets != 0 || snapshot.RelayReturnTCPChecksumFailures != 0 ||
		snapshot.RelayReturnOversizePackets != 0 {
		t.Fatalf("return TCP snapshot=%+v", snapshot)
	}
}

func TestPacketPumpV1CommitsEachAuthenticatedPacketBeforeOpeningTheNext(t *testing.T) {
	clientEndpoint, relayEndpoint, exporter := newProcessDuplexPairV1(t)
	bindProcessDuplexPairV1(t, clientEndpoint, relayEndpoint, exporter)
	clientCarrier, relayCarrier := net.Pipe()
	clientTUN := newMemoryPacketDeviceV1()
	relayTUN := newMemoryPacketDeviceV1()
	assigned := [4]byte{10, 89, 0, 2}
	program := testDuplexProgramV1()
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 4, IncompleteOps: 4, BufferBudget: 32768, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 4, IncompleteOps: 4, BufferBudget: 32768, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clientResults := make(chan error, 1)
	relayResults := make(chan error, 1)
	go func() { clientResults <- clientPump.Run(ctx) }()
	go func() { relayResults <- relayPump.Run(ctx) }()
	for sequence := byte(1); sequence <= 4; sequence++ {
		clientTUN.injectV1(t, testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{sequence}))
	}
	for sequence := byte(1); sequence <= 4; sequence++ {
		packet := receivePacketOrFailureV1(t, relayTUN, clientResults, relayResults)
		if packet[len(packet)-1] != sequence {
			t.Fatalf("packet %d delivered out of order", sequence)
		}
	}
	cancel()
	_ = clientPump.Close()
	_ = relayPump.Close()
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
	program := testDuplexProgramV1()
	for name, config := range map[string]PacketPumpConfigV1{
		"queue above process ceiling": {
			TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1,
			QueuePackets: 257, IncompleteOps: 1, BufferBudget: 1 << 24, IdleTimeout: time.Second,
		},
		"incomplete above process ceiling": {
			TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1,
			QueuePackets: 1, IncompleteOps: 65, BufferBudget: 1 << 24, IdleTimeout: time.Second,
		},
		"assigned IPv4 without signed DNS": {
			TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1,
			AssignedIPv4: [4]byte{10, 89, 1, 2}, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 1 << 24, IdleTimeout: time.Second,
		},
		"signed DNS without assigned IPv4": {
			TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1,
			DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 1 << 24, IdleTimeout: time.Second,
		},
		"client and signed DNS addresses collide": {
			TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1,
			AssignedIPv4: testTunnelDNSIPv4V1, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 1 << 24, IdleTimeout: time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewPacketPumpV1(config); !errors.Is(err, ErrPacketPumpConfig) {
				t.Fatalf("unsafe process bound was accepted: %v", err)
			}
		})
	}
}

func TestPacketPumpV1AllowsSignedQueueBoundsIndependentOfWireConcurrency(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	carrier, peer := net.Pipe()
	defer carrier.Close()
	defer peer.Close()
	program := testDuplexProgramV1()
	const queuePackets = uint16(100)
	const incompleteOps = uint16(64)
	maxPacket := min(program.Limits.MaxPayloadBytes, 65535)
	budget := uint64(maxPacket) * uint64(queuePackets+incompleteOps)
	if _, err := NewPacketPumpV1(PacketPumpConfigV1{
		TUN: device, Carrier: carrier, Endpoint: clientEndpoint, Program: program,
		Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1,
		QueuePackets: queuePackets, IncompleteOps: incompleteOps,
		BufferBudget: budget, IdleTimeout: time.Second,
	}); err != nil {
		t.Fatalf("signed queue bounds were incorrectly coupled to wire concurrency: %v", err)
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
	clientPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: clientTUN, Carrier: clientCarrier, Endpoint: clientEndpoint, Program: program, Direction: DirectionClientV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	relayPump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: relayTUN, Carrier: relayCarrier, Endpoint: relayEndpoint, Program: program, Direction: DirectionRelayV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 2, BufferBudget: 16384, IdleTimeout: time.Second})
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
	if got := relayPump.SnapshotV1().TUNWriteFailureCode; got != PacketPumpTUNWriteFailureShortV1 {
		t.Fatalf("TUN write failure code=%q", got)
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

func TestPacketPumpTUNWriteFailureClassificationPreservesOnlyBoundedErrno(t *testing.T) {
	code, errno := classifyPacketPumpTUNWriteFailureV1(0, 1, os.NewSyscallError("write", syscall.EINVAL))
	if got := packetPumpTUNWriteFailureCodeV1(code); got != PacketPumpTUNWriteFailureInvalidV1 {
		t.Fatalf("failure code=%q", got)
	}
	if errno != uint32(syscall.EINVAL) {
		t.Fatalf("errno=%d", errno)
	}
}

func TestPacketPumpV1OutboundQueueFullFailsClosed(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	carrier, peer := net.Pipe()
	defer peer.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: carrier, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: time.Second})
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

func TestPacketPumpV1DropsBoundedInvalidTUNPacketsWithoutForwarding(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, peer := net.Pipe()
	defer peer.Close()
	assigned := [4]byte{10, 89, 0, 2}
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{
		TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(),
		Direction: DirectionClientV1, AssignedIPv4: assigned, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 1,
		BufferBudget: 12288, IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := make(chan []byte, 1)
	failures := make(chan error, 1)
	go pump.readTUNV1(ctx, output, failures)
	// A kernel packet from a stale or otherwise unassigned tunnel source must be
	// discarded on the client. Sending it to the relay would turn one harmless
	// local packet into a fail-closed authenticated-session rejection.
	device.injectV1(t, testIPv4PacketV1([4]byte{10, 89, 0, 3}, [4]byte{1, 1, 1, 1}, 17, []byte{1}))
	want := testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 17, []byte{2})
	device.injectV1(t, want)
	select {
	case got := <-output:
		if string(got) != string(want) {
			t.Fatal("valid packet changed after rejected kernel packet")
		}
		clear(got)
	case err := <-failures:
		t.Fatalf("bounded invalid packet terminated pump: %v", err)
	case <-time.After(time.Second):
		t.Fatal("valid packet was not forwarded")
	}
	if got := pump.SnapshotV1().RejectedTUNPacketCode; got != PacketRejectionSourceV1 {
		t.Fatalf("rejection code=%v, want %v", got, PacketRejectionSourceV1)
	}
	cancel()
	_ = pump.Close()
}

func TestPacketPumpV1InvalidTUNPacketFloodFailsClosed(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, peer := net.Pipe()
	defer peer.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{
		TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(),
		Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 2, IncompleteOps: 1,
		BufferBudget: 12288, IdleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	output := make(chan []byte, 1)
	failures := make(chan error, 1)
	go pump.readTUNV1(context.Background(), output, failures)
	for index := 0; index <= maxRejectedTUNPacketsV1; index++ {
		device.injectV1(t, testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{224, 0, 0, 22}, 1, []byte{byte(index)}))
	}
	select {
	case err := <-failures:
		if !errors.Is(err, ErrPacketDestination) {
			t.Fatalf("invalid flood result=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("invalid packet flood did not fail closed")
	}
	_ = pump.Close()
}

func TestPacketPumpV1IdleTimeoutIsTerminal(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, two := net.Pipe()
	defer two.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: 40 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := pump.Run(context.Background()); !errors.Is(err, ErrLinkFailure) {
		t.Fatalf("idle result=%v", err)
	}
}

func TestPacketPumpV1ReportsUnexpectedTUNClosureCategorically(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, two := net.Pipe()
	defer two.Close()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = device.Close()
	err = pump.Run(context.Background())
	if stage, ok := PacketPumpFailureStageV1(err); !ok || stage != PacketPumpStageTUNReadV1 || !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected terminal result: stage=%q ok=%v err=%v", stage, ok, err)
	}
	if strings.Contains(err.Error(), "EOF") {
		t.Fatalf("terminal error leaked its wrapped cause: %q", err)
	}
}

func TestPacketPumpV1ReportsUnexpectedCarrierClosureCategorically(t *testing.T) {
	clientEndpoint, _, _ := newProcessDuplexPairV1(t)
	device := newMemoryPacketDeviceV1()
	one, two := net.Pipe()
	pump, err := NewPacketPumpV1(PacketPumpConfigV1{TUN: device, Carrier: one, Endpoint: clientEndpoint, Program: testDuplexProgramV1(), Direction: DirectionClientV1, AssignedIPv4: [4]byte{10, 89, 0, 2}, DNSIPv4: testTunnelDNSIPv4V1, QueuePackets: 1, IncompleteOps: 1, BufferBudget: 8192, IdleTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_ = two.Close()
	err = pump.Run(context.Background())
	if stage, ok := PacketPumpFailureStageV1(err); !ok || stage != PacketPumpStageCarrierReadV1 || !errors.Is(err, io.EOF) {
		t.Fatalf("unexpected terminal result: stage=%q ok=%v err=%v", stage, ok, err)
	}
}

func TestPacketPumpV1SuppressesFailuresAfterAuthoritativeTeardown(t *testing.T) {
	t.Run("canceled", func(t *testing.T) {
		pump := &PacketPumpV1{closed: make(chan struct{})}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assertPacketPumpFailureSuppressedV1(t, pump, ctx)
	})
	t.Run("closed", func(t *testing.T) {
		pump := &PacketPumpV1{closed: make(chan struct{})}
		close(pump.closed)
		assertPacketPumpFailureSuppressedV1(t, pump, context.Background())
	})
}

func assertPacketPumpFailureSuppressedV1(t *testing.T, pump *PacketPumpV1, ctx context.Context) {
	t.Helper()
	for attempt := 0; attempt < 256; attempt++ {
		failures := make(chan error, 1)
		pump.reportFailureV1(ctx, failures, ErrPacketPumpIO)
		select {
		case err := <-failures:
			t.Fatalf("teardown failure escaped on attempt %d: %v", attempt, err)
		default:
		}
	}
}

type memoryPacketDeviceV1 struct {
	read   chan []byte
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

type shortWritePacketDeviceV1 struct{ *memoryPacketDeviceV1 }

type closeOrderEndpointV1 struct{ ProcessDuplexEndpointV1 }

func (closeOrderEndpointV1) Abort() {}

type closeSignalPacketDeviceV1 struct {
	closed chan struct{}
	once   sync.Once
}

func (*closeSignalPacketDeviceV1) Read([]byte) (int, error)        { return 0, io.EOF }
func (*closeSignalPacketDeviceV1) Write(value []byte) (int, error) { return len(value), nil }
func (device *closeSignalPacketDeviceV1) Close() error {
	device.once.Do(func() { close(device.closed) })
	return nil
}

type blockingClosePacketDeviceV1 struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*blockingClosePacketDeviceV1) Read([]byte) (int, error)        { return 0, io.EOF }
func (*blockingClosePacketDeviceV1) Write(value []byte) (int, error) { return len(value), nil }
func (device *blockingClosePacketDeviceV1) Close() error {
	device.once.Do(func() {
		close(device.started)
		<-device.release
	})
	return nil
}

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

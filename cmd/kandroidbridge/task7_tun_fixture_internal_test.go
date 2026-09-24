//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	kruntime "kurdistan/internal/runtime"
	"testing"
	"time"
)

// Hand-built request. The response builder under test is not used as an oracle.
func task7TunRequestTestV1() []byte {
	p := make([]byte, 44)
	copy(p, []byte{0x45, 0, 0, 44, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1, 0xc0, 0x01, 0x6f, 0x38, 0, 24, 0, 0})
	copy(p[28:], []byte{'K', '7', 'T', '1', 2, 1})
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:12], ^uint16(sum))
	return p
}
func task7TunHarnessTestV1(t *testing.T) (*kruntime.PacketPortV1, context.CancelFunc, <-chan error) {
	t.Helper()
	p, e := kruntime.NewPacketPortV1(1280)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- task7RunTunResponderV1(ctx, p, [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}, 1280) }()
	t.Cleanup(func() { cancel(); p.Close() })
	return p, cancel, done
}
func task7TunJoinTestV1(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case e := <-done:
		return e
	case <-time.After(time.Second):
		t.Fatal("responder did not join")
		return nil
	}
}
func task7TunWriteTestV1(t *testing.T, p *kruntime.PacketPortV1, b []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		n, e := p.Write(b)
		if e == nil && n != len(b) {
			t.Errorf("write length %d", n)
		}
		done <- e
	}()
	if e := task7TunJoinTestV1(t, done); e != nil {
		t.Fatal(e)
	}
}
func TestTask7TunResponderReturnsTwoExactPackets(t *testing.T) {
	p, cancel, done := task7TunHarnessTestV1(t)
	task7TunWriteTestV1(t, p, task7TunRequestTestV1())
	for seq := byte(1); seq <= 2; seq++ {
		b := make([]byte, 1280)
		n, e := p.Read(b)
		if e != nil || n != 44 {
			t.Fatalf("read %d %v", n, e)
		}
		if string(b[28:32]) != "K7R1" || b[32] != 2 || b[33] != seq || binary.BigEndian.Uint16(b[4:6]) != uint16(seq) || b[8] != 64 {
			t.Fatal("response identity")
		}
		if string(b[12:20]) != string([]byte{10, 77, 0, 1, 10, 77, 0, 2}) || binary.BigEndian.Uint16(b[20:22]) != 28472 || binary.BigEndian.Uint16(b[22:24]) != 49153 {
			t.Fatal("response tuple")
		}
		for _, v := range b[34:44] {
			if v != 0 {
				t.Fatal("response padding")
			}
		}
		sum := uint32(17 + 24)
		for i := 12; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		for i := 20; i < 44; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = sum&65535 + sum>>16
		}
		if sum != 65535 {
			t.Fatal("UDP checksum")
		}
		sum = 0
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		for sum>>16 != 0 {
			sum = sum&65535 + sum>>16
		}
		if sum != 65535 {
			t.Fatal("IP checksum")
		}
	}
	cancel()
	p.Close()
	task7TunJoinTestV1(t, done)
}
func TestTask7TunResponderRejectsNonFixturePackets(t *testing.T) {
	p, _, done := task7TunHarnessTestV1(t)
	for i := 0; i < 64; i++ {
		b := task7TunRequestTestV1()
		b[28] = 'X'
		task7TunWriteTestV1(t, p, b)
	}
	if task7TunJoinTestV1(t, done) == nil {
		t.Fatal("packet bound accepted")
	}
}
func TestTask7TunResponderCancellationJoinsBlockedReceive(t *testing.T) {
	p, cancel, done := task7TunHarnessTestV1(t)
	cancel()
	p.Close()
	task7TunJoinTestV1(t, done)
}
func TestTask7TunResponderCancellationJoinsBlockedSubmit(t *testing.T) {
	p, cancel, done := task7TunHarnessTestV1(t)
	task7TunWriteTestV1(t, p, task7TunRequestTestV1())
	// Observe an actual queued reply without consuming it. The next serial
	// Submit cannot progress while this real one-slot port remains occupied.
	if _, err := p.Read(make([]byte, 43)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal("first response not retained in the actual port")
	}
	select {
	case <-done:
		t.Fatal("responder exited before blocked submit cancellation")
	default:
	}
	cancel()
	p.Close()
	task7TunJoinTestV1(t, done)
}
func TestTask7TunResponderRejectsDuplicateRequest(t *testing.T) {
	p, _, done := task7TunHarnessTestV1(t)
	task7TunWriteTestV1(t, p, task7TunRequestTestV1())
	for i := 0; i < 2; i++ {
		if _, e := p.Read(make([]byte, 1280)); e != nil {
			t.Fatal(e)
		}
	}
	task7TunWriteTestV1(t, p, task7TunRequestTestV1())
	if task7TunJoinTestV1(t, done) == nil {
		t.Fatal("duplicate accepted")
	}
}

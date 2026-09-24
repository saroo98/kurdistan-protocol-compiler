//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	kruntime "kurdistan/internal/runtime"
	"testing"
	"time"
)

func task7DNSQueryTestV1() []byte {
	// Independent literal query, transaction 0x1234, RD, one A/INET question.
	p := make([]byte, 61)
	copy(p, []byte{0x45, 0, 0, 61, 0, 1, 0x40, 0, 64, 17, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1, 0xc0, 1, 0, 53, 0, 41, 0, 0})
	copy(p[28:], []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'u', 'p', 'd', 'a', 't', 'e', 's', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1})
	task7DNSChecksumsTestV1(p)
	return p
}

func task7DNSChecksumsTestV1(p []byte) {
	p[10], p[11], p[26], p[27] = 0, 0, 0, 0
	checksum := func(parts ...[]byte) uint16 {
		var sum uint32
		for _, b := range parts {
			for i := 0; i < len(b); i += 2 {
				v := uint16(b[i]) << 8
				if i+1 < len(b) {
					v |= uint16(b[i+1])
				}
				sum += uint32(v)
			}
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	c := checksum(p[12:20], []byte{0, 17, 0, byte(len(p) - 20)}, p[20:])
	if c == 0 {
		c = 65535
	}
	binary.BigEndian.PutUint16(p[26:28], c)
}

func TestTask7MaintenanceDNSActualPacketPortReplyAndJoin(t *testing.T) {
	for _, mode := range []uint8{1, 2} {
		t.Run(string(rune('0'+mode)), func(t *testing.T) {
			p, err := kruntime.NewPacketPortV1(1280)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			defer p.Close()
			done := make(chan error, 1)
			go func() {
				done <- task7RunMaintenanceDNSResponderV1(ctx, p, [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}, 1280, mode)
			}()
			task7TunWriteTestV1(t, p, task7DNSQueryTestV1())
			var b [1500]byte
			n, err := p.Read(b[:])
			if err != nil {
				t.Fatal(err)
			}
			want := 92
			if mode == 2 {
				want = 61
			}
			if n != want {
				t.Fatalf("response size %d", n)
			}
			if !bytes.Equal(b[12:20], []byte{10, 77, 0, 1, 10, 77, 0, 2}) || binary.BigEndian.Uint16(b[20:22]) != 53 || binary.BigEndian.Uint16(b[22:24]) != 49153 {
				t.Fatal("wrong reply tuple")
			}
			copyB := append([]byte(nil), b[:n]...)
			task7DNSChecksumsTestV1(copyB)
			if !bytes.Equal(copyB, b[:n]) {
				t.Fatal("invalid response checksums")
			}
			var parser dnsmessage.Parser
			h, err := parser.Start(b[28:n])
			if err != nil || h.ID != 0x1234 || !h.Response || !h.RecursionDesired || h.Truncated != (mode == 2) {
				t.Fatal("reply header")
			}
			q, err := parser.Question()
			if err != nil || q.Name.String() != "updates.example." || q.Type != dnsmessage.TypeA || q.Class != dnsmessage.ClassINET {
				t.Fatal("reply question")
			}
			if _, err = parser.Question(); err != dnsmessage.ErrSectionDone {
				t.Fatal("extra question")
			}
			if mode == 1 {
				h, err := parser.AnswerHeader()
				if err != nil || h.Type != dnsmessage.TypeA || h.TTL != 1 {
					t.Fatal("answer header")
				}
				a, err := parser.AResource()
				if err != nil || a.A != [4]byte{8, 8, 8, 8} {
					t.Fatal("answer")
				}
			}
			if _, err = parser.AnswerHeader(); err != dnsmessage.ErrSectionDone {
				t.Fatal("extra answer")
			}
			cancel()
			p.Close()
			task7TunJoinTestV1(t, done)
		})
	}
}

func TestTask7MaintenanceDNSRejectsMalformedAndBoundsPackets(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(p []byte) { p[41] = 'x' }, func(p []byte) { p[58] = 28 }, func(p []byte) { p[60] = 2 },
		func(p []byte) { p[30] = 0x81 }, func(p []byte) { p[33] = 2 }, func(p []byte) { p[39] = 1 },
		func(p []byte) { p[6] = 0x20 }, func(p []byte) { p[19] = 9 }, func(p []byte) { p[23] = 54 },
	} {
		p := task7DNSQueryTestV1()
		mutate(p)
		task7DNSChecksumsTestV1(p)
		if task7MaintenanceDNSQueryV1(p, [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}) {
			t.Fatal("malformed query accepted")
		}
	}
	p, _ := kruntime.NewPacketPortV1(1280)
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- task7RunMaintenanceDNSResponderV1(ctx, p, [4]byte{10, 77, 0, 2}, [4]byte{10, 77, 0, 1}, 1280, 1)
	}()
	for i := 0; i < 64; i++ {
		b := task7DNSQueryTestV1()
		b[41] = 'x'
		task7DNSChecksumsTestV1(b)
		task7TunWriteTestV1(t, p, b)
	}
	if task7TunJoinTestV1(t, done) == nil {
		t.Fatal("quota exhaustion accepted")
	}
}

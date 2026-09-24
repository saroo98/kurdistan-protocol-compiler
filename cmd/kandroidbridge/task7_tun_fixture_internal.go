//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	kruntime "kurdistan/internal/runtime"
	"runtime"
)

var task7TunRejectedV1 = errors.New("task7_tun_fixture_rejected")

func task7TunChecksumV1(parts ...[]byte) uint16 {
	var sum uint32
	for _, b := range parts {
		for i := 0; i < len(b); i += 2 {
			sum += uint32(b[i]) << 8
			if i+1 < len(b) {
				sum += uint32(b[i+1])
			}
		}
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}

func task7TunRequestV1(p []byte, client, dns [4]byte) bool {
	if len(p) != 44 || p[0] != 0x45 || binary.BigEndian.Uint16(p[2:4]) != 44 ||
		binary.BigEndian.Uint16(p[6:8])&0xbfff != 0 || p[9] != 17 ||
		!bytes.Equal(p[12:16], client[:]) || !bytes.Equal(p[16:20], dns[:]) ||
		binary.BigEndian.Uint16(p[20:22]) == 0 || binary.BigEndian.Uint16(p[22:24]) != 28472 ||
		binary.BigEndian.Uint16(p[24:26]) != 24 || string(p[28:32]) != "K7T1" || p[32] < 2 || p[32] > 7 || p[33] != 1 {
		return false
	}
	for _, b := range p[34:] {
		if b != 0 {
			return false
		}
	}
	if _, err := kruntime.ValidateRelayOutboundIPPacketV1(p, client, dns, [16]byte{}, [16]byte{}); err != nil {
		return false
	}
	return binary.BigEndian.Uint16(p[26:28]) == 0 || task7TunChecksumV1(p[12:20], []byte{0, 17, 0, 24}, p[20:]) == 0
}

// Finite raw endpoint, not a DNS server or a general forwarding stack. All
// unsupported packets are consumed and dropped; no resolver or dial exists.
func task7RunTunResponderV1(ctx context.Context, port *kruntime.PacketPortV1, clientV4, dnsV4 [4]byte, mtu int) error {
	if port == nil || mtu < 44 || mtu > 1500 || clientV4 == ([4]byte{}) || dnsV4 == ([4]byte{}) {
		return task7TunRejectedV1
	}
	input := make([]byte, mtu)
	defer clear(input)
	var output [44]byte
	defer clear(output[:])
	matched := false
	for observed := 0; observed < 64; {
		token, n, err := port.Receive(ctx, input)
		// Acknowledge wakes the actual writer; it clears the receipt before the next
		// Receive can be admitted. Busy here is that bounded handoff, not a new slot.
		if errors.Is(err, kruntime.ErrPacketPortBusy) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			runtime.Gosched()
			continue
		}
		if err != nil {
			return err
		}
		observed++
		valid := task7TunRequestV1(input[:n], clientV4, dnsV4)
		if err = port.Acknowledge(ctx, token, n, nil); err != nil {
			return err
		}
		if !valid {
			continue
		}
		if matched {
			return task7TunRejectedV1
		}
		matched = true
		copy(output[:], input[:44])
		output[6] = 0
		output[7] = 0
		output[8] = 64
		copy(output[12:16], dnsV4[:])
		copy(output[16:20], clientV4[:])
		copy(output[20:22], input[22:24])
		copy(output[22:24], input[20:22])
		copy(output[28:32], "K7R1")
		for seq := byte(1); seq <= 2; seq++ {
			binary.BigEndian.PutUint16(output[4:6], uint16(seq))
			output[33] = seq
			output[10] = 0
			output[11] = 0
			binary.BigEndian.PutUint16(output[10:12], task7TunChecksumV1(output[:20]))
			output[26] = 0
			output[27] = 0
			checksum := task7TunChecksumV1(output[12:20], []byte{0, 17, 0, 24}, output[20:])
			if checksum == 0 {
				checksum = 65535
			}
			binary.BigEndian.PutUint16(output[26:28], checksum)
			if err = port.Submit(ctx, output[:]); err != nil {
				return err
			}
		}
	}
	return task7TunRejectedV1
}

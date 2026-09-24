//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	kruntime "kurdistan/internal/runtime"
	"runtime"
)

// One fixed, uncompressed A query. This fixture never resolves or dials a target.
func task7MaintenanceDNSQueryV1(p []byte, client, dns [4]byte) bool {
	if len(p) != 61 || p[0] != 0x45 || binary.BigEndian.Uint16(p[2:4]) != 61 ||
		binary.BigEndian.Uint16(p[6:8])&0xbfff != 0 || p[9] != 17 ||
		!bytes.Equal(p[12:16], client[:]) || !bytes.Equal(p[16:20], dns[:]) ||
		binary.BigEndian.Uint16(p[20:22]) == 0 || binary.BigEndian.Uint16(p[22:24]) != 53 ||
		binary.BigEndian.Uint16(p[24:26]) != 41 || task7TunChecksumV1(p[:20]) != 0 ||
		(binary.BigEndian.Uint16(p[26:28]) != 0 && task7TunChecksumV1(p[12:20], []byte{0, 17, 0, 41}, p[20:]) != 0) {
		return false
	}
	// Exact counts/flags and fixed uncompressed length exclude trailing or compressed data.
	if !bytes.Equal(p[30:40], []byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 0}) {
		return false
	}
	var parser dnsmessage.Parser
	if _, err := parser.Start(p[28:]); err != nil {
		return false
	}
	q, err := parser.Question()
	return err == nil && q.Name.String() == "updates.example." && q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET
}

func task7RunMaintenanceDNSResponderV1(ctx context.Context, port *kruntime.PacketPortV1, client, dns [4]byte, mtu int, mode uint8) error {
	if port == nil || mtu < 1280 || mtu > 1500 || (mode != 1 && mode != 2) || client == ([4]byte{}) || dns == ([4]byte{}) {
		return task7TunRejectedV1
	}
	var input, output [1500]byte
	var workspace [512]byte
	defer clear(input[:])
	defer clear(output[:])
	defer clear(workspace[:])
	matched := false
	for observed := 0; observed < 64; {
		token, n, err := port.Receive(ctx, input[:mtu])
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
		valid := task7MaintenanceDNSQueryV1(input[:n], client, dns)
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
		name, err := dnsmessage.NewName("updates.example.")
		if err != nil {
			return err
		}
		builder := dnsmessage.NewBuilder(workspace[:0], dnsmessage.Header{ID: binary.BigEndian.Uint16(input[28:30]), Response: true, RecursionDesired: true, Truncated: mode == 2})
		if err = builder.StartQuestions(); err != nil {
			return err
		}
		if err = builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			return err
		}
		if mode == 1 {
			if err = builder.StartAnswers(); err != nil {
				return err
			}
			if err = builder.AResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: [4]byte{8, 8, 8, 8}}); err != nil {
				return err
			}
		}
		payload, err := builder.Finish()
		if err != nil {
			return err
		}
		want := 64
		if mode == 2 {
			want = 33
		}
		if len(payload) != want {
			return task7TunRejectedV1
		}
		total := 28 + len(payload)
		copy(output[:28], input[:28])
		output[6] = 0
		output[7] = 0
		output[8] = 64
		binary.BigEndian.PutUint16(output[2:4], uint16(total))
		copy(output[12:16], dns[:])
		copy(output[16:20], client[:])
		copy(output[20:22], input[22:24])
		copy(output[22:24], input[20:22])
		binary.BigEndian.PutUint16(output[24:26], uint16(total-20))
		copy(output[28:total], payload)
		output[10], output[11], output[26], output[27] = 0, 0, 0, 0
		binary.BigEndian.PutUint16(output[10:12], task7TunChecksumV1(output[:20]))
		checksum := task7TunChecksumV1(output[12:20], []byte{0, 17, 0, byte(total - 20)}, output[20:total])
		if checksum == 0 {
			checksum = 65535
		}
		binary.BigEndian.PutUint16(output[26:28], checksum)
		if err = port.Submit(ctx, output[:total]); err != nil {
			return err
		}
	}
	return task7TunRejectedV1
}

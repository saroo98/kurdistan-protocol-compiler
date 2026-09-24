//go:build phase18productiontest && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestProductionFacadeGenuineStreamReceiptsAndFINV1(t *testing.T) {
	t.Run("FIN", func(t *testing.T) {
		testProductionFacadeGenuineStreamV1(t, "", testProductionFacadeOpenStreamV1, testProductionFacadeStreamReceiveV1)
	})
	t.Run("repeated-confirmation", func(t *testing.T) {
		testProductionFacadeGenuineStreamV1(t, "repeated", testProductionFacadeOpenStreamV1, testProductionFacadeStreamReceiveV1)
	})
	t.Run("pending-receipt", func(t *testing.T) {
		testProductionFacadeGenuineStreamV1(t, "pending", testProductionFacadeOpenStreamV1, testProductionFacadeStreamReceiveV1)
	})
	t.Run("parent-cancel-pending-receipt", func(t *testing.T) {
		testProductionFacadeGenuineStreamV1(t, "parent-cancel", testProductionFacadeOpenStreamV1, testProductionFacadeStreamReceiveV1)
	})
}

func testProductionFacadeGenuineStreamV1(t *testing.T, fault string, open func(uint64, []byte) (uint64, int32), receive func(uint64, uint64, []byte) (int, uint64, int32), probes ...func(uint64, []byte, []byte) (int, int32)) {
	_, old, listener, snapshot, now := productionSignedNetworkServicesFixtureV1(t, false, true)
	settings := productionFixtureSettingsV1()
	binary.BigEndian.PutUint16(settings[53:55], 128)
	settings[58] = 2
	p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: old, settings: settings}
	request := productionOwnerRequestV1(p)
	defer clear(request)
	testAndroidResetV1()
	testAndroidCaptureV1(t, [5][]byte{old.input.VerifyRequest, old.input.ActivationRecord, old.input.RecipientRequest, old.input.RecipientPrivate, settings})
	parent := testProductionCanonicalOpenOwnerV1(t, request, make([]byte, 32768), 0)
	defer func() {
		if s := testProductionFacadeCloseV1(parent); s != 0 {
			t.Error("close", s)
		}
	}()
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ready := make(chan productionOwnerRelayV1, 1)
	peer := make(chan error, 1)
	go func() {
		peer <- productionOwnerPeerV1(ctx, listener, snapshot, now, false, productionLocalServiceNetworkV1{address: target.Addr().String()}, ready)
	}()
	event := make([]byte, 32800)
	n, s := testProductionFacadeControlV1(parent, event)
	if s != 0 || n < 46 || event[5] != 1 {
		t.Fatal("socket", n, s)
	}
	if s = testProductionFacadeSocketV1(parent, binary.BigEndian.Uint64(event[32:40])); s != 0 {
		t.Fatal("protect", s)
	}
	for _, kind := range []byte{2, 3, 4} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			n, s = testProductionFacadeControlV1(parent, event)
			if s != 20 || time.Now().After(deadline) {
				break
			}
		}
		if s != 0 || n < 32 || event[5] != kind {
			t.Fatal("control", n, s, event[5], kind)
		}
	}
	select {
	case <-ready:
	case err := <-peer:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	child, s := open(parent, []byte{1, 1, 0, 4, 8, 8, 8, 8, 1, 187})
	if s != 0 || child == 0 {
		t.Fatal("open stream", child, s)
	}
	if s = testProductionFacadeStreamCloseV1(parent, ^uint64(0)); s != 3 {
		t.Fatal("unknown stream close", s)
	}
	connection, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err = connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if s = testProductionFacadeStreamSendV1(parent, child, []byte{3, 5, 7}); s != 0 {
		t.Fatal("send", s)
	}
	var sent [3]byte
	if _, err = io.ReadFull(connection, sent[:]); err != nil || sent != [3]byte{3, 5, 7} {
		t.Fatal("sent", err)
	}
	if _, err = connection.Write([]byte{2, 4, 6}); err != nil {
		t.Fatal(err)
	}
	short := bytes.Repeat([]byte{0xa5}, 2)
	n, token, s := receive(parent, child, short)
	if s != 4 || n != 0 || token != 0 || !bytes.Equal(short, []byte{0xa5, 0xa5}) {
		t.Fatal("short stream", n, token, s)
	}
	out := make([]byte, 16384)
	n, token, s = receive(parent, child, out)
	if s != 0 || token == 0 || !bytes.Equal(out[:n], []byte{2, 4, 6}) {
		t.Fatal("receive", n, token, s)
	}
	if fault == "parent-cancel" {
		if s = testProductionFacadeCancelV1(parent); s != 0 {
			t.Fatal("parent cancellation", s)
		}
		testProductionCancelledParentStillRegisteredV1(t, parent)
		cancel()
		select {
		case <-peer:
		case <-time.After(3 * time.Second):
			t.Fatal("parent cancel peer join")
		}
		return
	}
	if fault == "pending" {
		if s = testProductionFacadeStreamCloseV1(parent, child); s != 7 {
			t.Fatal("pending receipt closed clean", s)
		}
		if s = testProductionFacadeCancelV1(parent); s != 0 {
			t.Fatal("pending cancel", s)
		}
		cancel()
		select {
		case <-peer:
		case <-time.After(3 * time.Second):
			t.Fatal("pending peer join")
		}
		return
	}
	if s = testProductionFacadeStreamConfirmV1(parent, child, token, n); s != 0 {
		t.Fatal("confirm", s)
	}
	if fault == "repeated" {
		if s = testProductionFacadeStreamConfirmV1(parent, child, token, n); s != 3 {
			t.Fatal("repeat", s)
		}
		if s = testProductionFacadeStreamHalfCloseV1(parent, child); s != 3 {
			t.Fatal("terminal parent accepted FIN", s)
		}
		if s = testProductionFacadeCancelV1(parent); s != 0 {
			t.Fatal("cancel", s)
		}
		cancel()
		select {
		case <-peer:
		case <-time.After(3 * time.Second):
			t.Fatal("repeat peer join")
		}
		return
	}
	for i := 0; i < 2; i++ {
		if s = testProductionFacadeStreamHalfCloseV1(parent, child); s != 0 {
			t.Fatal("FIN", s)
		}
	}
	if n, err = connection.Read(out); n != 0 || err != io.EOF {
		t.Fatal("destination FIN", n, err)
	}
	if err = connection.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, token, s = receive(parent, child, out); n != 0 || token != 0 || s != 19 {
		t.Fatal("actual EOF", n, token, s)
	}
	if s = testProductionFacadeStreamCloseV1(parent, child); s != 0 {
		t.Fatal("stream close", s)
	}
	if s = testProductionFacadeStreamCloseV1(parent, child); s != 0 {
		t.Fatal("repeat stream close", s)
	}
	probeCall := testProductionFacadeProbeV1
	if len(probes) > 0 {
		probeCall = probes[0]
	}
	probe := []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}
	probeShort := bytes.Repeat([]byte{0xa5}, 20)
	if n, s = probeCall(parent, probe, probeShort); n != 0 || s != 4 || !bytes.Equal(probeShort, bytes.Repeat([]byte{0xa5}, 20)) {
		t.Fatal("short probe", n, s)
	}
	result := make([]byte, 21)
	if n, s = probeCall(parent, probe, result); n != 21 || s != 0 || result[1] != 2 || result[3] != 1 || result[4] != 1 || result[5] != 0 || binary.BigEndian.Uint16(result[19:]) != 0 {
		t.Fatal("actual active probe", n, s)
	}
	probeConnection, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	probeConnection.Close()
	if s = testProductionFacadeCancelV1(parent); s != 0 {
		t.Fatal("cancel", s)
	}
	cancel()
	select {
	case <-peer:
	case <-time.After(3 * time.Second):
		t.Fatal("peer join")
	}
}

func TestProductionFacadeGenuinePacketReceiptsV1(t *testing.T) {
	testProductionFacadeGenuinePacketReceiptsV1(t, testProductionFacadeReceivePacketV1, false)
}

func testProductionFacadeGenuinePacketReceiptsV1(t *testing.T, receive func(uint64, []byte) (int, uint64, int32), failedPublication bool) {
	_, old, listener, snapshot, now := productionSignedNetworkServicesFixtureV1(t, true, false)
	settings := productionFixtureSettingsV1()
	// This selected request uses the supported128MiB ceiling, not auto80.
	binary.BigEndian.PutUint16(settings[53:55], 128)
	p := &productionOwnerFixturePlatformV1{productionFixturePlatformV1: old, settings: settings}
	request := productionOwnerRequestV1(p)
	defer clear(request)
	testAndroidResetV1()
	testAndroidCaptureV1(t, [5][]byte{old.input.VerifyRequest, old.input.ActivationRecord, old.input.RecipientRequest, old.input.RecipientPrivate, settings})
	parent := testProductionCanonicalOpenOwnerV1(t, request, make([]byte, 32768), 0)
	defer func() {
		if s := testProductionFacadeCloseV1(parent); s != 0 {
			t.Error("canonical close", s)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ready := make(chan productionOwnerRelayV1, 1)
	peer := make(chan error, 1)
	go func() {
		peer <- productionOwnerPeerV1(ctx, listener, snapshot, now, true, productionLocalServiceNetworkV1{}, ready)
	}()
	event := make([]byte, 32800)
	n, s := testProductionFacadeControlV1(parent, event)
	if s != 0 || n < 46 || event[5] != 1 {
		t.Fatal("socket event", n, s)
	}
	token := binary.BigEndian.Uint64(event[32:40])
	if s = testProductionFacadeSocketV1(parent, token); s != 0 {
		t.Fatal("protect", s)
	}
	for _, kind := range []byte{2, 3, 4} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			n, s = testProductionFacadeControlV1(parent, event)
			if s != 20 || time.Now().After(deadline) {
				break
			}
		}
		if s != 0 || n < 32 || event[5] != kind {
			t.Fatal("control", n, s, event[5], kind, "body status", binary.BigEndian.Uint16(event[32:34]))
		}
	}
	var relay productionOwnerRelayV1
	select {
	case relay = <-ready:
	case err := <-peer:
		t.Fatal("peer", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	inbound := productionOwnerPacketV1([4]byte{8, 8, 8, 8}, relay.plan.ClientIPv4, 443, 12345, 29)
	if err := relay.port.Submit(ctx, inbound); err != nil {
		t.Fatal(err)
	}
	short := bytes.Repeat([]byte{0xa5}, 40)
	n, token, s = receive(parent, short)
	if s != 4 || n != 0 || token != 0 || !bytes.Equal(short, bytes.Repeat([]byte{0xa5}, 40)) {
		t.Fatal("short consumed", n, token, s)
	}
	output := bytes.Repeat([]byte{0xa5}, 65535)
	n, token, s = receive(parent, output)
	if failedPublication {
		if s != 18 || n != 0 || token != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 65535)) {
			t.Fatal("failed publication escaped", n, token, s)
		}
		// JNI has ended its retained frame and actually finalized the parent.
		if s = testProductionFacadeCloseV1(parent); s != 0 {
			t.Fatal("post-End finalization missing", s)
		}
		cancel()
		select {
		case <-peer:
		case <-time.After(3 * time.Second):
			t.Fatal("failed publication peer join")
		}
		return
	}
	if s != 0 || token == 0 || !bytes.Equal(output[:n], inbound) {
		t.Fatal("actual inbound", n, token, s)
	}
	if s = testProductionFacadeConfirmPacketV1(parent, token, n); s != 0 {
		t.Fatal("confirm", s)
	}
	if s = testProductionFacadeConfirmPacketV1(parent, token, n); s != 3 {
		t.Fatal("repeat", s)
	}
	if s = testProductionFacadeCancelV1(parent); s != 0 {
		t.Fatal("cancel", s)
	}
	cancel()
	select {
	case <-peer:
	case <-time.After(3 * time.Second):
		t.Fatal("peer join")
	}
}

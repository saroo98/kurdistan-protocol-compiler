// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"encoding/binary"
	runtimeengine "kurdistan/internal/runtime"
	"testing"
)

type maintenanceCaptureBoundaryV1 struct {
	maintenanceNeverCalledPlatform
	matches int
}

func (p *maintenanceCaptureBoundaryV1) MatchMaintenanceCaptureV1(MaintenanceCurrentInputV1, []byte) int32 {
	p.matches++
	return 22
}

func TestMaintenanceWireBudgetDeficitPrecedesCaptureAllocationV1(t *testing.T) {
	settings := productionSettingsMessageV1(productionSettingsRowsV1(false))
	binary.BigEndian.PutUint16(settings[53:55], 40)
	input := productionOpenFixtureV1(2, settings, []byte{2}, []byte{3}, []byte{4}, []byte{5})
	for _, deficit := range []bool{false, true} {
		r := new(HandleRegistry)
		inv, result := NewMaintenanceOutputInvocationV1(r, new(maintenanceOutputTestV1), 1, 1, 0)
		if result != 0 {
			t.Fatal(result)
		}
		charge := uint64(40 << 20)
		wantStatus, wantMatches := int32(22), 1
		if deficit {
			charge++
			wantStatus, wantMatches = 2, 0
		}
		platform := new(maintenanceCaptureBoundaryV1)
		parent, status := OpenMaintenanceWireV1Scoped(r, input, nil, platform,
			MaintenanceConfigV1{OutputMetadataBytes: charge}, inv)
		if parent != 0 || status != wantStatus || platform.matches != wantMatches || platform.called {
			t.Fatalf("deficit=%v parent=%d status=%d matches=%d admission=%v", deficit, parent, status, platform.matches, platform.called)
		}
	}
}

func TestMaintenanceWireProbeAggregateAndPreflightV1(t *testing.T) {
	q := runtimeengine.ProbeRequestV1{TargetID: 1, Method: 1, Samples: 3, AttemptTimeoutMillis: 1000, TotalTimeoutMillis: 1000}
	result := runtimeengine.ProbeAggregateV1{Path: runtimeengine.ProbeDisconnectedTCPConnectV1, Attempted: 2, HasLatency: true, LatencyMicros: 1000, LossPermille: 500}
	wire, status := encodeProbeAggregateWireV1(q, result, 8, runtimeengine.ProbeDisconnectedTCPConnectV1)
	want := []byte{1, 1, 1, 2, 1, 1, 1, 1, 0, 0, 3, 232, 0, 0, 0, 0, 1, 244, 0, 0, 8}
	if status != 0 || !bytes.Equal(wire[:], want) {
		t.Fatal("actual count encoding", status, wire)
	}
	result.Path = runtimeengine.ProbeActiveRelayEndToEndV1
	if _, status = encodeProbeAggregateWireV1(q, result, 8, runtimeengine.ProbeDisconnectedTCPConnectV1); status != 18 {
		t.Fatal("active path admitted", status)
	}
	output := bytes.Repeat([]byte{0xa5}, 21)
	request := []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}
	if n, status := RunMaintenanceProbeWireV1Scoped(nil, 0, request, output[:20], MaintenanceOutputInvocationV1{}); n != 0 || status != 4 {
		t.Fatal("short output", n, status)
	}
	request[0] = 2
	if n, status := RunMaintenanceProbeWireV1Scoped(nil, 0, request, output, MaintenanceOutputInvocationV1{}); n != 0 || status != 2 {
		t.Fatal("invalid request", n, status)
	}
	if !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 21)) {
		t.Fatal("refusal changed bytes")
	}
}

func TestMaintenanceWireOpeningReusesExactKPOAndSettingsBudgetV1(t *testing.T) {
	for _, memory := range []uint16{0, 40, 80, 128, 512} {
		settings := productionSettingsMessageV1(productionSettingsRowsV1(false))
		binary.BigEndian.PutUint16(settings[53:55], memory)
		input := productionOpenFixtureV1(2, settings, []byte{2}, []byte{3}, []byte{4}, []byte{5})
		current, _, budget, status := decodeMaintenanceOpeningV1(input)
		want := uint64(memory) << 20
		if want == 0 {
			want = 80 << 20
		}
		want = min(want, 128<<20)
		if status != 0 || budget != want || current.VerifyRequest[0] != 2 || current.ActivationRecord[0] != 3 || current.RecipientRequest[0] != 4 || current.RecipientPrivate[0] != 5 {
			t.Fatalf("memory=%d budget=%d status=%d", memory, budget, status)
		}
		current.RecipientPrivate[0] = 9
		if input[len(input)-1] != 9 {
			t.Fatal("borrow copied")
		}
		input[5] = 1
		if _, _, _, s := decodeMaintenanceOpeningV1(input); s != 2 {
			t.Fatal("production purpose admitted", s)
		}
	}
}

func TestMaintenanceWireOpeningRejectsMalformedBeforeNativeV1(t *testing.T) {
	settings := productionSettingsMessageV1(productionSettingsRowsV1(false))
	input := productionOpenFixtureV1(2, settings, []byte{2}, []byte{3}, []byte{4}, []byte{5})
	for n := 0; n < len(input); n++ {
		h, s := OpenMaintenanceWireV1Scoped(nil, input[:n], nil, nil, MaintenanceConfigV1{}, MaintenanceOutputInvocationV1{})
		if h != 0 || s != 2 {
			t.Fatalf("truncation %d handle=%d status=%d", n, h, s)
		}
	}
	input[32+4] = 2
	if _, _, _, s := decodeMaintenanceOpeningV1(input); s != 2 {
		t.Fatal("malformed settings admitted", s)
	}
}

//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestProductionFacadeV1CanonicalOpenFreshAuthenticatedFixture(t *testing.T) {
	now := time.Now().UTC()
	fixture := newReleaseMaintenanceFixtureAt(t, now.Add(-2*time.Second))
	// Canonical KPS row8 covers automatic80, explicit80 and128 compatibility.
	// Native limits and complete measured external charge remain intact.
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000800000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
	for _, memory := range []uint16{0, 80, 128} {
		t.Run(fmt.Sprintf("memoryMiB=%d", memory), func(t *testing.T) {
			testAndroidResetV1()
			binary.BigEndian.PutUint16(settings[53:55], memory)
			rows := [5][]byte{fixture.current.VerifyRequest, fixture.current.ActivationRecord, fixture.current.RecipientRequest, fixture.current.RecipientPrivate, settings}
			ordered := [5][]byte{rows[4], rows[0], rows[1], rows[2], rows[3]}
			request := make([]byte, 32)
			copy(request, "KPO1")
			request[4], request[5] = 1, 1
			for i := 0; i < 3; i++ {
				binary.BigEndian.PutUint32(request[12+4*i:], uint32(len(ordered[i])))
			}
			binary.BigEndian.PutUint16(request[24:], uint16(len(ordered[3])))
			binary.BigEndian.PutUint16(request[26:], uint16(len(ordered[4])))
			for _, row := range ordered {
				request = append(request, row...)
			}
			binary.BigEndian.PutUint32(request[8:], uint32(len(request)))
			defer clear(request)
			testAndroidCaptureV1(t, rows)
			output := bytes.Repeat([]byte{0xa5}, 100000)
			want := int32(0)
			parent := testProductionCanonicalOpenOwnerV1(t, request, output[10:32778], want)
			if parent != 0 {
				testProductionCanonicalLifecycleV1(t, parent)
			}
			if want != 0 && !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, len(output))) {
				t.Fatal("refused opening changed output")
			}
			if !bytes.Equal(output[:10], bytes.Repeat([]byte{0xa5}, 10)) || !bytes.Equal(output[32778:], bytes.Repeat([]byte{0xa5}, 100000-32778)) {
				t.Fatal("canonical output escaped borrowed logical slice")
			}
		})
	}
}

func TestProductionFacadeV1CanonicalOpenPreflightAndClaimedFailure(t *testing.T) {
	testProductionCanonicalOpenPreflightV1(t)
}

func TestProductionFacadeV1DirectBackingUsesActualLayoutAndExactBudget(t *testing.T) {
	got, status := testProductionDirectBackingV1(128 << 20)
	if status != 0 || got < 17<<20 || got >= 40<<20 {
		t.Fatal("direct C owned backing invalid", got, status)
	}
	if exact, status := testProductionDirectBackingV1(got); status != 0 || exact != got {
		t.Fatal("exact capacity refused", exact, status)
	}
	if deficit, status := testProductionDirectBackingV1(got - 1); status != 5 || deficit != 0 {
		t.Fatal("one byte deficit admitted", deficit, status)
	}
	t.Logf("source-derived direct C external backing=%d", got)
}

func TestProductionOpenAdapterV1MalformedRequestRetainsExactPlatformHolder(t *testing.T) {
	testProductionOpenMalformedV1(t)
}

func TestProductionFacadeV1ScalarPreflightAndNativeIdentity(t *testing.T) {
	for _, parent := range []uint64{0, 1, 1 << 63, ^uint64(0)} {
		for _, reason := range []uint8{0, 4, 255} {
			if got := testProductionReconnectV1(parent, reason); got != 2 {
				t.Fatalf("invalid command status=%d", got)
			}
		}
	}
	if got := testProductionReconnectV1(0, 1); got != 2 {
		t.Fatalf("zero parent status=%d", got)
	}
	for _, parent := range []uint64{1, 1 << 63, ^uint64(0)} {
		if got := testProductionReconnectV1(parent, 1); got != 3 {
			t.Fatalf("opaque unknown parent status=%d", got)
		}
	}
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	f.end()
	// A gate-only identity is not native authority. The actual scoped native
	// method must reject it and the facade must End its borrowed frame.
	if got := testProductionReconnectV1(uint64(f.parent()), 1); got != 3 {
		t.Fatalf("gate-only parent status=%d", got)
	}
	f.retire(t)
}

func TestProductionFacadeV1ScalarNativeRefusals(t *testing.T) {
	for _, parent := range []uint64{1, 1 << 63, ^uint64(0)} {
		for i, got := range testProductionScalarRefusalsV1(parent) {
			if got != 3 {
				t.Fatalf("scalar %d unknown opaque parent status=%d", i, got)
			}
		}
	}
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	f.end()
	for i, got := range testProductionScalarRefusalsV1(uint64(f.parent())) {
		if got != 3 {
			t.Fatalf("scalar %d gate-only parent status=%d", i, got)
		}
	}
	f.retire(t)
}

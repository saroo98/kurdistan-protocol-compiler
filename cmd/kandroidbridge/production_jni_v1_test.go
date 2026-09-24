//go:build phase18jnitest && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/runtimepolicy"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestCanonicalJNIHostDefaultBudgetsV1(t *testing.T) {
	for _, kind := range []byte{1, 2} {
		for _, memory := range []uint16{0, 80, 128} {
			t.Run(fmt.Sprintf("kind=%d/memory=%d", kind, memory), func(t *testing.T) {
				request, _ := maintenanceFacadeOpeningAtMemoryV1(t, memory)
				request[5] = kind
				if kind == 1 {
					testProductionJNIHostOpeningV1(t, request, bytes.Repeat([]byte{0xa5}, 100000), false)
				} else {
					testMaintenanceJNIHostOpeningV1(t, request, false)
				}
			})
		}
	}
}

func TestMaintenanceJNIHostGenuineDisconnectedProbeV1(t *testing.T) {
	maintenanceGenuineProbeHostV1(t, testMaintenanceJNIHostProbeCallV1)
}

func TestMaintenanceJNIHostGenuineProbeTerminalV1(t *testing.T) {
	maintenanceGenuineProbeTerminalHostV1(t, testMaintenanceJNIHostProbeCallV1)
}

func TestMaintenanceJNIHostCommittedCopyBorrowerDelaysCancellationV1(t *testing.T) {
	policy := &runtimepolicy.ProbesV1{Targets: []runtimepolicy.ProbeTargetV1{{ID: 1, Address: []byte{8, 8, 8, 8}, Port: 443, Methods: []uint8{1}, Modes: []uint8{1}, TimeoutMillis: 1000}}, MaxConcurrentOperations: 1, MaxSamplesPerOperation: 1, MinAttemptIntervalMillis: 1000, MaxAttemptsPerMinute: 1, MaxOperationMillis: 30000}
	opening, _ := maintenanceFacadeOpeningWithProbesV1(t, 80, policy)
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	maintenanceDecisionHostRouteV1 = func(network string, dst netip.AddrPort) netip.AddrPort {
		if network != "tcp" || dst != netip.MustParseAddrPort("8.8.8.8:443") {
			t.Error("wrong signed target")
			return netip.AddrPort{}
		}
		return listener.Addr().(*net.TCPAddr).AddrPort()
	}
	t.Cleanup(func() { maintenanceDecisionHostRouteV1 = nil })
	parent := testMaintenanceCanonicalParentV1(t, opening)
	output := bytes.Repeat([]byte{0xa5}, 21)
	completed := make(chan int32, 1)
	testJNICopyArmV1()
	go func() {
		n, s := testMaintenanceJNIHostProbeCallV1(parent, []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}, output)
		if s == 0 && n != 21 {
			s = -1
		}
		completed <- s
	}()
	wait := func(condition func() bool) {
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for !condition() {
			select {
			case <-tick.C:
			case <-deadline.C:
				testJNICopyReleaseV1()
				t.Fatal("caller-side fence not reached")
			}
		}
	}
	wait(testJNICopyEnteredV1)
	if !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, 21)) {
		testJNICopyReleaseV1()
		t.Fatal("copy occurred before metadata barrier")
	}
	cancelled := make(chan int32, 1)
	go func() { cancelled <- testMaintenanceCanonicalCancelCallV1(parent) }()
	wait(func() bool {
		return androidbridge.MaintenanceStatusV1(&registry, androidbridge.Handle(parent)) == androidbridge.MaintenanceCancelled
	})
	select {
	case <-cancelled:
		testJNICopyReleaseV1()
		t.Fatal("cancellation acknowledged before committed C/JNI borrower End")
	default:
	}
	testJNICopyReleaseV1()
	select {
	case s := <-completed:
		if s != 0 || output[3] != 1 || output[4] != 1 {
			t.Fatal("committed winner lost its actual copy", s, output)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("copy borrower did not end")
	}
	select {
	case s := <-cancelled:
		if s != 0 {
			t.Fatal("drained cancellation", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not drain")
	}
}

func TestProductionJNIHostOpenActualCoreAndMetadataFailureV1(t *testing.T) {
	now := time.Now().UTC()
	fixture := newReleaseMaintenanceFixtureAt(t, now.Add(-2*time.Second))
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000800000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
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
	for _, failWrite := range []bool{false, true} {
		testAndroidResetV1()
		testAndroidCaptureV1(t, rows)
		output := bytes.Repeat([]byte{0xa5}, 100000)
		testProductionJNIHostOpeningV1(t, request, output, failWrite)
		if failWrite && !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, len(output))) {
			t.Fatal("failed JNI metadata published bytes")
		}
		if !bytes.Equal(output[:10], bytes.Repeat([]byte{0xa5}, 10)) || !bytes.Equal(output[32778:], bytes.Repeat([]byte{0xa5}, 100000-32778)) {
			t.Fatal("JNI escaped logical slice")
		}
	}
}

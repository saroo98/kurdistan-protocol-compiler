//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"kurdistan/internal/androidbridge"
	"net/netip"
	"testing"
	"time"
	"unsafe"
)

func TestAndroidPlatformV1OutputOverlapCountsAdmittedFramesAndSharedSlots(t *testing.T) {
	// Linux 64-bit payloads measured in the accepted platform lane: shared
	// platform registry 12816, embedded selected state 200, each observer 24.
	// Fixed native HandleRegistry is 8208: mutex8 + 64 slots*88 +
	// 64 scope records*40 + maintenance epoch8. It is charged here once.
	// The existing per-owner helper already includes one retained observer
	// and the selected state. Do not add either a second time here.
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Fatal("this exact-layout evidence lane requires a 64-bit target")
	}
	// Process update registry: sizeof registry56 + 64*entry64 = 4152.
	if got := productionProcessUpdateRatesV1.OwnedBytes(); got != 4152 {
		t.Fatal("update registry layout", got)
	}
	for _, tc := range []struct{ frames, want uint64 }{{1, 25000}, {2, 25024}, {267, 31384}} {
		got, code := androidOutputOverlapBackingV1(tc.frames)
		if code != androidbridge.CodeOK || got != tc.want {
			t.Fatalf("frames=%d payload=%d code=%d want=%d", tc.frames, got, code, tc.want)
		}
	}
	for _, frames := range []uint64{0, ^uint64(0)} {
		if got, code := androidOutputOverlapBackingV1(frames); code == androidbridge.CodeOK || got != 0 {
			t.Fatalf("invalid/overflow frames=%d payload=%d code=%d", frames, got, code)
		}
	}
}

func TestAndroidPlatformV1CaptureBackingIsChargedOnceToSelectedHolder(t *testing.T) {
	// One2721543-byte five-span backing, fixed capture/copy structures692.
	if got := androidCaptureBackingV1(); got != 2722235 {
		t.Fatal("capture overlap", got)
	}
	for _, tc := range []struct {
		kind uint8
		want uint64
	}{{1, 2722579}, {2, 2722715}} {
		if got := androidPlatformBackingV1(tc.kind); got != tc.want {
			t.Fatal("selected holder capture charge", tc.kind, got)
		}
	}
}

func TestAndroidPlatformV1FinalizeRequiresExactExistingHolder(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	if got := finalizeAndroidPlatformV1(p.owner, 2); got != androidbridge.CodeStateCorrupt {
		t.Fatal("wrong kind accepted", got)
	}
	if got := finalizeAndroidPlatformV1(p.owner+10000, 1); got != androidbridge.CodeStateCorrupt {
		t.Fatal("missing owner treated as clean", got)
	}
	if got := finalizeAndroidPlatformV1(p.owner, 1); got != androidbridge.CodeOK {
		t.Fatal("exact holder cleanup", got)
	}
	if got := finalizeAndroidPlatformV1(p.owner, 1); got != androidbridge.CodeStateCorrupt {
		t.Fatal("previous holder treated as current clean", got)
	}
}

func TestAndroidPlatformV1SharedFinalizerRejectsMissingLease(t *testing.T) {
	if got := testAndroidSharedFinalizerMissingLeaseV1(); got != 25 {
		t.Fatal("missing exact lease treated as finalized", got)
	}
}

func TestAndroidPlatformV1SharedFinalizerRequiresPostEndReleaseReceipt(t *testing.T) {
	for _, kind := range []uint8{1, 2} {
		for _, holder := range []bool{false, true} {
			testAndroidSharedFinalizerV1(t, kind, holder)
		}
	}
}

func TestAndroidPlatformV1RootsDestinationIsBoundedAndFailureWiped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int32
		mutate bool
		want   androidbridge.MaintenanceResultV1
	}{
		{"success", 0, false, 0}, {"failure", 12, false, 12}, {"metadata", 0, true, 23}, {"unknown", 256, false, 23},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := testAndroidPlatformV1(t, 2)
			testAndroidResultV1(17, tc.status)
			if tc.mutate {
				testAndroidMutateCaptureV1()
			}
			dst := bytes.Repeat([]byte{0xa5}, 1048576)
			n, result := p.SystemRootsInto(context.Background(), dst)
			if result != tc.want {
				t.Fatal(n, result)
			}
			if result == 0 {
				if n != 8 || !bytes.Equal(dst[:8], []byte{1, 0, 1, 0, 0, 0, 1, 0x30}) {
					t.Fatal("typed callback output", n)
				}
			} else if n != 0 || !bytes.Equal(dst, make([]byte, len(dst))) {
				t.Fatal("partial roots escaped", n)
			}
		})
	}
}

func TestAndroidPlatformV1AlreadyCancelledNetworkDoesNotConsumeLossSlot(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lease, status := p.AcquireNetwork(ctx); lease != nil || status != androidbridge.MaintenanceCancelled {
		t.Fatal(status)
	}
	lease, status1 := p.AcquireNetwork(context.Background())
	if lease == nil || status1 != 0 {
		t.Fatal("cancelled admission consumed fixed slot", status1)
	}
	if lease.Close() != 0 || registration.Close() != 0 {
		t.Fatal("cleanup")
	}
}

type androidExpectationProbeV1 struct {
	platform *androidPlatformV1
	called   bool
	matched  androidbridge.ErrorCode
}

func TestAndroidPlatformV1SocketRejectsFabricatedExpectation(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	for _, expected := range []*androidbridge.ProductionSocketExpectationV1{nil, {}} {
		if socket, status := p.RegisterProductionSocketV1(context.Background(), expected); socket != nil || status != 1 {
			t.Fatal("fabricated identity", status)
		}
	}
}

func TestAndroidPlatformV1FinalOwnerCloseRequiresActualRetiredChildrenAndRetainsFailure(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(7, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	if status := p.closeOwnedV1(); status != androidbridge.CodeStateCorrupt {
		t.Fatal("live child close", status)
	}
	if status := registration.Close(); status != androidbridge.CodeStateCorrupt {
		t.Fatal("failed cleanup healed", status)
	}
}

func TestAndroidPlatformV1FinalOwnerCloseAfterChildRetirementReleasesOnlyItsFixedSlot(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(7, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	if status := registration.Close(); status != 0 {
		t.Fatal(status)
	}
	if status := p.closeOwnedV1(); status != 0 {
		t.Fatal(status)
	}
	androidPlatformsV1.Lock()
	retained := p.stateV1() != nil
	androidPlatformsV1.Unlock()
	if retained {
		t.Fatal("clean fixed Go owner retained")
	}
	if p.beginV1() {
		t.Fatal("retired owner readmitted")
	}
}

func TestAndroidPlatformV1CheckedPrivateMetadataConfigRejectsOverflowAndUsesRealProcessOwners(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	for _, external := range []uint64{0, ^uint64(0)} {
		if _, status := androidProductionRuntimeConfigV1(p, external); status == 0 {
			t.Fatal("unbounded external charge", external)
		}
	}
	config, status := androidProductionRuntimeConfigV1(p, 4096)
	if status != 0 || config.Platform != p || config.ProbeRates != productionProcessProbeRatesV1 || config.OutputMetadataBytes <= 4096 {
		t.Fatal("actual private composition", status, config.OutputMetadataBytes)
	}
	m := testAndroidPlatformV1(t, 2)
	maintenance, status := androidMaintenanceRuntimeConfigV1(m, androidbridge.MaintenanceConfigV1{}, 4096)
	if status != 0 || maintenance.Transport != m || maintenance.ProbeRates != productionProcessProbeRatesV1 || maintenance.UpdateRates != productionProcessUpdateRatesV1 || maintenance.OutputMetadataBytes <= 4096 {
		t.Fatal("actual maintenance composition", status)
	}
	t.Logf("Go retained payload: production=%d maintenance=%d; fixed owner state=%d platform=%d signal=%d call=%d revision=%d publication=%d socket=%d network=%d observer=%d global64=%d",
		androidPlatformBackingV1(1), androidPlatformBackingV1(2), unsafe.Sizeof(androidPlatformStateV1{}), unsafe.Sizeof(androidPlatformV1{}),
		unsafe.Sizeof(androidSignalV1{}), unsafe.Sizeof(androidCallV1{}), unsafe.Sizeof(androidRevisionV1{}), unsafe.Sizeof(androidPublicationV1{}),
		unsafe.Sizeof(androidSocketV1{}), unsafe.Sizeof(androidNetworkV1{}), cOutputObserverBackingV1(), unsafe.Sizeof(androidPlatformsV1))
}

func TestAndroidPlatformV1ActualFinalCallbackFailureCannotHeal(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	testAndroidResultV1(19, 25)
	if status := p.closeOwnedV1(); status != androidbridge.CodeStateCorrupt {
		t.Fatal(status)
	}
	testAndroidResultV1(19, 0)
	if status := p.closeOwnedV1(); status != androidbridge.CodeStateCorrupt {
		t.Fatal("callback failure healed", status)
	}
}

type androidSocketProbeV1 struct {
	*androidPlatformV1
	reached chan androidbridge.ProductionSocketRegistrationV1
	result  chan int32
}

func (p *androidSocketProbeV1) RegisterProductionSocketV1(ctx context.Context, e *androidbridge.ProductionSocketExpectationV1) (androidbridge.ProductionSocketRegistrationV1, int32) {
	socket, status := p.androidPlatformV1.RegisterProductionSocketV1(ctx, e)
	p.reached <- socket
	p.result <- status
	return socket, status
}

func TestAndroidPlatformV1SocketUsesActualNativeExpectationAndRetiresBeforeConnect(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protected, has uint8
		network        uint64
		want           int32
	}{
		{"false protect", 0, 0, 0, 16},
		{"implicit absent", 1, 0, 0, 0},
		{"implicit injection", 1, 1, 1 << 63, 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newReleaseMaintenanceFixture(t)
			settings, _ := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0020001e0001000100000000")
			rows := [5][]byte{fixture.current.VerifyRequest, fixture.current.ActivationRecord, fixture.current.RecipientRequest, fixture.current.RecipientPrivate, settings}
			ordered := [5][]byte{rows[4], rows[0], rows[1], rows[2], rows[3]}
			request := make([]byte, 32)
			copy(request, "KPO1")
			request[4] = 1
			request[5] = 1
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
			p := testAndroidPlatformV1(t, 1)
			testAndroidCaptureV1(t, rows)
			probe := &androidSocketProbeV1{androidPlatformV1: p, reached: make(chan androidbridge.ProductionSocketRegistrationV1, 1), result: make(chan int32, 1)}
			config := productionRuntimeConfigV1(probe)
			config.Now = func() time.Time { return fixture.now }
			handle, _, status := androidbridge.OpenProductionV1(&registry, request, make([]byte, 32768), config)
			if status != 0 || handle == 0 {
				t.Fatal("actual native opening", status)
			}
			defer func() {
				if status := androidbridge.CloseProductionV1(&registry, handle); status != 0 {
					t.Error("native close", status)
				}
			}()
			var socket androidbridge.ProductionSocketRegistrationV1
			select {
			case socket = <-probe.reached:
			case <-time.After(5 * time.Second):
				t.Fatal("native socket expectation not reached")
			}
			if status := <-probe.result; status != 0 || socket == nil || !socket.BindingRequiredV1() {
				t.Fatal("socket registration", status)
			}
			// Do not submit a native Confirm command. The genuine transport remains
			// unconnected, and native Close must retire the adopted platform child.
			if status := socket.ConfirmV1(tc.protected, tc.has, tc.network); status != tc.want {
				t.Fatal("platform confirmation", status, "want", tc.want)
			}
		})
	}
}
func (p *androidExpectationProbeV1) RegisterProductionCurrentV1(_ uint64, expected *androidbridge.ProductionCurrentExpectationV1, _ func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	p.called = true
	p.matched = p.platform.matchProductionV1(expected)
	// Stop this test-only native opening after real expectation comparison.
	return nil, androidbridge.CodeStateCorrupt
}
func (p *androidExpectationProbeV1) RegisterProductionSocketV1(context.Context, *androidbridge.ProductionSocketExpectationV1) (androidbridge.ProductionSocketRegistrationV1, int32) {
	return nil, 18
}

func TestAndroidPlatformV1RealCurrentAndSettingsExpectation(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	settings, err := hex.DecodeString("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0020001e0001000100000000")
	if err != nil {
		t.Fatal(err)
	}
	rows := [5][]byte{fixture.current.VerifyRequest, fixture.current.ActivationRecord, fixture.current.RecipientRequest, fixture.current.RecipientPrivate, settings}
	ordered := [5][]byte{rows[4], rows[0], rows[1], rows[2], rows[3]}
	request := make([]byte, 32)
	copy(request, "KPO1")
	request[4] = 1
	request[5] = 1
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
	for mismatch := -1; mismatch < 5; mismatch++ {
		t.Run(string(rune('A'+mismatch+1)), func(t *testing.T) {
			p := testAndroidPlatformV1(t, 1)
			captured := rows
			if mismatch >= 0 {
				captured[mismatch] = bytes.Clone(rows[mismatch])
				captured[mismatch][len(captured[mismatch])-1] ^= 1
				defer clear(captured[mismatch])
			}
			testAndroidCaptureV1(t, captured)
			probe := &androidExpectationProbeV1{platform: p}
			config := productionRuntimeConfigV1(probe)
			config.Now = func() time.Time { return fixture.now }
			handle, _, status := androidbridge.OpenProductionV1(&registry, request, make([]byte, 32768), config)
			if handle != 0 || status == 0 || !probe.called {
				t.Fatal("did not reach real expectation", handle, status, probe.called)
			}
			if (probe.matched == 0) != (mismatch < 0) {
				t.Fatal("real expectation comparison", mismatch, probe.matched)
			}
		})
	}
}

func TestAndroidPlatformV1CaptureExactStagingAndWipe(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	var retained [5][]byte
	called := false
	status := p.withCaptureV1(func(rows [5][]byte) bool {
		called = true
		retained = rows
		for i, n := range [5]int{2, 3, 5, 7, 11} {
			if len(rows[i]) != n || cap(rows[i]) != n || !bytes.Equal(rows[i], bytes.Repeat([]byte{byte(i + 1)}, n)) {
				t.Fatal("exact immutable capture stage", i)
			}
		}
		return true
	})
	if status != androidbridge.CodeOK || !called {
		t.Fatal(status, called)
	}
	for _, row := range retained {
		for _, b := range row {
			if b != 0 {
				t.Fatal("staging survived callback")
			}
		}
	}
}
func TestAndroidPlatformV1MutatedCopyMetadataNeverReachesExpectation(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	testAndroidMutateCaptureV1()
	called := false
	status := p.withCaptureV1(func(rows [5][]byte) bool { called = true; return true })
	if status == androidbridge.CodeOK || called {
		t.Fatal("mutated capacity accepted", status, called)
	}
}
func TestAndroidPlatformV1SignalsAreExactAndOneUse(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	count := 0
	signal, status := p.reserveRevisionV1(9, func() androidbridge.ErrorCode { count++; return androidbridge.CodeStateCorrupt })
	if status != 0 || signal == 0 {
		t.Fatal(status)
	}
	if androidRevisionSignalV1(p.owner+1, signal) != androidbridge.CodeStateCorrupt || count != 0 {
		t.Fatal("wrong owner")
	}
	if androidRevisionSignalV1(p.owner, signal+1) != androidbridge.CodeStateCorrupt || count != 0 {
		t.Fatal("wrong signal")
	}
	if androidRevisionSignalV1(p.owner, signal) != androidbridge.CodeStateCorrupt || count != 1 {
		t.Fatal("exact sink")
	}
	if androidRevisionSignalV1(p.owner, signal) != androidbridge.CodeStateCorrupt || count != 1 {
		t.Fatal("duplicate sink")
	}
}

func TestAndroidPlatformV1MaintenanceComparesIndependentFiveSpans(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	rows := [5][]byte{}
	for i, n := range [5]int{2, 3, 5, 7, 11} {
		rows[i] = bytes.Repeat([]byte{byte(i + 1)}, n)
	}
	for mismatch := -1; mismatch < 5; mismatch++ {
		input := rows
		if mismatch >= 0 {
			input[mismatch] = bytes.Clone(rows[mismatch])
			input[mismatch][0] ^= 1
		}
		current := androidbridge.MaintenanceCurrentInputV1{VerifyRequest: input[0], ActivationRecord: input[1], RecipientRequest: input[2], RecipientPrivate: input[3]}
		status := p.matchMaintenanceV1(current, input[4])
		if (status == 0) != (mismatch < 0) {
			t.Fatal("five-span comparison", mismatch, status)
		}
	}
}

func TestAndroidPlatformV1OriginalContextLivesUntilActualCallbackReturn(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan uint64, 1)
	release := make(chan struct{})
	done := make(chan androidbridge.ErrorCode, 1)
	go func() {
		_, status := p.withCallV1(ctx, func(id uint64) int32 { entered <- id; <-release; return 0 })
		done <- status
	}()
	id := <-entered
	if actual, ok := androidCallContextV1(p.owner, id); !ok || actual != ctx {
		t.Fatal("original context replaced")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("cancellation replaced inflight callback")
	default:
	}
	close(release)
	if status := <-done; status != androidbridge.CodeCancelled {
		t.Fatal(status)
	}
	if _, ok := androidCallContextV1(p.owner, id); ok {
		t.Fatal("ended context retained as usable")
	}
}
func TestAndroidPlatformV1CancelledBeforeAdmissionDoesNotInvokeJava(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	_, status := p.withCallV1(ctx, func(uint64) int32 { called = true; return 0 })
	if status != androidbridge.CodeCancelled || called {
		t.Fatal(status, called)
	}
}

func TestAndroidPlatformV1AbsentJavaWaitCancellationDoesNotInventCleanupFailure(t *testing.T) {
	p := testAndroidPlatformV1(t, 1)
	testAndroidResultV1(18, 6)
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	finished := make(chan androidbridge.ErrorCode, 1)
	go func() {
		_, status := p.withCallV1(ctx, func(uint64) int32 { close(entered); <-ctx.Done(); return 0 })
		finished <- status
	}()
	<-entered
	cancel()
	if status := <-finished; status != androidbridge.CodeCancelled {
		t.Fatal("absent Java wait was relabelled cleanup failure", status)
	}
	androidPlatformsV1.Lock()
	failure := p.stateV1().failure
	androidPlatformsV1.Unlock()
	if failure != 0 {
		t.Fatal("no cleanup failure occurred", failure)
	}
}
func TestAndroidPlatformV1MaintenanceStatusValidatedBeforeNarrowing(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	if got := p.maintenanceStatusV1(256); got != androidbridge.MaintenanceInternalFailure {
		t.Fatal("wrapped M1", got)
	}
}

func TestAndroidPlatformV1PublicationIsOneFixedChildAndCannotOutliveRegistration(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if status != 0 || registration == nil {
		t.Fatal(status)
	}
	if status := registration.Revalidate(context.Background()); status != 0 {
		t.Fatal(status)
	}
	first, m1 := registration.AcquirePublication(context.Background())
	if m1 != 0 || first == nil || !first.IsCurrent() {
		t.Fatal(m1)
	}
	if second, status := registration.AcquirePublication(context.Background()); status == 0 || second != nil {
		t.Fatal("second simultaneous publication")
	}
	if status := first.Close(); status != 0 {
		t.Fatal(status)
	}
	if first.IsCurrent() {
		t.Fatal("released publication still current")
	}
	second, m1 := registration.AcquirePublication(context.Background())
	if m1 != 0 || second == nil || !second.IsCurrent() || first.IsCurrent() {
		t.Fatal("successor aliases old lease", m1)
	}
	if status := second.Close(); status != 0 {
		t.Fatal(status)
	}
	if status := registration.Close(); status != 0 {
		t.Fatal(status)
	}
	if first.IsCurrent() || second.IsCurrent() {
		t.Fatal("closed registration still current")
	}
}

func TestAndroidPlatformV1RegistrationResourceRefusalKeepsActualBridgeStatus(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	testAndroidResultV1(3, 24)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if registration != nil || status != androidbridge.CodeResourceLimit {
		t.Fatal("changed bridge refusal", status)
	}
}
func TestAndroidPlatformV1PartialPublicationCleanupFailureCannotHeal(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	testAndroidResultV1(5, 10)
	testAndroidResultV1(7, 14)
	publication, result := registration.AcquirePublication(context.Background())
	if publication != nil || result == 0 {
		t.Fatal("partial publication escaped", result)
	}
	androidPlatformsV1.Lock()
	retained := p.stateV1().publication
	androidPlatformsV1.Unlock()
	if retained == nil || retained.IsCurrent() {
		t.Fatal("failed cleanup ownership lost")
	}
	testAndroidResultV1(7, 0)
	if retained.Close() == 0 {
		t.Fatal("later success healed cleanup")
	}
}

func TestAndroidPlatformV1OriginalDeadlineIsNotRelabelledCancellation(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if result := registration.Revalidate(ctx); result != androidbridge.MaintenanceTimeout {
		t.Fatal("deadline namespace", result)
	}
	if result := registration.Close(); result != 0 {
		t.Fatal(result)
	}
}

func TestAndroidPlatformV1LossIsFixedTypedAndCannotReachReplacement(t *testing.T) {
	p := testAndroidPlatformV1(t, 2)
	registration, status := p.Register(9, func() androidbridge.ErrorCode { return 0 })
	if status != 0 {
		t.Fatal(status)
	}
	first, result := p.AcquireNetwork(context.Background())
	if result != 0 || first == nil || !first.IsCurrent() {
		t.Fatal(result)
	}
	var dns [4]netip.AddrPort
	if n, result := first.DNSServersInto(&dns); n != 1 || result != 0 || dns[0] != netip.MustParseAddrPort("1.1.1.1:53") {
		t.Fatal(n, result, dns)
	}
	androidPlatformsV1.Lock()
	old := p.stateV1().signals[1].id
	androidPlatformsV1.Unlock()
	if androidLossSignalV1(p.owner, old, 2) == 0 {
		t.Fatal("wrong typed loss accepted")
	}
	if androidLossSignalV1(p.owner, old, 3) != 0 || first.IsCurrent() {
		t.Fatal("loss did not close current")
	}
	select {
	case <-first.Done():
	default:
		t.Fatal("loss did not close Done")
	}
	if first.Close() != 0 {
		t.Fatal("network close")
	}
	second, result := p.AcquireNetwork(context.Background())
	if result != 0 || second == nil || !second.IsCurrent() {
		t.Fatal(result)
	}
	if androidLossSignalV1(p.owner, old, 3) == 0 || !second.IsCurrent() {
		t.Fatal("stale loss touched replacement")
	}
	if second.Close() != 0 || registration.Close() != 0 {
		t.Fatal("cleanup")
	}
}

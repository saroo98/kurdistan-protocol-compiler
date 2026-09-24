// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"bytes"
	"context"
	"math"
	"sync/atomic"
	"testing"
	"time"

	runtimeengine "kurdistan/internal/runtime"
)

type productionFailedOpenPlatformV1 struct{ *productionSnapshotPlatformV1 }

func TestProductionSessionV1AutomaticReconnectPublishesBeforeNextOpening(t *testing.T) {
	parent := newTestProductionParentV1(t, &HandleRegistry{}, time.Time{})
	parent.admission = &productionAdmissionV1{monotonicDeadline: time.Now().Add(time.Minute)}
	v := &productionSessionV1{parent: parent, runDone: make(chan int32, 1)}
	v.projection.effectiveAutomaticReconnectMax = 3
	v.projection.signedReconnectMax = 3
	for attempt := byte(1); attempt <= 3; attempt++ {
		run := make(chan int32, 1)
		run <- 9
		if !v.waitCommandV1(run) {
			t.Fatal("automatic reconnect refused", attempt)
		}
		if result := <-v.runDone; result != 9 {
			t.Fatal("lost joined result", result)
		}
		if parent.controlCount != 1 {
			t.Fatal("missing reconnect event before next opening", parent.controlCount)
		}
		out := make([]byte, 64)
		n, status := parent.nextControlV1(context.Background(), out)
		if status != 0 || n != 35 || out[5] != byte(productionControlReconnectStartedV1) || !bytes.Equal(out[32:n], []byte{2, attempt, 3}) {
			t.Fatal("automatic reconnect event", n, status, out[:n])
		}
	}
}

func (p productionFailedOpenPlatformV1) RegisterProductionCurrentV1(epoch uint64, expected *ProductionCurrentExpectationV1, invalidate func() ErrorCode) (MaintenanceRevisionRegistrationV1, ErrorCode) {
	_, code := p.productionSnapshotPlatformV1.RegisterProductionCurrentV1(epoch, expected, invalidate)
	return p, code
}

func (p productionFailedOpenPlatformV1) RegisterProductionSocketV1(context.Context, *ProductionSocketExpectationV1) (ProductionSocketRegistrationV1, int32) {
	return nil, 3 // This test must abort before a socket is requested.
}
func (p productionFailedOpenPlatformV1) AcquirePublication(ctx context.Context) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	p.expected.parent.uses[productionUseCoordinatorV1].serial = math.MaxUint64
	return productionFailedOpenLeaseV1{p}, p.Revalidate(ctx)
}

type productionFailedOpenLeaseV1 struct {
	p productionFailedOpenPlatformV1
}

func (l productionFailedOpenLeaseV1) IsCurrent() bool  { return l.p.expected.MatchesV1(l.p.snapshot) }
func (l productionFailedOpenLeaseV1) Close() ErrorCode { return CodeOK }

func TestProductionSessionV1PostAdmissionAbortRetainsFailedCleanupCharge(t *testing.T) {
	f := newMaintenanceSignedFixture(t)
	p := productionFailedOpenPlatformV1{&productionSnapshotPlatformV1{snapshot: f.current, closeCode: CodeStateCorrupt}}
	rates, _ := runtimeengine.NewProbeRateRegistryV1(64)
	factory := &productionReservationFixtureV1{}
	settings := productionDefaultSettingsBytesV1()
	parts := productionInputPartsV1(f.current)
	request := productionOpenFixtureV1(1, settings, parts[0], parts[1], parts[2], parts[3])
	var registry HandleRegistry
	out := bytes.Repeat([]byte{0x6a}, 32768)
	h, n, s := OpenProductionV1(&registry, request, out, ProductionSessionConfigV1{Environment: &productionRealCurrentV1{}, Platform: p, Factory: factory, ProbeRates: rates, Now: func() time.Time { return f.now }, MonotonicNow: time.Now})
	if h != 0 || n != 0 || s != 5 || !bytes.Equal(out, bytes.Repeat([]byte{0x6a}, 32768)) || factory.prepares != 0 {
		t.Fatal("post-admission abort", h, n, s, factory.prepares)
	}
	owner := p.expected.parent
	v := owner.session
	if !owner.budget.records[v.ticket.index].live || owner.cleanupResult != 3 || !registry.slots[owner.ticket.index].privatelyReserved {
		t.Fatal("failed cleanup released session attribution", owner.budget.records[v.ticket.index].live, owner.cleanupResult)
	}
}

func TestProductionSessionV1OpaqueIDsCannotCoincideAcrossParents(t *testing.T) {
	a, b := new(productionSessionV1), new(productionSessionV1)
	x, s := a.freshTokenLockedV1()
	y, other := b.freshTokenLockedV1()
	if s != 0 || other != 0 || x == 0 || y == 0 || x == y {
		t.Fatal("cross-parent receipt collision", x, y, s, other)
	}
	var exhausted atomic.Uint64
	exhausted.Store(math.MaxUint64)
	if id, s := nextProductionOpaqueIDV1(&exhausted); id != 0 || s != 5 || exhausted.Load() != math.MaxUint64 {
		t.Fatal("ID wrapped", id, s)
	}
}

func TestProductionSessionV1OutputAndPurposePreflightBeforeReservation(t *testing.T) {
	for _, capacity := range []int{0, 32767} {
		r := new(HandleRegistry)
		out := bytes.Repeat([]byte{0x5a}, capacity)
		h, n, s := OpenProductionV1(r, nil, out, ProductionSessionConfigV1{})
		if h != 0 || n != 0 || s != 4 || !bytes.Equal(out, bytes.Repeat([]byte{0x5a}, capacity)) {
			t.Fatal("output preflight", h, n, s)
		}
		for _, slot := range r.slots {
			if slot.privatelyReserved || slot.occupied {
				t.Fatal("preflight reserved slot")
			}
		}
	}
}

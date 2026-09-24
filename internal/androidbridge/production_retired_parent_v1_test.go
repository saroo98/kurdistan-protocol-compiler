// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"testing"
	"time"
)

// Isolates actual native parent cancellation/join/retirement from signed opening.
// Public C opening and post-End publication are covered by the tagged host lane.
func retiredProductionFixtureV1(t *testing.T, r *HandleRegistry) (*productionParentV1, Handle) {
	t.Helper()
	p := newTestProductionParentV1(t, r, time.Time{})
	r.mu.Lock()
	slot := &r.slots[p.ticket.index]
	slot.productionGeneration++
	h := encodeHandle(p.ticket.index, slot.productionGeneration, HandleProductionSession)
	r.mu.Unlock()
	p.outputHandle, p.output, p.outputOwner = h, new(productionOutputTestV1), 1
	return p, h
}

func retireProductionFixtureV1(t *testing.T, p *productionParentV1) {
	t.Helper()
	if s := p.cancelV1(7); s != 0 {
		t.Fatal("cancel", s)
	}
	if s := p.joinV1(context.Background()); s != 0 {
		t.Fatal("join", s)
	}
	if s := p.retireV1(); s != 0 {
		t.Fatal("retire", s)
	}
}

func TestRetiredProductionParentRequiresPostEndPublication(t *testing.T) {
	r := new(HandleRegistry)
	p, h := retiredProductionFixtureV1(t, r)
	if s, ok := RetiredProductionParentResultV1(r, h); ok || s != 3 {
		t.Fatal("live", s, ok)
	}
	retireProductionFixtureV1(t, p)
	if s, ok := RetiredProductionParentResultV1(r, h); ok || s != 3 {
		t.Fatal("native-only", s, ok)
	}
	PublishRetiredMaintenanceParentResultV1(r, h, MaintenanceSuccess)
	if s, ok := RetiredProductionParentResultV1(r, h); ok || s != 3 {
		t.Fatal("wrong-kind publication", s, ok)
	}
	PublishRetiredProductionParentResultV1(r, h, 18)
	if s, ok := RetiredProductionParentResultV1(r, h); !ok || s != 18 {
		t.Fatal("exact failed completion", s, ok)
	}
	PublishRetiredProductionParentResultV1(r, h, 0)
	if s, ok := RetiredProductionParentResultV1(r, h); !ok || s != 18 {
		t.Fatal("sticky completion", s, ok)
	}
	if s, ok := RetiredMaintenanceParentResultV1(r, h); ok || s != MaintenanceInvalidState {
		t.Fatal("wrong kind", s, ok)
	}
	for _, bad := range []Handle{0, h + 1, h + (1 << 16), h | (1 << 48)} {
		if s, ok := RetiredProductionParentResultV1(r, bad); ok || s != 3 {
			t.Fatal("unknown", s, ok)
		}
	}
}

func TestRetiredMaintenanceParentActualCleanupAndSharedReplacement(t *testing.T) {
	_, r, mh, _, _, inv := maintenanceOutputOpenFixtureV1(t)
	if s := CloseMaintenanceV1Scoped(r, mh, inv); s != 0 {
		t.Fatal("maintenance close", s)
	}
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); ok || s != MaintenanceInvalidState {
		t.Fatal("native-only", s, ok)
	}
	PublishRetiredMaintenanceParentResultV1(r, mh, MaintenanceSuccess)
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); !ok || s != 0 {
		t.Fatal("completed maintenance", s, ok)
	}
	p, ph := retiredProductionFixtureV1(t, r)
	if uint16(ph) != uint16(mh) {
		t.Fatal("not same slot")
	}
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); !ok || s != 0 {
		t.Fatal("occupancy evicted history", s, ok)
	}
	retireProductionFixtureV1(t, p)
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); ok || s != MaintenanceInvalidState {
		t.Fatal("new retirement did not evict", s, ok)
	}
	PublishRetiredMaintenanceParentResultV1(r, mh, MaintenanceSuccess)
	if s, ok := RetiredProductionParentResultV1(r, ph); ok || s != 3 {
		t.Fatal("old publish acknowledged new", s, ok)
	}
	PublishRetiredProductionParentResultV1(r, ph, 0)
	if s, ok := RetiredProductionParentResultV1(r, ph); !ok || s != 0 {
		t.Fatal("completed production", s, ok)
	}
	if c := r.Free(mh); c != CodeAlreadyClosed {
		t.Fatal("legacy free changed", c)
	}
	if c := r.Cancel(mh); c != CodeAlreadyClosed {
		t.Fatal("legacy cancel changed", c)
	}
}

func retiredMaintenanceStateV1(t *testing.T, r *HandleRegistry) (*maintenanceAuthorityV1, Handle) {
	t.Helper()
	p := newMaintenanceStateFixture(t)
	p.registry, p.output, p.outputOwner = r, new(maintenanceOutputTestV1), 1
	h, code := r.Open(HandleMaintenance, p)
	if code != CodeOK {
		t.Fatal(code)
	}
	p.handle, p.outputHandle = h, h
	return p, h
}

type retiredHeldRegistrationV1 struct {
	maintenanceClockAdvanceRegistration
	entered, release chan struct{}
	result           ErrorCode
}

func (r *retiredHeldRegistrationV1) Close() ErrorCode {
	close(r.entered)
	<-r.release
	return r.result
}

func TestRetiredMaintenanceParentDelayedCompletionCannotReplaceNewerProduction(t *testing.T) {
	r := new(HandleRegistry)
	mp, mh := retiredMaintenanceStateV1(t, r)
	registration := &retiredHeldRegistrationV1{entered: make(chan struct{}), release: make(chan struct{})}
	mp.registration = registration
	done := make(chan ErrorCode, 1)
	go func() { done <- r.Free(mh) }()
	<-registration.entered
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); ok || s != MaintenanceInvalidState {
		t.Fatal("pending cleanup", s, ok)
	}
	pp, ph := retiredProductionFixtureV1(t, r)
	if uint16(mh) != uint16(ph) {
		t.Fatal("not reused slot")
	}
	retireProductionFixtureV1(t, pp)
	PublishRetiredProductionParentResultV1(r, ph, 0)
	close(registration.release)
	if code := <-done; code != CodeOK {
		t.Fatal(code)
	}
	PublishRetiredMaintenanceParentResultV1(r, mh, MaintenanceSuccess)
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); ok || s != MaintenanceInvalidState {
		t.Fatal("delayed old result inserted", s, ok)
	}
	if s, ok := RetiredProductionParentResultV1(r, ph); !ok || s != 0 {
		t.Fatal("new result overwritten", s, ok)
	}
}

func TestRetiredProductionParentReplacedByMaintenanceKeepsFailure(t *testing.T) {
	r := new(HandleRegistry)
	pp, ph := retiredProductionFixtureV1(t, r)
	retireProductionFixtureV1(t, pp)
	PublishRetiredProductionParentResultV1(r, ph, 0)
	mp, mh := retiredMaintenanceStateV1(t, r)
	if uint16(mh) != uint16(ph) {
		t.Fatal("not reused slot")
	}
	if s, ok := RetiredProductionParentResultV1(r, ph); !ok || s != 0 {
		t.Fatal("occupancy evicted", s, ok)
	}
	mp.noteCleanup(CodeStateCorrupt)
	if code := r.Free(mh); code != CodeStateCorrupt {
		t.Fatal("native failed cleanup", code)
	}
	if s, ok := RetiredProductionParentResultV1(r, ph); ok || s != 3 {
		t.Fatal("old history not replaced", s, ok)
	}
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); ok || s != MaintenanceInvalidState {
		t.Fatal("native failure published early", s, ok)
	}
	PublishRetiredMaintenanceParentResultV1(r, mh, MaintenanceSuccess)
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); !ok || s != MaintenanceInternalFailure {
		t.Fatal("native failure lost", s, ok)
	}
	PublishRetiredProductionParentResultV1(r, ph, 0)
	mp.DestroyResult()
	if s, ok := RetiredMaintenanceParentResultV1(r, mh); !ok || s != MaintenanceInternalFailure {
		t.Fatal("repeat reset sticky result", s, ok)
	}
}

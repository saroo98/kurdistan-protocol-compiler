//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

import (
	"fmt"
	"testing"
	"time"
	"unsafe"

	"kurdistan/internal/androidbridge"
)

func TestCOutputObserverV1TableValidation(t *testing.T) {
	for _, ns := range []struct {
		kind    uint8
		refusal int32
	}{{1, 2}, {2, 3}} {
		t.Run(fmt.Sprintf("namespace%d", ns.kind), func(t *testing.T) {
			f := newTestOutputFrameV1(t, ns.kind, 0)
			defer func() { f.end(); f.release(t) }()
			if status := f.badTableStatus(0); status != 0 {
				t.Fatalf("unmodified real table with admitted frame: got %d, want 0", status)
			}
			for bad := 1; bad <= 24; bad++ {
				t.Run(fmt.Sprintf("defect%d", bad), func(t *testing.T) {
					if status := f.badTableStatus(bad); status != ns.refusal {
						t.Fatalf("table validation got %d, want exact refusal %d", status, ns.refusal)
					}
				})
			}
			if status := f.badTableStatus(0); status != 0 {
				t.Fatalf("admitted identity damaged by validation: %d", status)
			}
		})
	}
}

func TestCOutputObserverV1ImmutableInvocation(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	inv, s := f.productionInvocation(0)
	if s != 0 {
		t.Fatal(s)
	}
	original := inv
	o := f.productionObserver()
	if s := o.ValidateInvocationV1(&androidbridge.HandleRegistry{}, f.owner, f.serial(), 0); s != 3 {
		t.Fatal("wrong registry", s)
	}
	if s := o.ValidateInvocationV1(&registry, f.owner+1, f.serial(), 0); s != 3 {
		t.Fatal("wrong owner", s)
	}
	f.bindProduction(t)
	if inv != original {
		t.Fatal("opening invocation mutated")
	}
	if _, s := f.productionInvocation(0); s == 0 {
		t.Fatal("old opening epoch accepted")
	}
	if _, s := f.productionInvocation(7); s != 0 {
		t.Fatal("bound reconstruction", s)
	}
	f.end()
	if s := o.ValidateInvocationV1(&registry, f.owner, 1, 7); s != 3 {
		t.Fatal("ended invocation accepted", s)
	}
	f.retire(t)
}

func TestCOutputObserverV1RealGateRoundTrip(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	o := f.productionObserver()
	if s := o.PrepareV1(f.serial(), 7, 1, 0, 0, time.Now().Add(time.Second), false); s != 0 {
		t.Fatal(s)
	}
	o.ParentTerminalV1(7, 7)
	if publish, s := f.commit(0); publish || s == 0 {
		t.Fatal("terminal lost", publish, s)
	}
	clean, s := o.ClaimReceiptV1(f.serial(), 7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0)
	if clean || s != 0 {
		t.Fatal("terminal is not retirement", clean, s)
	}
	o.ResourceRetiredV1(7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0, 0, 0)
	if s := o.FinishReceiptV1(f.serial(), 7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0, 0); s != 0 {
		t.Fatal(s)
	}
	f.end()
	f.release(t)

	f = newTestOutputFrameV1(t, 2, 0)
	f.bindMaintenance(t)
	m := f.maintenanceObserver()
	if _, s := f.maintenanceInvocation(7); s != 0 {
		t.Fatal(s)
	}
	if s := m.PrepareV1(f.serial(), 7, 0, time.Now().Add(time.Second), false); s != 0 {
		t.Fatal(s)
	}
	m.CandidateTerminalV1(7, 99, androidbridge.MaintenanceExpired)
	if publish, s := f.commit(0); !publish || s != 0 {
		t.Fatal("candidate0 invalidated", publish, s)
	}
	f.end()
	f.retire(t)
}

func TestCOutputObserverV1BoundEpochReconstruction(t *testing.T) {
	f := newTestOutputFrameV1(t, 2, 0)
	inv, s := f.maintenanceInvocation(0)
	if s != 0 {
		t.Fatal(s)
	}
	original := inv
	f.bindMaintenance(t)
	m := f.maintenanceObserver()
	if inv != original {
		t.Fatal("mutated opening identity")
	}
	if s := m.ValidateInvocationV1(&androidbridge.HandleRegistry{}, f.owner, f.serial(), 7); s != androidbridge.MaintenanceInvalidState {
		t.Fatal(s)
	}
	if s := m.PrepareV1(f.serial(), 7, 0, time.Now().Add(time.Second), false); s != 0 {
		t.Fatal(s)
	}
	m.ParentTerminalV1(7, androidbridge.MaintenanceCancelled)
	m.ResourceRetiredV1(7, androidbridge.MaintenanceOutputParentV1, f.parent(), 0, 0)
	if _, s := f.maintenanceInvocation(7); s != 0 {
		t.Fatal("exact retired reconstruction", s)
	}
	clean, s := m.ClaimReceiptV1(f.serial(), 7, androidbridge.MaintenanceOutputParentV1, f.parent(), 0, 0)
	if !clean || s != 0 {
		t.Fatal(clean, s)
	}
	if s := m.FinishReceiptV1(f.serial(), 7, androidbridge.MaintenanceOutputParentV1, f.parent(), 0, 0, 0); s != 0 {
		t.Fatal(s)
	}
	f.end()
	f.release(t)
	if _, s := f.maintenanceInvocation(7); s == 0 {
		t.Fatal("ended retired invocation accepted")
	}
}

func TestCOutputObserverV1AllTypedMethods(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	f.end()
	f.beginParent(t, 0, 0)
	p := f.productionObserver()
	if s := p.BindLaneV1(f.serial(), 7, 6, 1); s != 0 {
		t.Fatal(s)
	}
	p.AttemptTerminalV1(7, 1, 9)
	if s := p.PrepareV1(f.serial(), 7, 1, 0, 0, time.Now().Add(time.Second), false); s == 0 {
		t.Fatal("attempt loss ignored")
	}
	f.end()
	f.retire(t)
	f = newTestOutputFrameV1(t, 2, 0)
	f.bindMaintenance(t)
	m := f.maintenanceObserver()
	if s := m.BindLaneV1(f.serial(), 7, true); s != 0 {
		t.Fatal("same frame control transfer", s)
	}
	if s := m.SupersedeNormalV1(f.serial(), 7); s != 0 {
		t.Fatal(s)
	}
	// The opening expectation is Parent, so this frame cannot invent a
	// categorical terminal result or a child receipt during its transfer.
	f.end()
	f.retire(t)
}

func TestCOutputObserverV1CallbacksDoNotAllocate(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	p := f.productionObserver()
	deadline := time.Now().Add(time.Second)
	if s := p.PrepareV1(f.serial(), 7, 1, 0, 0, deadline, false); s != 0 {
		t.Fatal(s)
	}
	allocations := testing.AllocsPerRun(100, func() {
		p.ValidateInvocationV1(&registry, f.owner, f.serial(), 7)
		p.PrepareV1(f.serial(), 7, 1, 0, 0, deadline, false)
		p.ClaimReceiptV1(f.serial(), 7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0)
	})
	if allocations != 0 {
		t.Fatalf("observer callbacks allocated %g", allocations)
	}
	if s := p.FinishReceiptV1(f.serial(), 7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0, 0); s != 0 {
		t.Fatal(s)
	}
	f.end()
	f.retire(t)
}

func TestCOutputObserverV1NamespaceConversion(t *testing.T) {
	if got := testOutputMalformedMaintenanceV1(256); got != androidbridge.MaintenanceInternalFailure {
		t.Fatal("narrowed256", got)
	}
	if got := testOutputMalformedMaintenanceV1(-1); got != androidbridge.MaintenanceInternalFailure {
		t.Fatal("negative", got)
	}
	if got := testOutputMalformedProductionV1(256); got != 18 {
		t.Fatal(got)
	}
}

func TestCOutputObserverV1MonotonicConversion(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	o := f.productionObserver()
	if s := o.PrepareV1(f.serial(), 7, 1, 0, 0, time.Time{}, false); s == 0 {
		t.Fatal("zero deadline")
	}
	if s := o.PrepareV1(f.serial(), 7, 1, 0, 0, time.Now().Add(-time.Second), false); s == 0 {
		t.Fatal("expired deadline")
	}
	f.end()
	f.retire(t)
}

func TestCOutputObserverV1ClockFailureSticky(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	f.bindProduction(t)
	deadline := time.Now().Add(time.Second)
	if s := f.faultClockPrepare(deadline); s != 18 {
		t.Fatal(s)
	}
	o := f.productionObserver()
	if s := o.PrepareV1(f.serial(), 7, 1, 0, 0, deadline, false); s == 0 {
		t.Fatal("unknown C clock status did not latch failure")
	}
	f.end()
}

var retainedProductionObserverV1 androidbridge.ProductionOutputObserverV1
var retainedProductionInvocationV1 androidbridge.ProductionOutputInvocationV1

func TestCOutputObserverV1Backing(t *testing.T) {
	f := newTestOutputFrameV1(t, 1, 0)
	a := testing.AllocsPerRun(100, func() { o := f.productionObserver(); retainedProductionObserverV1 = &o })
	p, m := f.productionObserver(), f.maintenanceObserver()
	t.Logf("production observer=%d maintenance observer=%d retained allocations=%g", unsafe.Sizeof(p), unsafe.Sizeof(m), a)
	if a != 1 {
		t.Fatalf("unbounded/unexpected retained observer allocation count %g", a)
	}
	actualFactory := testing.AllocsPerRun(100, func() { retainedProductionInvocationV1, _ = f.productionInvocation(0) })
	if actualFactory != 1 {
		t.Fatalf("actual factory allocations %g", actualFactory)
	}
	t.Logf("actual immutable invocation factory retained allocations=%g; conditional payload with one live observer per frame plus parent: production=%d maintenance=%d (future caller lifetime not proven here)", actualFactory, 268*cOutputObserverBackingV1(), 3*cOutputObserverBackingV1())
	retainedProductionInvocationV1 = androidbridge.ProductionOutputInvocationV1{}
	if got := testing.AllocsPerRun(100, func() { p.ValidateInvocationV1(&registry, f.owner, f.serial(), 0) }); got != 0 {
		t.Fatalf("observer callback allocated %g", got)
	}
	retainedProductionObserverV1 = nil
	f.end()
	f.release(t)
}

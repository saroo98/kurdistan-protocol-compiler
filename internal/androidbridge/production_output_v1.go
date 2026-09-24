// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import (
	"context"
	"time"
)

type ProductionOutputReceiptKindV1 uint8

const (
	ProductionOutputParentV1         ProductionOutputReceiptKindV1 = 1
	ProductionOutputStreamV1         ProductionOutputReceiptKindV1 = 2
	ProductionOutputPacketDeliveryV1 ProductionOutputReceiptKindV1 = 3
	ProductionOutputStreamDeliveryV1 ProductionOutputReceiptKindV1 = 4
)

// Implementations are trusted bounded bookkeeping only. Under the native
// owner fence they may take their bookkeeping lock, but must not allocate,
// reenter Go, call a platform provider, copy output, cancel, close, or join.
type ProductionOutputObserverV1 interface {
	ValidateInvocationV1(registry *HandleRegistry, owner, call, epoch uint64) int32
	BindParentV1(call, epoch uint64) int32
	BindHandleV1(call, epoch uint64, parent Handle) int32
	BindLaneV1(call, epoch uint64, lane uint16, attempt uint64) int32
	PrepareV1(call, epoch, attempt, child, delivery uint64, deadline time.Time, terminalControl bool) int32
	ParentTerminalV1(epoch uint64, reason int32)
	AttemptTerminalV1(epoch, attempt uint64, reason int32)
	ClaimReceiptV1(call, epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64) (bool, int32)
	FinishReceiptV1(call, epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64, actualCleanupStatus int32) int32
	ResourceRetiredV1(epoch uint64, kind ProductionOutputReceiptKindV1, parent Handle, attempt, child, delivery uint64, actualCleanupStatus int32)
}

// Immutable private identity supplied by the trusted adapter, never request
// data. Epoch zero is opening-only. The zero value selects legacy behavior.
type ProductionOutputInvocationV1 struct {
	registry           *HandleRegistry
	observer           ProductionOutputObserverV1
	owner, call, epoch uint64
}

func NewProductionOutputInvocationV1(registry *HandleRegistry, observer ProductionOutputObserverV1, owner, call, epoch uint64) (ProductionOutputInvocationV1, int32) {
	if registry == nil || observer == nil || owner == 0 || call == 0 {
		return ProductionOutputInvocationV1{}, 2
	}
	if s := productionOutputStatusV1(observer.ValidateInvocationV1(registry, owner, call, epoch)); s != 0 {
		return ProductionOutputInvocationV1{}, s
	}
	return ProductionOutputInvocationV1{registry, observer, owner, call, epoch}, 0
}
func (inv ProductionOutputInvocationV1) legacyV1() bool {
	return inv.registry == nil && inv.observer == nil && inv.owner == 0 && inv.call == 0 && inv.epoch == 0
}
func (inv ProductionOutputInvocationV1) validV1() bool {
	return inv.registry != nil && inv.observer != nil && inv.owner != 0 && inv.call != 0
}
func productionOutputStatusV1(s int32) int32 {
	if !validProductionStatusV1(productionStatusV1(s)) || s == 19 || s == 20 {
		return 18
	}
	return s
}
func productionOutputOpeningV1(r *HandleRegistry, inv ProductionOutputInvocationV1, bytes, capacity uint64) int32 {
	if inv.legacyV1() {
		if bytes != 0 {
			return 2
		}
		return 0
	}
	if !inv.validV1() || inv.registry != r || inv.epoch != 0 || bytes == 0 || bytes > capacity || bytes > 128<<20 {
		return 2
	}
	return 0
}

func (p *productionParentV1) outputIdentityLockedV1(inv ProductionOutputInvocationV1) int32 {
	if inv.legacyV1() {
		return 0
	}
	if !inv.validV1() || inv.epoch == 0 || inv.registry != p.ticket.registry || inv.epoch != p.ticket.epoch || inv.owner != p.outputOwner || p.output == nil {
		return 3
	}
	return productionOutputStatusV1(p.output.ValidateInvocationV1(inv.registry, inv.owner, inv.call, inv.epoch))
}
func (p *productionParentV1) outputLaneLockedV1(inv ProductionOutputInvocationV1, lane uint16) int32 {
	if s := p.outputIdentityLockedV1(inv); s != 0 {
		return s
	}
	if inv.legacyV1() {
		return 0
	}
	return productionOutputStatusV1(p.output.BindLaneV1(inv.call, inv.epoch, lane, p.attempt))
}
func (p *productionParentV1) outputPrepareLockedV1(inv ProductionOutputInvocationV1, attempt, child, delivery uint64, deadline time.Time, terminal bool) int32 {
	if s := p.outputIdentityLockedV1(inv); s != 0 {
		return s
	}
	if inv.legacyV1() {
		return 0
	}
	if deadline.IsZero() && !terminal {
		return 18
	}
	return productionOutputStatusV1(p.output.PrepareV1(inv.call, inv.epoch, attempt, child, delivery, deadline, terminal))
}
func productionRetiredOutputV1(r *HandleRegistry, h Handle, inv ProductionOutputInvocationV1) int32 {
	if !inv.validV1() || inv.epoch == 0 || inv.registry != r {
		return 3
	}
	if s := productionOutputStatusV1(inv.observer.ValidateInvocationV1(r, inv.owner, inv.call, inv.epoch)); s != 0 {
		return s
	}
	if h == 0 {
		return 3
	}
	i := uint16(h)
	if i == 0 || int(i) > MaxBridgeHandles {
		return 3
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := &r.slots[i-1]
	if slot.retiredParent.valid && slot.retiredParent.kind == HandleProductionSession && slot.retiredParent.handle == h && slot.retiredParent.epoch == inv.epoch {
		return slot.retiredParent.nativeResult
	}
	return 3
}
func productionSessionOutputLookupV1(r *HandleRegistry, h Handle, inv ProductionOutputInvocationV1) (*productionSessionV1, int32) {
	if !inv.legacyV1() && (!inv.validV1() || inv.registry != r || inv.epoch == 0) {
		return nil, 3
	}
	v, s := productionSessionLookupV1(r, h)
	if s != 0 {
		return nil, s
	}
	v.parent.mu.Lock()
	s = v.parent.outputIdentityLockedV1(inv)
	v.parent.mu.Unlock()
	if s != 0 {
		return nil, s
	}
	return v, 0
}
func productionOutputDeadlineV1(a, b time.Time) time.Time {
	if a.IsZero() || !b.IsZero() && b.Before(a) {
		return b
	}
	return a
}
func (v *productionSessionV1) outputStreamScalarV1(inv ProductionOutputInvocationV1, use productionUseV1, child uint64, ctx context.Context) int32 {
	if inv.legacyV1() {
		return 0
	}
	p := v.parent
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := v.liveLockedV1(use); s != 0 {
		return s
	}
	if s := productionOperationStatusV1(ctx.Err()); s != 0 {
		return s
	}
	deadline, _ := ctx.Deadline()
	return p.outputPrepareLockedV1(inv, use.attempt, child, 0, productionOutputDeadlineV1(deadline, p.admission.monotonicDeadline), false)
}

// Saved by-value identity across teardown, not a receipt table or mutable
// authority graph. Its bounded stack backing is in the session charge.
type productionRetiredDeliveryV1 struct {
	attempt, child, delivery uint64
	actual                   int32
}

func (p *productionParentV1) outputRetiredDeliveryV1(child uint64, d productionDeliveryV1, actual int32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.output == nil || d.token == 0 {
		return
	}
	kind := ProductionOutputPacketDeliveryV1
	if child != 0 {
		kind = ProductionOutputStreamDeliveryV1
	}
	p.output.ResourceRetiredV1(p.ticket.epoch, kind, p.outputHandle, d.attempt, child, d.token, productionOutputStatusV1(actual))
}

func (inv ProductionOutputInvocationV1) claimV1(kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64) (bool, int32) {
	if !inv.validV1() || inv.epoch == 0 || parent == 0 {
		return false, 3
	}
	if s := productionOutputStatusV1(inv.observer.ValidateInvocationV1(inv.registry, inv.owner, inv.call, inv.epoch)); s != 0 {
		return false, s
	}
	retired, s := inv.observer.ClaimReceiptV1(inv.call, inv.epoch, kind, parent, child, delivery)
	return retired, productionOutputStatusV1(s)
}
func (inv ProductionOutputInvocationV1) finishV1(kind ProductionOutputReceiptKindV1, parent Handle, child, delivery uint64, actual int32) int32 {
	actual = productionOutputStatusV1(actual)
	s := productionOutputStatusV1(inv.observer.FinishReceiptV1(inv.call, inv.epoch, kind, parent, child, delivery, actual))
	if s != 0 {
		return s
	}
	return actual
}

// These typed cleanup paths reuse a claimed outer receipt. No new native
// output lane is taken, and only joined destruction can cover a missing child.
func DiscardProductionParentOutputV1(inv ProductionOutputInvocationV1, parent Handle) int32 {
	retired, s := inv.claimV1(ProductionOutputParentV1, parent, 0, 0)
	if s != 0 {
		return s
	}
	if !retired {
		v, lookup := productionSessionOutputLookupV1(inv.registry, parent, inv)
		s = lookup
		if s == 0 {
			s = v.closeOutputParentV1()
		}
	}
	return inv.finishV1(ProductionOutputParentV1, parent, 0, 0, s)
}
func DiscardProductionStreamOutputV1(inv ProductionOutputInvocationV1, parent Handle, child uint64) int32 {
	if child == 0 {
		return 3
	}
	retired, s := inv.claimV1(ProductionOutputStreamV1, parent, child, 0)
	if s != 0 {
		return s
	}
	if !retired {
		v, lookup := productionSessionOutputLookupV1(inv.registry, parent, inv)
		s = lookup
		if s == 0 {
			// Closed/tombstoned rows are not actual runtime retirement. Exact parent
			// teardown provides a bounded alternative to waiting for tombstone expiry.
			s = v.closeOutputParentV1()
		}
	}
	return inv.finishV1(ProductionOutputStreamV1, parent, child, 0, s)
}
func DiscardProductionPacketOutputV1(inv ProductionOutputInvocationV1, parent Handle, delivery uint64) int32 {
	if delivery == 0 {
		return 3
	}
	retired, s := inv.claimV1(ProductionOutputPacketDeliveryV1, parent, 0, delivery)
	if s != 0 {
		return s
	}
	if !retired {
		v, lookup := productionSessionOutputLookupV1(inv.registry, parent, inv)
		s = lookup
		if s == 0 {
			s = v.closeOutputParentV1()
		}
	}
	return inv.finishV1(ProductionOutputPacketDeliveryV1, parent, 0, delivery, s)
}
func DiscardProductionStreamDeliveryOutputV1(inv ProductionOutputInvocationV1, parent Handle, child, delivery uint64) int32 {
	if child == 0 || delivery == 0 {
		return 3
	}
	retired, s := inv.claimV1(ProductionOutputStreamDeliveryV1, parent, child, delivery)
	if s != 0 {
		return s
	}
	if !retired {
		v, lookup := productionSessionOutputLookupV1(inv.registry, parent, inv)
		s = lookup
		if s == 0 {
			s = v.closeOutputParentV1()
		}
	}
	return inv.finishV1(ProductionOutputStreamDeliveryV1, parent, child, delivery, s)
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

import "time"

type MaintenanceOutputReceiptKindV1 uint8

const (
	MaintenanceOutputParentV1    MaintenanceOutputReceiptKindV1 = 1
	MaintenanceOutputCandidateV1 MaintenanceOutputReceiptKindV1 = 2
)

// Trusted bounded bookkeeping only, with the same non-reentrancy and
// nonjoining contract as ProductionOutputObserverV1. Delivery is always zero.
type MaintenanceOutputObserverV1 interface {
	ValidateInvocationV1(registry *HandleRegistry, owner, call, epoch uint64) MaintenanceResultV1
	BindParentV1(call, epoch uint64) MaintenanceResultV1
	BindHandleV1(call, epoch uint64, parent Handle) MaintenanceResultV1
	BindLaneV1(call, epoch uint64, revocation bool) MaintenanceResultV1
	SupersedeNormalV1(call, epoch uint64) MaintenanceResultV1
	PrepareV1(call, epoch uint64, candidate MaintenanceCandidateID, deadline time.Time, terminalResult bool) MaintenanceResultV1
	ParentTerminalV1(epoch uint64, reason MaintenanceResultV1)
	CandidateTerminalV1(epoch uint64, candidate MaintenanceCandidateID, reason MaintenanceResultV1)
	ClaimReceiptV1(call, epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, delivery uint64) (bool, MaintenanceResultV1)
	FinishReceiptV1(call, epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, delivery uint64, actualCleanupStatus MaintenanceResultV1) MaintenanceResultV1
	ResourceRetiredV1(epoch uint64, kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, actualCleanupStatus MaintenanceResultV1)
}
type MaintenanceOutputInvocationV1 struct {
	registry           *HandleRegistry
	observer           MaintenanceOutputObserverV1
	owner, call, epoch uint64
}

func NewMaintenanceOutputInvocationV1(registry *HandleRegistry, observer MaintenanceOutputObserverV1, owner, call, epoch uint64) (MaintenanceOutputInvocationV1, MaintenanceResultV1) {
	if registry == nil || observer == nil || owner == 0 || call == 0 {
		return MaintenanceOutputInvocationV1{}, MaintenanceInvalidRequest
	}
	if s := normalizeMaintenancePlatformResult(observer.ValidateInvocationV1(registry, owner, call, epoch)); s != MaintenanceSuccess {
		return MaintenanceOutputInvocationV1{}, s
	}
	return MaintenanceOutputInvocationV1{registry, observer, owner, call, epoch}, MaintenanceSuccess
}
func (inv MaintenanceOutputInvocationV1) legacyV1() bool {
	return inv.registry == nil && inv.observer == nil && inv.owner == 0 && inv.call == 0 && inv.epoch == 0
}
func (inv MaintenanceOutputInvocationV1) validV1() bool {
	return inv.registry != nil && inv.observer != nil && inv.owner != 0 && inv.call != 0
}
func maintenanceOutputOpeningV1(r *HandleRegistry, inv MaintenanceOutputInvocationV1, bytes, capacity uint64) MaintenanceResultV1 {
	if inv.legacyV1() {
		if bytes != 0 {
			return MaintenanceInvalidRequest
		}
		return MaintenanceSuccess
	}
	if !inv.validV1() || inv.registry != r || inv.epoch != 0 || bytes == 0 || bytes > capacity || bytes > maxMaintenanceOwnerBudget {
		return MaintenanceInvalidRequest
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) outputIdentityLockedV1(inv MaintenanceOutputInvocationV1) MaintenanceResultV1 {
	if inv.legacyV1() {
		return MaintenanceSuccess
	}
	if !inv.validV1() || inv.epoch == 0 || inv.registry != p.registry || inv.epoch != p.parentEpoch || inv.owner != p.outputOwner || p.output == nil {
		return MaintenanceInvalidState
	}
	return normalizeMaintenancePlatformResult(p.output.ValidateInvocationV1(inv.registry, inv.owner, inv.call, inv.epoch))
}
func (p *maintenanceAuthorityV1) outputLaneLockedV1(inv MaintenanceOutputInvocationV1, control bool) MaintenanceResultV1 {
	if s := p.outputIdentityLockedV1(inv); s != MaintenanceSuccess {
		return s
	}
	if inv.legacyV1() {
		return MaintenanceSuccess
	}
	return normalizeMaintenancePlatformResult(p.output.BindLaneV1(inv.call, inv.epoch, control))
}
func (p *maintenanceAuthorityV1) outputPrepareLockedV1(inv MaintenanceOutputInvocationV1, child MaintenanceCandidateID, deadline time.Time, terminal bool) MaintenanceResultV1 {
	if s := p.outputIdentityLockedV1(inv); s != MaintenanceSuccess {
		return s
	}
	if inv.legacyV1() {
		return MaintenanceSuccess
	}
	if deadline.IsZero() && !terminal {
		return MaintenanceInternalFailure
	}
	return normalizeMaintenancePlatformResult(p.output.PrepareV1(inv.call, inv.epoch, child, deadline, terminal))
}
func maintenanceParentOutputV1(r *HandleRegistry, h Handle, inv MaintenanceOutputInvocationV1) (*maintenanceAuthorityV1, MaintenanceResultV1) {
	if !inv.legacyV1() && (!inv.validV1() || inv.registry != r || inv.epoch == 0) {
		return nil, MaintenanceInvalidState
	}
	p, s := maintenanceParentV1(r, h)
	if s != MaintenanceSuccess {
		return nil, s
	}
	p.mu.Lock()
	s = p.outputIdentityLockedV1(inv)
	p.mu.Unlock()
	if s != MaintenanceSuccess {
		return nil, s
	}
	return p, MaintenanceSuccess
}
func (p *maintenanceAuthorityV1) outputCandidateTerminalLockedV1(reason MaintenanceResultV1) {
	if p.output != nil && p.candidateID != 0 {
		p.output.CandidateTerminalV1(p.parentEpoch, p.candidateID, reason)
	}
}

func maintenanceOutputCleanupResultV1(code ErrorCode) MaintenanceResultV1 {
	switch code {
	case CodeOK:
		return MaintenanceSuccess
	case CodeInvalidHandle, CodeAlreadyClosed, CodeWrongHandleType:
		return MaintenanceInvalidState
	default:
		return MaintenanceInternalFailure
	}
}

// Lifecycle lookup admits a cancelled exact-kind slot without changing legacy
// Get/Cancel/Free. The native object remains the sole cleanup-state authority.
func maintenanceOutputLifecycleParentV1(inv MaintenanceOutputInvocationV1, h Handle) (*maintenanceAuthorityV1, MaintenanceResultV1) {
	if !inv.validV1() || inv.epoch == 0 {
		return nil, MaintenanceInvalidState
	}
	if s := normalizeMaintenancePlatformResult(inv.observer.ValidateInvocationV1(inv.registry, inv.owner, inv.call, inv.epoch)); s != 0 {
		return nil, s
	}
	i, g, k, ok := decodeHandle(h)
	if !ok || k != HandleMaintenance {
		return nil, MaintenanceInvalidState
	}
	r := inv.registry
	r.mu.Lock()
	slot := &r.slots[i]
	p, typed := slot.value.(*maintenanceAuthorityV1)
	valid := slot.occupied && slot.generation == g && slot.kind == HandleMaintenance && typed && p != nil
	r.mu.Unlock()
	if !valid {
		return nil, MaintenanceInvalidState
	}
	p.mu.Lock()
	s := p.outputIdentityLockedV1(inv)
	valid = p.handle == h
	p.mu.Unlock()
	if s != 0 {
		return nil, s
	}
	if !valid {
		return nil, MaintenanceInvalidState
	}
	return p, MaintenanceSuccess
}
func CancelMaintenanceV1Scoped(registry *HandleRegistry, parent Handle, inv MaintenanceOutputInvocationV1) MaintenanceResultV1 {
	if registry != inv.registry {
		return MaintenanceInvalidState
	}
	p, s := maintenanceOutputLifecycleParentV1(inv, parent)
	if s != 0 {
		return s
	}
	code := registry.Cancel(parent)
	p.noteCleanup(code)
	return maintenanceOutputCleanupResultV1(code)
}
func CloseMaintenanceV1Scoped(registry *HandleRegistry, parent Handle, inv MaintenanceOutputInvocationV1) MaintenanceResultV1 {
	if registry != inv.registry {
		return MaintenanceInvalidState
	}
	p, s := maintenanceOutputLifecycleParentV1(inv, parent)
	if s != 0 {
		return s
	}
	code := registry.Free(parent)
	p.noteCleanup(code)
	return maintenanceOutputCleanupResultV1(code)
}
func (inv MaintenanceOutputInvocationV1) claimV1(kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID) (bool, MaintenanceResultV1) {
	if !inv.validV1() || inv.epoch == 0 || parent == 0 {
		return false, MaintenanceInvalidState
	}
	if s := normalizeMaintenancePlatformResult(inv.observer.ValidateInvocationV1(inv.registry, inv.owner, inv.call, inv.epoch)); s != 0 {
		return false, s
	}
	retired, s := inv.observer.ClaimReceiptV1(inv.call, inv.epoch, kind, parent, child, 0)
	return retired, normalizeMaintenancePlatformResult(s)
}
func (inv MaintenanceOutputInvocationV1) finishV1(kind MaintenanceOutputReceiptKindV1, parent Handle, child MaintenanceCandidateID, actual MaintenanceResultV1) MaintenanceResultV1 {
	actual = normalizeMaintenancePlatformResult(actual)
	s := normalizeMaintenancePlatformResult(inv.observer.FinishReceiptV1(inv.call, inv.epoch, kind, parent, child, 0, actual))
	if s != 0 {
		return s
	}
	return actual
}
func DiscardMaintenanceParentOutputV1(inv MaintenanceOutputInvocationV1, parent Handle) MaintenanceResultV1 {
	retired, s := inv.claimV1(MaintenanceOutputParentV1, parent, 0)
	if s != 0 {
		return s
	}
	if !retired {
		p, lookup := maintenanceOutputLifecycleParentV1(inv, parent)
		s = lookup
		if s == 0 {
			code := inv.registry.Free(parent)
			p.noteCleanup(code)
			s = maintenanceOutputCleanupResultV1(code)
		}
	}
	return inv.finishV1(MaintenanceOutputParentV1, parent, 0, s)
}
func DiscardMaintenanceCandidateOutputV1(inv MaintenanceOutputInvocationV1, parent Handle, child MaintenanceCandidateID) MaintenanceResultV1 {
	if child == 0 {
		return MaintenanceInvalidState
	}
	retired, s := inv.claimV1(MaintenanceOutputCandidateV1, parent, child)
	if s != 0 {
		return s
	}
	if !retired {
		p, lookup := maintenanceOutputLifecycleParentV1(inv, parent)
		s = lookup
		if s == 0 {
			// A scoped output frame already owns admission. Use the private native
			// release path with no observer-lane reacquisition; if normal native
			// admission is unavailable, exact parent destruction owns joined cleanup.
			s = p.releaseOutputCandidateV1(child)
			if s != MaintenanceSuccess {
				code := inv.registry.Free(parent)
				p.noteCleanup(code)
				s = maintenanceOutputCleanupResultV1(code)
			}
		}
	}
	return inv.finishV1(MaintenanceOutputCandidateV1, parent, child, s)
}
func (p *maintenanceAuthorityV1) releaseOutputCandidateV1(child MaintenanceCandidateID) MaintenanceResultV1 {
	p.retirementMu.Lock()
	defer p.retirementMu.Unlock()
	p.mu.Lock()
	if p.operation != nil || p.retirementBusy || p.revocationBusy || p.candidateID != child || p.candidate == nil {
		p.mu.Unlock()
		return MaintenanceInvalidState
	}
	p.retirementBusy = true
	p.outputCandidateTerminalLockedV1(MaintenanceCancelled)
	candidate := p.detachCandidateLocked()
	p.armTimerAtLocked(p.parentTimerAt, maintenanceTimerParent)
	p.mu.Unlock()
	p.retireCandidateHeld(candidate, child)
	p.mu.Lock()
	p.retirementBusy = false
	p.mu.Unlock()
	return MaintenanceSuccess
}

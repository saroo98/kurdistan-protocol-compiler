// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"time"

	"kurdistan/internal/selfhost"
)

func (p *maintenanceAuthorityV1) beginOperation() (*maintenanceOperationV1, MaintenanceResultV1) {
	return p.beginOperationOutputV1(MaintenanceOutputInvocationV1{}, false)
}
func (p *maintenanceAuthorityV1) beginOperationOutputV1(inv MaintenanceOutputInvocationV1, laneBound bool) (*maintenanceOperationV1, MaintenanceResultV1) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if s := p.outputIdentityLockedV1(inv); s != MaintenanceSuccess {
		return nil, s
	}
	if p.terminalSet {
		return nil, p.terminal
	}
	if p.revocationBusy || p.retirementBusy || p.operation != nil {
		return nil, MaintenanceResourceLimit
	}
	if p.operationEpoch == ^uint64(0) {
		return nil, MaintenanceResourceLimit
	}
	if !laneBound {
		if s := p.outputLaneLockedV1(inv, false); s != MaintenanceSuccess {
			return nil, s
		}
	}
	p.operationEpoch++
	ctx, cancel := context.WithCancel(context.Background())
	op := &maintenanceOperationV1{epoch: p.operationEpoch, ctx: ctx, outputContext: ctx, cancel: cancel, done: make(chan struct{}), output: inv}
	p.operation = op
	return op, MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) finishOperation(op *maintenanceOperationV1) {
	if op == nil {
		return
	}
	op.finishOnce.Do(func() {
		op.cancel()
		op.completionGuard = nil
		p.mu.Lock()
		candidate := p.pendingCandidate
		candidateID := p.pendingCandidateID
		p.pendingCandidate = nil
		p.pendingCandidateID = 0
		cleanup := p.cleanupPending
		p.cleanupPending = false
		p.mu.Unlock()
		p.retireResources(candidate, cleanup, candidateID)
		p.mu.Lock()
		if p.operation == op {
			p.operation = nil
		}
		p.mu.Unlock()
		close(op.done)
	})
}

func (p *maintenanceAuthorityV1) revalidatePlatform(op *maintenanceOperationV1) MaintenanceResultV1 {
	p.mu.Lock()
	registration := p.registration
	live := !p.terminalSet && p.operation == op && !op.cancelled
	p.mu.Unlock()
	if !live || registration == nil {
		return MaintenanceCancelled
	}
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	result := normalizeMaintenancePlatformResult(registration.Revalidate(op.ctx))
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	if result != MaintenanceSuccess {
		p.mu.Lock()
		if p.terminalSet {
			result = p.terminal
		}
		p.mu.Unlock()
		return result
	}
	p.mu.Lock()
	live = !p.terminalSet && p.operation == op && !op.cancelled
	if p.terminalSet {
		result = p.terminal
	}
	p.mu.Unlock()
	if !live || op.ctx.Err() != nil {
		if result != MaintenanceSuccess {
			return result
		}
		return MaintenanceCancelled
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) trustedNow(op *maintenanceOperationV1) (time.Time, MaintenanceResultV1) {
	now := p.now()
	return p.acceptTrustedNow(op, now)
}

func (p *maintenanceAuthorityV1) trustedNowAndMonotonic(op *maintenanceOperationV1) (time.Time, time.Time, MaintenanceResultV1) {
	now := p.now()
	monotonicNow := p.monotonicNow()
	accepted, result := p.acceptTrustedNow(op, now)
	if result != MaintenanceSuccess || monotonicNow.IsZero() {
		if result == MaintenanceSuccess {
			result = p.failOperation(op, MaintenanceExpired)
		}
		return time.Time{}, time.Time{}, result
	}
	return accepted, monotonicNow, MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) acceptTrustedNow(op *maintenanceOperationV1, now time.Time) (time.Time, MaintenanceResultV1) {
	p.mu.Lock()
	if p.terminalSet || p.operation != op || op.cancelled {
		result := p.terminal
		if !p.terminalSet {
			result = MaintenanceCancelled
		}
		p.mu.Unlock()
		return time.Time{}, result
	}
	if now.IsZero() || now.Unix() <= 0 || now.Before(p.lastNow) {
		p.mu.Unlock()
		return time.Time{}, p.failOperation(op, MaintenanceExpired)
	}
	p.lastNow = now
	p.mu.Unlock()
	return now, MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) acquirePublication(op *maintenanceOperationV1) (MaintenancePublicationLeaseV1, MaintenanceResultV1) {
	p.mu.Lock()
	registration := p.registration
	live := !p.terminalSet && p.operation == op && !op.cancelled
	p.mu.Unlock()
	if !live || registration == nil {
		return nil, MaintenanceCancelled
	}
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	lease, result := registration.AcquirePublication(op.ctx)
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	result = normalizeMaintenancePlatformResult(result)
	if result != MaintenanceSuccess || lease == nil {
		if lease != nil {
			if code := p.closePublicationLease(op, lease); code != CodeOK {
				return nil, p.publicationCleanupFailure(op, code)
			}
		}
		if result == MaintenanceSuccess {
			result = MaintenanceInternalFailure
		}
		return nil, result
	}
	p.mu.Lock()
	live = p.operationCanPublishLocked(op)
	p.mu.Unlock()
	if !live {
		if code := p.closePublicationLease(op, lease); code != CodeOK {
			return nil, p.publicationCleanupFailure(op, code)
		}
		return nil, MaintenanceCancelled
	}
	if !p.publicationLeaseCurrent(op, lease) {
		if code := p.closePublicationLease(op, lease); code != CodeOK {
			return nil, p.publicationCleanupFailure(op, code)
		}
		p.mu.Lock()
		if p.terminalSet {
			result = p.terminal
		} else {
			result = MaintenanceCancelled
		}
		p.mu.Unlock()
		return nil, result
	}
	return lease, MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) publicationLeaseCurrent(op *maintenanceOperationV1, lease MaintenancePublicationLeaseV1) bool {
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	current := lease.IsCurrent()
	p.mu.Lock()
	op.inPlatform = false
	live := p.operationCanPublishLocked(op)
	p.mu.Unlock()
	return current && live
}

func (p *maintenanceAuthorityV1) closePublicationLease(op *maintenanceOperationV1, lease MaintenancePublicationLeaseV1) ErrorCode {
	p.mu.Lock()
	op.inPlatform = true
	p.mu.Unlock()
	code := lease.Close()
	p.mu.Lock()
	op.inPlatform = false
	p.mu.Unlock()
	return code
}

func (p *maintenanceAuthorityV1) finishPublication(op *maintenanceOperationV1, lease MaintenancePublicationLeaseV1) MaintenanceResultV1 {
	if code := p.closePublicationLease(op, lease); code != CodeOK {
		return p.publicationCleanupFailure(op, code)
	}
	if result := p.checkCompletion(op); result != MaintenanceSuccess {
		return result
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.terminalSet {
		return p.terminal
	}
	if p.operation != op || op.cancelled || op.ctx.Err() != nil {
		return MaintenanceCancelled
	}
	if !op.outputPrepared {
		deadline := p.parentTimerAt
		if !op.deadline.IsZero() && op.deadline.Before(deadline) {
			deadline = op.deadline
		}
		op.outputPrepared = true // refusal must not prepare a second identity
		return p.outputPrepareLockedV1(op.output, 0, deadline, false)
	}
	return MaintenanceSuccess
}

// finishPublicationAndRetireDetached closes the one-shot publication barrier
// before destroying unpublished selfhost resources. Keeping this ordering in
// one helper makes cleanup incapable of extending the bounded publication
// interval, including when Close itself reports cleanup uncertainty.
func (p *maintenanceAuthorityV1) finishPublicationAndRetireDetached(op *maintenanceOperationV1, lease MaintenancePublicationLeaseV1,
	candidate *selfhost.LiveMaintenanceCandidate, owner *selfhost.LiveMaintenanceAdmission, candidateID ...MaintenanceCandidateID,
) MaintenanceResultV1 {
	result := p.finishPublication(op, lease)
	p.retirementMu.Lock()
	p.retireCandidateHeld(candidate, candidateID...)
	if owner != nil {
		if p.destroyOwner != nil {
			p.destroyOwner(owner)
		} else {
			owner.Destroy()
		}
	}
	p.retirementMu.Unlock()
	return result
}

func (p *maintenanceAuthorityV1) operationCanPublishLocked(op *maintenanceOperationV1) bool {
	return !p.terminalSet && p.operation == op && !op.cancelled && op.ctx.Err() == nil && (op.deadline.IsZero() || time.Now().Before(op.deadline))
}

func (p *maintenanceAuthorityV1) noteCleanup(code ErrorCode) {
	if code == CodeOK {
		return
	}
	p.mu.Lock()
	if p.cleanupCode == CodeOK {
		p.cleanupCode = code
	}
	p.mu.Unlock()
}

func (p *maintenanceAuthorityV1) detachCandidateLocked() *selfhost.LiveMaintenanceCandidate {
	candidate := p.candidate
	p.candidate = nil
	p.candidateID = 0
	p.candidateEnd = time.Time{}
	return candidate
}

func (p *maintenanceAuthorityV1) invalidateFromPlatform() ErrorCode {
	if p.shutdown(MaintenanceCancelled, true, true) {
		return CodeStateCorrupt
	}
	p.mu.Lock()
	code := p.cleanupCode
	p.mu.Unlock()
	return code
}

func (p *maintenanceAuthorityV1) Cancel() ErrorCode {
	p.shutdown(MaintenanceCancelled, true)
	p.closeTransport()
	p.closeRegistration()
	p.mu.Lock()
	code := p.cleanupCode
	p.mu.Unlock()
	return code
}

func (p *maintenanceAuthorityV1) DestroyResult() ErrorCode {
	if p == nil {
		return CodeOK
	}
	p.shutdown(MaintenanceCancelled, false)
	p.closeRegistration()
	p.stopSupervisor()
	p.closeTransport()
	p.registry.releaseMaintenanceScope(p)
	p.mu.Lock()
	code := p.cleanupCode
	p.handle = 0
	if p.output != nil {
		p.output.ResourceRetiredV1(p.parentEpoch, MaintenanceOutputParentV1, p.outputHandle, 0, maintenanceOutputCleanupResultV1(code))
	}
	p.mu.Unlock()
	p.recordRetiredOutputV1(code)
	return code
}

func (p *maintenanceAuthorityV1) shutdown(result MaintenanceResultV1, stopTimer bool, platformCallback ...bool) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	if !p.terminalSet {
		p.terminalSet = true
		p.terminal = result
		if p.output != nil {
			p.output.ParentTerminalV1(p.parentEpoch, result)
		}
	}
	candidateID := p.candidateID
	p.outputCandidateTerminalLockedV1(p.terminal)
	candidate := p.detachCandidateLocked()
	op := p.operation
	selfCall := false
	if op != nil {
		op.cancelled = true
		op.cancel()
		selfCall = op.inPlatform && len(platformCallback) != 0 && platformCallback[0]
	}
	if candidate != nil && selfCall {
		p.pendingCandidate = candidate
		p.pendingCandidateID = candidateID
		candidate = nil
	}
	if selfCall {
		p.cleanupPending = true
	}
	p.mu.Unlock()
	if selfCall {
		if stopTimer {
			p.stopOnce.Do(func() { close(p.timerStop) })
		}
		return true
	}
	p.mu.Lock()
	retirementDone := p.retirementDone
	p.mu.Unlock()
	if op != nil {
		<-op.done
	}
	if retirementDone != nil {
		<-retirementDone
	}
	p.retireResources(candidate, true, candidateID)
	if stopTimer {
		p.stopSupervisor()
	}
	return false
}

func (p *maintenanceAuthorityV1) failOperation(op *maintenanceOperationV1, result MaintenanceResultV1) MaintenanceResultV1 {
	p.mu.Lock()
	if p.terminalSet {
		result = p.terminal
		p.mu.Unlock()
		return result
	}
	p.terminalSet = true
	p.terminal = result
	if p.output != nil {
		p.output.ParentTerminalV1(p.parentEpoch, result)
	}
	if p.operation == op {
		op.cancelled = true
		op.cancel()
		candidateID := p.candidateID
		p.outputCandidateTerminalLockedV1(result)
		if candidate := p.detachCandidateLocked(); candidate != nil {
			p.pendingCandidate = candidate
			p.pendingCandidateID = candidateID
		}
		p.cleanupPending = true
	}
	p.stopOnce.Do(func() { close(p.timerStop) })
	p.mu.Unlock()
	return result
}

func (p *maintenanceAuthorityV1) publicationCleanupFailure(op *maintenanceOperationV1, code ErrorCode) MaintenanceResultV1 {
	p.noteCleanup(code)
	return p.failOperation(op, MaintenanceInternalFailure)
}

func (p *maintenanceAuthorityV1) retireCandidate(candidate *selfhost.LiveMaintenanceCandidate, candidateID ...MaintenanceCandidateID) {
	p.retireResources(candidate, false, candidateID...)
}

func (p *maintenanceAuthorityV1) retireResources(candidate *selfhost.LiveMaintenanceCandidate, owner bool, candidateID ...MaintenanceCandidateID) {
	p.retirementMu.Lock()
	defer p.retirementMu.Unlock()
	p.retireCandidateHeld(candidate, candidateID...)
	if owner {
		p.retireOwnerOnceHeld()
	}
}

func (p *maintenanceAuthorityV1) retireCandidateHeld(candidate *selfhost.LiveMaintenanceCandidate, candidateID ...MaintenanceCandidateID) {
	if candidate == nil {
		return
	}
	if p.destroyCandidate != nil {
		p.destroyCandidate(candidate)
	} else {
		candidate.Destroy()
	}
	if len(candidateID) != 0 && candidateID[0] != 0 {
		p.mu.Lock()
		if p.output != nil {
			p.output.ResourceRetiredV1(p.parentEpoch, MaintenanceOutputCandidateV1, p.outputHandle, candidateID[0], MaintenanceSuccess)
		}
		p.mu.Unlock()
	}
}

func (p *maintenanceAuthorityV1) retireOwnerOnce() {
	p.retireResources(nil, true)
}

func (p *maintenanceAuthorityV1) retireOwnerOnceHeld() {
	p.resourcesOnce.Do(func() {
		p.mu.Lock()
		owner := p.owner
		p.owner = nil
		p.mu.Unlock()
		if owner == nil {
			return
		}
		if p.destroyOwner != nil {
			p.destroyOwner(owner)
			return
		}
		owner.Destroy()
	})
}

func (p *maintenanceAuthorityV1) closeRegistration() {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		registration := p.registration
		p.registration = nil
		p.mu.Unlock()
		if registration != nil {
			p.noteCleanup(registration.Close())
		}
	})
}

func (p *maintenanceAuthorityV1) stopSupervisor() {
	p.stopOnce.Do(func() { close(p.timerStop) })
	<-p.timerDone
}

func (p *maintenanceAuthorityV1) armTimerAtLocked(deadline time.Time, kind uint8) {
	p.timerAt = deadline
	p.timerKind = kind
	p.timerSeq++
	select {
	case p.timerWake <- struct{}{}:
	default:
	}
}

func maintenanceMonotonicDeadlineV1(now, deadline, monotonicNow time.Time) (time.Time, bool) {
	if now.IsZero() || deadline.IsZero() || monotonicNow.IsZero() || !deadline.After(now) {
		return time.Time{}, false
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return time.Time{}, false
	}
	result := monotonicNow.Add(remaining)
	return result, result.After(monotonicNow)
}

func (p *maintenanceAuthorityV1) runTimerSupervisor() {
	defer close(p.timerDone)
	for {
		p.mu.Lock()
		at, kind, seq := p.timerAt, p.timerKind, p.timerSeq
		terminal := p.terminalSet
		p.mu.Unlock()
		if terminal {
			return
		}
		if kind == maintenanceTimerNone {
			select {
			case <-p.timerWake:
				continue
			case <-p.timerStop:
				return
			}
		}
		select {
		case <-p.timerWake:
		default:
		}
		wait := time.Until(at)
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
			if p.expireTimer(seq, kind) {
				return
			}
		case <-p.timerWake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-p.timerStop:
			if !timer.Stop() {
				<-timer.C
			}
			return
		}
	}
}

func (p *maintenanceAuthorityV1) expireTimer(seq uint64, kind uint8) bool {
	p.retirementMu.Lock()
	p.mu.Lock()
	if p.terminalSet || seq != p.timerSeq || kind != p.timerKind || p.retirementBusy {
		terminal := p.terminalSet
		p.mu.Unlock()
		p.retirementMu.Unlock()
		return terminal
	}
	p.retirementBusy = true
	retirementDone := make(chan struct{})
	p.retirementDone = retirementDone
	if kind == maintenanceTimerParent {
		p.terminalSet = true
		p.terminal = MaintenanceExpired
		if p.output != nil {
			p.output.ParentTerminalV1(p.parentEpoch, p.terminal)
		}
	}
	candidateID := p.candidateID
	p.outputCandidateTerminalLockedV1(MaintenanceExpired)
	candidate := p.detachCandidateLocked()
	op := p.operation
	if op != nil {
		op.cancelled = true
		op.cancel()
	}
	if kind == maintenanceTimerCandidate && !p.terminalSet {
		p.armTimerAtLocked(p.parentTimerAt, maintenanceTimerParent)
	}
	p.mu.Unlock()
	p.retirementMu.Unlock()
	if op != nil {
		<-op.done
	}
	p.retirementMu.Lock()
	p.retireCandidateHeld(candidate, candidateID)
	p.mu.Lock()
	terminal := p.terminalSet
	p.mu.Unlock()
	if terminal {
		p.retireOwnerOnceHeld()
	}
	p.mu.Lock()
	p.retirementBusy = false
	p.retirementDone = nil
	p.mu.Unlock()
	close(retirementDone)
	p.retirementMu.Unlock()
	return terminal
}

func MaintenanceStatusV1(registry *HandleRegistry, parent Handle) MaintenanceResultV1 {
	owner, result := maintenanceParentV1(registry, parent)
	if result != MaintenanceSuccess {
		return result
	}
	owner.mu.Lock()
	if owner.terminalSet {
		result := owner.terminal
		owner.mu.Unlock()
		return result
	}
	owner.mu.Unlock()
	now := owner.now()
	owner.mu.Lock()
	if owner.terminalSet {
		result := owner.terminal
		owner.mu.Unlock()
		return result
	}
	candidateExpired := owner.candidate != nil && !now.Before(owner.candidateEnd)
	parentExpired := owner.owner == nil || now.IsZero() || now.Unix() <= 0 || now.Before(owner.lastNow) || !now.Before(owner.parentEnd)
	if !parentExpired {
		owner.lastNow = now
	}
	owner.mu.Unlock()
	if parentExpired {
		owner.shutdown(MaintenanceExpired, true)
		return MaintenanceExpired
	}
	if candidateExpired {
		owner.expireCandidateIdle(now)
	}
	return MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) expireCandidateIdle(now time.Time) {
	p.retirementMu.Lock()
	p.mu.Lock()
	if p.terminalSet || p.retirementBusy || p.candidate == nil || now.Before(p.candidateEnd) {
		p.mu.Unlock()
		p.retirementMu.Unlock()
		return
	}
	p.retirementBusy = true
	retirementDone := make(chan struct{})
	p.retirementDone = retirementDone
	candidateID := p.candidateID
	p.outputCandidateTerminalLockedV1(MaintenanceExpired)
	candidate := p.detachCandidateLocked()
	op := p.operation
	if op != nil {
		op.cancelled = true
		op.cancel()
	}
	p.armTimerAtLocked(p.parentTimerAt, maintenanceTimerParent)
	p.mu.Unlock()
	p.retirementMu.Unlock()
	if op != nil {
		<-op.done
	}
	p.retirementMu.Lock()
	p.retireCandidateHeld(candidate, candidateID)
	p.mu.Lock()
	terminal := p.terminalSet
	p.mu.Unlock()
	if terminal {
		p.retireOwnerOnceHeld()
	}
	p.mu.Lock()
	p.retirementBusy = false
	p.retirementDone = nil
	p.mu.Unlock()
	close(retirementDone)
	p.retirementMu.Unlock()
}

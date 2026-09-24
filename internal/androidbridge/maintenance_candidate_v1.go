// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"errors"
	"math"
	"time"

	"kurdistan/internal/selfhost"
)

func VerifyMaintenanceCandidateV1(registry *HandleRegistry, parent Handle, artifact []byte) MaintenanceCandidateResultV1 {
	return VerifyMaintenanceCandidateV1Scoped(registry, parent, artifact, MaintenanceOutputInvocationV1{})
}
func VerifyMaintenanceCandidateV1Scoped(registry *HandleRegistry, parent Handle, artifact []byte, inv MaintenanceOutputInvocationV1) MaintenanceCandidateResultV1 {
	owner, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: result}
	}
	op, result := owner.beginOperationOutputV1(inv, false)
	if result != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: result}
	}
	defer owner.finishOperation(op)
	return owner.verifyMaintenanceCandidateV1(op, artifact)
}

func (owner *maintenanceAuthorityV1) verifyMaintenanceCandidateV1(op *maintenanceOperationV1, artifact []byte) MaintenanceCandidateResultV1 {
	result := MaintenanceSuccess
	if result = owner.checkCompletion(op); result != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: result}
	}
	if result = owner.revalidatePlatform(op); result != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: result}
	}
	now, result := owner.trustedNow(op)
	if result != MaintenanceSuccess {
		return MaintenanceCandidateResultV1{Result: result}
	}
	owner.mu.Lock()
	admission := owner.owner
	owner.mu.Unlock()
	if admission == nil {
		return MaintenanceCandidateResultV1{Result: MaintenanceInvalidState}
	}
	if err := admission.RevalidateAt(now); err != nil {
		result = maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			result = owner.failOperation(op, MaintenanceExpired)
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	candidate, noChange, err := admission.VerifyCandidateAt(artifact, now)
	if err != nil {
		return MaintenanceCandidateResultV1{Result: maintenanceResultFromError(err)}
	}
	if !noChange && candidate == nil {
		return MaintenanceCandidateResultV1{Result: MaintenanceInternalFailure}
	}
	var preview selfhost.LiveMaintenancePreviewV1
	if candidate != nil {
		var ok bool
		preview, ok = candidate.PreviewV1()
		if !ok || !validMaintenancePreviewV1(preview) {
			owner.retireCandidate(candidate)
			return MaintenanceCandidateResultV1{Result: MaintenanceInternalFailure}
		}
	}
	var completionNow, completionMonotonicNow time.Time
	if candidate != nil {
		completionNow, completionMonotonicNow, result = owner.trustedNowAndMonotonic(op)
	} else {
		completionNow, result = owner.trustedNow(op)
	}
	if result != MaintenanceSuccess {
		owner.retireCandidate(candidate)
		return MaintenanceCandidateResultV1{Result: result}
	}
	var deadline, preservedMonotonicDeadline time.Time
	if candidate != nil {
		var deadlineOK bool
		deadline, deadlineOK = maintenanceCandidateDeadlineV1(completionNow, owner.parentEnd, candidate.AuthorityDeadline())
		if !deadlineOK {
			owner.retireCandidate(candidate)
			return MaintenanceCandidateResultV1{Result: MaintenanceExpired}
		}
		preservedMonotonicDeadline, deadlineOK = maintenanceMonotonicDeadlineV1(completionNow, deadline, completionMonotonicNow)
		if deadlineOK && owner.parentTimerAt.Before(preservedMonotonicDeadline) {
			preservedMonotonicDeadline = owner.parentTimerAt
		}
		if !deadlineOK || !preservedMonotonicDeadline.After(completionMonotonicNow) {
			owner.retireCandidate(candidate)
			return MaintenanceCandidateResultV1{Result: MaintenanceExpired}
		}
	}
	lease, result := owner.acquirePublication(op)
	if result != MaintenanceSuccess {
		owner.retireCandidate(candidate)
		return MaintenanceCandidateResultV1{Result: result}
	}
	if result = owner.checkCompletion(op); result != MaintenanceSuccess {
		if closeResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil); closeResult != MaintenanceSuccess {
			result = closeResult
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	finalNow, finalMonotonicNow, result := owner.trustedNowAndMonotonic(op)
	if result != MaintenanceSuccess {
		if leaseResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	if noChange {
		owner.mu.Lock()
		live := owner.operationCanPublishLocked(op) && finalNow.Before(owner.parentEnd)
		owner.mu.Unlock()
		if !live {
			result = owner.finishPublication(op, lease)
			if result == MaintenanceSuccess {
				result = MaintenanceCancelled
			}
			return MaintenanceCandidateResultV1{Result: result}
		}
		if result = owner.finishPublication(op, lease); result != MaintenanceSuccess {
			return MaintenanceCandidateResultV1{Result: result}
		}
		return MaintenanceCandidateResultV1{Result: MaintenanceNoChange}
	}
	if !finalNow.Before(deadline) || !finalNow.Before(candidate.AuthorityDeadline()) {
		result = MaintenanceExpired
		if leaseResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	monotonicDeadline, monotonicOK := maintenanceShortenMonotonicDeadlineV1(
		finalNow, deadline, finalMonotonicNow, preservedMonotonicDeadline, owner.parentTimerAt,
	)
	if !monotonicOK {
		result = MaintenanceExpired
		if leaseResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return MaintenanceCandidateResultV1{Result: result}
	}

	owner.mu.Lock()
	if !owner.operationCanPublishLocked(op) || owner.candidate != nil || !finalNow.Before(owner.parentEnd) {
		owner.mu.Unlock()
		result = owner.finishPublicationAndRetireDetached(op, lease, candidate, nil)
		if result == MaintenanceSuccess {
			result = MaintenanceCancelled
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	id, ok := owner.allocateCandidateIDLocked()
	if !ok {
		owner.mu.Unlock()
		result = owner.finishPublicationAndRetireDetached(op, lease, candidate, nil)
		if result == MaintenanceSuccess {
			result = MaintenanceResourceLimit
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	owner.candidate = candidate
	owner.candidateID = id
	owner.candidateEnd = deadline
	kind := maintenanceTimerCandidate
	if deadline.Equal(owner.parentEnd) {
		kind = maintenanceTimerParent
	}
	owner.armTimerAtLocked(monotonicDeadline, kind)
	result = owner.outputPrepareLockedV1(op.output, id, monotonicDeadline, false)
	op.outputPrepared = true // even refusal must not prepare a second identity
	owner.mu.Unlock()
	if result != MaintenanceSuccess {
		owner.mu.Lock()
		if owner.candidate == candidate && owner.candidateID == id {
			owner.outputCandidateTerminalLockedV1(result)
			owner.detachCandidateLocked()
			owner.armTimerAtLocked(owner.parentTimerAt, maintenanceTimerParent)
		} else {
			candidate = nil
		}
		owner.mu.Unlock()
		if closeResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil, id); closeResult != MaintenanceSuccess {
			result = closeResult
		}
		return MaintenanceCandidateResultV1{Result: result}
	}
	return owner.completeCandidatePublication(op, lease, candidate, id, preview)
}

func (owner *maintenanceAuthorityV1) completeCandidatePublication(op *maintenanceOperationV1, lease MaintenancePublicationLeaseV1, candidate *selfhost.LiveMaintenanceCandidate, id MaintenanceCandidateID, preview selfhost.LiveMaintenancePreviewV1) MaintenanceCandidateResultV1 {
	result := MaintenanceSuccess
	if result = owner.finishPublication(op, lease); result != MaintenanceSuccess {
		// A fetch timeout does not terminalize the parent. Its failed return
		// must still revoke the just-published child after closing the lease.
		owner.mu.Lock()
		if owner.candidate == candidate && owner.candidateID == id {
			owner.outputCandidateTerminalLockedV1(result)
			owner.detachCandidateLocked()
			owner.armTimerAtLocked(owner.parentTimerAt, maintenanceTimerParent)
		} else {
			candidate = nil
		}
		owner.mu.Unlock()
		owner.retireCandidate(candidate, id)
		return MaintenanceCandidateResultV1{Result: result}
	}
	return MaintenanceCandidateResultV1{Result: MaintenanceSuccess, Candidate: id, Preview: preview}
}

func (p *maintenanceAuthorityV1) allocateCandidateIDLocked() (MaintenanceCandidateID, bool) {
	if p.nextChildID == ^MaintenanceCandidateID(0) {
		return 0, false
	}
	p.nextChildID++
	return p.nextChildID, true
}

func MaterializeMaintenanceCandidateV1(registry *HandleRegistry, parent Handle, candidateID MaintenanceCandidateID, dst []byte) (int, MaintenanceResultV1) {
	return MaterializeMaintenanceCandidateV1Scoped(registry, parent, candidateID, dst, MaintenanceOutputInvocationV1{})
}
func MaterializeMaintenanceCandidateV1Scoped(registry *HandleRegistry, parent Handle, candidateID MaintenanceCandidateID, dst []byte, inv MaintenanceOutputInvocationV1) (int, MaintenanceResultV1) {
	owner, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != MaintenanceSuccess {
		return 0, result
	}
	op, result := owner.beginOperationOutputV1(inv, false)
	if result != MaintenanceSuccess {
		return 0, result
	}
	defer owner.finishOperation(op)
	if result = owner.revalidatePlatform(op); result != MaintenanceSuccess {
		return 0, result
	}
	now, result := owner.trustedNow(op)
	if result != MaintenanceSuccess {
		return 0, result
	}
	owner.mu.Lock()
	admission, child, liveID, deadline := owner.owner, owner.candidate, owner.candidateID, owner.candidateEnd
	owner.mu.Unlock()
	if candidateID == 0 || liveID != candidateID || child == nil || admission == nil {
		return 0, MaintenanceInvalidState
	}
	if !now.Before(deadline) {
		owner.expireCandidateNow(child, candidateID, op)
		return 0, MaintenanceExpired
	}
	if err := admission.RevalidateAt(now); err != nil {
		result = maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			return 0, owner.failOperation(op, MaintenanceExpired)
		}
		if result == MaintenanceCancelled || result == MaintenanceInvalidState {
			owner.expireCandidateNow(child, candidateID, op)
		}
		return 0, result
	}
	if err := admission.RevalidateCandidateAt(child, now); err != nil {
		result = maintenanceResultFromError(err)
		if result == MaintenanceExpired || result == MaintenanceCancelled || result == MaintenanceInvalidState {
			owner.expireCandidateNow(child, candidateID, op)
		}
		return 0, result
	}
	lease, result := owner.acquirePublication(op)
	if result != MaintenanceSuccess {
		return 0, result
	}
	finalNow, result := owner.trustedNow(op)
	if result != MaintenanceSuccess {
		if leaseResult := owner.finishPublication(op, lease); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return 0, result
	}

	owner.mu.Lock()
	parentExpired := !finalNow.Before(owner.parentEnd)
	candidateExpired := !finalNow.Before(owner.candidateEnd)
	if !owner.operationCanPublishLocked(op) || owner.candidate != child || owner.candidateID != candidateID || parentExpired || candidateExpired {
		if candidateExpired && !parentExpired && owner.candidate == child {
			owner.outputCandidateTerminalLockedV1(MaintenanceExpired)
			owner.detachCandidateLocked()
			owner.armTimerAtLocked(owner.parentTimerAt, maintenanceTimerParent)
		}
		owner.mu.Unlock()
		if parentExpired {
			result = owner.failOperation(op, MaintenanceExpired)
		}
		if candidateExpired && !parentExpired {
			if leaseResult := owner.finishPublicationAndRetireDetached(op, lease, child, nil, candidateID); leaseResult != MaintenanceSuccess {
				return 0, leaseResult
			}
			return 0, MaintenanceExpired
		}
		if leaseResult := owner.finishPublication(op, lease); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		if result != MaintenanceSuccess {
			return 0, result
		}
		return 0, MaintenanceCancelled
	}
	if len(dst) < child.ArtifactLength() {
		owner.mu.Unlock()
		if result := owner.finishPublication(op, lease); result != MaintenanceSuccess {
			return 0, result
		}
		return 0, MaintenanceSizeLimit
	}
	n, err := admission.CopyCandidateInto(child, dst)
	if err == nil {
		owner.detachCandidateLocked()
		owner.armTimerAtLocked(owner.parentTimerAt, maintenanceTimerParent)
		result = owner.outputPrepareLockedV1(op.output, 0, owner.parentTimerAt, false)
		op.outputPrepared = true
	}
	owner.mu.Unlock()
	leaseResult := owner.finishPublication(op, lease)
	if err != nil {
		if n > 0 {
			clear(dst[:n])
		}
		if leaseResult != MaintenanceSuccess {
			return 0, leaseResult
		}
		return 0, maintenanceResultFromError(err)
	}
	owner.retireCandidate(child, candidateID)
	if result != MaintenanceSuccess && leaseResult == MaintenanceSuccess {
		leaseResult = result
	}
	if leaseResult != MaintenanceSuccess {
		if n > 0 {
			clear(dst[:n])
		}
		return 0, leaseResult
	}
	return n, MaintenanceSuccess
}

func ReleaseMaintenanceCandidateV1(registry *HandleRegistry, parent Handle, candidateID MaintenanceCandidateID) MaintenanceResultV1 {
	return ReleaseMaintenanceCandidateV1Scoped(registry, parent, candidateID, MaintenanceOutputInvocationV1{})
}
func ReleaseMaintenanceCandidateV1Scoped(registry *HandleRegistry, parent Handle, candidateID MaintenanceCandidateID, inv MaintenanceOutputInvocationV1) MaintenanceResultV1 {
	owner, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != MaintenanceSuccess {
		return result
	}
	op, result := owner.beginOperationOutputV1(inv, false)
	if result != MaintenanceSuccess {
		return result
	}
	defer owner.finishOperation(op)
	owner.mu.Lock()
	if candidateID == 0 || owner.candidateID != candidateID || owner.candidate == nil {
		owner.mu.Unlock()
		return MaintenanceInvalidState
	}
	owner.outputCandidateTerminalLockedV1(MaintenanceCancelled)
	candidate := owner.detachCandidateLocked()
	owner.armTimerAtLocked(owner.parentTimerAt, maintenanceTimerParent)
	owner.mu.Unlock()
	owner.retireCandidate(candidate, candidateID)
	if !inv.legacyV1() {
		owner.mu.Lock()
		if !owner.operationCanPublishLocked(op) {
			result = MaintenanceCancelled
		} else {
			result = owner.outputPrepareLockedV1(inv, 0, owner.parentTimerAt, false)
		}
		owner.mu.Unlock()
		return result
	}
	return MaintenanceSuccess
}

func SubmitMaintenanceCurrentRevocationV1(registry *HandleRegistry, parent Handle, publication []byte) MaintenanceResultV1 {
	return SubmitMaintenanceCurrentRevocationV1Scoped(registry, parent, publication, MaintenanceOutputInvocationV1{})
}
func SubmitMaintenanceCurrentRevocationV1Scoped(registry *HandleRegistry, parent Handle, publication []byte, inv MaintenanceOutputInvocationV1) MaintenanceResultV1 {
	owner, result := maintenanceParentOutputV1(registry, parent, inv)
	if result != MaintenanceSuccess {
		return result
	}
	op, result := owner.beginRevocationOutputV1(inv)
	if result != MaintenanceSuccess {
		return result
	}
	defer owner.finishRevocationOperation(op)
	if result = owner.revalidatePlatform(op); result != MaintenanceSuccess {
		return result
	}
	now, result := owner.trustedNow(op)
	if result != MaintenanceSuccess {
		return result
	}
	owner.mu.Lock()
	admission := owner.owner
	owner.mu.Unlock()
	if admission == nil {
		return MaintenanceInvalidState
	}
	if err := admission.RevalidateAt(now); err != nil {
		result = maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			result = owner.failOperation(op, MaintenanceExpired)
		}
		return result
	}
	proof, err := admission.VerifyCurrentRevocationAt(publication, now)
	if errors.Is(err, selfhost.ErrNoCurrentRevocation) {
		return MaintenanceNotAdmitted
	}
	if err != nil {
		result = maintenanceResultFromError(err)
		if result == MaintenanceExpired {
			result = owner.failOperation(op, MaintenanceExpired)
		}
		return result
	}
	lease, result := owner.acquirePublication(op)
	if result != MaintenanceSuccess {
		return result
	}
	finalNow, result := owner.trustedNow(op)
	if result != MaintenanceSuccess {
		if leaseResult := owner.finishPublication(op, lease); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return result
	}
	owner.mu.Lock()
	parentExpired := !finalNow.Before(owner.parentEnd)
	owner.mu.Unlock()
	if parentExpired {
		result = owner.failOperation(op, MaintenanceExpired)
		if leaseResult := owner.finishPublication(op, lease); leaseResult != MaintenanceSuccess {
			result = leaseResult
		}
		return result
	}
	if !admission.IsCurrentRevocationAt(proof, finalNow) {
		if result = owner.finishPublication(op, lease); result != MaintenanceSuccess {
			return result
		}
		return MaintenanceInvalidState
	}
	owner.mu.Lock()
	if !owner.operationCanPublishLocked(op) || !finalNow.Before(owner.parentEnd) {
		owner.mu.Unlock()
		if result = owner.finishPublication(op, lease); result != MaintenanceSuccess {
			return result
		}
		return MaintenanceCancelled
	}
	owner.terminalSet = true
	owner.terminal = MaintenanceRevoked
	if owner.output != nil {
		owner.output.ParentTerminalV1(owner.parentEpoch, MaintenanceRevoked)
	}
	owner.outputCandidateTerminalLockedV1(MaintenanceRevoked)
	candidateID := owner.candidateID
	candidate := owner.detachCandidateLocked()
	// Authenticated terminal output carries no fresh authority lifetime. The
	// native-only terminal attestation is distinct from ordinary zero deadline.
	result = owner.outputPrepareLockedV1(op.output, 0, time.Time{}, true)
	owner.stopOnce.Do(func() { close(owner.timerStop) })
	owner.mu.Unlock()
	leaseResult := owner.finishPublicationAndRetireDetached(op, lease, candidate, nil, candidateID)
	owner.retireOwnerOnce()
	if leaseResult != MaintenanceSuccess && leaseResult != MaintenanceRevoked {
		return leaseResult
	}
	if result != MaintenanceSuccess {
		return result
	}
	return MaintenanceRevoked
}

func (p *maintenanceAuthorityV1) beginRevocationOperation() (*maintenanceOperationV1, MaintenanceResultV1) {
	return p.beginRevocationOutputV1(MaintenanceOutputInvocationV1{})
}
func (p *maintenanceAuthorityV1) beginRevocationOutputV1(inv MaintenanceOutputInvocationV1) (*maintenanceOperationV1, MaintenanceResultV1) {
	p.mu.Lock()
	if s := p.outputIdentityLockedV1(inv); s != MaintenanceSuccess {
		p.mu.Unlock()
		return nil, s
	}
	if p.terminalSet {
		result := p.terminal
		p.mu.Unlock()
		return nil, result
	}
	if p.revocationBusy || p.retirementBusy {
		p.mu.Unlock()
		return nil, MaintenanceResourceLimit
	}
	if s := p.outputLaneLockedV1(inv, true); s != MaintenanceSuccess {
		p.mu.Unlock()
		return nil, s
	}
	if !inv.legacyV1() {
		if s := normalizeMaintenancePlatformResult(p.output.SupersedeNormalV1(inv.call, inv.epoch)); s != MaintenanceSuccess {
			p.mu.Unlock()
			return nil, s
		}
	}
	p.revocationBusy = true
	prior := p.operation
	if prior != nil {
		prior.cancelled = true
		prior.cancel()
	}
	p.mu.Unlock()
	if prior != nil {
		<-prior.done
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.terminalSet {
		p.revocationBusy = false
		return nil, p.terminal
	}
	if p.retirementBusy || p.operation != nil || p.operationEpoch == math.MaxUint64 {
		p.revocationBusy = false
		return nil, MaintenanceResourceLimit
	}
	p.operationEpoch++
	ctx, cancel := context.WithCancel(context.Background())
	op := &maintenanceOperationV1{epoch: p.operationEpoch, ctx: ctx, cancel: cancel, done: make(chan struct{}), output: inv}
	p.operation = op
	return op, MaintenanceSuccess
}

func (p *maintenanceAuthorityV1) finishRevocationOperation(op *maintenanceOperationV1) {
	p.finishOperation(op)
	p.mu.Lock()
	p.revocationBusy = false
	p.mu.Unlock()
}

func (p *maintenanceAuthorityV1) expireCandidateNow(candidate *selfhost.LiveMaintenanceCandidate, id MaintenanceCandidateID, op *maintenanceOperationV1) {
	p.mu.Lock()
	if p.operation == op && p.candidate == candidate && p.candidateID == id {
		p.outputCandidateTerminalLockedV1(MaintenanceExpired)
		p.detachCandidateLocked()
		p.armTimerAtLocked(p.parentTimerAt, maintenanceTimerParent)
	}
	p.mu.Unlock()
	p.retireCandidate(candidate, id)
}

func maintenanceCandidateDeadlineV1(now, current, candidate time.Time) (time.Time, bool) {
	if now.IsZero() || now.Unix() <= 0 || now.Unix() > math.MaxInt64-60 || !current.After(now) || !candidate.After(now) {
		return time.Time{}, false
	}
	deadline := now.Add(60 * time.Second)
	if current.Before(deadline) {
		deadline = current
	}
	if candidate.Before(deadline) {
		deadline = candidate
	}
	return deadline, deadline.After(now)
}

func maintenanceShortenMonotonicDeadlineV1(now, deadline, monotonicNow, preserved, parent time.Time) (time.Time, bool) {
	mapped, ok := maintenanceMonotonicDeadlineV1(now, deadline, monotonicNow)
	if !ok || preserved.IsZero() || parent.IsZero() {
		return time.Time{}, false
	}
	if preserved.Before(mapped) {
		mapped = preserved
	}
	if parent.Before(mapped) {
		mapped = parent
	}
	if !mapped.After(monotonicNow) {
		return time.Time{}, false
	}
	return mapped, true
}

func validMaintenancePreviewV1(preview selfhost.LiveMaintenancePreviewV1) bool {
	if !preview.DeploymentMatch || preview.Generation == 0 || preview.ArtifactLength == 0 ||
		preview.ExpiryCategory > 1 || preview.RotationFlags > 7 || preview.RotationFlags&2 != 0 ||
		preview.RevocationCategory != 0 || preview.CompatibilityCategory != 0 {
		return false
	}
	for _, value := range preview.ChangedCategories {
		if value > 1 {
			return false
		}
	}
	return true
}

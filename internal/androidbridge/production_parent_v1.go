// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"math"
	"sync"
	"time"
	"unsafe"
)

const (
	productionParentOpenV1       uint8 = 1
	productionParentCancellingV1 uint8 = 2
	productionParentCancelledV1  uint8 = 3
	productionParentClosedV1     uint8 = 4

	productionUseSlotCountV1   = 203
	productionUseOpeningV1     = 0
	productionUseControlPollV1 = 1
	productionUseCoordinatorV1 = 5
	productionUseAttemptV1     = 202

	// Go1.26.6 sync primitives, context cancellation nodes, two channel
	// headers, and one timer are conservatively covered by this bounded
	// metadata allowance. Payloads and future owner resources are excluded.
	productionRuntimeMetadataAllowanceV1 = uint64(4096)
)

type productionSlotTicketV1 struct {
	registry *HandleRegistry
	index    uint16
	epoch    uint64
}

type productionUseV1 struct {
	parent  *productionParentV1
	index   uint16
	serial  uint64
	attempt uint64
}

type productionUseRecordV1 struct {
	serial  uint64
	attempt uint64
	budget  productionBudgetTicketV1
	live    bool
}

type productionParentV1 struct {
	mu sync.Mutex

	ticket        productionSlotTicketV1
	state         uint8
	terminal      productionStatusV1
	cleanupResult int32
	deadline      time.Time
	attempt       uint64
	activeUses    uint16
	uses          [productionUseSlotCountV1]productionUseRecordV1
	budget        *productionBudgetV1
	admission     *productionAdmissionV1
	session       *productionSessionV1
	output        ProductionOutputObserverV1
	outputOwner   uint64
	outputHandle  Handle

	cancelContext context.Context
	cancel        context.CancelFunc
	joined        chan struct{}
	joinedClosed  bool
	controlWake   chan struct{}

	controlArena            [productionControlArenaBytesV1]byte
	controlDescriptors      [productionControlOrdinaryDescriptorsV1]productionControlDescriptorV1
	controlHead             uint8
	controlTail             uint8
	controlCount            uint8
	controlBytes            uint32
	controlWriteOffset      uint32
	terminalControl         productionControlDescriptorV1
	terminalControlSet      bool
	terminalControlObserved bool
	terminalControlKind     productionControlKindV1
	nextControlSequence     uint64
	controlRetryDeadline    time.Time
	controlRetryStatus      productionStatusV1
}

// Replace a counted admission stage in the same ledger record. This neither
// releases a live graph between stages nor changes the ledger's capacity.
func (parent *productionParentV1) resizeAdmissionTicketV1(ticket productionBudgetTicketV1, owned uint64) int32 {
	ledger := parent.budget
	if ticket.ledger != ledger || ticket.index == 0 || int(ticket.index) >= len(ledger.records) {
		return int32(productionInvalidStateV1)
	}
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	r := &ledger.records[ticket.index]
	if !r.live || r.serial != ticket.serial || r.charge.queued != 0 || r.charge.owned > ledger.owned {
		return int32(productionInvalidStateV1)
	}
	base := ledger.owned - r.charge.owned
	if owned > ledger.cap || base > ledger.cap-owned {
		return int32(productionResourceLimitV1)
	}
	r.charge.owned = owned
	ledger.owned = base + owned
	return int32(productionSuccessV1)
}

func productionParentFixedBytesV1() (uint64, int32) {
	parentBytes := uint64(unsafe.Sizeof(productionParentV1{}))
	budgetBytes := uint64(unsafe.Sizeof(productionBudgetV1{}))
	if parentBytes > math.MaxUint64-budgetBytes-productionRuntimeMetadataAllowanceV1 {
		return 0, int32(productionInternalFailureV1)
	}
	return parentBytes + budgetBytes + productionRuntimeMetadataAllowanceV1, int32(productionSuccessV1)
}

func reserveProductionSlotV1(registry *HandleRegistry) (productionSlotTicketV1, int32) {
	if registry == nil {
		return productionSlotTicketV1{}, int32(productionInvalidRequestV1)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for index := range registry.slots {
		slot := &registry.slots[index]
		if slot.occupied || slot.privatelyReserved || slot.productionReservationEpoch == math.MaxUint64 || slot.productionGeneration == math.MaxUint32 {
			continue
		}
		slot.productionReservationEpoch++
		slot.privatelyReserved = true
		slot.productionConstructionClaim = false
		slot.productionParent = nil
		return productionSlotTicketV1{registry: registry, index: uint16(index), epoch: slot.productionReservationEpoch}, int32(productionSuccessV1)
	}
	return productionSlotTicketV1{}, int32(productionResourceLimitV1)
}

func releaseProductionSlotV1(ticket productionSlotTicketV1) int32 {
	if ticket.registry == nil || ticket.epoch == 0 || int(ticket.index) >= len(ticket.registry.slots) {
		return int32(productionInvalidStateV1)
	}
	ticket.registry.mu.Lock()
	defer ticket.registry.mu.Unlock()
	slot := &ticket.registry.slots[ticket.index]
	if !slot.privatelyReserved || slot.productionConstructionClaim || slot.productionReservationEpoch != ticket.epoch || slot.productionParent != nil {
		return int32(productionInvalidStateV1)
	}
	slot.privatelyReserved = false
	return int32(productionSuccessV1)
}

func claimProductionConstructionV1(ticket productionSlotTicketV1) int32 {
	if ticket.registry == nil || ticket.epoch == 0 || int(ticket.index) >= len(ticket.registry.slots) {
		return int32(productionInvalidStateV1)
	}
	ticket.registry.mu.Lock()
	defer ticket.registry.mu.Unlock()
	slot := &ticket.registry.slots[ticket.index]
	if !slot.privatelyReserved || slot.productionConstructionClaim || slot.productionReservationEpoch != ticket.epoch || slot.productionParent != nil {
		return int32(productionInvalidStateV1)
	}
	slot.productionConstructionClaim = true
	return int32(productionSuccessV1)
}

func rollbackProductionConstructionV1(ticket productionSlotTicketV1, releaseReservation bool) {
	if ticket.registry == nil || ticket.epoch == 0 || int(ticket.index) >= len(ticket.registry.slots) {
		return
	}
	ticket.registry.mu.Lock()
	slot := &ticket.registry.slots[ticket.index]
	if slot.privatelyReserved && slot.productionConstructionClaim && slot.productionReservationEpoch == ticket.epoch && slot.productionParent == nil {
		slot.productionConstructionClaim = false
		if releaseReservation {
			slot.privatelyReserved = false
		}
	}
	ticket.registry.mu.Unlock()
}

func newProductionParentV1(ticket productionSlotTicketV1, capacity uint64, deadline time.Time) (*productionParentV1, int32) {
	if ticket.registry == nil || ticket.epoch == 0 || int(ticket.index) >= len(ticket.registry.slots) {
		return nil, int32(productionInvalidStateV1)
	}
	if status := claimProductionConstructionV1(ticket); status != int32(productionSuccessV1) {
		return nil, status
	}
	budget, status := newProductionBudgetV1(capacity)
	if status != int32(productionSuccessV1) {
		rollbackProductionConstructionV1(ticket, true)
		return nil, status
	}
	cancelContext, cancel := context.WithCancel(context.Background())
	parent := &productionParentV1{
		ticket:              ticket,
		state:               productionParentOpenV1,
		deadline:            deadline,
		attempt:             1,
		budget:              budget,
		cancelContext:       cancelContext,
		cancel:              cancel,
		joined:              make(chan struct{}),
		controlWake:         make(chan struct{}, 1),
		nextControlSequence: 1,
	}
	ticket.registry.mu.Lock()
	slot := &ticket.registry.slots[ticket.index]
	if !slot.privatelyReserved || !slot.productionConstructionClaim || slot.productionReservationEpoch != ticket.epoch || slot.productionParent != nil {
		ticket.registry.mu.Unlock()
		cancel()
		rollbackProductionConstructionV1(ticket, false)
		return nil, int32(productionInvalidStateV1)
	}
	slot.productionParent = parent
	slot.productionConstructionClaim = false
	ticket.registry.mu.Unlock()
	return parent, int32(productionSuccessV1)
}

func validProductionTerminalStatusV1(status productionStatusV1) bool {
	return validProductionStatusV1(status) && status != productionSuccessV1 && status != productionEndOfStreamV1 && status != productionNoEventV1
}

func productionUseAttemptScopedV1(index uint16) bool {
	return index != productionUseOpeningV1 && index != productionUseControlPollV1 && index != productionUseCoordinatorV1
}

func (parent *productionParentV1) deadlineExpiredLockedV1(now time.Time) bool {
	return !parent.deadline.IsZero() && !now.Before(parent.deadline)
}

func (parent *productionParentV1) terminalOperationStatusLockedV1() int32 {
	if parent.terminal == productionAuthorityRevokedV1 {
		return int32(productionAuthorityRevokedV1)
	}
	return int32(productionCancelledV1)
}

func (parent *productionParentV1) fenceLockedV1(reason productionStatusV1) (cancelNow bool) {
	if parent.state != productionParentOpenV1 {
		return false
	}
	parent.state = productionParentCancellingV1
	parent.terminal = reason
	if parent.output != nil {
		parent.output.ParentTerminalV1(parent.ticket.epoch, int32(reason))
	}
	parent.clearOrdinaryControlLockedV1()
	parent.clearControlRetryLockedV1()
	if parent.activeUses == 0 {
		parent.state = productionParentCancelledV1
		if !parent.joinedClosed {
			close(parent.joined)
			parent.joinedClosed = true
		}
	}
	return true
}

func (parent *productionParentV1) beginUseV1(index uint16, charge productionBudgetChargeV1) (productionUseV1, int32) {
	return parent.beginUseOutputV1(index, charge, ProductionOutputInvocationV1{}, false)
}

func (parent *productionParentV1) beginUseOutputV1(index uint16, charge productionBudgetChargeV1, inv ProductionOutputInvocationV1, laneBound bool) (productionUseV1, int32) {
	if parent == nil || int(index) >= len(parent.uses) {
		return productionUseV1{}, int32(productionInvalidRequestV1)
	}
	parent.mu.Lock()
	if s := parent.outputIdentityLockedV1(inv); s != 0 {
		parent.mu.Unlock()
		return productionUseV1{}, s
	}
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return productionUseV1{}, int32(productionInvalidStateV1)
	}
	if parent.state != productionParentOpenV1 {
		status := parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return productionUseV1{}, status
	}
	if parent.deadlineExpiredLockedV1(time.Now()) {
		cancelNow := parent.fenceLockedV1(productionAuthorityExpiredV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return productionUseV1{}, int32(productionAuthorityExpiredV1)
	}
	record := &parent.uses[index]
	if record.live {
		parent.mu.Unlock()
		return productionUseV1{}, int32(productionResourceLimitV1)
	}
	if record.serial == math.MaxUint64 {
		parent.mu.Unlock()
		return productionUseV1{}, int32(productionResourceLimitV1)
	}
	if !laneBound {
		if s := parent.outputLaneLockedV1(inv, index); s != 0 {
			parent.mu.Unlock()
			return productionUseV1{}, s
		}
	}
	if !inv.legacyV1() {
		if charge.owned > math.MaxUint64-uint64(unsafe.Sizeof(inv)) {
			parent.mu.Unlock()
			return productionUseV1{}, 5
		}
		charge.owned += uint64(unsafe.Sizeof(inv))
	}
	budgetTicket, status := parent.budget.reserveV1(charge)
	if status != int32(productionSuccessV1) {
		parent.mu.Unlock()
		return productionUseV1{}, status
	}
	record.serial++
	record.attempt = parent.attempt
	record.budget = budgetTicket
	record.live = true
	parent.activeUses++
	use := productionUseV1{parent: parent, index: index, serial: record.serial, attempt: record.attempt}
	parent.mu.Unlock()
	return use, int32(productionSuccessV1)
}

func (parent *productionParentV1) finishUseV1(use productionUseV1) int32 {
	if parent == nil || use.parent != parent || int(use.index) >= len(parent.uses) || use.serial == 0 {
		return int32(productionInvalidStateV1)
	}
	parent.mu.Lock()
	record := &parent.uses[use.index]
	if !record.live || record.serial != use.serial || record.attempt != use.attempt {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	var attempt *ProductionAttemptAdmissionV1
	if use.index == productionUseAttemptV1 && parent.admission != nil {
		attempt = parent.admission.attempt
		if attempt != nil {
			if attempt.use != use || attempt.released || attempt.borrow != nil && (!attempt.borrow.closed || attempt.borrow.active) {
				parent.mu.Unlock()
				return int32(productionInvalidStateV1)
			}
			select {
			case <-attempt.resources.installation.Done():
			default:
				parent.mu.Unlock()
				return int32(productionInvalidStateV1)
			}
		}
	}
	if status := parent.budget.releaseV1(record.budget); status != int32(productionSuccessV1) {
		parent.mu.Unlock()
		return status
	}
	record.budget = productionBudgetTicketV1{}
	record.live = false
	if attempt != nil {
		if parent.budget.releaseV1(attempt.ticket) != int32(productionSuccessV1) {
			parent.mu.Unlock()
			return int32(productionInternalFailureV1)
		}
		attempt.released = true
		parent.admission.attempt = nil
	}
	if parent.activeUses == 0 {
		parent.mu.Unlock()
		return int32(productionInternalFailureV1)
	}
	parent.activeUses--
	if parent.session != nil {
		parent.session.signalV1()
	}
	if parent.state == productionParentCancellingV1 && parent.activeUses == 0 {
		parent.state = productionParentCancelledV1
		if !parent.joinedClosed {
			close(parent.joined)
			parent.joinedClosed = true
		}
	}
	parent.mu.Unlock()
	return int32(productionSuccessV1)
}

func (parent *productionParentV1) useCurrentV1(use productionUseV1) int32 {
	if parent == nil || use.parent != parent || int(use.index) >= len(parent.uses) || use.serial == 0 {
		return int32(productionInvalidStateV1)
	}
	parent.mu.Lock()
	record := &parent.uses[use.index]
	if !record.live || record.serial != use.serial || record.attempt != use.attempt ||
		(productionUseAttemptScopedV1(use.index) && use.attempt != parent.attempt) {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	if parent.state != productionParentOpenV1 {
		status := parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return status
	}
	if parent.deadlineExpiredLockedV1(time.Now()) {
		cancelNow := parent.fenceLockedV1(productionAuthorityExpiredV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return int32(productionAuthorityExpiredV1)
	}
	parent.mu.Unlock()
	return int32(productionSuccessV1)
}

func (parent *productionParentV1) cancelV1(reasonValue int32) int32 {
	if parent == nil {
		return int32(productionInvalidStateV1)
	}
	reason := productionStatusV1(reasonValue)
	if !validProductionTerminalStatusV1(reason) {
		return int32(productionInvalidRequestV1)
	}
	parent.mu.Lock()
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return parent.retiredResultV1()
	}
	cancelNow := parent.fenceLockedV1(reason)
	parent.mu.Unlock()
	if cancelNow {
		parent.cancel()
		parent.signalControlV1()
	}
	return int32(productionSuccessV1)
}

func (parent *productionParentV1) joinV1(ctx context.Context) int32 {
	if parent == nil || ctx == nil {
		return int32(productionInvalidRequestV1)
	}
	parent.mu.Lock()
	if parent.state == productionParentOpenV1 {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	joined := parent.joined
	parent.mu.Unlock()
	select {
	case <-joined:
		return int32(productionSuccessV1)
	case <-ctx.Done():
		return int32(productionTimeoutV1)
	}
}

func (parent *productionParentV1) nextAttemptV1() (uint64, int32) {
	if parent == nil {
		return 0, int32(productionInvalidStateV1)
	}
	parent.mu.Lock()
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return 0, int32(productionInvalidStateV1)
	}
	if parent.state != productionParentOpenV1 {
		status := parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return 0, status
	}
	if parent.deadlineExpiredLockedV1(time.Now()) {
		cancelNow := parent.fenceLockedV1(productionAuthorityExpiredV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return 0, int32(productionAuthorityExpiredV1)
	}
	for index := range parent.uses {
		if parent.uses[index].live && productionUseAttemptScopedV1(uint16(index)) {
			parent.mu.Unlock()
			return 0, int32(productionInvalidStateV1)
		}
	}
	if parent.attempt == math.MaxUint64 {
		cancelNow := parent.fenceLockedV1(productionInternalFailureV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return 0, int32(productionInternalFailureV1)
	}
	parent.attempt++
	epoch := parent.attempt
	parent.mu.Unlock()
	return epoch, int32(productionSuccessV1)
}

func (parent *productionParentV1) retireV1() int32 {
	if parent == nil {
		return int32(productionInvalidStateV1)
	}
	parent.mu.Lock()
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return parent.retiredResultV1()
	}
	if parent.state != productionParentCancelledV1 || parent.activeUses != 0 || !parent.joinedClosed {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	admission := parent.admission
	if admission != nil {
		parent.mu.Unlock()
		if status := admission.closeV1(context.Background()); status != int32(productionSuccessV1) {
			return status
		}
		parent.mu.Lock()
		if parent.state == productionParentClosedV1 {
			parent.mu.Unlock()
			return parent.retiredResultV1()
		}
		if parent.state != productionParentCancelledV1 || parent.activeUses != 0 {
			parent.mu.Unlock()
			return int32(productionInvalidStateV1)
		}
	}
	result := parent.cleanupResult
	if result != int32(productionSuccessV1) && !validProductionTerminalStatusV1(productionStatusV1(result)) {
		result = int32(productionInternalFailureV1)
	}
	parent.clearControlLockedV1()
	parent.state = productionParentClosedV1
	parent.cleanupResult = result
	parent.mu.Unlock()

	registry := parent.ticket.registry
	registry.mu.Lock()
	slot := &registry.slots[parent.ticket.index]
	if !slot.privatelyReserved || slot.productionConstructionClaim || slot.productionReservationEpoch != parent.ticket.epoch || slot.productionParent != parent {
		registry.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	slot.productionParent = nil
	slot.privatelyReserved = false
	retired := retiredParentV1{epoch: parent.ticket.epoch, kind: HandleProductionSession, nativeResult: result, valid: true}
	if parent.session != nil {
		retired.handle = parent.session.handle
	}
	if parent.outputHandle != 0 {
		retired.handle = parent.outputHandle
	}
	slot.retiredParent = retired
	registry.mu.Unlock()
	parent.mu.Lock()
	if parent.output != nil {
		parent.output.ResourceRetiredV1(parent.ticket.epoch, ProductionOutputParentV1, parent.outputHandle, parent.attempt, 0, 0, result)
	}
	parent.mu.Unlock()
	return result
}

func (parent *productionParentV1) retiredResultV1() int32 {
	registry := parent.ticket.registry
	if registry == nil {
		return int32(productionInvalidStateV1)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	slot := &registry.slots[parent.ticket.index]
	if slot.retiredParent.valid && slot.retiredParent.kind == HandleProductionSession && slot.retiredParent.epoch == parent.ticket.epoch && slot.productionReservationEpoch == parent.ticket.epoch {
		return slot.retiredParent.nativeResult
	}
	return int32(productionInvalidStateV1)
}

func (parent *productionParentV1) signalControlV1() {
	select {
	case parent.controlWake <- struct{}{}:
	default:
	}
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"context"
	"encoding/binary"
	"math"
	"time"
	"unsafe"
)

const (
	productionControlHeaderBytesV1           = 32
	productionControlMaximumBodyBytesV1      = 32768
	productionControlMaxEventBytesV1         = productionControlHeaderBytesV1 + productionControlMaximumBodyBytesV1
	productionControlArenaBytesV1            = 131072
	productionControlReservedTerminalBytesV1 = 34
	productionControlOrdinaryBytesV1         = productionControlArenaBytesV1 - productionControlReservedTerminalBytesV1
	productionControlOrdinaryDescriptorsV1   = 63
	productionControlPollMaximumV1           = 250 * time.Millisecond
)

type productionControlKindV1 uint8

const (
	productionControlSocketProtectionRequiredV1 productionControlKindV1 = 1
	productionControlTransportConnectingV1      productionControlKindV1 = 2
	productionControlTransportReadyV1           productionControlKindV1 = 3
	productionControlRoutePlanReadyV1           productionControlKindV1 = 4
	productionControlMetricsUpdatedV1           productionControlKindV1 = 5
	productionControlPathChangedV1              productionControlKindV1 = 6
	productionControlFallbackStartedV1          productionControlKindV1 = 7
	productionControlReconnectStartedV1         productionControlKindV1 = 8
	productionControlDegradedV1                 productionControlKindV1 = 9
	productionControlRevokedV1                  productionControlKindV1 = 10
	productionControlFailedV1                   productionControlKindV1 = 11
	productionControlStoppedV1                  productionControlKindV1 = 12
)

type productionControlRecordV1 struct {
	kind     productionControlKindV1
	epoch    uint64
	sequence uint64
	body     []byte
}

type productionControlDescriptorV1 struct {
	kind   productionControlKindV1
	epoch  uint64
	offset uint32
	size   uint32
}

func validateProductionControlBodyV1(kind productionControlKindV1, body []byte) int32 {
	if kind < productionControlSocketProtectionRequiredV1 || kind > productionControlStoppedV1 {
		return int32(productionInvalidRequestV1)
	}
	if len(body) > productionControlMaximumBodyBytesV1 {
		return int32(productionSizeLimitV1)
	}
	switch kind {
	case productionControlRoutePlanReadyV1, productionControlPathChangedV1:
		_, status := decodeProductionSnapshotV1(body)
		return int32(status)
	case productionControlSocketProtectionRequiredV1:
		if len(body) != 14 || binary.BigEndian.Uint64(body[0:8]) == 0 || int32(binary.BigEndian.Uint32(body[8:12])) < 0 || body[12] != 1 || body[13] > 1 {
			return int32(productionInvalidRequestV1)
		}
	case productionControlTransportConnectingV1, productionControlTransportReadyV1,
		productionControlRevokedV1, productionControlStoppedV1:
		if len(body) != 0 {
			return int32(productionInvalidRequestV1)
		}
	case productionControlMetricsUpdatedV1:
		if len(body) != 42 || body[40] > 64 || body[41] > 4 {
			return int32(productionInvalidRequestV1)
		}
	case productionControlFallbackStartedV1:
		if len(body) != 2 || body[0] == 0 || body[0] > body[1] {
			return int32(productionInvalidRequestV1)
		}
	case productionControlReconnectStartedV1:
		if len(body) != 3 || body[0] < 1 || body[0] > 4 || body[1] == 0 || body[1] > body[2] {
			return int32(productionInvalidRequestV1)
		}
	case productionControlDegradedV1:
		if len(body) != 1 || body[0] < 1 || body[0] > 3 {
			return int32(productionInvalidRequestV1)
		}
	case productionControlFailedV1:
		if len(body) != 2 {
			return int32(productionInvalidRequestV1)
		}
		failure := productionStatusV1(binary.BigEndian.Uint16(body))
		if !validProductionTerminalStatusV1(failure) {
			return int32(productionInvalidRequestV1)
		}
	}
	return int32(productionSuccessV1)
}

func encodeProductionControlFixedV1(record productionControlRecordV1, dst []byte) (int, int32) {
	status := validateProductionControlBodyV1(record.kind, record.body)
	if status != int32(productionSuccessV1) {
		return 0, status
	}
	if record.epoch == 0 || record.sequence == 0 {
		return 0, int32(productionInvalidRequestV1)
	}
	total := productionControlHeaderBytesV1 + len(record.body)
	if total < productionControlHeaderBytesV1 || total > productionControlMaxEventBytesV1 {
		return 0, int32(productionSizeLimitV1)
	}
	if len(dst) < total {
		return 0, int32(productionSizeLimitV1)
	}
	copy(dst[0:4], "KPC1")
	dst[4] = 1
	dst[5] = byte(record.kind)
	dst[6], dst[7] = 0, 0
	binary.BigEndian.PutUint32(dst[8:12], uint32(total))
	binary.BigEndian.PutUint64(dst[12:20], record.epoch)
	binary.BigEndian.PutUint64(dst[20:28], record.sequence)
	binary.BigEndian.PutUint32(dst[28:32], uint32(len(record.body)))
	copy(dst[32:total], record.body)
	return total, int32(productionSuccessV1)
}

func (parent *productionParentV1) enqueueControlFixedV1(kind productionControlKindV1, body []byte) int32 {
	if parent == nil {
		return int32(productionInvalidStateV1)
	}
	status := validateProductionControlBodyV1(kind, body)
	if status != int32(productionSuccessV1) {
		return status
	}
	parent.mu.Lock()
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return int32(productionInvalidStateV1)
	}
	if parent.terminalControlObserved {
		status = int32(productionCancelledV1)
		if parent.terminalControlKind == productionControlRevokedV1 {
			status = int32(productionAuthorityRevokedV1)
		}
		parent.mu.Unlock()
		return status
	}
	if parent.deadlineExpiredLockedV1(time.Now()) && parent.state == productionParentOpenV1 {
		cancelNow := parent.fenceLockedV1(productionAuthorityExpiredV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return int32(productionAuthorityExpiredV1)
	}
	if kind == productionControlRevokedV1 {
		parent.clearOrdinaryControlLockedV1()
		parent.installTerminalControlLockedV1(kind, nil)
		cancelNow := parent.fenceLockedV1(productionAuthorityRevokedV1)
		if !cancelNow {
			parent.terminal = productionAuthorityRevokedV1
		}
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
		}
		parent.signalControlV1()
		return int32(productionSuccessV1)
	}
	if kind == productionControlFailedV1 || kind == productionControlStoppedV1 {
		if parent.terminalControlSet {
			status = parent.terminalOperationStatusLockedV1()
			parent.mu.Unlock()
			return status
		}
		parent.installTerminalControlLockedV1(kind, body)
		reason := productionCancelledV1
		if kind == productionControlFailedV1 {
			reason = productionStatusV1(binary.BigEndian.Uint16(body))
		}
		cancelNow := parent.fenceLockedV1(reason)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
		}
		parent.signalControlV1()
		return int32(productionSuccessV1)
	}
	if parent.state != productionParentOpenV1 {
		status = parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return status
	}
	if kind == productionControlMetricsUpdatedV1 {
		for count, index := uint8(0), parent.controlHead; count < parent.controlCount; count, index = count+1, (index+1)%productionControlOrdinaryDescriptorsV1 {
			descriptor := &parent.controlDescriptors[index]
			if descriptor.kind == kind && descriptor.epoch == parent.attempt {
				parent.writeStoredControlAtLockedV1(descriptor.offset, kind, parent.attempt, body)
				parent.mu.Unlock()
				parent.signalControlV1()
				return int32(productionSuccessV1)
			}
		}
	}
	total := productionControlHeaderBytesV1 + len(body)
	if parent.controlCount >= productionControlOrdinaryDescriptorsV1 || uint64(parent.controlBytes)+uint64(total) > productionControlOrdinaryBytesV1 {
		parent.clearOrdinaryControlLockedV1()
		failureBody := [2]byte{0, byte(productionResourceLimitV1)}
		parent.installTerminalControlLockedV1(productionControlFailedV1, failureBody[:])
		cancelNow := parent.fenceLockedV1(productionResourceLimitV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
		}
		parent.signalControlV1()
		return int32(productionResourceLimitV1)
	}
	parent.appendOrdinaryControlLockedV1(kind, body)
	parent.mu.Unlock()
	parent.signalControlV1()
	return int32(productionSuccessV1)
}

// Caller holds parent.mu and has checked exact descriptor and byte capacity.
func (parent *productionParentV1) appendOrdinaryControlLockedV1(kind productionControlKindV1, body []byte) {
	total := productionControlHeaderBytesV1 + len(body)
	offset := parent.controlWriteOffset
	parent.writeStoredControlAtLockedV1(offset, kind, parent.attempt, body)
	parent.controlDescriptors[parent.controlTail] = productionControlDescriptorV1{kind: kind, epoch: parent.attempt, offset: offset, size: uint32(total)}
	parent.controlTail = (parent.controlTail + 1) % productionControlOrdinaryDescriptorsV1
	parent.controlCount++
	parent.controlBytes += uint32(total)
	parent.controlWriteOffset = (offset + uint32(total)) % productionControlOrdinaryBytesV1
}

func (parent *productionParentV1) writeStoredControlAtLockedV1(offset uint32, kind productionControlKindV1, epoch uint64, body []byte) {
	var encoded [productionControlHeaderBytesV1]byte
	total := productionControlHeaderBytesV1 + len(body)
	copy(encoded[0:4], "KPC1")
	encoded[4] = 1
	encoded[5] = byte(kind)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(total))
	binary.BigEndian.PutUint64(encoded[12:20], epoch)
	binary.BigEndian.PutUint32(encoded[28:32], uint32(len(body)))
	parent.copyIntoOrdinaryControlLockedV1(offset, encoded[:])
	parent.copyIntoOrdinaryControlLockedV1((offset+productionControlHeaderBytesV1)%productionControlOrdinaryBytesV1, body)
}

func (parent *productionParentV1) copyIntoOrdinaryControlLockedV1(offset uint32, source []byte) {
	first := len(source)
	if remaining := productionControlOrdinaryBytesV1 - int(offset); first > remaining {
		first = remaining
	}
	copy(parent.controlArena[int(offset):int(offset)+first], source[:first])
	copy(parent.controlArena[0:len(source)-first], source[first:])
}

func (parent *productionParentV1) copyFromOrdinaryControlLockedV1(destination []byte, descriptor productionControlDescriptorV1) {
	size := int(descriptor.size)
	first := size
	if remaining := productionControlOrdinaryBytesV1 - int(descriptor.offset); first > remaining {
		first = remaining
	}
	copy(destination[:first], parent.controlArena[int(descriptor.offset):int(descriptor.offset)+first])
	copy(destination[first:size], parent.controlArena[0:size-first])
}

func (parent *productionParentV1) installTerminalControlLockedV1(kind productionControlKindV1, body []byte) {
	var encoded [productionControlReservedTerminalBytesV1]byte
	total := productionControlHeaderBytesV1 + len(body)
	copy(encoded[0:4], "KPC1")
	encoded[4] = 1
	encoded[5] = byte(kind)
	binary.BigEndian.PutUint32(encoded[8:12], uint32(total))
	binary.BigEndian.PutUint64(encoded[12:20], parent.attempt)
	binary.BigEndian.PutUint32(encoded[28:32], uint32(len(body)))
	copy(encoded[32:total], body)
	copy(parent.controlArena[productionControlOrdinaryBytesV1:productionControlOrdinaryBytesV1+total], encoded[:total])
	parent.terminalControl = productionControlDescriptorV1{kind: kind, epoch: parent.attempt, offset: productionControlOrdinaryBytesV1, size: uint32(total)}
	parent.terminalControlSet = true
}

func (parent *productionParentV1) enqueueOpaqueControlBytesLockedV1(size int, fill byte) int32 {
	if size < 0 {
		return int32(productionInvalidRequestV1)
	}
	if size > productionControlOrdinaryBytesV1 || parent.controlCount >= productionControlOrdinaryDescriptorsV1 || uint64(parent.controlBytes)+uint64(size) > productionControlOrdinaryBytesV1 {
		parent.clearOrdinaryControlLockedV1()
		failureBody := [2]byte{0, byte(productionResourceLimitV1)}
		parent.installTerminalControlLockedV1(productionControlFailedV1, failureBody[:])
		parent.fenceLockedV1(productionResourceLimitV1)
		return int32(productionResourceLimitV1)
	}
	offset := parent.controlWriteOffset
	first := size
	if remaining := productionControlOrdinaryBytesV1 - int(offset); first > remaining {
		first = remaining
	}
	for index := 0; index < first; index++ {
		parent.controlArena[int(offset)+index] = fill
	}
	for index := 0; index < size-first; index++ {
		parent.controlArena[index] = fill
	}
	parent.controlDescriptors[parent.controlTail] = productionControlDescriptorV1{offset: offset, size: uint32(size)}
	parent.controlTail = (parent.controlTail + 1) % productionControlOrdinaryDescriptorsV1
	parent.controlCount++
	parent.controlBytes += uint32(size)
	parent.controlWriteOffset = (offset + uint32(size)) % productionControlOrdinaryBytesV1
	return int32(productionSuccessV1)
}

func (parent *productionParentV1) beginControlPollV1() (productionUseV1, int32) {
	return parent.beginControlPollScopedV1(ProductionOutputInvocationV1{})
}
func (parent *productionParentV1) beginControlPollScopedV1(inv ProductionOutputInvocationV1) (productionUseV1, int32) {
	parent.mu.Lock()
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return productionUseV1{}, int32(productionInvalidStateV1)
	}
	if parent.state == productionParentOpenV1 && parent.deadlineExpiredLockedV1(time.Now()) {
		cancelNow := parent.fenceLockedV1(productionAuthorityExpiredV1)
		parent.mu.Unlock()
		if cancelNow {
			parent.cancel()
			parent.signalControlV1()
		}
		return productionUseV1{}, int32(productionAuthorityExpiredV1)
	}
	if parent.state != productionParentOpenV1 {
		status := parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return productionUseV1{}, status
	}
	record := &parent.uses[productionUseControlPollV1]
	if record.live || record.serial == math.MaxUint64 {
		parent.mu.Unlock()
		return productionUseV1{}, int32(productionResourceLimitV1)
	}
	if s := parent.outputIdentityLockedV1(inv); s != 0 {
		parent.mu.Unlock()
		return productionUseV1{}, s
	}
	charge := productionBudgetChargeV1{}
	if !inv.legacyV1() {
		charge.owned = uint64(unsafe.Sizeof(inv))
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
	use := productionUseV1{parent: parent, index: productionUseControlPollV1, serial: record.serial, attempt: record.attempt}
	parent.mu.Unlock()
	return use, int32(productionSuccessV1)
}

func productionControlCallerExpiredV1(done <-chan struct{}, deadline time.Time, hasDeadline bool, now time.Time) bool {
	select {
	case <-done:
		return true
	default:
	}
	return hasDeadline && !now.Before(deadline)
}

func (parent *productionParentV1) controlPollDeadlineLockedV1(callerDeadline time.Time, hasCallerDeadline bool, now time.Time) (time.Time, productionStatusV1, bool) {
	deadline := now.Add(productionControlPollMaximumV1)
	status := productionNoEventV1
	if !parent.deadline.IsZero() && parent.deadline.Before(deadline) {
		deadline = parent.deadline
		status = productionAuthorityExpiredV1
	}
	if hasCallerDeadline && callerDeadline.Before(deadline) {
		deadline = callerDeadline
		status = productionTimeoutV1
	}
	retry := false
	if !parent.controlRetryDeadline.IsZero() && !parent.controlRetryDeadline.After(deadline) {
		deadline = parent.controlRetryDeadline
		status = parent.controlRetryStatus
		retry = true
	}
	return deadline, status, retry
}

func (parent *productionParentV1) clearControlRetryLockedV1() {
	parent.controlRetryDeadline = time.Time{}
	parent.controlRetryStatus = 0
}

func (parent *productionParentV1) trySynchronousTerminalControlV1(callerDone <-chan struct{}, callerDeadline time.Time, hasCallerDeadline bool, dst []byte) (int, int32, bool) {
	return parent.trySynchronousTerminalControlScopedV1(callerDone, callerDeadline, hasCallerDeadline, dst, ProductionOutputInvocationV1{})
}
func (parent *productionParentV1) trySynchronousTerminalControlScopedV1(callerDone <-chan struct{}, callerDeadline time.Time, hasCallerDeadline bool, dst []byte, inv ProductionOutputInvocationV1) (int, int32, bool) {
	parent.mu.Lock()
	if parent.state == productionParentOpenV1 {
		parent.mu.Unlock()
		return 0, 0, false
	}
	if parent.state == productionParentClosedV1 {
		parent.mu.Unlock()
		return 0, int32(productionInvalidStateV1), true
	}
	if parent.uses[productionUseControlPollV1].live {
		parent.mu.Unlock()
		return 0, int32(productionResourceLimitV1), true
	}
	now := time.Now()
	if productionControlCallerExpiredV1(callerDone, callerDeadline, hasCallerDeadline, now) {
		parent.mu.Unlock()
		return 0, int32(productionTimeoutV1), true
	}
	if parent.terminalControlObserved || !parent.terminalControlSet {
		status := parent.terminalOperationStatusLockedV1()
		parent.mu.Unlock()
		return 0, status, true
	}
	if !parent.controlRetryDeadline.IsZero() && !now.Before(parent.controlRetryDeadline) {
		retryStatus := parent.controlRetryStatus
		if retryStatus != productionAuthorityExpiredV1 {
			retryStatus = productionTimeoutV1
		}
		parent.mu.Unlock()
		return 0, int32(retryStatus), true
	}
	if s := parent.outputIdentityLockedV1(inv); s != 0 {
		parent.mu.Unlock()
		return 0, s, true
	}
	deadline := now.Add(productionControlPollMaximumV1)
	if hasCallerDeadline && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	written, status := parent.dequeueControlScopedLockedV1(dst, inv, deadline)
	if status == int32(productionSizeLimitV1) && parent.controlRetryDeadline.IsZero() {
		deadline, retryStatus, _ := parent.controlPollDeadlineLockedV1(callerDeadline, hasCallerDeadline, now)
		parent.controlRetryDeadline = deadline
		parent.controlRetryStatus = retryStatus
	} else if status == int32(productionSuccessV1) {
		parent.clearControlRetryLockedV1()
	}
	parent.mu.Unlock()
	return written, status, true
}

func (parent *productionParentV1) nextControlV1(ctx context.Context, dst []byte) (written int, status int32) {
	return parent.nextControlScopedV1(ctx, dst, ProductionOutputInvocationV1{})
}
func (parent *productionParentV1) nextControlScopedV1(ctx context.Context, dst []byte, inv ProductionOutputInvocationV1) (written int, status int32) {
	if parent == nil || ctx == nil {
		return 0, int32(productionInvalidRequestV1)
	}
	callerDone := ctx.Done()
	callerDeadline, hasCallerDeadline := ctx.Deadline()
	if productionControlCallerExpiredV1(callerDone, callerDeadline, hasCallerDeadline, time.Now()) {
		return 0, int32(productionTimeoutV1)
	}
	if written, status, handled := parent.trySynchronousTerminalControlScopedV1(callerDone, callerDeadline, hasCallerDeadline, dst, inv); handled {
		return written, status
	}
	use, status := parent.beginControlPollScopedV1(inv)
	if status != int32(productionSuccessV1) {
		if status == int32(productionCancelledV1) || status == int32(productionAuthorityRevokedV1) {
			if written, synchronousStatus, handled := parent.trySynchronousTerminalControlScopedV1(callerDone, callerDeadline, hasCallerDeadline, dst, inv); handled {
				return written, synchronousStatus
			}
		}
		return 0, status
	}
	defer func() {
		if finishStatus := parent.finishUseV1(use); status == int32(productionSuccessV1) && finishStatus != int32(productionSuccessV1) {
			written, status = 0, finishStatus
		}
	}()

	now := time.Now()
	parent.mu.Lock()
	pollDeadline, deadlineStatus, retryDeadline := parent.controlPollDeadlineLockedV1(callerDeadline, hasCallerDeadline, now)
	parent.mu.Unlock()
	timer := time.NewTimer(time.Until(pollDeadline))
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	for {
		parent.mu.Lock()
		now = time.Now()
		if productionControlCallerExpiredV1(callerDone, callerDeadline, hasCallerDeadline, now) {
			parent.mu.Unlock()
			return 0, int32(productionTimeoutV1)
		}
		if parent.state == productionParentOpenV1 {
			expiredStatus := productionStatusV1(0)
			expiredRetry := false
			if !parent.deadline.IsZero() && !now.Before(parent.deadline) {
				expiredStatus = productionAuthorityExpiredV1
			} else if !now.Before(pollDeadline) {
				expiredStatus = deadlineStatus
				expiredRetry = retryDeadline
				if expiredStatus != productionAuthorityExpiredV1 && (expiredRetry || parent.controlCount > 0 || parent.terminalControlSet) {
					expiredStatus = productionTimeoutV1
				}
			}
			if expiredStatus != 0 {
				cancelNow := false
				if expiredStatus == productionAuthorityExpiredV1 {
					cancelNow = parent.fenceLockedV1(productionAuthorityExpiredV1)
				}
				parent.mu.Unlock()
				if cancelNow {
					parent.cancel()
					parent.signalControlV1()
				}
				return 0, int32(expiredStatus)
			}
		}
		written, status = parent.dequeueControlScopedLockedV1(dst, inv, pollDeadline)
		if status != int32(productionNoEventV1) {
			if status == int32(productionSizeLimitV1) {
				if parent.controlRetryDeadline.IsZero() {
					parent.controlRetryDeadline = pollDeadline
					parent.controlRetryStatus = deadlineStatus
				}
			} else if status == int32(productionSuccessV1) {
				parent.clearControlRetryLockedV1()
			}
			cancelNow := parent.state != productionParentOpenV1 && parent.cancelContext.Err() == nil
			parent.mu.Unlock()
			if cancelNow {
				parent.cancel()
				parent.signalControlV1()
			}
			return written, status
		}
		if parent.state != productionParentOpenV1 {
			status = parent.terminalOperationStatusLockedV1()
			parent.mu.Unlock()
			return 0, status
		}
		parent.mu.Unlock()
		select {
		case <-parent.controlWake:
			continue
		case <-parent.cancelContext.Done():
			parent.mu.Lock()
			hasTerminal := parent.terminalControlSet
			status = parent.terminalOperationStatusLockedV1()
			parent.mu.Unlock()
			if hasTerminal {
				continue
			}
			return 0, status
		case <-callerDone:
			return 0, int32(productionTimeoutV1)
		case <-timer.C:
			if deadlineStatus == productionAuthorityExpiredV1 {
				_ = parent.cancelV1(int32(productionAuthorityExpiredV1))
				return 0, int32(productionAuthorityExpiredV1)
			}
			if deadlineStatus == productionTimeoutV1 {
				return 0, int32(productionTimeoutV1)
			}
			parent.mu.Lock()
			pending := parent.controlCount > 0 || parent.terminalControlSet
			if retryDeadline && !parent.controlRetryDeadline.IsZero() {
				pending = true
			}
			parent.mu.Unlock()
			if pending {
				return 0, int32(productionTimeoutV1)
			}
			return 0, int32(productionNoEventV1)
		}
	}
}

func (parent *productionParentV1) dequeueControlLockedV1(dst []byte) (int, int32) {
	return parent.dequeueControlScopedLockedV1(dst, ProductionOutputInvocationV1{}, time.Time{})
}
func (parent *productionParentV1) dequeueControlScopedLockedV1(dst []byte, inv ProductionOutputInvocationV1, deadline time.Time) (int, int32) {
	if parent.state != productionParentOpenV1 {
		parent.clearOrdinaryControlLockedV1()
	}
	if parent.controlCount > 0 && parent.nextControlSequence == math.MaxUint64 {
		parent.clearOrdinaryControlLockedV1()
		failureBody := [2]byte{0, byte(productionInternalFailureV1)}
		parent.installTerminalControlLockedV1(productionControlFailedV1, failureBody[:])
		parent.fenceLockedV1(productionInternalFailureV1)
	}
	var descriptor productionControlDescriptorV1
	terminal := false
	if parent.controlCount > 0 {
		descriptor = parent.controlDescriptors[parent.controlHead]
	} else if parent.terminalControlSet {
		descriptor = parent.terminalControl
		terminal = true
	} else {
		return 0, int32(productionNoEventV1)
	}
	if int(descriptor.size) > len(dst) {
		return 0, int32(productionSizeLimitV1)
	}
	// A control use survives attempt transitions. Its finite outer frame is
	// already admitted, but its output lane must bind the selected descriptor,
	// not the attempt that happened to be current before the poll waited.
	if !inv.legacyV1() {
		if s := parent.outputIdentityLockedV1(inv); s != 0 {
			return 0, s
		}
		if s := productionOutputStatusV1(parent.output.BindLaneV1(inv.call, inv.epoch, 1, descriptor.epoch)); s != 0 {
			return 0, s
		}
	}
	if s := parent.outputPrepareLockedV1(inv, descriptor.epoch, 0, 0, deadline, terminal); s != 0 {
		return 0, s
	}
	if terminal {
		copy(dst[:descriptor.size], parent.controlArena[descriptor.offset:descriptor.offset+descriptor.size])
	} else {
		parent.copyFromOrdinaryControlLockedV1(dst, descriptor)
	}
	sequence := parent.nextControlSequence
	binary.BigEndian.PutUint64(dst[20:28], sequence)
	if terminal {
		for index := uint32(0); index < descriptor.size; index++ {
			parent.controlArena[descriptor.offset+index] = 0
		}
		parent.terminalControlSet = false
		parent.terminalControlObserved = true
		parent.terminalControlKind = descriptor.kind
		parent.terminalControl = productionControlDescriptorV1{}
	} else {
		parent.zeroOrdinaryControlLockedV1(descriptor)
		parent.controlDescriptors[parent.controlHead] = productionControlDescriptorV1{}
		parent.controlHead = (parent.controlHead + 1) % productionControlOrdinaryDescriptorsV1
		parent.controlCount--
		parent.controlBytes -= descriptor.size
	}
	if sequence != math.MaxUint64 {
		parent.nextControlSequence++
	}
	return int(descriptor.size), int32(productionSuccessV1)
}

func (parent *productionParentV1) zeroOrdinaryControlLockedV1(descriptor productionControlDescriptorV1) {
	first := int(descriptor.size)
	if remaining := productionControlOrdinaryBytesV1 - int(descriptor.offset); first > remaining {
		first = remaining
	}
	for index := 0; index < first; index++ {
		parent.controlArena[int(descriptor.offset)+index] = 0
	}
	for index := 0; index < int(descriptor.size)-first; index++ {
		parent.controlArena[index] = 0
	}
}

func (parent *productionParentV1) clearOrdinaryControlLockedV1() {
	for count, index := uint8(0), parent.controlHead; count < parent.controlCount; count, index = count+1, (index+1)%productionControlOrdinaryDescriptorsV1 {
		parent.zeroOrdinaryControlLockedV1(parent.controlDescriptors[index])
		parent.controlDescriptors[index] = productionControlDescriptorV1{}
	}
	parent.controlHead = 0
	parent.controlTail = 0
	parent.controlCount = 0
	parent.controlBytes = 0
	parent.controlWriteOffset = 0
}

func (parent *productionParentV1) clearControlLockedV1() {
	parent.clearOrdinaryControlLockedV1()
	for index := productionControlOrdinaryBytesV1; index < len(parent.controlArena); index++ {
		parent.controlArena[index] = 0
	}
	parent.terminalControl = productionControlDescriptorV1{}
	parent.terminalControlSet = false
}

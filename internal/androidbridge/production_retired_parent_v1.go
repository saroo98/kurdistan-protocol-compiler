// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package androidbridge

// One bounded history per existing slot, shared by both new parent kinds.
// Native retirement is distinct from the adapter's post-End release receipt.
type retiredParentV1 struct {
	handle                        Handle
	epoch                         uint64
	nativeResult, publishedResult int32
	kind                          HandleType
	valid, published              bool
}

func retiredParentIndexV1(h Handle, kind HandleType) (uint16, bool) {
	raw := uint64(h)
	index := uint16(raw)
	if index == 0 || int(index) > MaxBridgeHandles || uint32(raw>>16) == 0 ||
		HandleType(raw>>56) != kind || raw&(uint64(0xff)<<48) != 0 {
		return 0, false
	}
	return index - 1, true
}

func retiredParentResultV1(r *HandleRegistry, h Handle, kind HandleType) (int32, bool) {
	i, ok := retiredParentIndexV1(h, kind)
	if r == nil || !ok {
		return 0, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record := &r.slots[i].retiredParent
	if !record.valid || !record.published || record.handle != h || record.kind != kind {
		return 0, false
	}
	return record.publishedResult, true
}

func RetiredProductionParentResultV1(r *HandleRegistry, h Handle) (int32, bool) {
	if s, ok := retiredParentResultV1(r, h, HandleProductionSession); ok {
		return s, true
	}
	return 3, false
}
func RetiredMaintenanceParentResultV1(r *HandleRegistry, h Handle) (MaintenanceResultV1, bool) {
	if s, ok := retiredParentResultV1(r, h, HandleMaintenance); ok {
		return MaintenanceResultV1(s), true
	}
	return MaintenanceInvalidState, false
}

func publishRetiredParentV1(r *HandleRegistry, h Handle, kind HandleType, actual int32) {
	i, ok := retiredParentIndexV1(h, kind)
	if r == nil || !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	record := &r.slots[i].retiredParent
	if !record.valid || record.handle != h || record.kind != kind || record.published {
		return
	}
	record.publishedResult = record.nativeResult
	if record.nativeResult == 0 {
		record.publishedResult = actual
	}
	record.published = true
}

// Trusted adapter calls only after its exact post-End claim has finished.
// A superseded record is left untouched; absence is never cleanup proof.
func PublishRetiredProductionParentResultV1(r *HandleRegistry, h Handle, actual int32) {
	publishRetiredParentV1(r, h, HandleProductionSession, productionOutputStatusV1(actual))
}
func PublishRetiredMaintenanceParentResultV1(r *HandleRegistry, h Handle, actual MaintenanceResultV1) {
	publishRetiredParentV1(r, h, HandleMaintenance, int32(normalizeMaintenancePlatformResult(actual)))
}

func (p *maintenanceAuthorityV1) recordRetiredOutputV1(code ErrorCode) {
	if p.registry == nil || p.output == nil {
		return
	}
	i, ok := retiredParentIndexV1(p.outputHandle, HandleMaintenance)
	if !ok {
		return
	}
	r := p.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	slot := &r.slots[i]
	if slot.occupied || slot.privatelyReserved || slot.generation != uint32(uint64(p.outputHandle)>>16) ||
		slot.productionReservationEpoch != p.outputSlotProductionEpoch {
		return
	}
	// Repeated destruction must not reset an already published sticky result.
	if slot.retiredParent.valid && slot.retiredParent.handle == p.outputHandle && slot.retiredParent.kind == HandleMaintenance {
		return
	}
	slot.retiredParent = retiredParentV1{handle: p.outputHandle, epoch: p.parentEpoch, kind: HandleMaintenance,
		nativeResult: int32(maintenanceOutputCleanupResultV1(code)), valid: true}
}

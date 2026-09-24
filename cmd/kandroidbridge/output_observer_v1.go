//go:build cgo

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "output_callbacks_v1.h"
*/
import "C"

import (
	"kurdistan/internal/androidbridge"
	"time"
	"unsafe"
)

// Only the immutable loaded-library table and scalar owner cross into C.
// Registry identity stays entirely in Go. No Go/native result graph is held.
type cOutputObserverV1 struct {
	table    *C.kvpn_output_callbacks_v1
	registry *androidbridge.HandleRegistry
	owner    uint64
}
type productionCOutputObserverV1 cOutputObserverV1
type maintenanceCOutputObserverV1 cOutputObserverV1

var _ androidbridge.ProductionOutputObserverV1 = (*productionCOutputObserverV1)(nil)
var _ androidbridge.MaintenanceOutputObserverV1 = (*maintenanceCOutputObserverV1)(nil)

func newProductionCOutputInvocationV1(table *C.kvpn_output_callbacks_v1, owner, call, epoch uint64) (androidbridge.ProductionOutputInvocationV1, int32) {
	if C.kvpn_output_table_valid_v1(table) != 1 {
		return androidbridge.ProductionOutputInvocationV1{}, 2
	}
	o := &productionCOutputObserverV1{table, &registry, owner}
	return androidbridge.NewProductionOutputInvocationV1(&registry, o, owner, call, epoch)
}
func newMaintenanceCOutputInvocationV1(table *C.kvpn_output_callbacks_v1, owner, call, epoch uint64) (androidbridge.MaintenanceOutputInvocationV1, androidbridge.MaintenanceResultV1) {
	if C.kvpn_output_table_valid_v1(table) != 1 {
		return androidbridge.MaintenanceOutputInvocationV1{}, androidbridge.MaintenanceInvalidRequest
	}
	o := &maintenanceCOutputObserverV1{table, &registry, owner}
	return androidbridge.NewMaintenanceOutputInvocationV1(&registry, o, owner, call, epoch)
}

// Concrete retained allocation payload, excluding native invocation/interface
// fields already charged in 6b2. The actual producer must add C and Java backing.
func cOutputObserverBackingV1() uint64 {
	p, m := unsafe.Sizeof(productionCOutputObserverV1{}), unsafe.Sizeof(maintenanceCOutputObserverV1{})
	if m > p {
		p = m
	}
	return uint64(p)
}
func outputBoolV1(v bool) C.uint8_t {
	if v {
		return 1
	}
	return 0
}

func (o *productionCOutputObserverV1) status(epoch uint64, s C.int32_t) int32 {
	v := int32(s)
	if v < 0 || v > 26 || v == 19 || v == 20 {
		// An invalid reason is the typed gate's corruption latch, not a
		// categorical terminal attestation.
		C.kvpn_output_prod_parent_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), -1)
		return 18
	}
	return v
}
func (o *maintenanceCOutputObserverV1) status(epoch uint64, s C.int32_t) androidbridge.MaintenanceResultV1 {
	v := int32(s) // validate int32 before narrowing to uint8
	if v < 0 || v > 23 || v == 1 {
		C.kvpn_output_maint_parent_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), -1)
		return androidbridge.MaintenanceInternalFailure
	}
	return androidbridge.MaintenanceResultV1(v)
}
func (o *productionCOutputObserverV1) ValidateInvocationV1(r *androidbridge.HandleRegistry, owner, call, epoch uint64) int32 {
	if r != o.registry || r != &registry || owner != o.owner {
		return 3
	}
	return o.status(epoch, C.kvpn_output_prod_validate_invocation_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch)))
}
func (o *maintenanceCOutputObserverV1) ValidateInvocationV1(r *androidbridge.HandleRegistry, owner, call, epoch uint64) androidbridge.MaintenanceResultV1 {
	if r != o.registry || r != &registry || owner != o.owner {
		return androidbridge.MaintenanceInvalidState
	}
	return o.status(epoch, C.kvpn_output_maint_validate_invocation_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch)))
}

// Sampling C first makes conversion latency shorten validity. No absolute Go
// timestamps, timer allocation, wall-clock fallback, or absent ordinary limit.
func outputDeadlineV1(table *C.kvpn_output_callbacks_v1, deadline time.Time, terminal bool) (C.uint8_t, C.uint64_t, C.uint64_t, int32) {
	if deadline.IsZero() {
		if terminal {
			return 0, 0, 0, 0
		}
		return 0, 0, 0, 3
	}
	sample := C.kvpn_output_clock_sample_v1(table)
	if sample.status != 0 || sample.now == 0 {
		return 0, 0, 0, 18
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0, 0, 0, 8
	}
	return 1, sample.now, C.uint64_t(remaining), 0
}
func (o *productionCOutputObserverV1) PrepareV1(call, epoch, attempt, child, delivery uint64, deadline time.Time, terminal bool) int32 {
	has, sample, remaining, s := outputDeadlineV1(o.table, deadline, terminal)
	if s != 0 {
		if s == 18 {
			return o.status(epoch, -1)
		}
		return s
	}
	return o.status(epoch, C.kvpn_output_prod_prepare_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint64_t(attempt), C.uint64_t(child), C.uint64_t(delivery), has, sample, remaining, outputBoolV1(terminal)))
}
func (o *maintenanceCOutputObserverV1) PrepareV1(call, epoch uint64, candidate androidbridge.MaintenanceCandidateID, deadline time.Time, terminal bool) androidbridge.MaintenanceResultV1 {
	has, sample, remaining, s := outputDeadlineV1(o.table, deadline, terminal)
	if s != 0 {
		switch s {
		case 3:
			return androidbridge.MaintenanceInvalidState
		case 8:
			return androidbridge.MaintenanceTimeout
		default:
			return o.status(epoch, -1)
		}
	}
	return o.status(epoch, C.kvpn_output_maint_prepare_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint64_t(candidate), has, sample, remaining, outputBoolV1(terminal)))
}

func (o *productionCOutputObserverV1) BindParentV1(call, epoch uint64) int32 {
	return o.status(epoch, C.kvpn_output_prod_bind_parent_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch)))
}

func (o *productionCOutputObserverV1) BindHandleV1(call, epoch uint64, parent androidbridge.Handle) int32 {
	return o.status(epoch, C.kvpn_output_prod_bind_handle_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint64_t(parent)))
}

func (o *productionCOutputObserverV1) BindLaneV1(call, epoch uint64, lane uint16, attempt uint64) int32 {
	return o.status(epoch, C.kvpn_output_prod_bind_lane_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint16_t(lane), C.uint64_t(attempt)))
}

func (o *productionCOutputObserverV1) FinishReceiptV1(call, epoch uint64, kind androidbridge.ProductionOutputReceiptKindV1, parent androidbridge.Handle, child uint64, delivery uint64, actual int32) int32 {
	return o.status(epoch, C.kvpn_output_prod_finish_receipt_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(child), C.uint64_t(delivery), C.int32_t(actual)))
}

func (o *productionCOutputObserverV1) ClaimReceiptV1(call, epoch uint64, kind androidbridge.ProductionOutputReceiptKindV1, parent androidbridge.Handle, child uint64, delivery uint64) (bool, int32) {
	r := C.kvpn_output_prod_claim_result_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(child), C.uint64_t(delivery))
	s := o.status(epoch, r.status)
	if r.retired > 1 {
		return false, o.status(epoch, -1)
	}
	if s != 0 {
		return false, s
	}
	return r.retired == 1, 0
}
func (o *productionCOutputObserverV1) ParentTerminalV1(epoch uint64, reason int32) {
	C.kvpn_output_prod_parent_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.int32_t(reason))
}

func (o *productionCOutputObserverV1) AttemptTerminalV1(epoch, attempt uint64, reason int32) {
	C.kvpn_output_prod_attempt_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.uint64_t(attempt), C.int32_t(reason))
}
func (o *productionCOutputObserverV1) ResourceRetiredV1(epoch uint64, kind androidbridge.ProductionOutputReceiptKindV1, parent androidbridge.Handle, attempt, child, delivery uint64, actual int32) {
	C.kvpn_output_prod_resource_retired_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(attempt), C.uint64_t(child), C.uint64_t(delivery), C.int32_t(actual))
}

func (o *maintenanceCOutputObserverV1) BindParentV1(call, epoch uint64) androidbridge.MaintenanceResultV1 {
	return o.status(epoch, C.kvpn_output_maint_bind_parent_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch)))
}

func (o *maintenanceCOutputObserverV1) BindHandleV1(call, epoch uint64, parent androidbridge.Handle) androidbridge.MaintenanceResultV1 {
	return o.status(epoch, C.kvpn_output_maint_bind_handle_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint64_t(parent)))
}

func (o *maintenanceCOutputObserverV1) BindLaneV1(call, epoch uint64, revocation bool) androidbridge.MaintenanceResultV1 {
	return o.status(epoch, C.kvpn_output_maint_bind_lane_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), outputBoolV1(revocation)))
}

func (o *maintenanceCOutputObserverV1) SupersedeNormalV1(call, epoch uint64) androidbridge.MaintenanceResultV1 {
	return o.status(epoch, C.kvpn_output_maint_supersede_normal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch)))
}

func (o *maintenanceCOutputObserverV1) FinishReceiptV1(call, epoch uint64, kind androidbridge.MaintenanceOutputReceiptKindV1, parent androidbridge.Handle, child androidbridge.MaintenanceCandidateID, delivery uint64, actual androidbridge.MaintenanceResultV1) androidbridge.MaintenanceResultV1 {
	return o.status(epoch, C.kvpn_output_maint_finish_receipt_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(child), C.uint64_t(delivery), C.int32_t(actual)))
}

func (o *maintenanceCOutputObserverV1) ClaimReceiptV1(call, epoch uint64, kind androidbridge.MaintenanceOutputReceiptKindV1, parent androidbridge.Handle, child androidbridge.MaintenanceCandidateID, delivery uint64) (bool, androidbridge.MaintenanceResultV1) {
	r := C.kvpn_output_maint_claim_result_v1(o.table, C.uint64_t(o.owner), C.uint64_t(call), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(child), C.uint64_t(delivery))
	s := o.status(epoch, r.status)
	if r.retired > 1 {
		return false, o.status(epoch, -1)
	}
	if s != 0 {
		return false, s
	}
	return r.retired == 1, 0
}
func (o *maintenanceCOutputObserverV1) ParentTerminalV1(epoch uint64, reason androidbridge.MaintenanceResultV1) {
	C.kvpn_output_maint_parent_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.int32_t(reason))
}

func (o *maintenanceCOutputObserverV1) CandidateTerminalV1(epoch uint64, candidate androidbridge.MaintenanceCandidateID, reason androidbridge.MaintenanceResultV1) {
	C.kvpn_output_maint_candidate_terminal_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.uint64_t(candidate), C.int32_t(reason))
}
func (o *maintenanceCOutputObserverV1) ResourceRetiredV1(epoch uint64, kind androidbridge.MaintenanceOutputReceiptKindV1, parent androidbridge.Handle, child androidbridge.MaintenanceCandidateID, actual androidbridge.MaintenanceResultV1) {
	C.kvpn_output_maint_resource_retired_v1(o.table, C.uint64_t(o.owner), C.uint64_t(epoch), C.uint8_t(kind), C.uint64_t(parent), C.uint64_t(child), C.int32_t(actual))
}

//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#cgo CFLAGS: -D_POSIX_C_SOURCE=200809L -I${SRCDIR} -pthread
#cgo LDFLAGS: -pthread
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_abi.h"
kvpn_output_call_v1 *kvpn_output_test_frame_v1(uint8_t);
const kvpn_output_callbacks_v1 *kvpn_output_test_bad_table_v1(uint8_t);
const kvpn_output_callbacks_v1 *kvpn_output_test_fault_table_v1(uint8_t, int32_t);
*/
import "C"

import (
	"kurdistan/internal/androidbridge"
	"testing"
	"time"
)

func testProductionReconnectV1(parent uint64, reason uint8) int32 {
	return int32(C.kvpn_prod_reconnect_v1(C.uint64_t(parent), C.uint8_t(reason)))
}

func testProductionScalarRefusalsV1(parent uint64) []int32 {
	p := C.uint64_t(parent)
	return []int32{
		int32(C.kvpn_prod_confirm_socket_v1(p, 0, 1, 0, 0)),
		int32(C.kvpn_prod_confirm_packet_v1(p, 0, 0)),
		int32(C.kvpn_prod_reject_packet_v1(p, 0)),
		int32(C.kvpn_prod_handover_v1(p, 0, 0)),
		int32(C.kvpn_stream_confirm_v1(p, 0, 0, 0)),
		int32(C.kvpn_stream_reject_v1(p, 0, 0)),
		int32(C.kvpn_stream_half_close_v1(p, 0)),
		int32(C.kvpn_stream_cancel_v1(p, 0)),
		int32(C.kvpn_stream_close_v1(p, 0)),
	}
}

type testOutputFrameV1 struct {
	ptr   *C.kvpn_output_call_v1
	table *C.kvpn_output_callbacks_v1
	owner uint64
	kind  uint8
}

func newTestOutputFrameV1(t *testing.T, kind, slot uint8) testOutputFrameV1 {
	t.Helper()
	f := testOutputFrameV1{ptr: C.kvpn_output_test_frame_v1(C.uint8_t(slot)), table: C.kvpn_output_callbacks_table_v1(), kind: kind}
	var owner, lease C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(C.uint8_t(kind), &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	f.owner = uint64(owner)
	if s := C.kvpn_output_begin_open_v1(lease, C.uint8_t(kind), f.ptr); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_output_expect_receipt_v1(f.ptr, 1); s != 0 {
		t.Fatal(s)
	}
	return f
}
func (f testOutputFrameV1) serial() uint64 { return uint64(f.ptr.serial) }
func (f testOutputFrameV1) parent() androidbridge.Handle {
	return androidbridge.Handle(f.owner + 10000)
}
func (f testOutputFrameV1) productionObserver() productionCOutputObserverV1 {
	return productionCOutputObserverV1{f.table, &registry, f.owner}
}
func (f testOutputFrameV1) maintenanceObserver() maintenanceCOutputObserverV1 {
	return maintenanceCOutputObserverV1{f.table, &registry, f.owner}
}
func (f testOutputFrameV1) productionInvocation(epoch uint64) (androidbridge.ProductionOutputInvocationV1, int32) {
	return newProductionCOutputInvocationV1(f.table, f.owner, f.serial(), epoch)
}
func (f testOutputFrameV1) maintenanceInvocation(epoch uint64) (androidbridge.MaintenanceOutputInvocationV1, androidbridge.MaintenanceResultV1) {
	return newMaintenanceCOutputInvocationV1(f.table, f.owner, f.serial(), epoch)
}
func (f testOutputFrameV1) bindProduction(t *testing.T) {
	t.Helper()
	o := f.productionObserver()
	if s := o.BindParentV1(f.serial(), 7); s != 0 {
		t.Fatal(s)
	}
	if s := o.BindHandleV1(f.serial(), 7, f.parent()); s != 0 {
		t.Fatal(s)
	}
	if s := o.BindLaneV1(f.serial(), 7, 0, 1); s != 0 {
		t.Fatal(s)
	}
}
func (f testOutputFrameV1) bindMaintenance(t *testing.T) {
	t.Helper()
	o := f.maintenanceObserver()
	if s := o.BindParentV1(f.serial(), 7); s != 0 {
		t.Fatal(s)
	}
	if s := o.BindHandleV1(f.serial(), 7, f.parent()); s != 0 {
		t.Fatal(s)
	}
	if s := o.BindLaneV1(f.serial(), 7, false); s != 0 {
		t.Fatal(s)
	}
}
func (f testOutputFrameV1) end() { C.kvpn_output_end_v1(f.ptr) }
func (f testOutputFrameV1) commit(native int32) (bool, int32) {
	var p C.uint8_t
	s := C.kvpn_output_try_commit_v1(f.ptr, C.int32_t(native), &p)
	return p == 1, int32(s)
}
func (f testOutputFrameV1) release(t *testing.T) {
	t.Helper()
	if s := C.kvpn_output_owner_release_v1(C.uint64_t(f.owner)); s != 0 {
		t.Fatal(s)
	}
}
func (f testOutputFrameV1) retire(t *testing.T) {
	if f.kind == 1 {
		o := f.productionObserver()
		o.ResourceRetiredV1(7, androidbridge.ProductionOutputParentV1, f.parent(), 0, 0, 0, 0)
	} else {
		o := f.maintenanceObserver()
		o.ResourceRetiredV1(7, androidbridge.MaintenanceOutputParentV1, f.parent(), 0, 0)
	}
	f.release(t)
}
func (f testOutputFrameV1) badTableStatus(defect int) int32 {
	table := C.kvpn_output_test_bad_table_v1(C.uint8_t(defect))
	if f.kind == 1 {
		_, status := newProductionCOutputInvocationV1(table, f.owner, f.serial(), 0)
		return status
	}
	_, status := newMaintenanceCOutputInvocationV1(table, f.owner, f.serial(), 0)
	return int32(status)
}
func testOutputMalformedMaintenanceV1(s int32) androidbridge.MaintenanceResultV1 {
	table := C.kvpn_output_test_fault_table_v1(2, C.int32_t(s))
	_, result := newMaintenanceCOutputInvocationV1(table, 1, 1, 0)
	return result
}
func testOutputMalformedProductionV1(s int32) int32 {
	table := C.kvpn_output_test_fault_table_v1(1, C.int32_t(s))
	_, result := newProductionCOutputInvocationV1(table, 1, 1, 0)
	return result
}

func (f testOutputFrameV1) beginParent(t *testing.T, class, expectation uint8) {
	t.Helper()
	if s := C.kvpn_output_begin_parent_v1(C.uint64_t(f.parent()), C.uint8_t(f.kind), C.uint8_t(class), f.ptr); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_output_expect_receipt_v1(f.ptr, C.uint8_t(expectation)); s != 0 {
		t.Fatal(s)
	}
}
func (f testOutputFrameV1) faultClockPrepare(deadline time.Time) int32 {
	o := productionCOutputObserverV1{C.kvpn_output_test_fault_table_v1(3, 256), &registry, f.owner}
	return o.PrepareV1(f.serial(), 7, 1, 0, 0, deadline, false)
}

//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include "android_callbacks_v1.h"
#include "production_scoped_exports_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_production_facade_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_android_callbacks.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_abi.h"
const kvpn_android_callbacks_v1 *kvpn_android_test_table_v1(void);
void kvpn_android_test_reset_v1(void);
void kvpn_android_test_mutate_v1(void);
void kvpn_android_test_result_v1(uint8_t, int32_t);
void kvpn_android_test_network_current_v1(uint8_t);
int32_t kvpn_android_test_capture_v1(const uint8_t *, uint32_t, const uint32_t *);
int32_t kvpn_android_test_install_receiver_v1(uint64_t);
uint32_t kvpn_android_test_call_count_v1(uint8_t);
int32_t kvpn_android_test_roots_v1(const uint8_t *, uint32_t);
*/
import "C"

import (
	"bytes"
	"kurdistan/internal/androidbridge"
	"runtime"
	"testing"
	"unsafe"
)

func testAndroidSharedFinalizerMissingLeaseV1() int32 {
	return int32(C.kvpn_android_finalize_failed_opening_v1(0, 1))
}

func testMaintenanceHostRootsV1(t *testing.T, roots []byte) {
	var data *C.uint8_t
	if len(roots) > 0 {
		data = (*C.uint8_t)(unsafe.Pointer(&roots[0]))
	}
	if s := C.kvpn_android_test_roots_v1(data, C.uint32_t(len(roots))); s != 0 {
		t.Fatal("host roots", s)
	}
}
func testMaintenanceCanonicalParentV1(t *testing.T, input []byte) uint64 {
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &parent); s != 0 {
		t.Fatal("parent open", s)
	}
	t.Cleanup(func() {
		if s := C.kvpn_maintenance_close_v1(parent); s != 0 {
			t.Error("parent close", s)
		}
	})
	return uint64(parent)
}
func testMaintenanceCanonicalUpdateCallV1(parent uint64, output []byte) (int, int32) {
	request := []byte{1, 3, 232}
	var n C.uint32_t
	s := C.kvpn_maintenance_check_update_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), 3, (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n)
	return int(n), int32(s)
}

func testMaintenanceCanonicalProbeCallV1(parent uint64, request, output []byte) (int, int32) {
	var n C.uint32_t
	s := C.kvpn_maintenance_run_probe_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n)
	return int(n), int32(s)
}

func testMaintenanceBindCountV1() uint32 { return uint32(C.kvpn_android_test_call_count_v1(15)) }
func testMaintenanceNetworkLostV1()      { C.kvpn_android_test_network_current_v1(0) }
func testMaintenanceCanonicalCancelCallV1(parent uint64) int32 {
	return int32(C.kvpn_maintenance_cancel_v1(C.uint64_t(parent)))
}
func testMaintenanceCanonicalMaterializeCallV1(parent, child uint64, output []byte) (int, int32) {
	var n C.uint32_t
	s := C.kvpn_maintenance_materialize_v1(C.uint64_t(parent), C.uint64_t(child), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n)
	return int(n), int32(s)
}

func testMaintenanceCanonicalCandidateV1(t *testing.T, input, artifact []byte, release bool, consume func(uint64, uint64)) {
	t.Helper()
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &parent); s != 0 {
		t.Fatal("candidate parent open", s)
	}
	t.Cleanup(func() {
		if s := C.kvpn_maintenance_close_v1(parent); s != 0 {
			t.Error("candidate parent close", s)
		}
	})
	// Fixture preparation only: real signed candidate verification in an exact
	// retained native/C frame. This is not canonical checkUpdate fetch proof.
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if s := C.kvpn_output_begin_parent_v1(parent, 2, 0, &frame); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_output_expect_receipt_v1(&frame, 2); s != 0 {
		t.Fatal(s)
	}
	inv, result := newMaintenanceCOutputInvocationV1(C.kvpn_output_callbacks_table_v1(), uint64(frame.owner), uint64(frame.serial), uint64(frame.epoch))
	if result != 0 {
		t.Fatal(result)
	}
	candidate := androidbridge.VerifyMaintenanceCandidateV1Scoped(&registry, androidbridge.Handle(parent), artifact, inv)
	if candidate.Result != 0 || candidate.Candidate == 0 {
		C.kvpn_output_end_v1(&frame)
		t.Fatal("verified fixture candidate", candidate.Result)
	}
	var published C.uint8_t
	if s := C.kvpn_output_try_commit_v1(&frame, 0, &published); s != 0 || published != 1 {
		C.kvpn_output_end_v1(&frame)
		t.Fatal("candidate fixture commit", s, published)
	}
	C.kvpn_output_end_v1(&frame)
	child := C.uint64_t(candidate.Candidate)
	if consume != nil {
		consume(uint64(parent), uint64(child))
		return
	}
	if release {
		if s := C.kvpn_maintenance_release_update_v1(parent, child); s != 0 {
			t.Fatal("canonical release", s)
		}
		if s := C.kvpn_maintenance_release_update_v1(parent, child); s != 3 {
			t.Fatal("canonical repeated release", s)
		}
		return
	}
	output := bytes.Repeat([]byte{0xa5}, len(artifact)+7)
	var written C.uint32_t
	if s := C.kvpn_maintenance_materialize_v1(parent, child, (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(artifact)-1), &written); s != 4 || written != 0 || output[0] != 0xa5 {
		t.Fatal("short materialize consumed candidate", s, written)
	}
	if s := C.kvpn_maintenance_materialize_v1(parent, child, (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written); s != 0 || int(written) != len(artifact) || !bytes.Equal(output[:len(artifact)], artifact) || output[len(artifact)] != 0xa5 {
		t.Fatal("canonical materialized artifact", s, written)
	}
	clear(output)
	if s := C.kvpn_maintenance_materialize_v1(parent, child, (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written); s != 3 || written != 0 {
		t.Fatal("consumed candidate resurrected", s, written)
	}
}

func testMaintenanceCanonicalRefusalsV1(t *testing.T) {
	var backing, again C.uint64_t
	if s := C.kvpn_maintenance_direct_backing_v1(128<<20, &backing); s != 0 || backing == 0 {
		t.Fatal("backing", s, backing)
	}
	if s := C.kvpn_maintenance_direct_backing_v1(backing, &again); s != 0 || again != backing {
		t.Fatal("exact backing", s, again)
	}
	if s := C.kvpn_maintenance_direct_backing_v1(backing-1, &again); s != 5 || again != 0 {
		t.Fatal("deficit backing", s, again)
	}
	t.Logf("source-derived maintenance external backing=%d", uint64(backing))
	for _, wrongKind := range []bool{false, true} {
		testAndroidResetV1()
		var owner, lease, parent C.uint64_t
		kind := C.uint8_t(2)
		if wrongKind {
			kind = 1
		}
		if s := C.kvpn_output_owner_reserve_v1(kind, &owner, &lease); s != 0 {
			t.Fatal(s)
		}
		if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
			t.Fatal(s)
		}
		input := make([]byte, 32)
		// Structural alias validation must not zero into the borrowed request.
		input[0] = 99
		if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), 32, lease, (*C.uint64_t)(unsafe.Pointer(&input[0]))); s != 2 || input[0] != 99 {
			t.Fatal("aliased scalar", s, input[0])
		}
		s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), 32, lease, &parent)
		if wrongKind {
			if s != 3 || parent != 0 {
				t.Fatal("wrong kind", s, parent)
			}
			// The still-unclaimed production-kind token crosses its real
			// malformed opening/finalizer, not a test-only release shortcut.
			if h, n, s := testProductionCanonicalOpenCallV1(uint64(lease), input, make([]byte, 32768)); s != 2 || h != 0 || n != 0 {
				t.Fatal("wrong kind consumed lease", s, h, n)
			}
		} else {
			if s != 2 || parent != 0 {
				t.Fatal("malformed opening", s, parent)
			}
			if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), 32, lease, &parent); s != 3 {
				t.Fatal("malformed token reused", s)
			}
		}
	}
}

func testMaintenanceCanonicalCaptureRefusalV1(t *testing.T, input []byte, wantStatus int32, wantCaptures uint32) {
	t.Helper()
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal(s)
	}
	s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &parent)
	if parent != 0 {
		_ = C.kvpn_maintenance_close_v1(parent)
	}
	if int32(s) != wantStatus || parent != 0 || uint32(C.kvpn_android_test_call_count_v1(1)) != wantCaptures || C.kvpn_android_test_call_count_v1(3) != 0 {
		t.Fatal("opening refusal crossed wrong admission stage", s, parent, C.kvpn_android_test_call_count_v1(1), C.kvpn_android_test_call_count_v1(3))
	}
}

func testMaintenanceCanonicalOpenLifecycleV1(t *testing.T, input []byte) {
	t.Helper()
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal(s)
	}
	// Null input preflight cannot consume the token. Exact scalar output is zero.
	parent = 99
	if s := C.kvpn_maintenance_open_v1(nil, 0, lease, &parent); s != 2 || parent != 0 {
		t.Fatal("maintenance preflight", s, parent)
	}
	s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &parent)
	t.Logf("maintenance canonical status=%d register=%d publication=%d", s, uint32(C.kvpn_android_test_call_count_v1(3)), uint32(C.kvpn_android_test_call_count_v1(5)))
	if s != 0 || parent == 0 {
		t.Fatal("maintenance open", s, parent)
	}
	if C.kvpn_android_test_call_count_v1(3) != 1 || C.kvpn_android_test_call_count_v1(5) != 1 {
		t.Fatal("maintenance registration/publication bypassed")
	}
	var repeated C.uint64_t
	if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &repeated); s != 3 || repeated != 0 {
		t.Fatal("maintenance token reuse", s, repeated)
	}
	update := []byte{1, 3, 232}
	output := bytes.Repeat([]byte{0xa5}, 38)
	var written C.uint32_t = 99
	if s := C.kvpn_maintenance_check_update_v1(parent, (*C.uint8_t)(unsafe.Pointer(&update[0])), 3, (*C.uint8_t)(unsafe.Pointer(&output[0])), 37, &written); s != 4 || written != 0 || output[0] != 0xa5 {
		t.Fatal("short update output consumed decision", s, written)
	}
	update[0] = 2
	if s := C.kvpn_maintenance_check_update_v1(parent, (*C.uint8_t)(unsafe.Pointer(&update[0])), 3, (*C.uint8_t)(unsafe.Pointer(&output[0])), 38, &written); s != 2 || written != 0 || output[0] != 0xa5 {
		t.Fatal("invalid update request published decision", s, written)
	}
	update[0] = 1
	if s := C.kvpn_maintenance_check_update_v1(parent, (*C.uint8_t)(unsafe.Pointer(&update[0])), 3, (*C.uint8_t)(unsafe.Pointer(&output[0])), 38, &written); s != 0 || written != 3 || !bytes.Equal(output[:3], []byte{1, 0, 12}) || output[3] != 0xa5 {
		t.Fatal("actual roots rejection not encoded as prepared M1", s, written, output[:3])
	}
	if s := C.kvpn_maintenance_materialize_v1(parent, 1, (*C.uint8_t)(unsafe.Pointer(&output[0])), 38, &written); s != 3 || written != 0 {
		t.Fatal("unknown candidate materialize", s, written)
	}
	if s := C.kvpn_maintenance_release_update_v1(parent, 1); s != 3 {
		t.Fatal("unknown candidate release", s)
	}
	probe := []byte{1, 0, 1, 1, 3, 232, 3, 232, 1}
	if s := C.kvpn_maintenance_run_probe_v1(parent, (*C.uint8_t)(unsafe.Pointer(&probe[0])), 9, (*C.uint8_t)(unsafe.Pointer(&output[0])), 38, &written); s != 1 || written != 0 {
		t.Fatal("unsigned probe admitted", s, written)
	}
	if s := C.kvpn_maintenance_cancel_v1(parent); s != 0 {
		t.Fatal("maintenance cancel", s)
	}
	if s := C.kvpn_maintenance_cancel_v1(parent); s != 0 {
		t.Fatal("maintenance repeat cancel", s)
	}
	if r, ok := androidbridge.RetiredMaintenanceParentResultV1(&registry, androidbridge.Handle(parent)); ok || r != androidbridge.MaintenanceInvalidState {
		t.Fatal("cancel retired parent", r, ok)
	}
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if s := C.kvpn_output_begin_parent_v1(parent, 2, 2, &frame); s != 0 {
		t.Fatal("cancel released registration", s)
	}
	if s := C.kvpn_maintenance_close_v1(parent); s != 5 {
		t.Fatal("busy maintenance fallback", s)
	}
	C.kvpn_output_end_v1(&frame)
	if s := C.kvpn_maintenance_close_v1(parent); s != 0 {
		t.Fatal("maintenance close", s)
	}
	if r, ok := androidbridge.RetiredMaintenanceParentResultV1(&registry, androidbridge.Handle(parent)); !ok || r != 0 {
		t.Fatal("maintenance post-End publication", r, ok)
	}
	if s := C.kvpn_maintenance_close_v1(parent); s != 0 {
		t.Fatal("maintenance repeat close", s)
	}
	if s := C.kvpn_maintenance_cancel_v1(parent); s != 0 {
		t.Fatal("maintenance retired cancel", s)
	}
	if s := C.kvpn_maintenance_close_v1(parent ^ (1 << 48)); s != 3 {
		t.Fatal("maintenance unknown parent", s)
	}
}

func testProductionFacadeProbeV1(parent uint64, request, output []byte) (int, int32) {
	var n C.uint32_t
	s := C.kvpn_prod_run_probe_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n)
	return int(n), int32(s)
}

func testProductionFacadeOpenStreamV1(parent uint64, request []byte) (uint64, int32) {
	var child C.uint64_t
	s := C.kvpn_prod_open_stream_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), &child)
	return uint64(child), int32(s)
}
func testProductionFacadeStreamSendV1(parent, child uint64, input []byte) int32 {
	return int32(C.kvpn_stream_send_v1(C.uint64_t(parent), C.uint64_t(child), (*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input))))
}
func testProductionFacadeStreamReceiveV1(parent, child uint64, output []byte) (int, uint64, int32) {
	var n C.uint32_t
	var token C.uint64_t
	s := C.kvpn_stream_receive_v1(C.uint64_t(parent), C.uint64_t(child), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n, &token)
	return int(n), uint64(token), int32(s)
}
func testProductionFacadeStreamConfirmV1(parent, child, token uint64, n int) int32 {
	return int32(C.kvpn_stream_confirm_v1(C.uint64_t(parent), C.uint64_t(child), C.uint64_t(token), C.uint32_t(n)))
}
func testProductionFacadeStreamHalfCloseV1(parent, child uint64) int32 {
	return int32(C.kvpn_stream_half_close_v1(C.uint64_t(parent), C.uint64_t(child)))
}
func testProductionFacadeStreamCloseV1(parent, child uint64) int32 {
	return int32(C.kvpn_stream_close_v1(C.uint64_t(parent), C.uint64_t(child)))
}

func testProductionFacadeControlV1(parent uint64, output []byte) (int, int32) {
	var written C.uint32_t
	s := C.kvpn_prod_next_control_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written)
	return int(written), int32(s)
}
func testProductionFacadeSocketV1(parent, token uint64) int32 {
	return int32(C.kvpn_prod_confirm_socket_v1(C.uint64_t(parent), C.uint64_t(token), 1, 0, 0))
}
func testProductionFacadeReceivePacketV1(parent uint64, output []byte) (int, uint64, int32) {
	var written C.uint32_t
	var token C.uint64_t
	s := C.kvpn_prod_receive_packet_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written, &token)
	return int(written), uint64(token), int32(s)
}
func testProductionFacadeConfirmPacketV1(parent, token uint64, n int) int32 {
	return int32(C.kvpn_prod_confirm_packet_v1(C.uint64_t(parent), C.uint64_t(token), C.uint32_t(n)))
}
func testProductionFacadeCloseV1(parent uint64) int32 {
	return int32(C.kvpn_prod_close_v1(C.uint64_t(parent)))
}
func testProductionFacadeCancelV1(parent uint64) int32 {
	return int32(C.kvpn_prod_cancel_v1(C.uint64_t(parent)))
}

func testProductionDirectBackingV1(capacity uint64) (uint64, int32) {
	var out C.uint64_t
	status := C.kvpn_prod_direct_backing_v1(C.uint64_t(capacity), &out)
	return uint64(out), int32(status)
}

func testProductionCanonicalOpenCallV1(lease uint64, input, output []byte) (uint64, uint32, int32) {
	var in, out *C.uint8_t
	if len(input) != 0 {
		in = (*C.uint8_t)(unsafe.Pointer(&input[0]))
	}
	if len(output) != 0 {
		out = (*C.uint8_t)(unsafe.Pointer(&output[0]))
	}
	parent, written := C.uint64_t(99), C.uint32_t(99)
	status := C.kvpn_prod_open_v1(in, C.uint32_t(len(input)), C.uint64_t(lease), &parent,
		out, C.uint32_t(len(output)), &written)
	return uint64(parent), uint32(written), int32(status)
}

func testProductionCanonicalOpenOwnerV1(t *testing.T, input, output []byte, want int32) uint64 {
	t.Helper()
	var owner, lease C.uint64_t
	if got := C.kvpn_output_owner_reserve_v1(1, &owner, &lease); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_android_test_install_receiver_v1(owner); got != 0 {
		t.Fatal(got)
	}
	parent, written, status := testProductionCanonicalOpenCallV1(uint64(lease), input, output)
	t.Logf("canonical status=%d captureSizes=%d captureCopies=%d registrations=%d publications=%d", status,
		uint32(C.kvpn_android_test_call_count_v1(0)), uint32(C.kvpn_android_test_call_count_v1(1)),
		uint32(C.kvpn_android_test_call_count_v1(2)), uint32(C.kvpn_android_test_call_count_v1(5)))
	if status != want || (status == 0 && (parent == 0 || written < 220 || written > 32768 || string(output[:4]) != "KPN1")) ||
		(status != 0 && (parent != 0 || written != 0)) {
		t.Fatal("actual canonical opening rejected", status, parent, written)
	}
	if status == 0 && (C.kvpn_android_test_call_count_v1(2) != 1 || C.kvpn_android_test_call_count_v1(5) != 1) {
		t.Fatal("opening bypassed actual current registration/publication")
	}
	if again, n, s := testProductionCanonicalOpenCallV1(uint64(lease), input, output); s != 3 || again != 0 || n != 0 {
		t.Fatal("published parent token reused", s, again, n)
	}
	return parent
}

func testProductionCanonicalOpenTeardownV1(t *testing.T, parent uint64) {
	t.Helper()
	// Test teardown only. This is the actual scoped native retirement, not a
	// canonical close implementation or a legacy unscoped free shortcut.
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if got := C.kvpn_output_begin_parent_v1(C.uint64_t(parent), 1, 2, &frame); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_output_expect_receipt_v1(&frame, 0); got != 0 {
		t.Fatal(got)
	}
	inv, status := newProductionCOutputInvocationV1(C.kvpn_output_callbacks_table_v1(), uint64(frame.owner), uint64(frame.serial), uint64(frame.epoch))
	if status != 0 {
		t.Fatal(status)
	}
	status = androidbridge.CloseProductionV1Scoped(&registry, androidbridge.Handle(parent), inv)
	if got := C.kvpn_output_retirement_drain_v1(&frame, C.int32_t(status)); got != 0 {
		t.Fatal(got)
	}
	C.kvpn_output_end_v1(&frame)
	if got := C.kvpn_android_finalize_parent_v1(C.uint64_t(parent), 1); got != 0 {
		t.Fatal("post-End native parent finalization", got)
	}
}

func testProductionCanonicalLifecycleV1(t *testing.T, parent uint64) {
	t.Helper()
	if got := C.kvpn_prod_cancel_v1(C.uint64_t(parent)); got != 0 {
		t.Fatal("cancel", got)
	}
	if got := C.kvpn_prod_cancel_v1(C.uint64_t(parent)); got != 0 {
		t.Fatal("registered repeat cancel", got)
	}
	if got, ok := androidbridge.RetiredProductionParentResultV1(&registry, androidbridge.Handle(parent)); ok || got != 3 {
		t.Fatal("cancel freed parent", got, ok)
	}
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if got := C.kvpn_output_begin_parent_v1(C.uint64_t(parent), 1, 2, &frame); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_prod_close_v1(C.uint64_t(parent)); got != 5 {
		t.Fatal("busy owner fell back", got)
	}
	C.kvpn_output_end_v1(&frame)
	if got := C.kvpn_prod_close_v1(C.uint64_t(parent)); got != 0 {
		t.Fatal("canonical close", got)
	}
	if got, ok := androidbridge.RetiredProductionParentResultV1(&registry, androidbridge.Handle(parent)); !ok || got != 0 {
		t.Fatal("post-End not published", got, ok)
	}
	if got := C.kvpn_prod_close_v1(C.uint64_t(parent)); got != 0 {
		t.Fatal("exact repeated close", got)
	}
	if got := C.kvpn_prod_cancel_v1(C.uint64_t(parent)); got != 0 {
		t.Fatal("exact retired cancel", got)
	}
	if got := C.kvpn_prod_close_v1(C.uint64_t(parent ^ (1 << 48))); got != 3 {
		t.Fatal("arbitrary invalid close", got)
	}
}

func testProductionCancelledParentStillRegisteredV1(t *testing.T, parent uint64) {
	t.Helper()
	if got, ok := androidbridge.RetiredProductionParentResultV1(&registry, androidbridge.Handle(parent)); ok || got != 3 {
		t.Fatal("cancel published platform retirement", got, ok)
	}
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if got := C.kvpn_output_begin_parent_v1(C.uint64_t(parent), 1, 2, &frame); got != 0 {
		t.Fatal("cancel lost C registration", got)
	}
	C.kvpn_output_end_v1(&frame)
}

func testProductionCanonicalOpenPreflightV1(t *testing.T) {
	t.Helper()
	C.kvpn_android_test_reset_v1()
	var owner, lease C.uint64_t
	if got := C.kvpn_output_owner_reserve_v1(1, &owner, &lease); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_android_test_install_receiver_v1(owner); got != 0 {
		t.Fatal(got)
	}
	input := make([]byte, 32)
	arena := bytes.Repeat([]byte{0xa5}, 100000)
	aliasWritten := C.uint32_t(99)
	aliasStatus := C.kvpn_prod_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), 32, lease,
		(*C.uint64_t)(unsafe.Pointer(&input[0])), (*C.uint8_t)(unsafe.Pointer(&arena[10])), 32768, &aliasWritten)
	if aliasStatus != 2 || aliasWritten != 99 || !bytes.Equal(input, make([]byte, 32)) ||
		!bytes.Equal(arena, bytes.Repeat([]byte{0xa5}, len(arena))) {
		t.Fatal("structurally aliased scalar metadata wrote before validation", aliasStatus, aliasWritten)
	}
	parent, written, status := testProductionCanonicalOpenCallV1(uint64(lease), input, arena[10:32777])
	if status != 4 || parent != 0 || written != 0 || !bytes.Equal(arena, bytes.Repeat([]byte{0xa5}, len(arena))) {
		t.Fatal("short fixed output claimed/corrupted", status, parent, written)
	}
	// Reusing the still-unclaimed token for a well-sized, malformed KPO crosses
	// actual Go admission and must finalize the created holder before return.
	parent, written, status = testProductionCanonicalOpenCallV1(uint64(lease), input, arena[10:32778])
	if status != 2 || parent != 0 || written != 0 || !bytes.Equal(arena, bytes.Repeat([]byte{0xa5}, len(arena))) {
		t.Fatal("bounded arena malformed opening", status, parent, written)
	}
	if got := C.kvpn_output_begin_open_v1(lease, 1, &C.kvpn_output_call_v1{}); got != 3 {
		t.Fatal("consumed lease remained reusable", got)
	}
}

func testAndroidSharedFinalizerV1(t *testing.T, kind uint8, holder bool) {
	t.Helper()
	C.kvpn_android_test_reset_v1()
	var owner, lease C.uint64_t
	if got := C.kvpn_output_owner_reserve_v1(C.uint8_t(kind), &owner, &lease); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_android_test_install_receiver_v1(owner); got != 0 {
		t.Fatal(got)
	}
	var frame C.kvpn_output_call_v1
	var pin runtime.Pinner
	pin.Pin(&frame)
	defer pin.Unpin()
	if got := C.kvpn_output_begin_open_v1(lease, C.uint8_t(kind), &frame); got != 0 {
		t.Fatal(got)
	}
	var created C.uint8_t
	if holder {
		if _, code := newAndroidPlatformV1(C.kvpn_android_test_table_v1(), uint64(owner), kind); code != 0 {
			t.Fatal(code)
		}
		created = 1
	}
	if got := C.kvpn_output_opening_stage_v1(&frame, created); got != 0 {
		t.Fatal(got)
	}
	if got := C.kvpn_android_finalize_failed_opening_v1(lease, C.uint8_t(kind)); got != 25 {
		t.Fatal("finalized with live output frame", got)
	}
	C.kvpn_output_end_v1(&frame)
	if got := C.kvpn_android_finalize_failed_opening_v1(lease, C.uint8_t(3-kind)); got != 25 {
		t.Fatal("wrong-kind lease finalized", got)
	}
	if got := C.kvpn_android_finalize_failed_opening_v1(lease, C.uint8_t(kind)); got != 0 {
		t.Fatal("exact post-End release receipt missing", got)
	}
	if got := C.kvpn_android_finalize_failed_opening_v1(lease, C.uint8_t(kind)); got != 25 {
		t.Fatal("missing released lease treated as current proof", got)
	}
	if holder && finalizeAndroidPlatformV1(uint64(owner), kind) == 0 {
		t.Fatal("exact Go holder was not retired")
	}
}

func testProductionOpenMalformedV1(t *testing.T) {
	C.kvpn_android_test_reset_v1()
	f := newTestOutputFrameV1(t, 1, 0)
	input := []byte("invalid KPO")
	output := bytes.Repeat([]byte{0xa5}, 32768)
	var parent C.uint64_t
	var written C.uint32_t
	status := C.kvpn_prod_open_core_v1(f.ptr, C.kvpn_android_test_table_v1(),
		(*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), (*C.uint8_t)(unsafe.Pointer(&output[0])), 1,
		&parent, &written)
	if status != 2 || parent != 0 || written != 0 || !bytes.Equal(output, bytes.Repeat([]byte{0xa5}, len(output))) {
		t.Fatal("malformed native opening changed output or lost holder", status, parent, written)
	}
	f.end()
	// Host callback fixture only. This is exact Go-holder retirement evidence,
	// not Java callback/global-ref/C-release execution.
	if got := finalizeAndroidPlatformV1(f.owner, 1); got != 0 {
		t.Fatal(got)
	}
	f.release(t)
}

func testAndroidPlatformV1(t *testing.T, kind uint8) *androidPlatformV1 {
	t.Helper()
	C.kvpn_android_test_reset_v1()
	var owner, lease C.uint64_t
	if status := C.kvpn_output_owner_reserve_v1(C.uint8_t(kind), &owner, &lease); status != 0 {
		t.Fatal(status)
	}
	platform, status := newAndroidPlatformV1(C.kvpn_android_test_table_v1(), uint64(owner), kind)
	if status != 0 {
		t.Fatal(status)
	}
	t.Cleanup(func() {
		platform.releaseTestOwnerV1(t)
		if status := C.kvpn_output_abandon_unclaimed_v1(lease); status != 0 {
			t.Fatal(status)
		}
	})
	return platform
}
func testAndroidMutateCaptureV1() { C.kvpn_android_test_mutate_v1() }
func testAndroidResetV1()         { C.kvpn_android_test_reset_v1() }
func testAndroidResultV1(method uint8, result int32) {
	C.kvpn_android_test_result_v1(C.uint8_t(method), C.int32_t(result))
}

func testAndroidCaptureV1(t *testing.T, rows [5][]byte) {
	t.Helper()
	var sizes [5]C.uint32_t
	var backing []byte
	for i, row := range rows {
		sizes[i] = C.uint32_t(len(row))
		backing = append(backing, row...)
	}
	defer clear(backing)
	if status := C.kvpn_android_test_capture_v1((*C.uint8_t)(unsafe.Pointer(&backing[0])), C.uint32_t(len(backing)), &sizes[0]); status != 0 {
		t.Fatal(status)
	}
}

// Host-only cleanup of the C-table fixture, not a release lifecycle provider.
func (p *androidPlatformV1) releaseTestOwnerV1(t *testing.T) {
	t.Helper()
	androidPlatformsV1.Lock()
	defer androidPlatformsV1.Unlock()
	state := p.stateV1()
	if state == nil {
		return
	} // Actual closeOwnedV1 already retired this Go fixture slot.
	if state.busy || state.signals[0].running || state.signals[1].running {
		t.Fatal("fixture still owns active work")
	}
	*state = androidPlatformStateV1{}
}

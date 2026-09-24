//go:build phase18jnitest && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include <stdint.h>
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_android_callbacks.h"
int32_t kvpn_test_jni_maintenance_open_v1(uint8_t *, uint32_t, uint64_t, int32_t, uint64_t *);
int32_t kvpn_test_jni_maintenance_cancel_v1(uint64_t);
int32_t kvpn_test_jni_maintenance_close_v1(uint64_t);
int32_t kvpn_test_jni_maintenance_update_v1(uint64_t, uint8_t *, int32_t, uint32_t *);
void kvpn_test_jni_maintenance_remaining_v1(uint64_t);
int32_t kvpn_test_jni_maintenance_probe_v1(uint64_t, uint8_t *, uint8_t *, uint32_t *);
void kvpn_test_jni_copy_arm_v1(void);
int32_t kvpn_test_jni_copy_entered_v1(void);
void kvpn_test_jni_copy_release_v1(void);
int32_t kvpn_test_jni_maintenance_materialize_v1(uint64_t, uint64_t, uint8_t *, uint32_t, int32_t, uint32_t *);
int32_t kvpn_android_test_install_receiver_v1(uint64_t);
int32_t kvpn_test_jni_prod_open_v1(uint8_t *, uint32_t, uint64_t, uint8_t *, uint32_t, int32_t, uint64_t *, uint32_t *);
int32_t kvpn_test_jni_prod_cancel_v1(uint64_t);
int32_t kvpn_test_jni_prod_close_v1(uint64_t);
void kvpn_test_jni_prod_inputs_v1(uint64_t);
void kvpn_test_jni_prod_control_v1(uint64_t);
int32_t kvpn_test_jni_prod_receive_packet_v1(uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *, int32_t);
int32_t kvpn_test_jni_prod_open_stream_v1(uint64_t, uint8_t *, uint32_t, uint64_t *);
int32_t kvpn_test_jni_stream_receive_v1(uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
int32_t kvpn_test_jni_prod_probe_v1(uint64_t, uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *);
*/
import "C"

import (
	"testing"
	"unsafe"
)

func testMaintenanceJNIHostMaterializeV1(parent, child uint64, output []byte, failure bool) (int, int32) {
	var written C.uint32_t
	var fail C.int32_t
	if failure {
		fail = 1
	}
	s := C.kvpn_test_jni_maintenance_materialize_v1(C.uint64_t(parent), C.uint64_t(child), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), fail, &written)
	return int(written), int32(s)
}

func testMaintenanceJNIHostProbeCallV1(parent uint64, request, output []byte) (int, int32) {
	var n C.uint32_t
	s := C.kvpn_test_jni_maintenance_probe_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), (*C.uint8_t)(unsafe.Pointer(&output[0])), &n)
	return int(n), int32(s)
}

func testJNICopyArmV1()          { C.kvpn_test_jni_copy_arm_v1() }
func testJNICopyEnteredV1() bool { return C.kvpn_test_jni_copy_entered_v1() != 0 }
func testJNICopyReleaseV1()      { C.kvpn_test_jni_copy_release_v1() }

func testMaintenanceJNIHostUpdateCallV1(t *testing.T, parent uint64, output []byte, failure bool) (int, int32) {
	arena := make([]byte, 48)
	for i := range arena {
		arena[i] = 0xa5
	}
	defer clear(arena)
	var fail C.int32_t
	if failure {
		fail = 1
	}
	var n C.uint32_t
	s := C.kvpn_test_jni_maintenance_update_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&arena[0])), fail, &n)
	for _, value := range arena[:7] {
		if value != 0xa5 {
			t.Fatal("JNI changed prefix")
		}
	}
	for _, value := range arena[45:] {
		if value != 0xa5 {
			t.Fatal("JNI changed suffix")
		}
	}
	copy(output, arena[7:45])
	return int(n), int32(s)
}

func testMaintenanceJNIHostOpeningV1(t *testing.T, request []byte, failWrite bool) {
	t.Helper()
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal(s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal(s)
	}
	fail := C.int32_t(0)
	if failWrite {
		fail = 1
	}
	s := C.kvpn_test_jni_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), lease, fail, &parent)
	if failWrite {
		if s != 18 || parent != 0 {
			t.Fatal("maintenance failed metadata", s, parent)
		}
		// Actual post-End finalizer at host receiver boundary. Kotlin finally
		// owns this same acknowledgement in the trusted Android crossing.
		if s := C.kvpn_android_finalize_failed_opening_v1(lease, 2); s != 0 {
			t.Fatal("maintenance failed finalization", s)
		}
		return
	}
	if s != 0 || parent == 0 {
		if parent == 0 {
			if cleanup := C.kvpn_android_finalize_failed_opening_v1(lease, 2); cleanup != 0 {
				t.Fatal("refused maintenance finalization", s, cleanup)
			}
		}
		t.Fatal("maintenance JNI open", s, parent)
	}
	C.kvpn_test_jni_maintenance_remaining_v1(parent)
	output := make([]byte, 48)
	for i := range output {
		output[i] = 0xa5
	}
	var written C.uint32_t
	if s := C.kvpn_test_jni_maintenance_update_v1(parent, (*C.uint8_t)(unsafe.Pointer(&output[0])), 0, &written); s != 0 || written != 3 || output[7] != 1 || output[8] != 0 || output[9] != 12 || output[6] != 0xa5 || output[10] != 0xa5 {
		t.Fatal("JNI actual prepared update decision", s, written, output[7:10])
	}
	// Its next genuine decision is rate-limited. A final metadata failure must
	// leave every caller byte untouched despite native preparation/commit.
	for i := range output {
		output[i] = 0xa5
	}
	if s := C.kvpn_test_jni_maintenance_update_v1(parent, (*C.uint8_t)(unsafe.Pointer(&output[0])), 1, &written); s != 18 || written != 0 {
		t.Fatal("JNI update metadata failure", s, written)
	}
	for _, value := range output {
		if value != 0xa5 {
			t.Fatal("undelivered update bytes escaped")
		}
	}
	if s := C.kvpn_test_jni_maintenance_cancel_v1(parent); s != 0 {
		t.Fatal("maintenance JNI cancel", s)
	}
	if s := C.kvpn_test_jni_maintenance_close_v1(parent); s != 0 {
		t.Fatal("maintenance JNI close", s)
	}
	if s := C.kvpn_test_jni_maintenance_close_v1(parent); s != 0 {
		t.Fatal("maintenance JNI repeat close", s)
	}
}

func testProductionJNIHostProbeV1(parent uint64, request, output []byte) (int, int32) {
	var n C.uint32_t
	s := C.kvpn_test_jni_prod_probe_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &n)
	return int(n), int32(s)
}

func testProductionJNIHostOpenStreamV1(parent uint64, request []byte) (uint64, int32) {
	var child C.uint64_t
	s := C.kvpn_test_jni_prod_open_stream_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)), &child)
	return uint64(child), int32(s)
}
func testProductionJNIHostStreamReceiveV1(parent, child uint64, output []byte) (int, uint64, int32) {
	var written C.uint32_t
	var token C.uint64_t
	s := C.kvpn_test_jni_stream_receive_v1(C.uint64_t(parent), C.uint64_t(child), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written, &token)
	return int(written), uint64(token), int32(s)
}

func testProductionJNIHostReceivePacketV1(parent uint64, output []byte) (int, uint64, int32) {
	return testProductionJNIHostReceivePacketResultV1(parent, output, 0)
}
func testProductionJNIHostReceivePacketFailureV1(parent uint64, output []byte) (int, uint64, int32) {
	return testProductionJNIHostReceivePacketResultV1(parent, output, 1)
}
func testProductionJNIHostReceivePacketResultV1(parent uint64, output []byte, failure int32) (int, uint64, int32) {
	var written C.uint32_t
	var token C.uint64_t
	s := C.kvpn_test_jni_prod_receive_packet_v1(C.uint64_t(parent), (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), &written, &token, C.int32_t(failure))
	return int(written), uint64(token), int32(s)
}

func testProductionJNIHostOpeningV1(t *testing.T, request, output []byte, failWrite bool) {
	t.Helper()
	var owner, lease, parent C.uint64_t
	var written C.uint32_t
	if status := C.kvpn_output_owner_reserve_v1(1, &owner, &lease); status != 0 {
		t.Fatal(status)
	}
	if status := C.kvpn_android_test_install_receiver_v1(owner); status != 0 {
		t.Fatal(status)
	}
	failure := C.int32_t(0)
	if failWrite {
		failure = 1
	}
	status := C.kvpn_test_jni_prod_open_v1((*C.uint8_t)(unsafe.Pointer(&request[0])), C.uint32_t(len(request)),
		lease, (*C.uint8_t)(unsafe.Pointer(&output[0])), C.uint32_t(len(output)), failure, &parent, &written)
	if failWrite {
		if status != 18 || parent != 0 || written != 0 {
			t.Fatal("metadata failure escaped", status, parent, written)
		}
		// Models trusted Kotlin finally at the host receiver boundary, after JNI End.
		if status := C.kvpn_android_finalize_failed_opening_v1(lease, 1); status != 0 {
			t.Fatal("failed opening not finalized", status)
		}
		return
	}
	if status != 0 || parent == 0 || written < 220 || written > 32768 {
		if parent == 0 {
			if cleanup := C.kvpn_android_finalize_failed_opening_v1(lease, 1); cleanup != 0 {
				t.Fatal("refused production finalization", status, cleanup)
			}
		}
		t.Fatal("JNI opening rejected", status, parent, written)
	}
	if string(output[10:14]) != "KPN1" {
		t.Fatal("JNI snapshot missing")
	}
	C.kvpn_test_jni_prod_inputs_v1(parent)
	C.kvpn_test_jni_prod_control_v1(parent)
	for i := 0; i < 2; i++ {
		if status := C.kvpn_test_jni_prod_cancel_v1(parent); status != 0 {
			t.Fatal("JNI cancel", status)
		}
	}
	for i := 0; i < 2; i++ {
		if status := C.kvpn_test_jni_prod_close_v1(parent); status != 0 {
			t.Fatal("JNI close", status)
		}
	}
}

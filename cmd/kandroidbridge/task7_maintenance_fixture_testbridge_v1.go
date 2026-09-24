//go:build phase9internal && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include <string.h>
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_abi.h"
int32_t kvpn_android_test_install_receiver_v1(uint64_t);
const kvpn_output_callbacks_v1 *kvpn_output_test_bad_table_v1(uint8_t);
extern int32_t kvpn_task7_maintenance_run_v1(kvpn_output_callbacks_v1 *,uint64_t,uint64_t,uint64_t,uint64_t,uint32_t,int64_t *,uint32_t);
static int32_t task7_measure_host(uint64_t parent,uint32_t id,uint32_t length,uint8_t mode,int64_t *output,uint8_t *committed) {
    kvpn_output_call_v1 frame = {0};
    int64_t stage[24]; for (int i=0;i<24;++i) stage[i]=-1;
    int32_t s=kvpn_output_begin_parent_v1(parent,2,mode==3?1:0,&frame);
    *committed=0;
    if(s) return s;
    if(mode!=1) s=kvpn_output_expect_receipt_v1(&frame,mode==2?1:0);
    kvpn_output_callbacks_v1 *table=(kvpn_output_callbacks_v1 *)(mode==4?kvpn_output_test_bad_table_v1(19):kvpn_output_callbacks_table_v1());
    if(!s) s=kvpn_task7_maintenance_run_v1(table,frame.owner,frame.serial,frame.epoch,parent,id,stage,length);
    if(!s) {
        // A real C sticky failure between Prepare and commit must suppress delivery.
        if(mode==5) kvpn_output_note_failure_v1(&frame,18);
        s=kvpn_output_try_commit_v1(&frame,0,committed);
        if(!s && !*committed) s=18;
        if(!s) memcpy(output,stage,sizeof(stage));
    }
    kvpn_output_end_v1(&frame);
    return s;
}
*/
import "C"

import (
	"testing"
	"unsafe"
)

func testTask7MaintenanceParentV1(t *testing.T, input []byte, closeStatus int32) uint64 {
	t.Helper()
	var owner, lease, parent C.uint64_t
	if s := C.kvpn_output_owner_reserve_v1(2, &owner, &lease); s != 0 {
		t.Fatal("reserve", s)
	}
	if s := C.kvpn_android_test_install_receiver_v1(owner); s != 0 {
		t.Fatal("receiver", s)
	}
	if s := C.kvpn_maintenance_open_v1((*C.uint8_t)(unsafe.Pointer(&input[0])), C.uint32_t(len(input)), lease, &parent); s != 0 {
		t.Fatal("open", s)
	}
	t.Cleanup(func() {
		if got := int32(C.kvpn_maintenance_close_v1(parent)); got != closeStatus {
			t.Fatal("actual parent cleanup", got, closeStatus)
		}
	})
	return uint64(parent)
}

func testTask7MaintenanceCGoV1(parent uint64, caseID, length uint32, mode uint8) (out [24]int64, status int32, commit bool) {
	for i := range out {
		out[i] = -1
	}
	var committed C.uint8_t
	s := C.task7_measure_host(C.uint64_t(parent), C.uint32_t(caseID), C.uint32_t(length), C.uint8_t(mode), (*C.int64_t)(unsafe.Pointer(&out[0])), &committed)
	return out, int32(s), committed == 1
}

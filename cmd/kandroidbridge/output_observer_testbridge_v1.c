//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
/* Host-only compilation of the actual provider, never a parallel gate. */
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_platform_finalize_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_production_spans_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_production_facade_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_stream_facade_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_maintenance_facade_v1.c"

static kvpn_output_call_v1 test_frames[8];
kvpn_output_call_v1 *kvpn_output_test_frame_v1(uint8_t slot) {
    return slot < 8 ? &test_frames[slot] : NULL;
}
const kvpn_output_callbacks_v1 *kvpn_output_test_bad_table_v1(uint8_t defect) {
    static kvpn_output_callbacks_v1 t;
    t = *kvpn_output_callbacks_table_v1();
    if (defect == 1) t.version = 2;
    if (defect == 2) --t.struct_size;
    switch (defect) {
    case 3: t.monotonic_now_ns = NULL; break;
    case 4: t.prod_validate_invocation = NULL; break;
    case 5: t.prod_bind_parent = NULL; break;
    case 6: t.prod_bind_handle = NULL; break;
    case 7: t.prod_bind_lane = NULL; break;
    case 8: t.prod_prepare = NULL; break;
    case 9: t.prod_parent_terminal = NULL; break;
    case 10: t.prod_attempt_terminal = NULL; break;
    case 11: t.prod_claim_receipt = NULL; break;
    case 12: t.prod_finish_receipt = NULL; break;
    case 13: t.prod_resource_retired = NULL; break;
    case 14: t.maint_validate_invocation = NULL; break;
    case 15: t.maint_bind_parent = NULL; break;
    case 16: t.maint_bind_handle = NULL; break;
    case 17: t.maint_bind_lane = NULL; break;
    case 18: t.maint_supersede_normal = NULL; break;
    case 19: t.maint_prepare = NULL; break;
    case 20: t.maint_parent_terminal = NULL; break;
    case 21: t.maint_candidate_terminal = NULL; break;
    case 22: t.maint_claim_receipt = NULL; break;
    case 23: t.maint_finish_receipt = NULL; break;
    case 24: t.maint_resource_retired = NULL; break;
    default: break;
    }
    return &t;
}

static int32_t fault_status;
static int32_t fault_validate(uint64_t o, uint64_t c, uint64_t e) {
    (void)o; (void)c; (void)e; return fault_status;
}
static int32_t fault_clock(uint64_t *now) { *now = 0; return fault_status; }
const kvpn_output_callbacks_v1 *kvpn_output_test_fault_table_v1(uint8_t ns, int32_t status) {
    static kvpn_output_callbacks_v1 t;
    t = *kvpn_output_callbacks_table_v1(); fault_status = status;
    if (ns == 1) t.prod_validate_invocation = fault_validate;
    else if (ns == 2) t.maint_validate_invocation = fault_validate;
    else t.monotonic_now_ns = fault_clock;
    return &t;
}

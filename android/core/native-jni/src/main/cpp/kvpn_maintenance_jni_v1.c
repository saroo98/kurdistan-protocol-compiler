// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_production_jni_v1.h"
#include "kvpn_production_facade_v1.h"
#include "production_scoped_exports_v1.h"
#include "kvpn_android_callbacks.h"
#include <stdlib.h>
#include <string.h>

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceMaterializeV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong candidate, jobject output, jint position, jint limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    if (status) return status;
    if (!parent || !candidate) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    status = kvpn_production_jni_span_v1(env, output, position, limit, 1, 1, UINT32_MAX, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_materialize_core_v1(&call, (uint64_t)parent, (uint64_t)candidate, stage->bytes,
        span.length < sizeof(stage->bytes) ? span.length : sizeof(stage->bytes), &stage->written);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) {
            jlong value = (jlong)stage->written;
            status = kvpn_production_jni_write_v1(env, metadata, 1, &value);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else memcpy(span.data, stage->bytes, stage->written);
        }
    }
    /* Native materialization consumes its candidate before preparation. A
     * later undelivered result cannot recreate or release that old child. */
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceReleaseUpdateV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong candidate) {
    (void)env; (void)receiver;
    if (!parent || !candidate) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_release_update_core_v1(&call, (uint64_t)parent, (uint64_t)candidate);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
    }
    kvpn_output_end_v1(&call);
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceRunProbeV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject request, jint position, jint limit,
    jobject output, jint output_position, jint output_limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    if (status) return status;
    if (!parent || (int64_t)limit - position != 9) return 2;
    kvpn_production_span_v1 input, span; uint64_t input_backing = 0, output_backing = 0;
    status = kvpn_production_jni_span_v1(env, request, position, limit, 0, 9, 9, &input, &input_backing);
    if (!status) status = kvpn_production_jni_span_v1(env, output, output_position, output_limit, 1, 21, UINT32_MAX, &span, &output_backing);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, span.data, span.length)) return 2;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_run_probe_core_v1(&call, (uint64_t)parent, input.data, input.length, stage->bytes, &stage->written);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) {
            jlong value = 21;
            status = kvpn_production_jni_write_v1(env, metadata, 1, &value);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else memcpy(span.data, stage->bytes, 21);
        }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCheckUpdateV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject request, jint position, jint limit,
    jobject output, jint output_position, jint output_limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    if (status) return status;
    if (!parent || (int64_t)limit - position != 3) return 2;
    kvpn_production_span_v1 input, span; uint64_t input_backing = 0, output_backing = 0;
    status = kvpn_production_jni_span_v1(env, request, position, limit, 0, 3, 3, &input, &input_backing);
    if (!status) status = kvpn_production_jni_span_v1(env, output, output_position, output_limit, 1, 38, UINT32_MAX, &span, &output_backing);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, span.data, span.length)) return 2;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    uint8_t published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 2);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_check_update_core_v1(&call, (uint64_t)parent, input.data, input.length, stage);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) {
            jlong value = (jlong)stage->written;
            status = kvpn_production_jni_write_v1(env, metadata, 1, &value);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else { memcpy(span.data, stage->bytes, stage->written); published = 1; }
        }
    }
    if (stage && !published && stage->candidate && kvpn_maintenance_discard_candidate_core_v1(&call, (uint64_t)parent, stage->candidate)) status = 18;
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceOpenV1(
    JNIEnv *env, jobject receiver, jobject request, jint position, jint limit, jlong lease, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    if (status) return status;
    if (!lease) return 2;
    kvpn_production_span_v1 input;
    uint64_t backing = 0, external = 0;
    status = kvpn_production_jni_span_v1(env, request, position, limit, 0, 1, 2721575, &input, &backing);
    if (status) return status;
    status = kvpn_production_jni_backing_v1(KVPN_OUTPUT_MAINTENANCE_V1, input.length, 128ULL << 20, &external);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_open_v1((uint64_t)lease, KVPN_OUTPUT_MAINTENANCE_V1, &call);
    if (status) return status;
    uint64_t parent = 0;
    uint8_t entered = 0, published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 1);
    if (!status) {
        entered = 1;
        status = kvpn_maintenance_open_core_v1(&call, kvpn_android_callbacks_table_v1(), input.data, input.length, external, &parent);
        if (!status) {
            uint8_t commit = 0;
            status = kvpn_output_try_commit_v1(&call, 0, &commit);
            if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
            if (!status) {
                const jlong value[1] = {(jlong)parent};
                status = kvpn_production_jni_write_v1(env, metadata, 1, value);
                if (status && kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            }
            if (!status) {
                status = kvpn_output_opening_published_v1(&call);
                if (status) { const jlong zero[1] = {0}; (void)kvpn_production_jni_write_v1(env, metadata, 1, zero); }
            }
            if (!status) published = 1;
        }
        if (!published && parent && kvpn_maintenance_discard_parent_core_v1(&call, parent)) status = 18;
    }
    if (!entered && kvpn_output_opening_stage_v1(&call, 0)) status = 18;
    kvpn_output_end_v1(&call);
    /* Exact receiver/guard failed-opening acknowledgement remains in trusted
     * Kotlin finally after this End, as for production opening. */
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCancelV1(
    JNIEnv *env, jobject receiver, jlong parent) {
    (void)env; (void)receiver;
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, &call, &absent);
    if (absent) return kvpn_go_maintenance_retired_result_v1((uint64_t)parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_cancel_core_v1(&call, (uint64_t)parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCloseV1(
    JNIEnv *env, jobject receiver, jlong parent) {
    (void)env; (void)receiver;
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1, &call, &absent);
    if (absent) return kvpn_go_maintenance_retired_result_v1((uint64_t)parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_close_core_v1(&call, (uint64_t)parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    if (!status && kvpn_android_finalize_parent_v1((uint64_t)parent, KVPN_OUTPUT_MAINTENANCE_V1)) status = 18;
    return status;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_production_facade_v1.h"
#include "kvpn_production_jni_v1.h"
#include "kvpn_android_callbacks.h"
#include <stdlib.h>
#include <string.h>

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamReceiveV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child, jobject output, jint position, jint limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 2);
    if (status) return status;
    if (!parent || !child) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    status = kvpn_production_jni_span_v1(env, output, position, limit, 1, 1, 16384, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 4);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_stream_receive_core_v1(&call, (uint64_t)parent, (uint64_t)child, stage->bytes, span.length, &stage->written, &stage->token);
    if (status == 0 || status == 19) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, status, &publish);
        if ((status == 0 || status == 19) && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (publish) {
            jlong values[2] = {(jlong)stage->written, (jlong)stage->token};
            if (kvpn_production_jni_write_v1(env, metadata, 2, values)) {
                status = 18;
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else {
                if (!status) memcpy(span.data, stage->bytes, stage->written);
                published = 1;
            }
        }
    }
    if (stage && stage->token && !published) {
        if (kvpn_stream_discard_delivery_core_v1(&call, (uint64_t)parent, (uint64_t)child, stage->token)) status = 18;
        else discarded = 1;
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamSendV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child, jobject input, jint position, jint limit) {
    (void)receiver;
    if (!parent || !child) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    int32_t status = kvpn_production_jni_span_v1(env, input, position, limit, 0, 1, 16384, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call,
        kvpn_stream_send_core_v1(&call, (uint64_t)parent, (uint64_t)child, span.data, span.length));
    kvpn_output_end_v1(&call);
    return status;
}
#include <jni.h>

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamConfirmV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child, jlong token, jlong length) {
    (void)env; (void)receiver;
    if (!parent || length < 0 || (uint64_t)length > UINT32_MAX) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_confirm_core_v1(&call, (uint64_t)parent, (uint64_t)child, (uint64_t)token, (uint32_t)length));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamRejectV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child, jlong token) {
    (void)env; (void)receiver;
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_reject_core_v1(&call, (uint64_t)parent, (uint64_t)child, (uint64_t)token));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamHalfCloseV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child) {
    (void)env; (void)receiver;
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_half_close_core_v1(&call, (uint64_t)parent, (uint64_t)child));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamCancelV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child) {
    (void)env; (void)receiver;
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_cancel_core_v1(&call, (uint64_t)parent, (uint64_t)child));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamCloseV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong child) {
    (void)env; (void)receiver;
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_close_core_v1(&call, (uint64_t)parent, (uint64_t)child));
    kvpn_output_end_v1(&call);
    return status;
}

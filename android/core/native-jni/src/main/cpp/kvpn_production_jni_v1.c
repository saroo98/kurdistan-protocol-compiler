// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_production_facade_v1.h"
#include "kvpn_production_jni_v1.h"
#include "kvpn_android_callbacks.h"
#include "production_scoped_exports_v1.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#ifdef KVPN_ANDROID_PLATFORM_INTERNAL_V1
void kvpn_task7_rejection_v1(uint8_t, uint8_t, int32_t);
#define TASK7_CONTROL_REJECTION(p,s) kvpn_task7_rejection_v1(0,(p),(s))
#else
#define TASK7_CONTROL_REJECTION(p,s) ((void)0)
#endif

int32_t kvpn_production_jni_backing_v1(uint8_t kind, uint32_t length, uint64_t capacity, uint64_t *out) {
    if (!out) return 2;
    *out = 0;
    uint64_t direct = 0, java = 0, shared = 0, owner = 0, frames = 0;
    int32_t status = kvpn_production_java_payload_v1(kind, length, capacity, &java);
    if (status) return status;
    status = kind == KVPN_OUTPUT_PRODUCTION_V1 ? kvpn_prod_direct_backing_v1(capacity, &direct) :
        kvpn_maintenance_direct_backing_v1(capacity, &direct);
    if (status) return status;
    status = kvpn_output_layout_v1(kind, &shared, &owner, &frames);
    if (status) return status;
    if (!frames || frames % sizeof(kvpn_output_call_v1)) return 18;
    /* Direct backing already owns the four plain platform borrows. Add only
     * actual JNI holder differences, callback-local aggregate arrays, static
     * VM/once storage and native method-pointer arrays. Object/ART headers
     * and VM local-frame internals remain a separate reference inventory. */
    uint64_t native = 2 * (sizeof(kvpn_android_java_call_v1) - sizeof(kvpn_platform_borrow_v1)) +
        sizeof(JavaVM *) + sizeof(pthread_once_t) + 2 * sizeof(jint[5]) +
        sizeof(jobject[5]) + sizeof(kvpn_cb_output_v1 *[5]) + 2 * (sizeof(jint) + sizeof(jlong)) +
        2 * sizeof(const char *[20]);
    uint64_t per_frame = 2 * sizeof(kvpn_production_span_v1) + sizeof(uint64_t[2]) + 2 * sizeof(jlong[2]);
    uint64_t count = frames / sizeof(kvpn_output_call_v1), total;
    if (per_frame > UINT64_MAX / count || !kvpn_production_add_v1(direct, java, &total) ||
        !kvpn_production_add_v1(total, native, &total) ||
        !kvpn_production_add_v1(total, count * per_frame, &total) || total > capacity) return 5;
    *out = total;
    return 0;
}

static int jni_failed(JNIEnv *env) {
    if (!(*env)->ExceptionCheck(env)) return 0;
    (*env)->ExceptionClear(env);
    return 1;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdRunProbeV1(
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
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_prod_run_probe_core_v1(&call, (uint64_t)parent, input.data, input.length, stage->bytes, &stage->written);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
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

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenStreamV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject request, jint position, jint limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    if (status) return status;
    if (!parent) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    status = kvpn_production_jni_span_v1(env, request, position, limit, 0, 7, 259, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    uint64_t child = 0; uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 2);
    if (!status) status = kvpn_prod_open_stream_core_v1(&call, (uint64_t)parent, span.data, span.length, &child);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) {
            jlong value = (jlong)child;
            status = kvpn_production_jni_write_v1(env, metadata, 1, &value);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else published = 1;
        }
    }
    if (child && !published) {
        if (kvpn_prod_discard_stream_core_v1(&call, (uint64_t)parent, child)) status = 18;
        else discarded = 1;
    }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdReceivePacketV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject output, jint position, jint limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 2);
    if (status) return status;
    if (!parent) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    status = kvpn_production_jni_span_v1(env, output, position, limit, 1, 1, 65535, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 3);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_prod_receive_packet_core_v1(&call, (uint64_t)parent, stage->bytes, span.length, &stage->written, &stage->token);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) {
            jlong values[2] = {(jlong)stage->written, (jlong)stage->token};
            status = kvpn_production_jni_write_v1(env, metadata, 2, values);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else { memcpy(span.data, stage->bytes, stage->written); published = 1; }
        }
    }
    if (stage && stage->token && !published) {
        if (kvpn_prod_discard_packet_core_v1(&call, (uint64_t)parent, stage->token)) status = 18;
        else discarded = 1;
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdNextControlV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject output, jint position, jint limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 1);
    TASK7_CONTROL_REJECTION(1,status);
    if (status) return status;
    if (!parent) { TASK7_CONTROL_REJECTION(2,2); return 2; }
    kvpn_production_span_v1 span; uint64_t backing = 0;
    status = kvpn_production_jni_span_v1(env, output, position, limit, 1, 1, 32800, &span, &backing);
    TASK7_CONTROL_REJECTION(3,status);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_CONTROL_V1, &call);
    TASK7_CONTROL_REJECTION(4,status);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    TASK7_CONTROL_REJECTION(5,status);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) { status = 5; TASK7_CONTROL_REJECTION(6,status); } }
    if (!status) {
        status = kvpn_prod_next_control_core_v1(&call, (uint64_t)parent, stage->bytes, span.length, &stage->written);
        TASK7_CONTROL_REJECTION(7,status);
    }
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        TASK7_CONTROL_REJECTION(8,status);
        if (!status) {
            jlong value = (jlong)stage->written;
            status = kvpn_production_jni_write_v1(env, metadata, 1, &value);
            TASK7_CONTROL_REJECTION(9,status);
            if (status) {
                if (kvpn_output_publication_undelivered_v1(&call)) kvpn_output_note_failure_v1(&call, 18);
            } else memcpy(span.data, stage->bytes, stage->written);
        }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdSubmitPacketV1(
    JNIEnv *env, jobject receiver, jlong parent, jobject input, jint position, jint limit) {
    (void)receiver;
    if (!parent) return 2;
    kvpn_production_span_v1 span; uint64_t backing = 0;
    int32_t status = kvpn_production_jni_span_v1(env, input, position, limit, 0, 1, 65535, &span, &backing);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call,
        kvpn_prod_submit_packet_core_v1(&call, (uint64_t)parent, span.data, span.length));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_production_jni_metadata_v1(JNIEnv *env, jlongArray output, jsize count) {
    if (!output || count < 1 || count > 2) return 2;
    jsize actual = (*env)->GetArrayLength(env, output);
    if (jni_failed(env)) return 18;
    if (actual != count) return 2;
    const jlong zero[2] = {0, 0};
    (*env)->SetLongArrayRegion(env, output, 0, count, zero);
    return jni_failed(env) ? 18 : 0;
}

int32_t kvpn_production_jni_write_v1(JNIEnv *env, jlongArray output, jsize count, const jlong *values) {
    if (!output || !values || count < 1 || count > 2) return 2;
    (*env)->SetLongArrayRegion(env, output, 0, count, values);
    if (!jni_failed(env)) return 0;
    const jlong zero[2] = {0, 0};
    (*env)->SetLongArrayRegion(env, output, 0, count, zero);
    (void)jni_failed(env);
    return 18;
}

int32_t kvpn_production_jni_span_v1(JNIEnv *env, jobject buffer, jint position, jint limit,
    uint8_t writable, uint32_t minimum, uint32_t maximum, kvpn_production_span_v1 *out, uint64_t *backing) {
    if (out) { out->data = NULL; out->length = 0; }
    if (backing) *backing = 0;
    if (!buffer || !out || !backing || writable > 1) return 2;
    jlong capacity = (*env)->GetDirectBufferCapacity(env, buffer);
    if (jni_failed(env)) return 18;
    if (capacity < 0 || (uint64_t)capacity > UINT32_MAX) return 2;
    void *address = (*env)->GetDirectBufferAddress(env, buffer);
    if (jni_failed(env)) return 18;
    if (!address) return 2;
    jclass type = (*env)->GetObjectClass(env, buffer);
    if (jni_failed(env) || !type) return 18;
    int32_t status = 18;
    jmethodID get_position = (*env)->GetMethodID(env, type, "position", "()I");
    if (jni_failed(env) || !get_position) goto done;
    jmethodID get_limit = (*env)->GetMethodID(env, type, "limit", "()I");
    if (jni_failed(env) || !get_limit) goto done;
    jmethodID is_readonly = (*env)->GetMethodID(env, type, "isReadOnly", "()Z");
    if (jni_failed(env) || !is_readonly) goto done;
    jint actual_position = (*env)->CallIntMethod(env, buffer, get_position);
    if (jni_failed(env)) goto done;
    jint actual_limit = (*env)->CallIntMethod(env, buffer, get_limit);
    if (jni_failed(env)) goto done;
    jboolean readonly = (*env)->CallBooleanMethod(env, buffer, is_readonly);
    if (jni_failed(env)) goto done;
    if (readonly > 1 || (writable && readonly)) { status = 2; goto done; }
    status = kvpn_production_span_v1_init(address, capacity, actual_position, actual_limit,
        position, limit, minimum, maximum, out);
    if (!status) *backing = (uint64_t)capacity;
done:
    (*env)->DeleteLocalRef(env, type);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenV1(
    JNIEnv *env, jobject receiver, jobject request, jint position, jint limit, jlong lease,
    jobject snapshot, jint snapshot_position, jint snapshot_limit, jlongArray metadata) {
    (void)receiver;
    int32_t status = kvpn_production_jni_metadata_v1(env, metadata, 2);
    if (status) return status;
    if (!lease) return 2;
    kvpn_production_span_v1 input, output;
    uint64_t input_backing = 0, output_backing = 0, external = 0;
    status = kvpn_production_jni_span_v1(env, request, position, limit, 0, 1, 2721575, &input, &input_backing);
    if (status) return status;
    status = kvpn_production_jni_span_v1(env, snapshot, snapshot_position, snapshot_limit,
        1, 32768, UINT32_MAX, &output, &output_backing);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, output.data, output.length)) return 2;
    status = kvpn_production_jni_backing_v1(KVPN_OUTPUT_PRODUCTION_V1, input.length, 128ULL << 20, &external);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_open_v1((uint64_t)lease, KVPN_OUTPUT_PRODUCTION_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t entered_core = 0, published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 1);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) {
        entered_core = 1;
        status = kvpn_prod_open_core_v1(&call, kvpn_android_callbacks_table_v1(), input.data,
            input.length, stage->bytes, external, &stage->parent, &stage->written);
        if (status < 0 || status > 26 || status == 19 || status == 20 ||
            (!status && (!stage->parent || stage->written < 220 || stage->written > 32768))) {
            kvpn_output_note_failure_v1(&call, 18); status = 18;
        }
        if (!status) {
            uint8_t commit = 0;
            status = kvpn_output_try_commit_v1(&call, 0, &commit);
            if (!status && !commit) status = 18;
            if (!status) {
                const jlong values[2] = {(jlong)stage->parent, (jlong)stage->written};
                status = kvpn_production_jni_write_v1(env, metadata, 2, values);
                if (status && kvpn_output_publication_undelivered_v1(&call))
                    kvpn_output_note_failure_v1(&call, 18);
            }
            if (!status) {
                status = kvpn_output_opening_published_v1(&call);
                if (status) {
                    const jlong zero[2] = {0, 0};
                    (void)kvpn_production_jni_write_v1(env, metadata, 2, zero);
                }
            }
            if (!status) { memcpy(output.data, stage->bytes, stage->written); published = 1; }
        }
        if (!published && stage->parent && kvpn_prod_discard_parent_core_v1(&call, stage->parent)) status = 18;
    }
    if (!entered_core && kvpn_output_opening_stage_v1(&call, 0)) status = 18;
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    /* The trusted opening finally owns exact-receiver failed finalization and
     * acknowledges it on the SAME runtime guard. Do not consume that proof. */
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCancelV1(
    JNIEnv *env, jobject receiver, jlong parent) {
    (void)env; (void)receiver;
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, &call, &absent);
    if (absent) return kvpn_go_prod_retired_result_v1((uint64_t)parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_prod_cancel_core_v1(&call, (uint64_t)parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCloseV1(
    JNIEnv *env, jobject receiver, jlong parent) {
    (void)env; (void)receiver;
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, &call, &absent);
    if (absent) return kvpn_go_prod_retired_result_v1((uint64_t)parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_prod_close_core_v1(&call, (uint64_t)parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    if (!status && kvpn_android_finalize_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdConfirmSocketV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong token, jint protected_ok, jint has_network, jlong network) {
    (void)env; (void)receiver;
    if (!parent || protected_ok > 1 || has_network > 1 || ((has_network == 0) != (network == 0)) || protected_ok < 0 || has_network < 0) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_confirm_socket_core_v1(&call, (uint64_t)parent, (uint64_t)token, (uint8_t)protected_ok, (uint8_t)has_network, (uint64_t)network));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdConfirmPacketV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong token, jlong length) {
    (void)env; (void)receiver;
    if (!parent || length < 0 || (uint64_t)length > UINT32_MAX) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_confirm_packet_core_v1(&call, (uint64_t)parent, (uint64_t)token, (uint32_t)length));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdRejectPacketV1(
    JNIEnv *env, jobject receiver, jlong parent, jlong token) {
    (void)env; (void)receiver;
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_reject_packet_core_v1(&call, (uint64_t)parent, (uint64_t)token));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdHandoverV1(
    JNIEnv *env, jobject receiver, jlong parent, jint has_network, jlong network) {
    (void)env; (void)receiver;
    if (!parent || has_network > 1 || ((has_network == 0) != (network == 0)) || has_network < 0) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_handover_core_v1(&call, (uint64_t)parent, (uint8_t)has_network, (uint64_t)network));
    kvpn_output_end_v1(&call);
    return status;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdReconnectV1(
    JNIEnv *env, jobject receiver, jlong parent, jint reason) {
    (void)env; (void)receiver;
    if (!parent || reason < 1 || reason > 3) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1((uint64_t)parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_reconnect_core_v1(&call, (uint64_t)parent, (uint8_t)reason));
    kvpn_output_end_v1(&call);
    return status;
}

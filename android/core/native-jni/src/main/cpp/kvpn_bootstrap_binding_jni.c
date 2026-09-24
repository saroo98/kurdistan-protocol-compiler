/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright 2026 Saro */
#include <jni.h>
#include <stdint.h>
#include <stddef.h>
#include "bootstrap_binding_v1.h"

typedef struct { uint8_t *data; uint32_t length; } bootstrap_span_v1;

static void bootstrap_wipe_v1(uint8_t *data, uint32_t length) {
    volatile uint8_t *cursor = data;
    while (length-- != 0) *cursor++ = 0;
}

static int bootstrap_direct_v1(JNIEnv *env, jobject buffer, int writable, bootstrap_span_v1 *result) {
    if (buffer == NULL || (*env)->ExceptionCheck(env)) return 0;
    const jlong capacity = (*env)->GetDirectBufferCapacity(env, buffer);
    if ((*env)->ExceptionCheck(env) || capacity <= 0 || (uint64_t)capacity > UINT32_MAX) return 0;
    uint8_t *base = (*env)->GetDirectBufferAddress(env, buffer);
    if ((*env)->ExceptionCheck(env) || base == NULL) return 0;
    jclass type = (*env)->GetObjectClass(env, buffer);
    if (type == NULL || (*env)->ExceptionCheck(env)) return 0;
    jmethodID position_method = (*env)->GetMethodID(env, type, "position", "()I");
    if (position_method == NULL || (*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, type); return 0; }
    jmethodID limit_method = (*env)->GetMethodID(env, type, "limit", "()I");
    if (limit_method == NULL || (*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, type); return 0; }
    jmethodID readonly_method = (*env)->GetMethodID(env, type, "isReadOnly", "()Z");
    if (position_method == NULL || limit_method == NULL || readonly_method == NULL || (*env)->ExceptionCheck(env)) {
        (*env)->DeleteLocalRef(env, type); return 0;
    }
    const jint position = (*env)->CallIntMethod(env, buffer, position_method);
    if ((*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, type); return 0; }
    const jint limit = (*env)->CallIntMethod(env, buffer, limit_method);
    if ((*env)->ExceptionCheck(env)) { (*env)->DeleteLocalRef(env, type); return 0; }
    const jboolean readonly = (*env)->CallBooleanMethod(env, buffer, readonly_method);
    (*env)->DeleteLocalRef(env, type);
    if ((*env)->ExceptionCheck(env) || (writable && readonly) || position < 0 || limit <= position || limit > capacity) return 0;
    if ((uintptr_t)base > UINTPTR_MAX - (uintptr_t)limit) return 0;
    result->data = base + position;
    result->length = (uint32_t)(limit - position);
    return 1;
}

static int bootstrap_disjoint_v1(const bootstrap_span_v1 *spans, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        const uintptr_t start = (uintptr_t)spans[i].data;
        if (start > UINTPTR_MAX - spans[i].length) return 0;
        for (size_t j = 0; j < i; ++j)
            if (start < (uintptr_t)spans[j].data + spans[j].length &&
                (uintptr_t)spans[j].data < start + spans[i].length) return 0;
    }
    return 1;
}

static void bootstrap_u32_v1(uint8_t *out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24); out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8); out[3] = (uint8_t)value;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBootstrapLegacyBindingV1(
    JNIEnv *env, jobject self, jobject verify, jobject activation, jobject recipient,
    jobject private_key, jobject policy, jobject output) {
    (void)self;
    jobject objects[6] = {verify, activation, recipient, private_key, policy, output};
    bootstrap_span_v1 spans[6] = {{0}};
    for (size_t i = 0; i < 6; ++i)
        if (!bootstrap_direct_v1(env, objects[i], i == 5, &spans[i])) return (*env)->ExceptionCheck(env) ? 14 : 1;
    const uint32_t maxima[5] = {1405996, 1118299, 512, 128, 16777};
    for (size_t i = 0; i < 5; ++i) if (spans[i].length > maxima[i]) return 2;
    if (spans[5].length < 41) return 2;
    if (!bootstrap_disjoint_v1(spans, 6)) return 1;
    const int32_t status = kvpn_bootstrap_legacy_binding_v1(
        spans[0].data, spans[0].length, spans[1].data, spans[1].length,
        spans[2].data, spans[2].length, spans[3].data, spans[3].length,
        spans[4].data, spans[4].length, spans[5].data, spans[5].length);
    if (status != 0 || (*env)->ExceptionCheck(env)) {
        bootstrap_wipe_v1(spans[5].data, 41);
        return status == KVPN_BOOTSTRAP_CAPACITY_INVARIANT_V1 ? status : ((*env)->ExceptionCheck(env) ? 14 : status);
    }
    return 0;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBootstrapProductionBindingV1(
    JNIEnv *env, jobject self, jobject verify, jobject activation, jobject recipient,
    jobject private_key, jobject settings, jobject output, jobject active,
    jobject disconnected, jobject metadata) {
    (void)self;
    jobject objects[9] = {verify, activation, recipient, private_key, settings, output, active, disconnected, metadata};
    bootstrap_span_v1 spans[9] = {{0}};
    for (size_t i = 0; i < 9; ++i)
        if (!bootstrap_direct_v1(env, objects[i], i >= 5, &spans[i])) return (*env)->ExceptionCheck(env) ? 18 : 2;
    const uint32_t maxima[5] = {1405996, 1118299, 512, 128, 196608};
    for (size_t i = 0; i < 5; ++i) if (spans[i].length > maxima[i]) return 4;
    if (spans[5].length < 44 || spans[6].length < 512 || spans[7].length < 512 || spans[8].length != 8) return 4;
    if (!bootstrap_disjoint_v1(spans, 9)) return 2;
    bootstrap_wipe_v1(spans[8].data, 8);
    uint32_t active_written = 0, disconnected_written = 0;
    int32_t status = kvpn_bootstrap_production_binding_v1(
        spans[0].data, spans[0].length, spans[1].data, spans[1].length,
        spans[2].data, spans[2].length, spans[3].data, spans[3].length,
        spans[4].data, spans[4].length, spans[5].data, spans[5].length,
        spans[6].data, spans[6].length, &active_written,
        spans[7].data, spans[7].length, &disconnected_written);
    if ((*env)->ExceptionCheck(env) && status != KVPN_BOOTSTRAP_CAPACITY_INVARIANT_V1) status = 18;
    if (status == 0 && (active_written < 54 || active_written > 512 || disconnected_written < 54 || disconnected_written > 512)) status = 18;
    if (status != 0) {
        bootstrap_wipe_v1(spans[5].data, 44);
        bootstrap_wipe_v1(spans[6].data, 512); bootstrap_wipe_v1(spans[7].data, 512);
        return status;
    }
    /* Fixed lane placement is the role binding; KPA1 itself has no mode byte. */
    bootstrap_u32_v1(spans[8].data, active_written);
    bootstrap_u32_v1(spans[8].data + 4, disconnected_written);
    return 0;
}

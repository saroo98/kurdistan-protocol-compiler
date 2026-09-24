// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_ANDROID_PLATFORM_INTERNAL_V1
#error "The platform conformance driver is internal-only"
#endif
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include "kvpn_android_callbacks.h"
#include "kvpn_output_gate_v1.h"

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidPlatformConformanceV1_nativeCopyLayout(
        JNIEnv *env, jobject receiver, jlongArray output) {
    (void)receiver;
    if (!output || (*env)->GetArrayLength(env, output) != 12) return 1;
    jlong values[12] = {0};
    (*env)->SetLongArrayRegion(env, output, 0, 12, values);
    if ((*env)->ExceptionCheck(env)) return 25;
    if (!kvpn_android_table_valid_v1(kvpn_android_callbacks_table_v1())) return 25;
    uint64_t shared = 0, owner = 0, frames = 0;
    for (uint8_t kind = 1; kind <= 2; ++kind) {
        if (kvpn_output_layout_v1(kind, &shared, &owner, &frames)) return 25;
        unsigned base = (kind - 1u) * 3u;
        values[base] = (jlong)shared; values[base+1] = (jlong)owner; values[base+2] = (jlong)frames;
    }
    values[6] = sizeof(kvpn_android_callbacks_v1); values[7] = _Alignof(kvpn_android_callbacks_v1);
    values[8] = sizeof(kvpn_platform_borrow_v1); values[9] = _Alignof(kvpn_platform_borrow_v1);
    values[10] = sizeof(kvpn_cb_network_snapshot_v1); values[11] = sizeof(kvpn_cb_socket_expectation_v1);
    (*env)->SetLongArrayRegion(env, output, 0, 12, values);
    return (*env)->ExceptionCheck(env) ? 25 : 0;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidPlatformConformanceV1_nativeRejectUnownedCancellation(
        JNIEnv *env, jobject receiver) {
    (void)env; (void)receiver;
    return kvpn_android_callbacks_table_v1()->cancel_call(0, UINT64_MAX);
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidPlatformConformanceV1_nativeCopyCapture(
        JNIEnv *env, jobject receiver, jlong owner, jobject verify, jobject activation, jobject recipient,
        jobject private_recipient, jobject settings, jintArray written) {
    (void)receiver;
    if (!owner || !written || (*env)->GetArrayLength(env, written) != 5) return 1;
    jint lengths[5] = {0};
    (*env)->SetIntArrayRegion(env, written, 0, 5, lengths);
    if ((*env)->ExceptionCheck(env)) return 25;
    jobject buffers[5] = {verify, activation, recipient, private_recipient, settings};
    const uint32_t maxima[5] = {1405996, 1118299, 512, 128, 196608};
    kvpn_cb_capture_output_v1 output = {0};
    kvpn_cb_output_v1 *spans[5] = {&output.verify_request, &output.activation_record, &output.recipient_request,
        &output.recipient_private, &output.settings};
    for (unsigned i = 0; i < 5; ++i) {
        jlong capacity = buffers[i] ? (*env)->GetDirectBufferCapacity(env, buffers[i]) : -1;
        if (capacity <= 0 || capacity > maxima[i]) return 1;
        spans[i]->data = (*env)->GetDirectBufferAddress(env, buffers[i]);
        spans[i]->capacity = (uint32_t)capacity;
        if (!spans[i]->data || (*env)->ExceptionCheck(env)) return 1;
        uintptr_t start = (uintptr_t)spans[i]->data;
        if (start > UINTPTR_MAX - spans[i]->capacity) return 1;
        for (unsigned j = 0; j < i; ++j) {
            uintptr_t other = (uintptr_t)spans[j]->data;
            if (start < other + spans[j]->capacity && other < start + spans[i]->capacity) return 1;
        }
    }
    int32_t status = kvpn_android_callbacks_table_v1()->capture_copy_into((uint64_t)owner, &output);
    if (!status) {
        for (unsigned i = 0; i < 5; ++i) {
            if (spans[i]->written != spans[i]->capacity) status = 25;
            lengths[i] = (jint)spans[i]->written;
        }
        if (!status) (*env)->SetIntArrayRegion(env, written, 0, 5, lengths);
        if ((*env)->ExceptionCheck(env)) status = 25;
    }
    if (status) {
        for (unsigned i = 0; i < 5; ++i) memset(spans[i]->data, 0, spans[i]->capacity);
        memset(lengths, 0, sizeof(lengths));
        if (!(*env)->ExceptionCheck(env)) (*env)->SetIntArrayRegion(env, written, 0, 5, lengths);
    }
    return status;
}

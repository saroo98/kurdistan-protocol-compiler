// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include <jni.h>
#include <stdint.h>
#ifndef KVPN_ANDROID_PLATFORM_INTERNAL_V1
#error "Conformance JNI requires the explicit internal source guard"
#endif
#define KVPN_INVALID_ARGUMENT 1

int32_t kvpn_phase11_roundtrip(
    uint8_t *input,
    uint32_t input_length,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_runtime_session_roundtrip(
    uint64_t handle,
    uint8_t *input,
    uint32_t input_length,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);

static uint8_t *direct_buffer(JNIEnv *env, jobject buffer, jlong *capacity) {
    if (buffer == NULL || capacity == NULL) {
        return NULL;
    }
    *capacity = (*env)->GetDirectBufferCapacity(env, buffer);
    if (*capacity < 0 || *capacity > UINT32_MAX) {
        return NULL;
    }
    return (uint8_t *)(*env)->GetDirectBufferAddress(env, buffer);
}

static uint8_t *array_bytes(JNIEnv *env, jbyteArray array, jbyte **elements, uint32_t *length) {
    if (array == NULL) {
        *elements = NULL;
        *length = 0;
        return NULL;
    }
    jsize size = (*env)->GetArrayLength(env, array);
    if (size < 0) {
        return NULL;
    }
    *elements = (*env)->GetByteArrayElements(env, array, NULL);
    if (*elements == NULL && size != 0) {
        return NULL;
    }
    *length = (uint32_t)size;
    return (uint8_t *)*elements;
}

static void release_array(JNIEnv *env, jbyteArray array, jbyte *elements) {
    if (array != NULL && elements != NULL) {
        (*env)->ReleaseByteArrayElements(env, array, elements, JNI_ABORT);
    }
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_InternalConformanceBridge_nativePhase11RoundTrip(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (input == NULL || output_length == NULL ||
        (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *input_elements = NULL;
    uint32_t input_length = 0;
    uint8_t *input_bytes = array_bytes(env, input, &input_elements, &input_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (input_bytes == NULL || target == NULL) {
        release_array(env, input, input_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_phase11_roundtrip(
        input_bytes,
        input_length,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_InternalConformanceBridge_nativeRuntimeSessionRoundTrip(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jbyteArray input,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (input == NULL || output_length == NULL ||
        (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *input_elements = NULL;
    uint32_t input_length = 0;
    uint8_t *input_bytes = array_bytes(env, input, &input_elements, &input_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (input_bytes == NULL || target == NULL) {
        release_array(env, input, input_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_runtime_session_roundtrip(
        (uint64_t)handle,
        input_bytes,
        input_length,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

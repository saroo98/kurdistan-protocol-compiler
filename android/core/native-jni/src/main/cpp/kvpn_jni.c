// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "kvpn_abi.h"

#define KVPN_INVALID_ARGUMENT 1
#define KVPN_SIZE_LIMIT 2

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

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeAbiInfo(
    JNIEnv *env,
    jobject receiver,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (output_length == NULL || (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_abi_info(target, (uint32_t)capacity, &length);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeVerifyPreview(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (input == NULL || metadata == NULL || (*env)->GetArrayLength(env, metadata) != 2) {
        return KVPN_INVALID_ARGUMENT;
    }
    jsize input_length = (*env)->GetArrayLength(env, input);
    if (input_length <= 0) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *source = (*env)->GetByteArrayElements(env, input, NULL);
    if (source == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    uint32_t length = 0;
    int32_t code = kvpn_verify_preview(
        (uint8_t *)source,
        (uint32_t)input_length,
        &handle,
        target,
        (uint32_t)capacity,
        &length);
    (*env)->ReleaseByteArrayElements(env, input, source, JNI_ABORT);
    jlong values[2] = {(jlong)handle, (jlong)length};
    (*env)->SetLongArrayRegion(env, metadata, 0, 2, values);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationOpen(
    JNIEnv *env,
    jobject receiver,
    jlong verified,
    jlongArray output_handle) {
    (void)receiver;
    if (output_handle == NULL || (*env)->GetArrayLength(env, output_handle) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    int32_t code = kvpn_activation_open((uint64_t)verified, &handle);
    jlong value = (jlong)handle;
    (*env)->SetLongArrayRegion(env, output_handle, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationNext(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (metadata == NULL || (*env)->GetArrayLength(env, metadata) != 3) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t sequence = 0;
    uint32_t kind = 0;
    uint32_t length = 0;
    int32_t code = kvpn_activation_next(
        (uint64_t)handle,
        &sequence,
        &kind,
        target,
        (uint32_t)capacity,
        &length);
    jlong values[3] = {(jlong)sequence, (jlong)kind, (jlong)length};
    (*env)->SetLongArrayRegion(env, metadata, 0, 3, values);
    return code;
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
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientCreate(
    JNIEnv *env,
    jobject receiver,
    jint validity_seconds,
    jlongArray output_handle) {
    (void)receiver;
    if (validity_seconds <= 0 || output_handle == NULL ||
        (*env)->GetArrayLength(env, output_handle) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    int32_t code = kvpn_recipient_create((uint32_t)validity_seconds, &handle);
    if (code == 0) {
        jlong value = (jlong)handle;
        (*env)->SetLongArrayRegion(env, output_handle, 0, 1, &value);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientRequest(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (output_length == NULL || (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_recipient_request(
        (uint64_t)handle,
        target,
        (uint32_t)capacity,
        &length);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientPrivateExport(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (output_length == NULL || (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_recipient_private_export(
        (uint64_t)handle,
        target,
        (uint32_t)capacity,
        &length);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRecipientValidate(
    JNIEnv *env,
    jobject receiver,
    jbyteArray recipient_request,
    jbyteArray recipient_private) {
    (void)receiver;
    if (recipient_request == NULL || recipient_private == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *request_elements = NULL;
    jbyte *private_elements = NULL;
    uint32_t request_length = 0;
    uint32_t private_length = 0;
    uint8_t *request_bytes = array_bytes(env, recipient_request, &request_elements, &request_length);
    uint8_t *private_bytes = array_bytes(env, recipient_private, &private_elements, &private_length);
    if (request_bytes == NULL || private_bytes == NULL) {
        release_array(env, recipient_request, request_elements);
        release_array(env, recipient_private, private_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    int32_t code = kvpn_recipient_validate(
        request_bytes,
        request_length,
        private_bytes,
        private_length);
    release_array(env, recipient_request, request_elements);
    release_array(env, recipient_private, private_elements);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeVerifyPreviewWithRecipient(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jbyteArray recipient_request,
    jbyteArray recipient_private,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (input == NULL || recipient_request == NULL || recipient_private == NULL ||
        metadata == NULL || (*env)->GetArrayLength(env, metadata) != 2) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *input_elements = NULL;
    jbyte *request_elements = NULL;
    jbyte *private_elements = NULL;
    uint32_t input_length = 0;
    uint32_t request_length = 0;
    uint32_t private_length = 0;
    uint8_t *input_bytes = array_bytes(env, input, &input_elements, &input_length);
    uint8_t *request_bytes = array_bytes(env, recipient_request, &request_elements, &request_length);
    uint8_t *private_bytes = array_bytes(env, recipient_private, &private_elements, &private_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (input_bytes == NULL || request_bytes == NULL || private_bytes == NULL || target == NULL) {
        release_array(env, input, input_elements);
        release_array(env, recipient_request, request_elements);
        release_array(env, recipient_private, private_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    uint32_t length = 0;
    int32_t code = kvpn_verify_preview_with_recipient(
        input_bytes,
        input_length,
        request_bytes,
        request_length,
        private_bytes,
        private_length,
        &handle,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    release_array(env, recipient_request, request_elements);
    release_array(env, recipient_private, private_elements);
    if (code == 0) {
        jlong values[2] = {(jlong)handle, (jlong)length};
        (*env)->SetLongArrayRegion(env, metadata, 0, 2, values);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeActivationSubmit(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jlong sequence,
    jint kind,
    jboolean storage_ok,
    jbyteArray active,
    jbyteArray last_known_good,
    jbyteArray reopened) {
    (void)receiver;
    jbyte *active_elements = NULL;
    jbyte *last_elements = NULL;
    jbyte *reopened_elements = NULL;
    uint32_t active_length = 0;
    uint32_t last_length = 0;
    uint32_t reopened_length = 0;
    uint8_t *active_bytes = array_bytes(env, active, &active_elements, &active_length);
    uint8_t *last_bytes = array_bytes(env, last_known_good, &last_elements, &last_length);
    uint8_t *reopened_bytes = array_bytes(env, reopened, &reopened_elements, &reopened_length);
    if ((active != NULL && active_bytes == NULL && active_length != 0) ||
        (last_known_good != NULL && last_bytes == NULL && last_length != 0) ||
        (reopened != NULL && reopened_bytes == NULL && reopened_length != 0)) {
        release_array(env, active, active_elements);
        release_array(env, last_known_good, last_elements);
        release_array(env, reopened, reopened_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    int32_t code = kvpn_activation_submit(
        (uint64_t)handle,
        (uint64_t)sequence,
        (uint32_t)kind,
        storage_ok == JNI_TRUE ? 1 : 0,
        active_bytes,
        active_length,
        last_bytes,
        last_length,
        reopened_bytes,
        reopened_length);
    release_array(env, active, active_elements);
    release_array(env, last_known_good, last_elements);
    release_array(env, reopened, reopened_elements);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticPrepare(
    JNIEnv *env,
    jobject receiver,
    jbyteArray request,
    jlongArray output_handle) {
    (void)receiver;
    if (request == NULL || output_handle == NULL ||
        (*env)->GetArrayLength(env, output_handle) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *elements = NULL;
    uint32_t length = 0;
    uint8_t *bytes = array_bytes(env, request, &elements, &length);
    if (bytes == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    int32_t code = kvpn_diagnostic_prepare(bytes, length, &handle);
    release_array(env, request, elements);
    jlong value = (jlong)handle;
    (*env)->SetLongArrayRegion(env, output_handle, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticPreview(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (output_length == NULL || (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_diagnostic_preview(
        (uint64_t)handle,
        target,
        (uint32_t)capacity,
        &length);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticConfirm(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jboolean approved,
    jbyteArray preview) {
    (void)receiver;
    if (preview == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *elements = NULL;
    uint32_t length = 0;
    uint8_t *bytes = array_bytes(env, preview, &elements, &length);
    if (bytes == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    int32_t code = kvpn_diagnostic_confirm(
        (uint64_t)handle,
        approved == JNI_TRUE ? 1 : 0,
        bytes,
        length);
    release_array(env, preview, elements);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDiagnosticBuild(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (output_length == NULL || (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (target == NULL) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_diagnostic_build(
        (uint64_t)handle,
        target,
        (uint32_t)capacity,
        &length);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupCreate(
    JNIEnv *env,
    jobject receiver,
    jbyteArray payload,
    jbyteArray passphrase,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (payload == NULL || passphrase == NULL || output_length == NULL ||
        (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *payload_elements = NULL;
    jbyte *passphrase_elements = NULL;
    uint32_t payload_length = 0;
    uint32_t passphrase_length = 0;
    uint8_t *payload_bytes = array_bytes(env, payload, &payload_elements, &payload_length);
    uint8_t *passphrase_bytes = array_bytes(
        env,
        passphrase,
        &passphrase_elements,
        &passphrase_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (payload_bytes == NULL || passphrase_bytes == NULL || target == NULL) {
        release_array(env, payload, payload_elements);
        release_array(env, passphrase, passphrase_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_backup_create(
        payload_bytes,
        payload_length,
        passphrase_bytes,
        passphrase_length,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, payload, payload_elements);
    release_array(env, passphrase, passphrase_elements);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupOpenPreview(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jbyteArray passphrase,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (input == NULL || passphrase == NULL || metadata == NULL ||
        (*env)->GetArrayLength(env, metadata) != 2) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *input_elements = NULL;
    jbyte *passphrase_elements = NULL;
    uint32_t input_length = 0;
    uint32_t passphrase_length = 0;
    uint8_t *input_bytes = array_bytes(env, input, &input_elements, &input_length);
    uint8_t *passphrase_bytes = array_bytes(
        env,
        passphrase,
        &passphrase_elements,
        &passphrase_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (input_bytes == NULL || passphrase_bytes == NULL || target == NULL) {
        release_array(env, input, input_elements);
        release_array(env, passphrase, passphrase_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t handle = 0;
    uint32_t length = 0;
    int32_t code = kvpn_backup_open_preview(
        input_bytes,
        input_length,
        passphrase_bytes,
        passphrase_length,
        &handle,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    release_array(env, passphrase, passphrase_elements);
    jlong values[2] = {(jlong)handle, (jlong)length};
    (*env)->SetLongArrayRegion(env, metadata, 0, 2, values);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeBackupRestore(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jbyteArray preview,
    jobject output,
    jintArray output_length) {
    (void)receiver;
    if (preview == NULL || output_length == NULL ||
        (*env)->GetArrayLength(env, output_length) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    jbyte *preview_elements = NULL;
    uint32_t preview_length = 0;
    uint8_t *preview_bytes = array_bytes(env, preview, &preview_elements, &preview_length);
    jlong capacity = 0;
    uint8_t *target = direct_buffer(env, output, &capacity);
    if (preview_bytes == NULL || target == NULL) {
        release_array(env, preview, preview_elements);
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t length = 0;
    int32_t code = kvpn_backup_restore(
        (uint64_t)handle,
        preview_bytes,
        preview_length,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, preview, preview_elements);
    jint value = (jint)length;
    (*env)->SetIntArrayRegion(env, output_length, 0, 1, &value);
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativePhase11RoundTrip(
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
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionOpen(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (input == NULL || metadata == NULL ||
        (*env)->GetArrayLength(env, metadata) != 2) {
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
    uint64_t handle = 0;
    uint32_t length = 0;
    int32_t code = kvpn_runtime_session_open(
        input_bytes,
        input_length,
        &handle,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    if (code == 0) {
        jlong values[2] = {(jlong)handle, (jlong)length};
        (*env)->SetLongArrayRegion(env, metadata, 0, 2, values);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionRoundTrip(
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

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSessionOpenV2(
    JNIEnv *env,
    jobject receiver,
    jbyteArray input,
    jobject output,
    jlongArray metadata) {
    (void)receiver;
    if (input == NULL || metadata == NULL ||
        (*env)->GetArrayLength(env, metadata) != 2) {
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
    uint64_t handle = 0;
    uint32_t length = 0;
    int32_t code = kvpn_runtime_session_open_v2(
        input_bytes,
        input_length,
        &handle,
        target,
        (uint32_t)capacity,
        &length);
    release_array(env, input, input_elements);
    if (code == 0) {
        jlong values[2] = {(jlong)handle, (jlong)length};
        (*env)->SetLongArrayRegion(env, metadata, 0, 2, values);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSocketPrepare(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jintArray output_fd) {
    (void)receiver;
    if (output_fd == NULL || (*env)->GetArrayLength(env, output_fd) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    int32_t fd = -1;
    int32_t code = kvpn_runtime_socket_prepare((uint64_t)handle, &fd);
    if (code == 0) {
        jint value = (jint)fd;
        (*env)->SetIntArrayRegion(env, output_fd, 0, 1, &value);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeSocketCommitProtected(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jboolean protected_socket) {
    (void)env;
    (void)receiver;
    return kvpn_runtime_socket_commit_protected(
        (uint64_t)handle,
        protected_socket == JNI_TRUE ? 1 : 0);
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeTunAttach(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jint fd) {
    (void)env;
    (void)receiver;
    return kvpn_runtime_tun_attach((uint64_t)handle, (int32_t)fd);
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeStatus(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jintArray output_state) {
    (void)receiver;
    if (output_state == NULL || (*env)->GetArrayLength(env, output_state) != 1) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint32_t state = 0;
    int32_t code = kvpn_runtime_status((uint64_t)handle, &state);
    if (code == 0) {
        jint value = (jint)state;
        (*env)->SetIntArrayRegion(env, output_state, 0, 1, &value);
    }
    return code;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeDiagnostics(
    JNIEnv *env,
    jobject receiver,
    jlong handle,
    jlongArray output) {
    (void)receiver;
    const jsize output_count = 14;
    if (output == NULL || (*env)->GetArrayLength(env, output) != output_count) {
        return KVPN_INVALID_ARGUMENT;
    }
    uint64_t values[13] = {0};
    int32_t code = kvpn_runtime_diagnostics_v1((uint64_t)handle, values, 13);
    if (code != 0) {
        return code;
    }
    uint32_t rejection_code = 0;
    code = kvpn_runtime_rejection_code_v1((uint64_t)handle, &rejection_code);
    if (code != 0) {
        return code;
    }
    jlong converted[14] = {0};
    for (jsize index = 0; index < 13; index++) {
        if (values[index] > INT64_MAX) {
            return KVPN_SIZE_LIMIT;
        }
        converted[index] = (jlong)values[index];
    }
    converted[13] = (jlong)rejection_code;
    (*env)->SetLongArrayRegion(env, output, 0, output_count, converted);
    return (*env)->ExceptionCheck(env) ? KVPN_INVALID_ARGUMENT : 0;
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeRuntimeStop(
    JNIEnv *env,
    jobject receiver,
    jlong handle) {
    (void)env;
    (void)receiver;
    return kvpn_runtime_stop((uint64_t)handle);
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeCancel(
    JNIEnv *env,
    jobject receiver,
    jlong handle) {
    (void)env;
    (void)receiver;
    return kvpn_cancel((uint64_t)handle);
}

JNIEXPORT jint JNICALL
Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeFree(
    JNIEnv *env,
    jobject receiver,
    jlong handle) {
    (void)env;
    (void)receiver;
    return kvpn_free((uint64_t)handle);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return JNI_VERSION_1_6;
}

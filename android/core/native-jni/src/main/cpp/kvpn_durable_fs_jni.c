// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include <jni.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "kvpn_durable_fs.h"

static void wipe_free(uint8_t *bytes, size_t length) {
    if (bytes == NULL) return;
    volatile uint8_t *p = bytes;
    while (length-- != 0) *p++ = 0;
    free(bytes);
}

static int longs(JNIEnv *env, jlongArray array, size_t length, int64_t *out) {
    if (array == NULL || (*env)->GetArrayLength(env, array) != (jsize)length || length > 6) return 0;
    jlong values[6];
    (*env)->GetLongArrayRegion(env, array, 0, (jsize)length, values);
    if ((*env)->ExceptionCheck(env)) return 0;
    for (size_t i = 0; i < length; ++i) out[i] = values[i];
    return 1;
}

static int directory_arg(JNIEnv *env, jlongArray input, struct kvpn_fs_directory *d) {
    int64_t values[4];
    if (!longs(env, input, 4, values)) return 0;
    d->fd = values[0]; d->uid = values[1]; d->device = values[2]; d->inode = values[3];
    return kvpn_fs_valid_directory(d);
}

static int bytes_arg(JNIEnv *env, jbyteArray input, size_t limit, uint8_t **bytes, size_t *length, int optional) {
    *bytes = NULL;
    *length = 0;
    if (input == NULL) return optional;
    jsize size = (*env)->GetArrayLength(env, input);
    if (size < 0 || (uint64_t)size > limit) return 0;
    uint8_t *copy = malloc(size == 0 ? 1 : (size_t)size);
    if (copy == NULL) return 0;
    if (size != 0) (*env)->GetByteArrayRegion(env, input, 0, size, (jbyte *)copy);
    if ((*env)->ExceptionCheck(env)) { wipe_free(copy, (size_t)size); return 0; }
    *bytes = copy;
    *length = (size_t)size;
    return 1;
}

static int leaf_arg(JNIEnv *env, jbyteArray input, uint8_t **bytes, size_t *length) {
    return bytes_arg(env, input, KVPN_FS_MAX_LEAF, bytes, length, 0) && kvpn_fs_valid_leaf(*bytes, *length);
}

/* DurableRawResult snapshots constructor arguments. These local Java arrays
 * remain producer-owned and must be wiped even if construction throws. JNI
 * array operations require temporarily clearing and then restoring a pending
 * exception. A cleanup failure cannot return an apparently valid result. */
static int wipe_result_inputs(JNIEnv *env, jlongArray info, size_t count, jbyteArray data, size_t length) {
    jthrowable pending = (*env)->ExceptionOccurred(env);
    if (pending != NULL) (*env)->ExceptionClear(env);
    const jlong empty_info[7] = {0};
    const jbyte empty_data[1024] = {0};
    if (info != NULL && count != 0) (*env)->SetLongArrayRegion(env, info, 0, (jsize)count, empty_info);
    size_t offset = 0;
    while (data != NULL && offset < length && !(*env)->ExceptionCheck(env)) {
        size_t remaining = length - offset;
        size_t part = remaining < sizeof(empty_data) ? remaining : sizeof(empty_data);
        (*env)->SetByteArrayRegion(env, data, (jsize)offset, (jsize)part, empty_data);
        offset += part;
    }
    int clean = !(*env)->ExceptionCheck(env);
    if (pending != NULL) {
        if (!clean) (*env)->ExceptionClear(env);
        (*env)->Throw(env, pending);
        (*env)->DeleteLocalRef(env, pending);
    }
    return clean && pending == NULL;
}

/* Failed operations never have metadata or byte payloads. Only verified reads
 * and synchronization observations expose bytes. */
static jobject result(JNIEnv *env, int code, const int64_t *metadata, size_t count, const uint8_t *bytes, size_t length) {
    if ((*env)->ExceptionCheck(env)) return NULL;
    if (code != KVPN_FS_OK) { count = 0; bytes = NULL; length = 0; }
    if (count > 7 || length > KVPN_FS_MAX_BYTES) return NULL;
    jclass type = (*env)->FindClass(env, "org/kurdistanvpn/core/nativeapi/DurableRawResult");
    if (type == NULL) return NULL;
    jmethodID ctor = (*env)->GetMethodID(env, type, "<init>", "(I[J[B)V");
    if (ctor == NULL) { (*env)->DeleteLocalRef(env, type); return NULL; }
    jlongArray info = (*env)->NewLongArray(env, (jsize)count);
    if (info == NULL) { (*env)->DeleteLocalRef(env, type); return NULL; }
    if (count != 0) {
        jlong values[7];
        for (size_t i = 0; i < count; ++i) values[i] = metadata[i];
        (*env)->SetLongArrayRegion(env, info, 0, (jsize)count, values);
    }
    jbyteArray data = NULL;
    if (bytes != NULL && !(*env)->ExceptionCheck(env)) {
        data = (*env)->NewByteArray(env, (jsize)length);
        if (data != NULL && length != 0) (*env)->SetByteArrayRegion(env, data, 0, (jsize)length, (const jbyte *)bytes);
    }
    jobject value = NULL;
    if (!(*env)->ExceptionCheck(env)) value = (*env)->NewObject(env, type, ctor, (jint)code, info, data);
    if (!wipe_result_inputs(env, info, count, data, length)) {
        if (value != NULL) (*env)->DeleteLocalRef(env, value);
        value = NULL;
    }
    if (data != NULL) (*env)->DeleteLocalRef(env, data);
    (*env)->DeleteLocalRef(env, info);
    (*env)->DeleteLocalRef(env, type);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableRead(
    JNIEnv *env, jobject receiver, jlongArray input, jbyteArray name, jlong maximum) {
    (void)receiver;
    struct kvpn_fs_directory d;
    uint8_t *leaf = NULL, *output = NULL;
    size_t leaf_length = 0, length = 0;
    int64_t metadata[6] = {0};
    int code = KVPN_FS_INVALID;
    if (maximum > 0 && maximum <= KVPN_FS_MAX_BYTES && directory_arg(env, input, &d) &&
        leaf_arg(env, name, &leaf, &leaf_length)) {
        output = malloc((size_t)maximum);
        code = output == NULL ? KVPN_FS_IO : kvpn_fs_read(&d, leaf, leaf_length, (size_t)maximum, output, &length, metadata);
    }
    jobject value = result(env, code, metadata, 6, code == KVPN_FS_OK ? output : NULL, length);
    wipe_free(leaf, leaf_length);
    wipe_free(output, output == NULL ? 0 : (size_t)maximum);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativePrepareBorrowedPipe(
    JNIEnv *env, jobject receiver, jlong fd, jlong expected_uid, jint expected_access) {
    (void)receiver;
    int64_t metadata[6] = {0};
    int code = kvpn_pipe_prepare_borrowed(fd, expected_uid, expected_access, metadata);
    /* Even if Java result allocation throws, this borrowed FD is not ours to
     * close. Kotlin maps the ambiguous return to caller-owned cleanup. */
    return result(env, code, metadata, 6, NULL, 0);
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableOpenChild(
    JNIEnv *env, jobject receiver, jlongArray input, jbyteArray name, jlongArray expected) {
    (void)receiver;
    struct kvpn_fs_directory parent;
    uint8_t *leaf = NULL;
    size_t length = 0;
    int64_t identity[2] = {0}, metadata[6] = {0};
    int code = KVPN_FS_INVALID;
    if (directory_arg(env, input, &parent) && (expected == NULL || longs(env, expected, 2, identity)) &&
        leaf_arg(env, name, &leaf, &length))
        code = kvpn_fs_open_child_directory(&parent, leaf, length, expected == NULL ? NULL : identity, metadata);
    wipe_free(leaf, length);
    jobject value = result(env, code, metadata, 6, NULL, 0);
    if (value == NULL && code == KVPN_FS_OK) (void)kvpn_fs_close_directory(&metadata[0]);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableCreateChild(
    JNIEnv *env, jobject receiver, jlongArray input, jbyteArray name) {
    (void)receiver;
    struct kvpn_fs_directory parent;
    uint8_t *leaf = NULL;
    size_t length = 0;
    int64_t metadata[6] = {0};
    int code = KVPN_FS_INVALID;
    if (directory_arg(env, input, &parent) && leaf_arg(env, name, &leaf, &length))
        code = kvpn_fs_create_child_directory_exclusive(&parent, leaf, length, metadata);
    wipe_free(leaf, length);
    jobject value = result(env, code, metadata, 6, NULL, 0);
    if (value == NULL && code == KVPN_FS_OK) (void)kvpn_fs_close_directory(&metadata[0]);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableCloseDirectory(
    JNIEnv *env, jobject receiver, jlong handle) {
    (void)receiver;
    int64_t owned = handle;
    int code = kvpn_fs_close_directory(&owned);
    return result(env, code, NULL, 0, NULL, 0);
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableBootstrap(
    JNIEnv *env, jobject receiver, jlongArray input, jbyteArray name) {
    (void)receiver;
    struct kvpn_fs_directory d;
    uint8_t *leaf = NULL;
    size_t length = 0;
    int64_t metadata[6] = {0};
    int code = KVPN_FS_INVALID;
    if (directory_arg(env, input, &d) && leaf_arg(env, name, &leaf, &length)) code = kvpn_fs_bootstrap_lock(&d, leaf, length, metadata);
    wipe_free(leaf, length);
    return result(env, code, metadata, 6, NULL, 0);
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableList(
    JNIEnv *env, jobject receiver, jlongArray input, jlong maximum) {
    (void)receiver;
    struct kvpn_fs_directory d;
    uint8_t *output = NULL;
    size_t length = 0, capacity = 0;
    int64_t count = 0;
    int code = KVPN_FS_INVALID;
    if (maximum > 0 && maximum <= KVPN_FS_MAX_ENTRIES && directory_arg(env, input, &d)) {
        capacity = (size_t)maximum * KVPN_FS_ENTRY_BYTES;
        output = malloc(capacity);
        code = output == NULL ? KVPN_FS_IO : kvpn_fs_list(&d, (size_t)maximum, output, capacity, &length, &count);
    }
    jobject value = result(env, code, &count, 1, code == KVPN_FS_OK ? output : NULL, length);
    wipe_free(output, capacity);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableOpen(
    JNIEnv *env, jobject receiver, jlongArray input, jbyteArray name, jlongArray lock) {
    (void)receiver;
    struct kvpn_fs_directory d;
    uint8_t *leaf = NULL;
    size_t length = 0;
    int64_t identity[2] = {0}, session[2] = {-1, -1};
    int code = KVPN_FS_INVALID;
    if (directory_arg(env, input, &d) && longs(env, lock, 2, identity) && leaf_arg(env, name, &leaf, &length))
        code = kvpn_fs_open_writer(&d, leaf, length, identity, session);
    wipe_free(leaf, length);
    jobject value = result(env, code, session, 2, NULL, 0);
    /* JNI allocation failure cannot abandon a live flock/session. */
    if (value == NULL && code == KVPN_FS_OK) (void)kvpn_fs_close(session);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableClose(
    JNIEnv *env, jobject receiver, jlongArray handles) {
    (void)receiver;
    int64_t session[2] = {-1, -1};
    int code = longs(env, handles, 2, session) ? kvpn_fs_close(session) : KVPN_FS_INVALID;
    return result(env, code, NULL, 0, NULL, 0);
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableMutate(
    JNIEnv *env, jobject receiver, jlongArray handles, jlongArray input, jbyteArray lock_name,
    jlongArray lock, jbyteArray name, jbyteArray temporary, jlongArray old_identity,
    jbyteArray old, jbyteArray replacement, jlong maximum) {
    (void)receiver;
    struct kvpn_fs_directory d;
    int64_t session[2] = {-1, -1}, lock_id[2] = {0}, expected_id[2] = {0};
    uint8_t *lock_leaf = NULL, *leaf = NULL, *temp = NULL, *expected = NULL, *next = NULL;
    size_t lock_length = 0, leaf_length = 0, temp_length = 0, expected_length = 0, next_length = 0;
    int code = KVPN_FS_INVALID;
    int owned = longs(env, handles, 2, session) && session[0] >= 0 && session[0] <= INT_MAX &&
        session[1] >= 0 && session[1] <= INT_MAX && session[0] != session[1];
    if (owned && maximum > 0 && maximum <= KVPN_FS_MAX_BYTES && directory_arg(env, input, &d) &&
        longs(env, lock, 2, lock_id) && leaf_arg(env, lock_name, &lock_leaf, &lock_length) &&
        leaf_arg(env, name, &leaf, &leaf_length) &&
        ((old_identity == NULL && old == NULL) || (old_identity != NULL && old != NULL && longs(env, old_identity, 2, expected_id))) &&
        bytes_arg(env, temporary, KVPN_FS_MAX_LEAF, &temp, &temp_length, 1) &&
        bytes_arg(env, old, (size_t)maximum, &expected, &expected_length, 1) &&
        bytes_arg(env, replacement, (size_t)maximum, &next, &next_length, 1)) {
        code = kvpn_fs_mutate(session, &d, lock_leaf, lock_length, lock_id, leaf, leaf_length,
            temp, temp_length, old_identity == NULL ? NULL : expected_id, expected, expected_length,
            next, next_length, replacement != NULL, (size_t)maximum);
    }
    wipe_free(lock_leaf, lock_length);
    wipe_free(leaf, leaf_length);
    wipe_free(temp, temp_length);
    wipe_free(expected, expected_length);
    wipe_free(next, next_length);
    return result(env, code, NULL, 0, NULL, 0);
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableSyncExisting(
    JNIEnv *env, jobject receiver, jlongArray handles, jlongArray input, jbyteArray lock_name,
    jlongArray lock, jbyteArray name, jlongArray old_identity, jbyteArray old, jlong maximum) {
    (void)receiver;
    struct kvpn_fs_directory d;
    int64_t session[2] = {-1, -1}, lock_id[2] = {0}, expected_id[2] = {0}, metadata[6] = {0};
    uint8_t *lock_leaf = NULL, *leaf = NULL, *expected = NULL, *output = NULL;
    size_t lock_length = 0, leaf_length = 0, expected_length = 0, length = 0, capacity = 0;
    int code = KVPN_FS_INVALID;
    int owned = longs(env, handles, 2, session) && session[0] >= 0 && session[0] <= INT_MAX &&
        session[1] >= 0 && session[1] <= INT_MAX && session[0] != session[1];
    if (owned && maximum > 0 && maximum <= KVPN_FS_MAX_BYTES && directory_arg(env, input, &d) &&
        longs(env, lock, 2, lock_id) && longs(env, old_identity, 2, expected_id) &&
        leaf_arg(env, lock_name, &lock_leaf, &lock_length) && leaf_arg(env, name, &leaf, &leaf_length) &&
        bytes_arg(env, old, (size_t)maximum, &expected, &expected_length, 0)) {
        capacity = (size_t)maximum;
        output = malloc(capacity);
        code = output == NULL ? KVPN_FS_IO : kvpn_fs_sync_existing(session, &d, lock_leaf, lock_length, lock_id,
            leaf, leaf_length, expected_id, expected, expected_length, capacity, output, &length, metadata);
    }
    jobject value = result(env, code, metadata, 6, code == KVPN_FS_OK ? output : NULL, length);
    wipe_free(lock_leaf, lock_length);
    wipe_free(leaf, leaf_length);
    wipe_free(expected, expected_length);
    wipe_free(output, capacity);
    return value;
}

JNIEXPORT jobject JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeDurableRestrictExisting(
    JNIEnv *env, jobject receiver, jlongArray handles, jlongArray input, jbyteArray lock_name,
    jlongArray lock, jbyteArray name, jlong maximum) {
    (void)receiver;
    struct kvpn_fs_directory d;
    int64_t session[2] = {-1, -1}, lock_id[2] = {0}, metadata[7] = {0};
    uint8_t *lock_leaf = NULL, *leaf = NULL, *before = NULL, *output = NULL;
    size_t lock_length = 0, leaf_length = 0, length = 0, capacity = 0;
    int code = KVPN_FS_INVALID;
    int owned = longs(env, handles, 2, session) && session[0] >= 0 && session[0] <= INT_MAX &&
        session[1] >= 0 && session[1] <= INT_MAX && session[0] != session[1];
    if (owned && maximum > 0 && maximum <= KVPN_FS_MAX_BYTES && directory_arg(env, input, &d) &&
        longs(env, lock, 2, lock_id) && leaf_arg(env, lock_name, &lock_leaf, &lock_length) &&
        leaf_arg(env, name, &leaf, &leaf_length)) {
        capacity = (size_t)maximum;
        before = malloc(capacity);
        output = malloc(capacity);
        code = before == NULL || output == NULL ? KVPN_FS_IO : kvpn_fs_restrict_existing(session, &d,
            lock_leaf, lock_length, lock_id, leaf, leaf_length, capacity, before, output, &length, metadata);
    }
    jobject value = result(env, code, metadata, 7, code == KVPN_FS_OK ? output : NULL, length);
    wipe_free(lock_leaf, lock_length);
    wipe_free(leaf, leaf_length);
    wipe_free(before, capacity);
    wipe_free(output, capacity);
    return value;
}

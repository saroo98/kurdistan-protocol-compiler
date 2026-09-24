// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
/* The production helpers run against a deliberately small JNI environment
 * double. This tests adapter decisions/exception ordering, not VM execution. */
#include "kvpn_production_jni_v1.h"
#include "kvpn_abi.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { uint8_t *data; jlong capacity; jint position, limit; jboolean readonly, heap; } buffer;
typedef struct { jlong data[2]; jsize length; } metadata;
static int position_method, limit_method, readonly_method, class_marker;
static int refs, fail_method, fail_set;
static int set_call, fail_set_at;
static jboolean pending;
#ifdef KVPN_JNI_HOST_INTEGRATION_V1
#include <pthread.h>
static pthread_mutex_t copy_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t copy_condition = PTHREAD_COND_INITIALIZER;
static int copy_armed, copy_entered, copy_released;
void kvpn_test_jni_copy_arm_v1(void) {
    pthread_mutex_lock(&copy_mutex);
    assert(!copy_armed); copy_armed = 1; copy_entered = copy_released = 0;
    pthread_mutex_unlock(&copy_mutex);
}
int32_t kvpn_test_jni_copy_entered_v1(void) {
    pthread_mutex_lock(&copy_mutex); int32_t result = copy_entered;
    pthread_mutex_unlock(&copy_mutex); return result;
}
void kvpn_test_jni_copy_release_v1(void) {
    pthread_mutex_lock(&copy_mutex); copy_released = 1;
    pthread_cond_broadcast(&copy_condition); pthread_mutex_unlock(&copy_mutex);
}
static void hold_committed_copy_v1(jsize count, const jlong *values) {
    pthread_mutex_lock(&copy_mutex);
    if (copy_armed && count == 1 && values[0] == 21) {
        copy_entered = 1; pthread_cond_broadcast(&copy_condition);
        while (!copy_released) pthread_cond_wait(&copy_condition, &copy_mutex);
        copy_armed = 0;
    }
    pthread_mutex_unlock(&copy_mutex);
}
#endif
static jlong capacity(JNIEnv *e, jobject o) { (void)e; buffer *b = o; return b->heap ? -1 : b->capacity; }
static void *address(JNIEnv *e, jobject o) { (void)e; return ((buffer *)o)->data; }
static jclass object_class(JNIEnv *e, jobject o) { (void)e; (void)o; ++refs; return (jclass)&class_marker; }
static void delete_ref(JNIEnv *e, jobject o) { (void)e; assert(o == (jobject)&class_marker); --refs; }
static jmethodID method(JNIEnv *e, jclass c, const char *name, const char *signature) {
    (void)e; (void)c; (void)signature;
    if (fail_method) { pending = 1; return NULL; }
    if (!strcmp(name, "position")) return (jmethodID)&position_method;
    if (!strcmp(name, "limit")) return (jmethodID)&limit_method;
    assert(!strcmp(name, "isReadOnly")); return (jmethodID)&readonly_method;
}
static jint call_int(JNIEnv *e, jobject o, jmethodID m, ...) {
    (void)e; buffer *b = o;
    assert(m == (jmethodID)&position_method || m == (jmethodID)&limit_method);
    return m == (jmethodID)&position_method ? b->position : b->limit;
}
static jboolean call_bool(JNIEnv *e, jobject o, jmethodID m, ...) {
    (void)e; assert(m == (jmethodID)&readonly_method); return ((buffer *)o)->readonly;
}
static jboolean exception(JNIEnv *e) { (void)e; return pending; }
static void clear_exception(JNIEnv *e) { (void)e; pending = 0; }
static jsize array_length(JNIEnv *e, jarray o) { (void)e; return ((metadata *)o)->length; }
static void set_longs(JNIEnv *e, jlongArray o, jsize start, jsize count, const jlong *values) {
    (void)e; metadata *m = (metadata *)o; assert(start == 0 && count <= m->length);
    ++set_call;
#ifdef KVPN_JNI_HOST_INTEGRATION_V1
    hold_committed_copy_v1(count, values);
#endif
    if (fail_set || (fail_set_at && set_call == fail_set_at)) { if (fail_set) --fail_set; m->data[0] = values[0]; pending = 1; return; }
    memcpy(m->data, values, (size_t)count * sizeof(jlong));
}
static const struct JNINativeInterface functions = {
    .GetDirectBufferCapacity = capacity, .GetDirectBufferAddress = address,
    .GetObjectClass = object_class, .DeleteLocalRef = delete_ref, .GetMethodID = method,
    .CallIntMethod = call_int, .CallBooleanMethod = call_bool,
    .ExceptionCheck = exception, .ExceptionClear = clear_exception,
    .GetArrayLength = array_length, .SetLongArrayRegion = set_longs,
};

#ifdef KVPN_JNI_HOST_INTEGRATION_V1
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenV1(
    JNIEnv *, jobject, jobject, jint, jint, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCancelV1(JNIEnv *, jobject, jlong);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceOpenV1(JNIEnv *, jobject, jobject, jint, jint, jlong, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCheckUpdateV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceMaterializeV1(JNIEnv *, jobject, jlong, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceReleaseUpdateV1(JNIEnv *, jobject, jlong, jlong);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceRunProbeV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jobject, jint, jint, jlongArray);
int32_t kvpn_test_jni_maintenance_materialize_v1(uint64_t parent, uint64_t child, uint8_t *bytes, uint32_t length, int32_t failure, uint32_t *written) {
    JNIEnv env = &functions;
    buffer output = {bytes, length, 0, (jint)length, 0, 0};
    metadata values = {{99,99},1};
    set_call = 0; fail_set_at = failure ? 2 : 0;
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceMaterializeV1(
        &env, NULL, (jlong)parent, (jlong)child, (jobject)&output, 0, (jint)length, (jlongArray)&values);
    *written = (uint32_t)values.data[0]; fail_set_at = 0;
    assert(!pending && !refs && output.position == 0 && output.limit == (jint)length);
    return status;
}
void kvpn_test_jni_maintenance_remaining_v1(uint64_t parent) {
    JNIEnv env = &functions;
    uint8_t input[9] = {1,0,1,1,3,232,3,232,1}, bytes[48]; memset(bytes, 0xa5, sizeof(bytes));
    buffer request = {input, 9, 0, 9, 1, 0}, output = {bytes, 48, 7, 45, 0, 0};
    metadata values = {{99,99},1};
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceMaterializeV1(
        &env, NULL, (jlong)parent, 1, (jobject)&output, 7, 45, (jlongArray)&values) == 3 && !values.data[0]);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceReleaseUpdateV1(&env, NULL, (jlong)parent, 1) == 3);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceRunProbeV1(
        &env, NULL, (jlong)parent, (jobject)&request, 0, 9, (jobject)&output, 7, 45, (jlongArray)&values) == 1 && !values.data[0]);
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
    assert(!pending && !refs && output.position == 7 && output.limit == 45);
}
int32_t kvpn_test_jni_maintenance_probe_v1(uint64_t parent, uint8_t *input, uint8_t *bytes, uint32_t *written) {
    JNIEnv env = &functions;
    buffer request = {input, 9, 0, 9, 1, 0}, output = {bytes, 21, 0, 21, 0, 0};
    metadata values = {{99,99},1};
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceRunProbeV1(
        &env, NULL, (jlong)parent, (jobject)&request, 0, 9, (jobject)&output, 0, 21, (jlongArray)&values);
    *written = (uint32_t)values.data[0];
    assert(!pending && !refs && output.position == 0 && output.limit == 21 && request.position == 0 && request.limit == 9);
    return status;
}
int32_t kvpn_test_jni_maintenance_update_v1(uint64_t parent, uint8_t *bytes, int32_t failure, uint32_t *written) {
    JNIEnv env = &functions;
    uint8_t input[3] = {1,3,232};
    buffer request = {input, 3, 0, 3, 1, 0}, output = {bytes, 48, 7, 45, 0, 0};
    metadata values = {{99,99},1};
    set_call = 0; fail_set_at = failure ? 2 : 0;
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCheckUpdateV1(
        &env, NULL, (jlong)parent, (jobject)&request, 0, 3, (jobject)&output, 7, 45, (jlongArray)&values);
    assert(!pending && !refs && output.position == 7 && output.limit == 45);
    *written = (uint32_t)values.data[0]; fail_set_at = 0;
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCancelV1(JNIEnv *, jobject, jlong);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCloseV1(JNIEnv *, jobject, jlong);

int32_t kvpn_test_jni_maintenance_open_v1(uint8_t *input, uint32_t length, uint64_t lease, int32_t failure, uint64_t *parent) {
    JNIEnv env = &functions;
    buffer request = {input, length, 0, (jint)length, 1, 0};
    metadata values = {{99,99},1};
    set_call = 0; fail_set_at = failure ? 2 : 0;
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceOpenV1(
        &env, NULL, (jobject)&request, 0, (jint)length, (jlong)lease, (jlongArray)&values);
    assert(!pending && !refs && request.position == 0 && request.limit == (jint)length);
    *parent = (uint64_t)values.data[0]; fail_set_at = 0;
    return status;
}
int32_t kvpn_test_jni_maintenance_cancel_v1(uint64_t parent) {
    JNIEnv env = &functions;
    return Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCancelV1(&env, NULL, (jlong)parent);
}
int32_t kvpn_test_jni_maintenance_close_v1(uint64_t parent) {
    JNIEnv env = &functions;
    return Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeMaintenanceCloseV1(&env, NULL, (jlong)parent);
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCloseV1(JNIEnv *, jobject, jlong);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdSubmitPacketV1(JNIEnv *, jobject, jlong, jobject, jint, jint);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamSendV1(JNIEnv *, jobject, jlong, jlong, jobject, jint, jint);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdNextControlV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdReceivePacketV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenStreamV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamReceiveV1(JNIEnv *, jobject, jlong, jlong, jobject, jint, jint, jlongArray);
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdRunProbeV1(JNIEnv *, jobject, jlong, jobject, jint, jint, jobject, jint, jint, jlongArray);
int32_t kvpn_test_jni_prod_probe_v1(uint64_t parent, uint8_t *request, uint32_t length, uint8_t *bytes, uint32_t capacity_bytes, uint32_t *written) {
    JNIEnv env = &functions;
    buffer input = {request, length, 0, (jint)length, 1, 0}, output = {bytes, capacity_bytes, 0, (jint)capacity_bytes, 0, 0};
    metadata values = {{99,99},1};
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdRunProbeV1(&env, NULL, (jlong)parent,
        (jobject)&input, 0, (jint)length, (jobject)&output, 0, (jint)capacity_bytes, (jlongArray)&values);
    assert(input.position == 0 && input.limit == (jint)length && output.position == 0 && output.limit == (jint)capacity_bytes && !refs && !pending);
    *written = (uint32_t)values.data[0];
    return status;
}
int32_t kvpn_test_jni_prod_open_stream_v1(uint64_t parent, uint8_t *bytes, uint32_t length, uint64_t *child) {
    JNIEnv env = &functions;
    buffer input = {bytes, length, 0, (jint)length, 1, 0};
    metadata values = {{99,99},1};
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenStreamV1(&env, NULL,
        (jlong)parent, (jobject)&input, 0, (jint)length, (jlongArray)&values);
    assert(input.position == 0 && input.limit == (jint)length && !refs && !pending);
    *child = (uint64_t)values.data[0];
    return status;
}
int32_t kvpn_test_jni_stream_receive_v1(uint64_t parent, uint64_t child, uint8_t *bytes, uint32_t length, uint32_t *written, uint64_t *token) {
    JNIEnv env = &functions;
    buffer output = {bytes, length, 0, (jint)length, 0, 0};
    metadata values = {{99,99},2};
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamReceiveV1(&env, NULL,
        (jlong)parent, (jlong)child, (jobject)&output, 0, (jint)length, (jlongArray)&values);
    assert(output.position == 0 && output.limit == (jint)length && !refs && !pending);
    *written = (uint32_t)values.data[0]; *token = (uint64_t)values.data[1];
    return status;
}
int32_t kvpn_test_jni_prod_receive_packet_v1(uint64_t parent, uint8_t *bytes, uint32_t length, uint32_t *written, uint64_t *token, int32_t failure) {
    JNIEnv env = &functions;
    buffer output = {bytes, length, 0, (jint)length, 0, 0};
    metadata values = {{99,99},2};
    set_call = 0; fail_set_at = failure ? 2 : 0;
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdReceivePacketV1(&env, NULL,
        (jlong)parent, (jobject)&output, 0, (jint)length, (jlongArray)&values);
    assert(output.position == 0 && output.limit == (jint)length && !refs && !pending);
    *written = (uint32_t)values.data[0]; *token = (uint64_t)values.data[1];
    fail_set_at = 0;
    return status;
}
void kvpn_test_jni_prod_control_v1(uint64_t parent) {
    JNIEnv env = &functions;
    uint8_t bytes[100000]; memset(bytes, 0xa5, sizeof(bytes));
    uint32_t written = 99;
    assert(kvpn_prod_next_control_v1(parent, bytes + 10, 1, &written) == 4 && written == 0);
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
    buffer output = {bytes, sizeof(bytes), 7, 32810, 0, 0};
    metadata values = {{99,99},1};
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdNextControlV1(&env, NULL, (jlong)parent,
        (jobject)&output, 10, 11, (jlongArray)&values) == 4 && values.data[0] == 0);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdNextControlV1(&env, NULL, (jlong)parent,
        (jobject)&output, 10, 32810, (jlongArray)&values) == 0);
    assert(values.data[0] >= 32 && values.data[0] <= 32800 && !memcmp(bytes + 10, "KPC1", 4));
    for (size_t i = 0; i < 10; ++i) assert(bytes[i] == 0xa5);
    for (size_t i = 10 + (size_t)values.data[0]; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
    assert(output.position == 7 && output.limit == 32810 && !refs && !pending);
}
void kvpn_test_jni_prod_inputs_v1(uint64_t parent) {
    JNIEnv env = &functions;
    uint8_t bytes[100000]; memset(bytes, 0xa5, sizeof(bytes));
    buffer input = {bytes, sizeof(bytes), 7, 55, 1, 0};
    assert(kvpn_prod_submit_packet_v1(parent, bytes + 10, 1) == 3);
    assert(kvpn_stream_send_v1(parent, 1, bytes + 10, 1) == 3);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdSubmitPacketV1(&env, NULL, (jlong)parent, (jobject)&input, 10, 11) == 3);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamSendV1(&env, NULL, (jlong)parent, 1, (jobject)&input, 10, 11) == 3);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdSubmitPacketV1(&env, NULL, (jlong)parent, (jobject)&input, 6, 11) == 2);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamSendV1(&env, NULL, (jlong)parent, 1, (jobject)&input, 10, 56) == 2);
    assert(input.position == 7 && input.limit == 55 && !refs && !pending);
    input.position = 0; input.limit = sizeof(bytes);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdSubmitPacketV1(&env, NULL, (jlong)parent, (jobject)&input, 0, 65536) == 4);
    assert(Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeStreamSendV1(&env, NULL, (jlong)parent, 1, (jobject)&input, 0, 16385) == 4);
    assert(kvpn_prod_submit_packet_v1(parent, bytes, 0) == 2);
    assert(kvpn_stream_send_v1(parent, 1, bytes, 0) == 2);
    for (size_t i = 0; i < sizeof(bytes); ++i) assert(bytes[i] == 0xa5);
}
int32_t kvpn_test_jni_prod_open_v1(uint8_t *input, uint32_t length, uint64_t lease,
    uint8_t *output, uint32_t output_capacity, int32_t failure, uint64_t *parent, uint32_t *written) {
    JNIEnv env = &functions;
    /* Deliberately large foreign-arena capacity in this JNI double. Only the
     * allocated logical input/output slices are accessed by the real JNI. */
    buffer request = {input, failure ? length : UINT32_MAX, 0, (jint)length, 0, 0};
    buffer snapshot = {output, failure ? output_capacity : UINT32_MAX, 10, 32778, 0, 0};
    metadata values = {{99,99},2};
    set_call = 0; fail_set_at = failure ? 2 : 0;
    int32_t status = Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdOpenV1(
        &env, NULL, (jobject)&request, 0, (jint)length, (jlong)lease,
        (jobject)&snapshot, 10, 32778, (jlongArray)&values);
    assert(!pending && !refs && request.position == 0 && request.limit == (jint)length);
    assert(snapshot.position == 10 && snapshot.limit == 32778);
    *parent = (uint64_t)values.data[0]; *written = (uint32_t)values.data[1];
    fail_set_at = 0;
    return status;
}
int32_t kvpn_test_jni_prod_cancel_v1(uint64_t parent) {
    JNIEnv env = &functions;
    return Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCancelV1(&env, NULL, (jlong)parent);
}
int32_t kvpn_test_jni_prod_close_v1(uint64_t parent) {
    JNIEnv env = &functions;
    return Java_org_kurdistanvpn_core_nativejni_NativeBridge_nativeProdCloseV1(&env, NULL, (jlong)parent);
}
#else
int main(void) {
    JNIEnv env = &functions;
    uint8_t arena[100000]; memset(arena, 0xa5, sizeof(arena));
    buffer b = {arena, sizeof(arena), 7, 55, 0, 0};
    kvpn_production_span_v1 span = {0}; uint64_t backing = 0;
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 1, 1, 9, &span, &backing) == 0);
    assert(span.data == arena + 10 && span.length == 9 && backing == 100000 && refs == 0);
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 20, 1, 1, 9, &span, &backing) == 4);
    assert(!span.data && !span.length && !backing);
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, -1, 19, 1, 1, 9, &span, &backing) == 2);
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 6, 10, 1, 1, 9, &span, &backing) == 2);
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 50, 56, 1, 1, 9, &span, &backing) == 2);
    b.readonly = 1;
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 1, 1, 9, &span, &backing) == 2);
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 0, 1, 9, &span, &backing) == 0);
    b.heap = 1;
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 0, 1, 9, &span, &backing) == 2);
    b.heap = 0; b.capacity = (jlong)UINT32_MAX + 1;
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 0, 1, 9, &span, &backing) == 2);
    b.capacity = sizeof(arena);
    assert(kvpn_production_jni_span_v1(&env, NULL, 10, 19, 0, 1, 9, &span, &backing) == 2);
    fail_method = 1;
    assert(kvpn_production_jni_span_v1(&env, (jobject)&b, 10, 19, 0, 1, 9, &span, &backing) == 18);
    assert(!pending && refs == 0); fail_method = 0;
    for (size_t i = 0; i < sizeof(arena); ++i) assert(arena[i] == 0xa5);
    assert(b.position == 7 && b.limit == 55);
    metadata m = {{99,99},1};
    assert(kvpn_production_jni_metadata_v1(&env, (jlongArray)&m, 2) == 2 && m.data[0] == 99);
    m.length = 2;
    assert(kvpn_production_jni_metadata_v1(&env, (jlongArray)&m, 2) == 0 && !m.data[0] && !m.data[1]);
    jlong values[2] = {INT64_MIN,235};
    assert(kvpn_production_jni_write_v1(&env, (jlongArray)&m, 2, values) == 0 && m.data[0] == INT64_MIN);
    fail_set = 1;
    assert(kvpn_production_jni_write_v1(&env, (jlongArray)&m, 2, values) == 18);
    assert(!pending && !m.data[0] && !m.data[1]);
    puts("JNI helper double: bounded arena, NIO state, readonly/heap/overflow, metadata reset and exception cleanup PASS");
    return 0;
}
#endif

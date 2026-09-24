// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_android_callbacks.h"
#include "kvpn_output_gate_v1.h"
#include "kvpn_production_jni_v1.h"
#include "production_scoped_exports_v1.h"
#include <jni.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#ifdef KVPN_ANDROID_PLATFORM_INTERNAL_V1
void kvpn_task7_rejection_v1(uint8_t, uint8_t, int32_t);
#define TASK7_REVISION_REJECTION(p,s) kvpn_task7_rejection_v1(1,(p),(s))
#else
#define TASK7_REVISION_REJECTION(p,s) ((void)0)
#endif

static _Atomic(JavaVM *) java_vm;
static const char *const method_names[20] = {
    "captureSizes",
    "captureCopyInto",
    "productionCurrentRegister",
    "maintenanceCurrentRegister",
    "revisionRevalidate",
    "publicationAcquire",
    "publicationIsCurrent",
    "publicationClose",
    "revisionClose",
    "socketRegister",
    "socketConfirm",
    "socketClose",
    "maintenanceNetworkAcquire",
    "maintenanceNetworkSnapshot",
    "maintenanceNetworkIsCurrent",
    "maintenanceNetworkBindSocket",
    "maintenanceNetworkClose",
    "systemRootsInto",
    "cancelCall",
    "ownerClose"
};
static const char *const method_descriptors[20] = {
    "(J[I)I",
    "(JLjava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;[I)I",
    "(JJJ[J)I",
    "(JJJ[J)I",
    "(JJJ)I",
    "(JJJ[J)I",
    "(JJJ[I)I",
    "(JJJ)I",
    "(JJ)I",
    "(JJJJJIIIJJ[J[I)I",
    "(JJIIJ)I",
    "(JJ)I",
    "(JJJ[J)I",
    "(JJLjava/nio/ByteBuffer;[I)I",
    "(JJ[I)I",
    "(JJI)I",
    "(JJ)I",
    "(JJLjava/nio/ByteBuffer;[I)I",
    "(JJ)I",
    "(J)I"
};
typedef kvpn_android_java_call_v1 java_call;
static jlong jbits(uint64_t value) {
    jlong result;
    memcpy(&result, &value, sizeof(result));
    return result;
}
static void exception(java_call *call) {
    if (call->env && (*call->env)->ExceptionCheck(call->env)) {
        (*call->env)->ExceptionClear(call->env);
        call->failed = 1;
    }
}
static int attach_call(java_call *call) {
    call->vm = atomic_load(&java_vm);
    if (!call->vm) { call->failed = 1; return 0; }
    jint status = (*call->vm)->GetEnv(call->vm, (void **)&call->env, JNI_VERSION_1_6);
    if (status == JNI_EDETACHED) {
        if ((*call->vm)->AttachCurrentThread(call->vm, &call->env, NULL) != JNI_OK) {
            call->env = NULL; call->failed = 1; return 0;
        }
        call->attached = 1;
    } else if (status != JNI_OK) { call->env = NULL; call->failed = 1; return 0; }
    if ((*call->env)->PushLocalFrame(call->env, 16) != JNI_OK) {
        exception(call); call->failed = 1; return 0;
    }
    call->pushed = 1;
    return 1;
}
static int begin(java_call *call, uint64_t owner, uint8_t method, uint64_t context) {
    memset(call, 0, sizeof(*call));
    if (kvpn_platform_enter_v1(owner, method, context, &call->borrow)) return 0;
    return attach_call(call);
}
static int32_t finish(java_call *call, int32_t status, int32_t maximum, int32_t failure) {
    exception(call);
    if (status < 0 || status > maximum) call->failed = 1;
    if (call->pushed) {
        (*call->env)->PopLocalFrame(call->env, NULL);
        exception(call);
    }
    if (call->attached && (*call->vm)->DetachCurrentThread(call->vm) != JNI_OK) call->failed = 1;
    if (call->borrow.owner && kvpn_platform_leave_v1(&call->borrow, call->failed)) call->failed = 1;
    return call->failed ? failure : status;
}
static jintArray ints(java_call *call, jsize length) {
    jintArray result = (*call->env)->NewIntArray(call->env, length);
    exception(call);
    if (!result) call->failed = 1;
    return result;
}
static jlongArray longs(java_call *call) {
    jlongArray result = (*call->env)->NewLongArray(call->env, 1);
    exception(call);
    if (!result) call->failed = 1;
    return result;
}
static jobject buffer(java_call *call, kvpn_cb_output_v1 *span) {
    if (!span || !span->data || !span->capacity) { call->failed = 1; return NULL; }
    jobject result = (*call->env)->NewDirectByteBuffer(call->env, span->data, span->capacity);
    exception(call);
    if (!result) call->failed = 1;
    return result;
}
static uint64_t acquired(java_call *call, jlongArray array, uint8_t kind) {
    jlong value = 0;
    exception(call);
    if (array) (*call->env)->GetLongArrayRegion(call->env, array, 0, 1, &value);
    exception(call);
    uint64_t id = (uint64_t)value;
    if (id && kvpn_platform_child_adopt_v1(call->borrow.owner, kind, id)) call->failed = 1;
    return id;
}
static int32_t java_capture_sizes(uint64_t owner, kvpn_cb_capture_sizes_v1 *out) {
    if (!out) return 1;
    memset(out, 0, sizeof(*out));
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, 0, 0)) {
        jintArray values = ints(&call, 5);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method, jbits(owner), values);
            exception(&call);
            jint n[5] = {0};
            (*call.env)->GetIntArrayRegion(call.env, values, 0, 5, n);
            exception(&call);
            const jint bounds[5] = {1405996, 1118299, 512, 128, 196608};
            for (unsigned i = 0; i < 5; ++i) if (n[i] <= 0 || n[i] > bounds[i]) call.failed = 1;
            if (!call.failed) {
                out->verify_request = (uint32_t)n[0]; out->activation_record = (uint32_t)n[1];
                out->recipient_request = (uint32_t)n[2]; out->recipient_private = (uint32_t)n[3];
                out->settings = (uint32_t)n[4];
            }
        }
    }
    int32_t result = finish(&call, status, 25, 14);
    if (result) memset(out, 0, sizeof(*out));
    return result;
}
static int32_t java_capture_copy_into(uint64_t owner, kvpn_cb_capture_output_v1 *out) {
    if (!out) return 1;
    kvpn_cb_output_v1 *rows[5] = {&out->verify_request, &out->activation_record,
        &out->recipient_request, &out->recipient_private, &out->settings};
    const uint32_t bounds[5] = {1405996, 1118299, 512, 128, 196608};
    for (unsigned i = 0; i < 5; ++i) rows[i]->written = 0;
    for (unsigned i = 0; i < 5; ++i)
        if (!rows[i]->data || !rows[i]->capacity || rows[i]->capacity > bounds[i]) return 1;
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, 1, 0)) {
        jobject spans[5] = {0};
        for (unsigned i = 0; i < 5 && !call.failed; ++i) spans[i] = buffer(&call, rows[i]);
        jintArray written = !call.failed ? ints(&call, 5) : NULL;
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), spans[0], spans[1], spans[2], spans[3], spans[4], written);
            exception(&call);
            jint n[5] = {0};
            (*call.env)->GetIntArrayRegion(call.env, written, 0, 5, n);
            exception(&call);
            for (unsigned i = 0; i < 5; ++i) {
                if (n[i] < 0 || (uint32_t)n[i] != rows[i]->capacity) call.failed = 1;
                else rows[i]->written = (uint32_t)n[i];
            }
        }
    }
    int32_t result = finish(&call, status, 25, 14);
    if (result) for (unsigned i = 0; i < 5; ++i) rows[i]->written = 0;
    return result;
}

static int32_t register_current(uint64_t owner, uint64_t epoch, uint64_t signal, uint64_t *out, uint8_t method) {
    if (!out) return 1;
    *out = 0;
    if (!epoch || !signal || kvpn_platform_signal_install_v1(owner, 1, signal)) return 25;
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, method, 0)) {
        jlongArray result = longs(&call);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(epoch), jbits(signal), result);
            *out = acquired(&call, result, 1);
            if (!status && !*out) call.failed = 1;
        }
    }
    return finish(&call, status, 25, 14);
}
static int32_t java_production_current_register(uint64_t o, uint64_t e, uint64_t s, uint64_t *out) {
    return register_current(o, e, s, out, 2);
}
static int32_t java_maintenance_current_register(uint64_t o, uint64_t e, uint64_t s, uint64_t *out) {
    return register_current(o, e, s, out, 3);
}
static int32_t java_revision_revalidate(uint64_t owner, uint64_t revision, uint64_t context) {
    if (!context || !kvpn_platform_child_matches_v1(owner, 1, revision)) { TASK7_REVISION_REJECTION(1,4); return 4; }
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 4, context)) {
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
            jbits(owner), jbits(revision), jbits(context));
        TASK7_REVISION_REJECTION(3,status);
    } else { TASK7_REVISION_REJECTION(2,status); }
    status = finish(&call, status, 23, 23);
    TASK7_REVISION_REJECTION(4,status);
    return status;
}
static int32_t java_publication_acquire(uint64_t owner, uint64_t revision, uint64_t context, uint64_t *out) {
    if (!out) { TASK7_REVISION_REJECTION(8,3); return 3; }
    *out = 0;
    if (!context || !kvpn_platform_child_matches_v1(owner, 1, revision)) { TASK7_REVISION_REJECTION(8,4); return 4; }
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 5, context)) {
        jlongArray result = longs(&call);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(revision), jbits(context), result);
            TASK7_REVISION_REJECTION(9,status);
            *out = acquired(&call, result, 2);
            if (!status && !*out) call.failed = 1;
        }
    } else { TASK7_REVISION_REJECTION(8,status); }
    status = finish(&call, status, 23, 23);
    TASK7_REVISION_REJECTION(10,status);
    return status;
}
static int32_t java_publication_is_current(uint64_t owner, uint64_t revision, uint64_t publication, uint8_t *out) {
    if (!out) { TASK7_REVISION_REJECTION(11,1); return 1; }
    *out = 0;
    if (!kvpn_platform_child_matches_v1(owner, 1, revision) ||
        !kvpn_platform_child_matches_v1(owner, 2, publication)) { TASK7_REVISION_REJECTION(11,25); return 25; }
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, 6, 0)) {
        jintArray result = ints(&call, 1);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(revision), jbits(publication), result);
            exception(&call);
            jint value = 0;
            (*call.env)->GetIntArrayRegion(call.env, result, 0, 1, &value);
            exception(&call);
            if (value != 0 && value != 1) call.failed = 1;
            else *out = (uint8_t)value;
        }
    }
    int32_t result = finish(&call, status, 25, 14);
    TASK7_REVISION_REJECTION(11,result);
    if (result) *out = 0;
    else if (!*out) { TASK7_REVISION_REJECTION(12,1); }
    return result;
}
static int32_t java_publication_close(uint64_t owner, uint64_t revision, uint64_t publication) {
    if (!kvpn_platform_child_matches_v1(owner, 1, revision) ||
        !kvpn_platform_child_matches_v1(owner, 2, publication)) { TASK7_REVISION_REJECTION(13,25); return 25; }
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, 7, 0)) {
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
            jbits(owner), jbits(revision), jbits(publication));
        TASK7_REVISION_REJECTION(14,status);
    } else { TASK7_REVISION_REJECTION(13,status); }
    int32_t result = finish(&call, status, 25, 14);
    TASK7_REVISION_REJECTION(15,result);
    if (kvpn_platform_child_retire_v1(owner, 2, publication, result)) return 25;
    return result;
}
static int32_t close_child(uint64_t owner, uint64_t child, uint8_t kind, uint8_t method, int32_t maximum, int32_t failure) {
    if (!kvpn_platform_child_matches_v1(owner, kind, child)) return failure;
    java_call call;
    int32_t status = failure;
    if (begin(&call, owner, method, 0)) {
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method, jbits(owner), jbits(child));
        if (method == 11) TASK7_REVISION_REJECTION(6,status);
    } else if (method == 11) TASK7_REVISION_REJECTION(5,status);
    int32_t result = finish(&call, status, maximum, failure);
    if (method == 11) TASK7_REVISION_REJECTION(7,result);
    if (kvpn_platform_child_retire_v1(owner, kind, child, result)) return failure;
    return result;
}
static int32_t java_revision_close(uint64_t o, uint64_t r) { return close_child(o, r, 1, 8, 25, 25); }
static int32_t java_socket_close(uint64_t o, uint64_t s) { return close_child(o, s, 3, 11, 26, 18); }
static int32_t java_maintenance_network_close(uint64_t o, uint64_t n) { return close_child(o, n, 4, 16, 25, 25); }

static int32_t java_socket_register(uint64_t owner, uint64_t context, const kvpn_cb_socket_expectation_v1 *e,
        uint64_t signal, uint64_t *out, uint8_t *binding) {
    if (out) *out = 0;
    if (binding) *binding = 0;
    if (!out || !binding || !e || !context || !e->parent_epoch || !e->attempt || !e->socket_token ||
        e->fd < 0 || e->selection_explicit > 1 || e->has_network > 1 ||
        (e->has_network ? !e->network : e->network != 0) || !signal) return 2;
    if (kvpn_platform_signal_install_v1(owner, 2, signal)) return 18;
    java_call call;
    int32_t status = 18;
    if (begin(&call, owner, 9, context)) {
        jlongArray result = longs(&call);
        jintArray required = !call.failed ? ints(&call, 1) : NULL;
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(context), jbits(e->parent_epoch), jbits(e->attempt), jbits(e->socket_token),
                (jint)e->fd, (jint)e->selection_explicit, (jint)e->has_network,
                jbits(e->network), jbits(signal), result, required);
            *out = acquired(&call, result, 3);
            jint value = 0;
            (*call.env)->GetIntArrayRegion(call.env, required, 0, 1, &value);
            exception(&call);
            if ((!status && !*out) || (value != 0 && value != 1)) call.failed = 1;
            else *binding = (uint8_t)value;
        }
    }
    int32_t result = finish(&call, status, 26, 18);
    if (result) *binding = 0;
    return result;
}
static int32_t java_socket_confirm(uint64_t owner, uint64_t socket, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    if (protected_ok > 1 || has_network > 1 || (has_network ? !network : network != 0)) return 2;
    if (!kvpn_platform_child_matches_v1(owner, 3, socket)) return 3;
    java_call call;
    int32_t status = 18;
    if (begin(&call, owner, 10, 0))
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
            jbits(owner), jbits(socket), (jint)protected_ok, (jint)has_network, jbits(network));
    return finish(&call, status, 26, 18);
}

static int32_t java_maintenance_network_acquire(uint64_t owner, uint64_t context, uint64_t signal, uint64_t *out) {
    if (!out) return 3;
    *out = 0;
    if (!context || !signal || kvpn_platform_signal_install_v1(owner, 3, signal)) return 4;
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 12, context)) {
        jlongArray result = longs(&call);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(context), jbits(signal), result);
            *out = acquired(&call, result, 4);
            if (!status && !*out) call.failed = 1;
        }
    }
    return finish(&call, status, 23, 23);
}
static int32_t java_maintenance_network_snapshot(uint64_t owner, uint64_t network, kvpn_cb_network_snapshot_v1 *out) {
    if (!out) return 3;
    memset(out, 0, sizeof(*out));
    if (!kvpn_platform_child_matches_v1(owner, 4, network)) return 4;
    java_call call;
    int32_t status = 23;
    uint8_t bytes[76] = {0};
    kvpn_cb_output_v1 span = {bytes, sizeof(bytes), 0};
    if (begin(&call, owner, 13, 0)) {
        jobject destination = buffer(&call, &span);
        jintArray metadata = !call.failed ? ints(&call, 3) : NULL;
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(network), destination, metadata);
            exception(&call);
            jint values[3] = {0};
            (*call.env)->GetIntArrayRegion(call.env, metadata, 0, 3, values);
            exception(&call);
            if (values[0] < 1 || values[0] > 2 || values[1] < 1 || values[1] > 3 ||
                values[2] < 1 || values[2] > 4) call.failed = 1;
            else {
                out->mode = (uint8_t)values[0]; out->families = (uint8_t)values[1]; out->dns_count = (uint8_t)values[2];
                for (unsigned i = 0; i < 4; ++i) {
                    const uint8_t *row = bytes + i * 19;
                    if (i >= out->dns_count) {
                        for (unsigned j = 0; j < 19; ++j) if (row[j]) call.failed = 1;
                    } else {
                        if ((row[0] != 4 && row[0] != 6) || row[17] != 0 || row[18] != 53) call.failed = 1;
                        if (row[0] == 4) for (unsigned j = 5; j < 17; ++j) if (row[j]) call.failed = 1;
                        out->dns[i].family = row[0];
                        memcpy(out->dns[i].address, row + 1, 16);
                        out->dns[i].port = 53;
                    }
                }
            }
        }
    }
    memset(bytes, 0, sizeof(bytes));
    int32_t result = finish(&call, status, 23, 23);
    if (result) memset(out, 0, sizeof(*out));
    return result;
}
static int32_t java_maintenance_network_is_current(uint64_t owner, uint64_t network, uint8_t *out) {
    if (!out) return 3;
    *out = 0;
    if (!kvpn_platform_child_matches_v1(owner, 4, network)) return 4;
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 14, 0)) {
        jintArray result = ints(&call, 1);
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(network), result);
            exception(&call);
            jint value = 0;
            (*call.env)->GetIntArrayRegion(call.env, result, 0, 1, &value);
            exception(&call);
            if (value != 0 && value != 1) call.failed = 1;
            else *out = (uint8_t)value;
        }
    }
    int32_t result = finish(&call, status, 23, 23);
    if (result) *out = 0;
    return result;
}
static int32_t java_maintenance_network_bind_socket(uint64_t owner, uint64_t network, int32_t fd) {
    if (fd < 0) return 3;
    if (!kvpn_platform_child_matches_v1(owner, 4, network)) return 4;
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 15, 0))
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
            jbits(owner), jbits(network), (jint)fd);
    return finish(&call, status, 23, 23);
}
static int32_t java_system_roots_into(uint64_t owner, uint64_t context, kvpn_cb_output_v1 *out) {
    if (!out) return 3;
    out->written = 0;
    if (!context || !out->data || !out->capacity || out->capacity > 1048576) return 3;
    java_call call;
    int32_t status = 23;
    if (begin(&call, owner, 17, context)) {
        jobject destination = buffer(&call, out);
        jintArray written = !call.failed ? ints(&call, 1) : NULL;
        if (!call.failed) {
            status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method,
                jbits(owner), jbits(context), destination, written);
            exception(&call);
            jint length = 0;
            (*call.env)->GetIntArrayRegion(call.env, written, 0, 1, &length);
            exception(&call);
            if (length < 0 || (uint32_t)length > out->capacity || (!status && !length)) call.failed = 1;
            else out->written = (uint32_t)length;
        }
    }
    int32_t result = finish(&call, status, 23, 23);
    if (result) { memset(out->data, 0, out->capacity); out->written = 0; }
    return result;
}
static int32_t java_cancel_call(uint64_t owner, uint64_t context) {
    if (!context) return 1;
    java_call call = {0};
    int32_t admission = kvpn_platform_enter_v1(owner, 18, context, &call.borrow);
    if (admission == 6) {
        uint8_t cancelled = 0;
        /* Absence of a Java wait is meaningful only for the exact still-owned
         * original Go call. It is never a cleanup acknowledgment. */
        return kvpn_android_call_cancelled_v1(owner, context, &cancelled) == 0 ? 6 : 25;
    }
    if (admission) return admission;
    int32_t status = 14;
    if (attach_call(&call))
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method, jbits(owner), jbits(context));
    if (status) call.failed = 1;
    return finish(&call, status, 25, 14);
}

static int32_t java_owner_close(uint64_t owner) {
    java_call call;
    int32_t status = 14;
    if (begin(&call, owner, 19, 0))
        status = (*call.env)->CallIntMethod(call.env, call.borrow.object, call.borrow.method, jbits(owner));
    int32_t result = finish(&call, status, 25, 14);
    if (result) { kvpn_platform_fail_v1(owner); return result; }
    JavaVM *vm = atomic_load(&java_vm);
    JNIEnv *env = NULL;
    uint8_t attached = 0;
    jint environment = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (environment == JNI_EDETACHED) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK) {
            kvpn_platform_fail_v1(owner); return 25;
        }
        attached = 1;
    } else if (environment != JNI_OK) { kvpn_platform_fail_v1(owner); return 25; }
    void *object = NULL;
    result = kvpn_platform_detach_v1(owner, &object);
    if (!result) {
        (*env)->DeleteGlobalRef(env, object);
        if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); result = 25; }
    }
    if (attached && (*vm)->DetachCurrentThread(vm) != JNI_OK) result = 25;
    if (result) { kvpn_platform_fail_v1(owner); return result; }
    return kvpn_output_owner_release_v1(owner) == 0 ? 0 : 25;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_finalizeFailedOpening(
        JNIEnv *env, jobject receiver, jint kind, jlong lease) {
    if ((kind != 1 && kind != 2) || lease == 0) return 25;
    kvpn_platform_finalize_v1 claim = {0};
    if (kvpn_output_failed_opening_claim_v1((uint64_t)lease, (uint8_t)kind, &claim)) return 25;
    jboolean same = (*env)->IsSameObject(env, receiver, claim.object);
    uint8_t failed = (*env)->ExceptionCheck(env);
    if (failed) (*env)->ExceptionClear(env);
    if (!same || failed) {
        (void)kvpn_output_finalize_unclaim_v1(&claim);
        return 25;
    }
    return kvpn_android_finalize_claim_v1(&claim);
}

static kvpn_android_callbacks_v1 callbacks = {
    .version = 1, .struct_size = sizeof(kvpn_android_callbacks_v1),
    .capture_sizes = java_capture_sizes,
    .capture_copy_into = java_capture_copy_into,
    .production_current_register = java_production_current_register,
    .maintenance_current_register = java_maintenance_current_register,
    .revision_revalidate = java_revision_revalidate,
    .publication_acquire = java_publication_acquire,
    .publication_is_current = java_publication_is_current,
    .publication_close = java_publication_close,
    .revision_close = java_revision_close,
    .socket_register = java_socket_register,
    .socket_confirm = java_socket_confirm,
    .socket_close = java_socket_close,
    .maintenance_network_acquire = java_maintenance_network_acquire,
    .maintenance_network_snapshot = java_maintenance_network_snapshot,
    .maintenance_network_is_current = java_maintenance_network_is_current,
    .maintenance_network_bind_socket = java_maintenance_network_bind_socket,
    .maintenance_network_close = java_maintenance_network_close,
    .system_roots_into = java_system_roots_into,
    .cancel_call = java_cancel_call,
    .owner_close = java_owner_close
};
static pthread_once_t table_once = PTHREAD_ONCE_INIT;
static void initialize_table(void) { callbacks.output = kvpn_output_callbacks_table_v1(); }
const kvpn_android_callbacks_v1 *kvpn_android_callbacks_table_v1(void) {
    if (pthread_once(&table_once, initialize_table)) return NULL;
    return &callbacks; /* No field is changed after once publishes this table. */
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_registerOwned(
        JNIEnv *env, jobject receiver, jint kind, jlongArray output) {
    if (!output || (*env)->GetArrayLength(env, output) != 2 || (kind != 1 && kind != 2)) return 2;
    jlong values[2] = {0};
    (*env)->SetLongArrayRegion(env, output, 0, 2, values);
    if ((*env)->ExceptionCheck(env)) return 18;
    JavaVM *vm = NULL;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK || !vm) return 18;
    JavaVM *expected = NULL;
    if (!atomic_compare_exchange_strong(&java_vm, &expected, vm) && expected != vm) return 18;
    if (!kvpn_android_table_valid_v1(kvpn_android_callbacks_table_v1())) return 18;
    uint64_t owner = 0, lease = 0;
    int32_t status = kvpn_output_owner_reserve_v1((uint8_t)kind, &owner, &lease);
    if (status) return status;
    jobject global = (*env)->NewGlobalRef(env, receiver);
    jclass type = global ? (*env)->GetObjectClass(env, receiver) : NULL;
    void *methods[20] = {0};
    if (type) for (unsigned i = 0; i < 20; ++i) {
        methods[i] = (*env)->GetMethodID(env, type, method_names[i], method_descriptors[i]);
        if (!methods[i] || (*env)->ExceptionCheck(env)) break;
    }
    uint8_t failed = (*env)->ExceptionCheck(env) || !global || !type;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (type) (*env)->DeleteLocalRef(env, type);
    if (!failed) failed = kvpn_platform_install_v1(owner, global, methods) != 0;
    if (failed) {
        if (global) (*env)->DeleteGlobalRef(env, global);
        kvpn_output_abandon_unclaimed_v1(lease);
        return 18;
    }
    values[0] = jbits(owner); values[1] = jbits(lease);
    (*env)->SetLongArrayRegion(env, output, 0, 2, values);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        java_owner_close(owner);
        values[0] = 0; values[1] = 0;
        (*env)->SetLongArrayRegion(env, output, 0, 2, values);
        return 18;
    }
    return 0;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_abandonUnclaimed(
        JNIEnv *env, jobject receiver, jlong lease) {
    kvpn_platform_borrow_v1 borrow = {0};
    if (kvpn_platform_unclaimed_borrow_v1((uint64_t)lease, &borrow)) return 25;
    uint8_t same = (*env)->IsSameObject(env, receiver, borrow.object);
    uint8_t failed = (*env)->ExceptionCheck(env);
    if (failed) (*env)->ExceptionClear(env);
    if (kvpn_platform_leave_v1(&borrow, failed) || !same || failed) return 25;
    uint64_t owner = 0;
    if (kvpn_platform_abandon_owner_v1((uint64_t)lease, &owner)) return 25;
    return java_owner_close(owner);
}

static int32_t signal_owned(JNIEnv *env, jobject receiver, uint64_t owner, uint64_t signal, uint8_t kind, uint8_t fence) {
    if (kvpn_platform_signal_borrow_v1(owner, kind, signal)) return 25;
    jobject object = kvpn_platform_signal_object_v1(owner, kind, signal);
    int32_t status = 25;
    if (object && (*env)->IsSameObject(env, receiver, object) && !(*env)->ExceptionCheck(env)) {
        if (fence) status = kvpn_output_revision_prefence_v1(owner);
        else if (kind == 1) {
            status = kvpn_output_revision_begin_v1(owner);
            if (!status) status = kvpn_output_revision_finish_v1(owner, kvpn_android_revision_invalidated_v1(owner, signal));
        } else if (kind == 2) status = kvpn_android_socket_lost_v1(owner, signal);
        else status = kvpn_android_maintenance_network_lost_v1(owner, signal);
    }
    if ((*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); status = 25; }
    if (kvpn_platform_signal_return_v1(owner, kind, signal)) return 25;
    return status >= 0 && status <= 25 ? status : 25;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_revisionFence(
        JNIEnv *env, jobject receiver, jlong owner, jlong signal) {
    return signal_owned(env, receiver, (uint64_t)owner, (uint64_t)signal, 1, 1);
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_revisionInvalidated(
        JNIEnv *env, jobject receiver, jlong owner, jlong signal) {
    return signal_owned(env, receiver, (uint64_t)owner, (uint64_t)signal, 1, 0);
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_socketLost(
        JNIEnv *env, jobject receiver, jlong owner, jlong signal) {
    return signal_owned(env, receiver, (uint64_t)owner, (uint64_t)signal, 2, 0);
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_maintenanceNetworkLost(
        JNIEnv *env, jobject receiver, jlong owner, jlong signal) {
    return signal_owned(env, receiver, (uint64_t)owner, (uint64_t)signal, 3, 0);
}
static int query_borrow(JNIEnv *env, jobject receiver, uint64_t owner, uint64_t context, kvpn_platform_borrow_v1 *borrow) {
    if (kvpn_platform_query_enter_v1(owner, context, borrow)) return 0;
    jboolean same = (*env)->IsSameObject(env, receiver, borrow->object);
    jboolean failed = (*env)->ExceptionCheck(env);
    if (!same || failed) {
        if (failed) (*env)->ExceptionClear(env);
        kvpn_platform_query_leave_v1(borrow, failed);
        return 0;
    }
    return 1;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_callCancelled(
        JNIEnv *env, jobject receiver, jlong owner, jlong context, jintArray output) {
    if (!output || (*env)->GetArrayLength(env, output) != 1) return 1;
    jint value = 0;
    (*env)->SetIntArrayRegion(env, output, 0, 1, &value);
    if ((*env)->ExceptionCheck(env)) return 14;
    kvpn_platform_borrow_v1 borrow = {0};
    if (!query_borrow(env, receiver, (uint64_t)owner, (uint64_t)context, &borrow)) return 25;
    uint8_t cancelled = 0;
    int32_t status = kvpn_android_call_cancelled_v1((uint64_t)owner, (uint64_t)context, &cancelled);
    if (cancelled > 1 || status < 0 || status > 25) status = 25;
    if (!status) {
        value = cancelled;
        (*env)->SetIntArrayRegion(env, output, 0, 1, &value);
        if ((*env)->ExceptionCheck(env)) status = 14;
    }
    if (kvpn_platform_query_leave_v1(&borrow, status)) return 25;
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_AndroidProductionCallbacks_callRemainingMillis(
        JNIEnv *env, jobject receiver, jlong owner, jlong context, jintArray present, jlongArray remaining) {
    if (!present || !remaining || (*env)->GetArrayLength(env, present) != 1 ||
        (*env)->GetArrayLength(env, remaining) != 1) return 1;
    jint has = 0;
    jlong millis = 0;
    (*env)->SetIntArrayRegion(env, present, 0, 1, &has);
    if (!(*env)->ExceptionCheck(env)) (*env)->SetLongArrayRegion(env, remaining, 0, 1, &millis);
    if ((*env)->ExceptionCheck(env)) return 14;
    kvpn_platform_borrow_v1 borrow = {0};
    if (!query_borrow(env, receiver, (uint64_t)owner, (uint64_t)context, &borrow)) return 25;
    uint8_t deadline = 0;
    uint64_t duration = 0;
    int32_t status = kvpn_android_call_remaining_millis_v1((uint64_t)owner, (uint64_t)context, &deadline, &duration);
    if (deadline > 1 || duration > INT64_MAX || (!deadline && duration) || status < 0 || status > 25) status = 25;
    if (!status) {
        has = deadline; millis = (jlong)duration;
        (*env)->SetIntArrayRegion(env, present, 0, 1, &has);
        if (!(*env)->ExceptionCheck(env)) (*env)->SetLongArrayRegion(env, remaining, 0, 1, &millis);
        if ((*env)->ExceptionCheck(env)) status = 14;
    }
    if (kvpn_platform_query_leave_v1(&borrow, status)) return 25;
    return status;
}

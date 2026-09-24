// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include <jni.h>
#include <stdint.h>
#include "kvpn_output_gate_v1.h"

extern int32_t kvpn_task7_maintenance_run_v1(kvpn_output_callbacks_v1 *, uint64_t,
    uint64_t, uint64_t, uint64_t, uint32_t, int64_t *, uint32_t);

static int measurement_valid(const int64_t v[24], jint id) {
    if (v[0] != 1 || v[1] != id || v[2] != 1 || v[3] != 0 || v[7] != 0 ||
        v[17] != 0 || v[18] != 1 || v[19] != 0 || v[20] != 0 || v[21] != 0 ||
        v[22] != -1 || v[23] != -1) return 0;
    if (id == 3) {
        for (int i = 4; i <= 6; ++i) if (v[i] != -1) return 0;
        for (int i = 8; i <= 16; ++i) if (v[i] != -1) return 0;
        return 1;
    }
    if (v[4] != 0 || v[5] < 1 || v[5] > 512 || v[6] < 3 || v[6] > 1048576) return 0;
    if (id == 301 || id == 302) {
        if (v[9] != 1 || v[10] != 1 || v[11] != 1 || v[12] != -1 || v[15] != 0 || v[16] != 1) return 0;
        return id == 301 ? v[8] == 0 && v[13] == 1 && v[14] > 0 && v[14] <= 65536 :
            v[8] == 8 && v[13] == 0 && v[14] == 0;
    }
    if (id == 1) {
        for (int i = 8; i <= 16; ++i) if (v[i] != -1) return 0;
        return 1;
    }
    return v[8] == 13 && v[9] == 1 && v[10] == 1 && v[11] == 1 && v[12] == 1 &&
        v[13] == 0 && v[14] == 0 && v[15] == 0 && v[16] == 1;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7MaintenanceFixtureNative_nativeRun(
    JNIEnv *env, jobject self, jobject session, jint id, jlongArray output) {
    (void)self;
    jint status = 2;
    jclass expected = NULL, actual = NULL, parent_class = NULL;
    jobject parent = NULL;
    jmethodID begin = NULL, raw = NULL, finish = NULL;
    jthrowable original = NULL, cleanup = NULL;
    uint8_t java_admitted = 0, c_admitted = 0;
    kvpn_output_call_v1 call = {0};
    int64_t stage[24];
    for (int i = 0; i < 24; ++i) stage[i] = -1;
    if (!session || !output || ((id < 1 || id > 3) && id != 301 && id != 302) || (*env)->GetArrayLength(env, output) != 24) goto done;
    expected = (*env)->FindClass(env, "org/kurdistanvpn/core/nativejni/ProductionNativeMaintenanceV1");
    if (!expected || (*env)->ExceptionCheck(env)) goto done;
    actual = (*env)->GetObjectClass(env, session);
    if (!actual || (*env)->ExceptionCheck(env)) goto done;
    if (!(*env)->IsSameObject(env, expected, actual)) goto done;
    jfieldID field = (*env)->GetFieldID(env, expected, "parent", "Lorg/kurdistanvpn/core/nativejni/ProductionNativeParentV1;");
    if (!field || (*env)->ExceptionCheck(env)) goto done;
    parent = (*env)->GetObjectField(env, session, field);
    if (!parent || (*env)->ExceptionCheck(env)) goto done;
    parent_class = (*env)->GetObjectClass(env, parent);
    if (!parent_class || (*env)->ExceptionCheck(env)) goto done;
    begin = (*env)->GetMethodID(env, parent_class, "beginCall", "()I");
    if (!begin || (*env)->ExceptionCheck(env)) goto done;
    raw = (*env)->GetMethodID(env, parent_class, "rawHandle", "()J");
    if (!raw || (*env)->ExceptionCheck(env)) goto done;
    finish = (*env)->GetMethodID(env, parent_class, "finishCall", "()I");
    if (!finish || (*env)->ExceptionCheck(env)) goto done;
    status = (*env)->CallIntMethod(env, parent, begin);
    if ((*env)->ExceptionCheck(env) || status) goto done;
    java_admitted = 1;
    jlong handle = (*env)->CallLongMethod(env, parent, raw);
    if ((*env)->ExceptionCheck(env) || !handle) { status = 18; goto done; }
    status = kvpn_output_begin_parent_v1((uint64_t)handle, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) goto done;
    c_admitted = 1;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_task7_maintenance_run_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call.owner, call.serial, call.epoch, (uint64_t)handle, (uint32_t)id, stage, 24);
    if ((*env)->ExceptionCheck(env)) { status = 18; goto done; }
    if (!status && !measurement_valid(stage, id)) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
    if (!status) {
        uint8_t committed = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &committed);
        if (!status && committed != 1) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) stage[22] = 1;
    }
done:
    if ((*env)->ExceptionCheck(env)) { original = (*env)->ExceptionOccurred(env); (*env)->ExceptionClear(env); status = 18; }
    if (c_admitted) kvpn_output_end_v1(&call);
    if (java_admitted) {
        (void)(*env)->CallIntMethod(env, parent, finish);
        if ((*env)->ExceptionCheck(env)) { cleanup = (*env)->ExceptionOccurred(env); (*env)->ExceptionClear(env); status = 18; }
        else stage[23] = 1;
    }
    if (parent) (*env)->DeleteLocalRef(env, parent);
    if (parent_class) (*env)->DeleteLocalRef(env, parent_class);
    if (actual) (*env)->DeleteLocalRef(env, actual);
    if (expected) (*env)->DeleteLocalRef(env, expected);
    if (cleanup) { (*env)->Throw(env, cleanup); (*env)->DeleteLocalRef(env, cleanup); }
    else if (original) (*env)->Throw(env, original);
    if (original) (*env)->DeleteLocalRef(env, original);
    if (!status && !(*env)->ExceptionCheck(env)) (*env)->SetLongArrayRegion(env, output, 0, 24, (const jlong *)stage);
    return (*env)->ExceptionCheck(env) ? 18 : status;
}

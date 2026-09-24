// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_PRODUCTION_JNI_V1_H
#define KVPN_PRODUCTION_JNI_V1_H
#include <jni.h>
#include "kvpn_production_spans_v1.h"
#include "kvpn_output_gate_v1.h"

/* Shared actual callback holder layout, so JNI accounting does not guess its
 * padding. Ordinary callback and cancellation can overlap; queries use the
 * already-counted plain platform borrows. */
typedef struct {
    JNIEnv *env;
    JavaVM *vm;
    kvpn_platform_borrow_v1 borrow;
    uint8_t attached, pushed, failed;
} kvpn_android_java_call_v1;
int32_t kvpn_production_jni_backing_v1(uint8_t, uint32_t, uint64_t, uint64_t *);

/* Bounded preflight/publication helpers only, never operation dispatch or gate
 * ownership. JNI callers retain their own typed operation frame through copy. */
int32_t kvpn_production_jni_metadata_v1(JNIEnv *, jlongArray, jsize);
int32_t kvpn_production_jni_write_v1(JNIEnv *, jlongArray, jsize, const jlong *);
int32_t kvpn_production_jni_span_v1(JNIEnv *, jobject, jint, jint, uint8_t,
    uint32_t, uint32_t, kvpn_production_span_v1 *, uint64_t *);
#endif

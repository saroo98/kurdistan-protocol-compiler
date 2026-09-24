// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include <jni.h>
#include <stdint.h>
#include <pthread.h>
#ifndef KVPN_ANDROID_PLATFORM_INTERNAL_V1
#error "Task7 fixture requires internal source guard"
#endif
int32_t kvpn_task7_issue_v1(char *, uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *);
int32_t kvpn_task7_start_v1(char *, int32_t, int32_t);
int32_t kvpn_task7_snapshot_v1(uint64_t *, uint32_t);
int32_t kvpn_task7_cancel_v1(void);
int32_t kvpn_task7_finish_v1(void);

/* Internal only, no identity or exception data. One first failure per bucket. */
static pthread_mutex_t rejection_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t rejection_words[3];
static uint8_t rejection_order, rejection_armed;
void kvpn_task7_rejection_v1(uint8_t bucket, uint8_t phase, int32_t status) {
    if (bucket > 2 || !phase || phase > 15 || !status || (bucket == 0 && status == 20)) return;
    pthread_mutex_lock(&rejection_mutex);
    if (rejection_armed && !rejection_words[bucket]) {
        uint8_t bounded = status >= 0 && status <= 26 ? (uint8_t)status : 31;
        rejection_words[bucket] = (uint64_t)phase | ((uint64_t)bounded << 4) | ((uint64_t)++rejection_order << 9);
    }
    pthread_mutex_unlock(&rejection_mutex);
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7InstalledFixtureNative_nativeIssue(
    JNIEnv *env, jobject self, jstring directory, jbyteArray request, jobject output, jintArray written) {
    (void)self;
    if (!directory || !request || !output || !written || (*env)->GetArrayLength(env,written)!=1 ||
        (*env)->GetStringUTFLength(env,directory)>4096 || (*env)->GetDirectBufferCapacity(env,output)!=1052763) return 1;
    jint zero=0; (*env)->SetIntArrayRegion(env,written,0,1,&zero);
    jsize length=(*env)->GetArrayLength(env,request);
    if (length<1 || length>65536) return 1;
    uint8_t *dst=(*env)->GetDirectBufferAddress(env,output);
    if (!dst) return 1;
    const char *dir=(*env)->GetStringUTFChars(env,directory,NULL);
    if (!dir) return 1;
    jbyte *bytes=(*env)->GetByteArrayElements(env,request,NULL);
    if (!bytes) { (*env)->ReleaseStringUTFChars(env,directory,dir); return 1; }
    uint32_t size=0;
    int32_t status=kvpn_task7_issue_v1((char *)dir,(uint8_t *)bytes,(uint32_t)length,dst,1052763,&size);
    (*env)->ReleaseByteArrayElements(env,request,bytes,JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env,directory,dir);
    jint result=(jint)size; (*env)->SetIntArrayRegion(env,written,0,1,&result);
    return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7InstalledFixtureNative_nativeStart(
    JNIEnv *env, jobject self, jstring directory, jint level, jint fixture_mode) {
    (void)self;
    if (!directory || (*env)->GetStringUTFLength(env,directory)>4096 || (level!=0 && level!=16 && level!=32 && level!=64)) return 1;
    if (fixture_mode<0 || fixture_mode>2 || (fixture_mode!=0 && level!=0)) return 1;
    const char *dir=(*env)->GetStringUTFChars(env,directory,NULL); if (!dir) return 1;
    int32_t status=kvpn_task7_start_v1((char *)dir,level,fixture_mode);
    if (!status) {
        pthread_mutex_lock(&rejection_mutex);
        for (int i=0;i<3;i++) rejection_words[i]=0;
        rejection_order=0; rejection_armed=1;
        pthread_mutex_unlock(&rejection_mutex);
    }
    (*env)->ReleaseStringUTFChars(env,directory,dir);return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7InstalledFixtureNative_nativeSnapshot(
    JNIEnv *env, jobject self, jlongArray output) {
    (void)self; if (!output || (*env)->GetArrayLength(env,output)!=16) return 1;
    uint64_t values[16]={0}; int32_t status=kvpn_task7_snapshot_v1(values,16);
    pthread_mutex_lock(&rejection_mutex);
    for (int i=0;i<3;i++) values[13+i]=rejection_words[i];
    pthread_mutex_unlock(&rejection_mutex);
    jlong result[16];for (int i=0;i<16;i++) result[i]=(jlong)values[i];
    (*env)->SetLongArrayRegion(env,output,0,16,result);return status;
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7InstalledFixtureNative_nativeCancel(JNIEnv *env,jobject self) {
    (void)env;(void)self;return kvpn_task7_cancel_v1();
}
JNIEXPORT jint JNICALL Java_org_kurdistanvpn_core_nativejni_Task7InstalledFixtureNative_nativeFinish(JNIEnv *env,jobject self) {
    (void)env;(void)self;return kvpn_task7_finish_v1();
}

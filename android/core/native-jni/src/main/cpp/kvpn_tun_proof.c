// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_tun_proof.h"
#include <fcntl.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>

int32_t kvpn_tun_read_identity_v1(int32_t fd,uint8_t *name,uint32_t capacity,uint32_t *written) {
    if (written) *written=0;
    if (name && capacity<=15) memset(name,0,capacity);
    if (fd<0 || !name || capacity!=15 || !written) return 1;
    int flags=fcntl(fd,F_GETFD);
    if (flags<0 || fcntl(fd,F_SETFD,flags|FD_CLOEXEC)<0) return 14;
    flags=fcntl(fd,F_GETFD);
    if (flags<0 || (flags&FD_CLOEXEC)==0) return 14;
    struct ifreq request;
    memset(&request,0,sizeof(request));
    if (ioctl(fd,TUNGETIFF,&request)<0) return 14;
    if ((request.ifr_flags&(IFF_TUN|IFF_NO_PI))!=(IFF_TUN|IFF_NO_PI) ||
        (request.ifr_flags&IFF_TAP)!=0) return 25;
    size_t size=0;
    while (size<IFNAMSIZ && request.ifr_name[size]) ++size;
    if (!size || size>15 || size==IFNAMSIZ) return 25;
    for (size_t i=0;i<size;++i) {
        unsigned char byte=(unsigned char)request.ifr_name[i];
        if (byte<33 || byte>126 || byte=='/') return 25;
    }
    memcpy(name,request.ifr_name,size); *written=(uint32_t)size;
    return 0;
}

#ifdef __ANDROID__
#include <jni.h>
JNIEXPORT jboolean JNICALL Java_org_kurdistanvpn_runtime_android_AndroidTunPacketEndpoint_prepareNonblocking(
        JNIEnv *env,jobject receiver,jint fd) {
    (void)env; (void)receiver;
    if (fd<0) return JNI_FALSE;
    int flags, result, retries=0;
    do { flags=fcntl(fd,F_GETFL); } while (flags<0 && errno==EINTR && ++retries<32);
    if (flags<0) return JNI_FALSE;
    retries=0;
    do { result=fcntl(fd,F_SETFL,flags|O_NONBLOCK); } while (result<0 && errno==EINTR && ++retries<32);
    return result==0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL Java_org_kurdistanvpn_runtime_android_RuntimeTunProofOwner_readTunIdentity(
        JNIEnv *env,jobject receiver,jint fd,jobject destination,jintArray output) {
    (void)receiver;
    if (!destination || !output || (*env)->GetArrayLength(env,output)!=1) return 1;
    jint zero=0;
    (*env)->SetIntArrayRegion(env,output,0,1,&zero);
    if ((*env)->ExceptionCheck(env)) return 14;
    jlong capacity=(*env)->GetDirectBufferCapacity(env,destination);
    uint8_t *bytes=(*env)->GetDirectBufferAddress(env,destination);
    if (!bytes || capacity!=15 || (*env)->ExceptionCheck(env)) return 1;
    uint32_t written=0;
    int32_t result=kvpn_tun_read_identity_v1(fd,bytes,15,&written);
    if (!result) {
        jint value=(jint)written;
        (*env)->SetIntArrayRegion(env,output,0,1,&value);
        if ((*env)->ExceptionCheck(env)) { memset(bytes,0,15); return 14; }
    }
    return result;
}
#endif

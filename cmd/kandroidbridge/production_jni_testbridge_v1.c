//go:build phase18jnitest && phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#define KVPN_JNI_HOST_INTEGRATION_V1 1
#include "../../android/core/native-jni/src/test/cpp/kvpn_production_jni_v1_test.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_production_jni_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_stream_jni_v1.c"
#include "../../android/core/native-jni/src/main/cpp/kvpn_maintenance_jni_v1.c"

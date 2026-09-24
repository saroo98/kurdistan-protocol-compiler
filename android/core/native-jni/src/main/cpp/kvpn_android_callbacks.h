// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_ANDROID_JNI_CALLBACKS_H
#define KVPN_ANDROID_JNI_CALLBACKS_H
#include "android_callbacks_v1.h"
#include "kvpn_output_gate_v1.h"
const kvpn_android_callbacks_v1 *kvpn_android_callbacks_table_v1(void);
int32_t kvpn_android_finalize_claim_v1(kvpn_platform_finalize_v1 *);
int32_t kvpn_android_finalize_failed_opening_v1(uint64_t lease, uint8_t kind);
int32_t kvpn_android_finalize_parent_v1(uint64_t parent, uint8_t kind);
#endif

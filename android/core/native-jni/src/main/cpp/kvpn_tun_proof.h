// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_TUN_PROOF_H
#define KVPN_TUN_PROOF_H
#include <stdint.h>
/* Caller owns the duplicate and serializes this short ioctl against its close. */
int32_t kvpn_tun_read_identity_v1(int32_t fd,uint8_t *name,uint32_t capacity,uint32_t *written);
#endif

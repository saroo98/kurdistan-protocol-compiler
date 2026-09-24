/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Copyright 2026 Saro */
#ifndef KVPN_BOOTSTRAP_BINDING_V1_H
#define KVPN_BOOTSTRAP_BINDING_V1_H
#include <stdint.h>

/* Private per-call anomaly signal, never a canonical runtime error/export.
 * JNI preserves this value; Java reports INTERNAL_FAILURE and retains refusal
 * even when all controllable buffers were wiped. */
#define KVPN_BOOTSTRAP_CAPACITY_INVARIANT_V1 (-6401)

/* Private synchronous read-only calculations. No pointer survives the call. */
int32_t kvpn_bootstrap_legacy_binding_v1(
    const uint8_t *, uint32_t, const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, uint8_t *, uint32_t);
int32_t kvpn_bootstrap_production_binding_v1(
    const uint8_t *, uint32_t, const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, const uint8_t *, uint32_t,
    const uint8_t *, uint32_t, uint8_t *, uint32_t,
    uint8_t *, uint32_t, uint32_t *, uint8_t *, uint32_t, uint32_t *);
#endif

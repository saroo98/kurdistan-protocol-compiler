// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_PRODUCTION_SPANS_V1_H
#define KVPN_PRODUCTION_SPANS_V1_H
#include <stddef.h>
#include <stdint.h>

typedef struct { uint8_t *data; uint32_t length; } kvpn_production_span_v1;
typedef struct { const void *data; uint64_t length; } kvpn_production_memory_v1;
/* At most two scalar outputs and two byte spans in the canonical ABI. This
 * check never writes, including for null/unaligned/overlapping metadata. */
int kvpn_production_metadata_v1(const kvpn_production_memory_v1 *, size_t,
    const kvpn_production_memory_v1 *, size_t);
/* Arithmetic validation only. Actual foreign memory validity is the caller's
 * precondition. Logical bounded slices can borrow larger backing arenas. */
int32_t kvpn_production_span_v1_init(void *, int64_t, int64_t, int64_t,
    int64_t, int64_t, uint32_t, uint32_t, kvpn_production_span_v1 *);
int kvpn_production_disjoint_v1(const void *, uint64_t, const void *, uint64_t);
int kvpn_production_add_v1(uint64_t, uint64_t, uint64_t *);
/* Trusted concrete Kotlin caller payload, not foreign arena ownership or VM
 * headers. Includes separately provisioned bounded UTF-16 logical content. */
int32_t kvpn_production_java_payload_v1(uint8_t kind, uint32_t request_length,
    uint64_t capacity, uint64_t *out);
/* Private arithmetic seam. The trusted caller supplies actual layout/sizeof
 * values and its source-derived overlap, never public request metadata. Shared
 * storage already contains all owners; no additional owner term is accepted. */
int32_t kvpn_production_backing_sum_v1(uint64_t shared, uint64_t frames,
    uint64_t frame_size, uint64_t fixed, uint64_t per_frame, uint64_t capacity,
    uint64_t *out);
void kvpn_production_wipe_v1(void *, size_t);
#endif

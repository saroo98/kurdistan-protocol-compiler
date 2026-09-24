// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_production_spans_v1.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    uint8_t arena[100] = {0};
    kvpn_production_span_v1 span = {0};
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 20, 30, 1, 10, &span) == 0);
    assert(span.data == arena + 20 && span.length == 10);
    assert(kvpn_production_span_v1_init(arena, UINT32_MAX, 0, UINT32_MAX, 1, 11, 1, 10, &span) == 0);
    assert(span.data == arena + 1 && span.length == 10);
    assert(kvpn_production_span_v1_init(arena, (int64_t)UINT32_MAX + 1, 0, 100, 0, 10, 1, 10, &span) == 2);
    assert(span.data == NULL && span.length == 0);
    assert(kvpn_production_span_v1_init(NULL, 100, 0, 100, 0, 10, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, -1, 0, 100, 0, 10, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, -1, 10, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 9, 19, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 85, 95, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 30, 20, 1, 10, &span) == 2);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 20, 20, 1, 10, &span) == 4);
    assert(kvpn_production_span_v1_init(arena, 100, 10, 90, 20, 31, 1, 10, &span) == 4);
    assert(kvpn_production_span_v1_init((void *)(UINTPTR_MAX - 4), 100, 0, 100, 0, 10, 1, 10, &span) == 2);
    assert(kvpn_production_disjoint_v1(arena, 10, arena + 10, 20));
    assert(!kvpn_production_disjoint_v1(arena, 10, arena + 9, 20));
    assert(!kvpn_production_disjoint_v1((void *)(UINTPTR_MAX - 4), 10, arena, 20));
    assert(!kvpn_production_disjoint_v1(NULL, 1, arena, 20));
    uint64_t sum = 99;
    /* The trusted typed caller uses logical KPO size, never foreign arena
     * capacity. Both acquisition and retained operation phases are charged. */
    uint64_t java_small = 0, java_large = 0;
    assert(kvpn_production_java_payload_v1(1, 32, UINT64_MAX, &java_small) == 0);
    assert(kvpn_production_java_payload_v1(1, 2721575, UINT64_MAX, &java_large) == 0);
    assert(java_small == 336827 && java_large == 8215413);
    assert(kvpn_production_java_payload_v1(1, 2721575, java_large - 1, &sum) == 5 && sum == 0);
    assert(kvpn_production_java_payload_v1(1, 2721575, java_large, &sum) == 0 && sum == java_large);
    assert(kvpn_production_java_payload_v1(2, 2721575, UINT64_MAX, &sum) == 0 && sum == 8182637);
    assert(kvpn_production_java_payload_v1(0, 32, UINT64_MAX, &sum) == 2 && sum == 0);
    assert(kvpn_production_java_payload_v1(1, 2721576, UINT64_MAX, &sum) == 4 && sum == 0);
    /* An omitted admitted pre-lane frame, truncated division, or wrapping
     * multiplication must not turn a one-byte deficit into an admission. */
    assert(kvpn_production_backing_sum_v1(100, 120, 40, 20, 11, 273, &sum) == 0 && sum == 273);
    assert(kvpn_production_backing_sum_v1(100, 120, 40, 20, 11, 272, &sum) == 5 && sum == 0);
    assert(kvpn_production_backing_sum_v1(100, 119, 40, 20, 11, UINT64_MAX, &sum) == 2 && sum == 0);
    assert(kvpn_production_backing_sum_v1(100, 0, 40, 20, 11, UINT64_MAX, &sum) == 2 && sum == 0);
    assert(kvpn_production_backing_sum_v1(100, 120, 0, 20, 11, UINT64_MAX, &sum) == 2 && sum == 0);
    assert(kvpn_production_backing_sum_v1(1, 2, 1, 0, UINT64_MAX, UINT64_MAX, &sum) == 5 && sum == 0);
    assert(kvpn_production_backing_sum_v1(UINT64_MAX, 1, 1, 0, 0, UINT64_MAX, &sum) == 5 && sum == 0);
    assert(kvpn_production_backing_sum_v1(1, 1, 1, UINT64_MAX, 0, UINT64_MAX, &sum) == 5 && sum == 0);
    assert(kvpn_production_backing_sum_v1(1, 1, 1, 0, 0, 2, &sum) == 0 && sum == 2);
    _Alignas(uint64_t) uint8_t metadata_arena[64];
    memset(metadata_arena, 0xa5, sizeof(metadata_arena));
    kvpn_production_memory_v1 scalars[2] = {{metadata_arena, 8}, {metadata_arena + 8, 4}};
    kvpn_production_memory_v1 bytes[2] = {{metadata_arena + 16, 8}, {metadata_arena + 32, 8}};
    assert(kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = metadata_arena + 4;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = metadata_arena + 17;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = metadata_arena + 16;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = metadata_arena + 32;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = NULL;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = (void *)(UINTPTR_MAX - 3);
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    scalars[1].data = metadata_arena + 8;
    scalars[1].length = 16;
    assert(!kvpn_production_metadata_v1(scalars, 2, bytes, 2));
    for (size_t i = 0; i < sizeof(metadata_arena); ++i) assert(metadata_arena[i] == 0xa5);
    assert(kvpn_production_add_v1(3, 4, &sum) && sum == 7);
    assert(!kvpn_production_add_v1(UINT64_MAX, 1, &sum) && sum == 0);
    memset(arena, 0xa5, sizeof(arena));
    kvpn_production_wipe_v1(arena + 5, 10);
    for (size_t i = 0; i < sizeof(arena); ++i) assert(arena[i] == (i >= 5 && i < 15 ? 0 : 0xa5));
    return 0;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_production_spans_v1.h"

static int address_range(const void *pointer, uint64_t length) {
    return pointer && length <= UINTPTR_MAX && (uintptr_t)pointer <= UINTPTR_MAX - (uintptr_t)length;
}
int32_t kvpn_production_span_v1_init(void *base, int64_t capacity,
    int64_t actual_position, int64_t actual_limit, int64_t position, int64_t limit,
    uint32_t minimum, uint32_t maximum, kvpn_production_span_v1 *out) {
    if (!out) return 2;
    *out = (kvpn_production_span_v1){0};
    if (!base || capacity < 0 || (uint64_t)capacity > UINT32_MAX ||
        actual_position < 0 || actual_limit < actual_position || actual_limit > capacity ||
        position < actual_position || limit < position || limit > actual_limit || minimum > maximum) return 2;
    if (!address_range(base, (uint64_t)limit)) return 2;
    uint64_t length = (uint64_t)(limit - position);
    if (length < minimum || length > maximum) return 4;
    out->data = (uint8_t *)base + position;
    out->length = (uint32_t)length;
    return 0;
}
int kvpn_production_disjoint_v1(const void *a, uint64_t an, const void *b, uint64_t bn) {
    if (!address_range(a, an) || !address_range(b, bn)) return 0;
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    return av + (uintptr_t)an <= bv || bv + (uintptr_t)bn <= av;
}
int kvpn_production_add_v1(uint64_t a, uint64_t b, uint64_t *out) {
    if (!out) return 0;
    *out = 0;
    if (a > UINT64_MAX - b) return 0;
    *out = a + b;
    return 1;
}
int32_t kvpn_production_java_payload_v1(uint8_t kind, uint32_t request_length,
    uint64_t capacity, uint64_t *out) {
    if (!out) return 2;
    *out = 0;
    if ((kind != 1 && kind != 2) || !request_length) return 2;
    if (request_length > 2721575) return 4;
    /* A malformed short KPO still reaches the canonical parser. Thirty-two
     * is a conservative scratch floor, not a second syntax decoder. */
    uint64_t kpo = request_length < 32 ? 32 : request_length;
    /* Same five-row KCT owner, six offsets, two compact KPA owners, facts
     * digest, two binding LongArray[2], two simultaneous digest copies. */
    uint64_t retained = kpo + 24 + 2 * 512 + 32 + 32 + 64;
    /* One DER<=16384; retained/fresh DNS <=3*4*16. JNI/delegate capture
     * IntArray[5] pair dominates ordinary callback metadata. Two query
     * roles retain at most IntArray[1]+LongArray[1] each. */
    uint64_t callbacks = 16384 + 3 * 4 * 16 + 2 * 5 * 4 + 2 * (4 + 8) + 8 + 4;
    /* captureProductionOpeningV1 holds five exact direct spans and one KPO.
     * Header writer/result/magic total68; size/written arrays total40.
     * These are gone before decodeOpening; the output and metadata remain. */
    uint64_t acquire = (kpo - 32) + kpo + 40 + 68 + (kind == 1 ? 32768 + 16 : 8);
    uint64_t live;
    if (kind == 1) {
        /* One proxy encoder: direct259 + writer259 + result259 + address253
         * + metadata8. Writer growth replaces its result-copy phase. */
        uint64_t ordinary = 259 + 259 + 259 + 253 + 8;
        /* One control poller only. Malformed bounded routes can retain260
         * addresses and256 sort keys, before validNetwork restricts to2.
         * The current key's intermediate bytes and IPv6 check are bounded.
         * Labels already accepted here retain3*96 UTF-16 code units. */
        uint64_t parse = 8 + 80 + 260 * 16 + 10 + 256 * 18 + 19 + 2 * 3 * 96;
        /* Valid snapshot construction instead has6 addresses,19 longs,
         * immutable fingerprint copies and one IP-parser80-byte peak.
         * Logical text: labels288,4 addresses*39,2 routes*(43+128 bits),
         * Normalization content: two39-character addresses, two43-character
         * CIDRs, prefix3 and eight4-character groups. Bit rendering instead
         * has CIDR43,address39,bits128,two16-character current chunks and
         * eight4-character groups. These phases do not overlap each other.
         * Two bytes/code-unit is provisioning, not measured String backing. */
        uint64_t normalize_text = 2 * 39 + 2 * 43 + 3 + 8 * 4;
        uint64_t bits_text = 43 + 39 + 128 + 2 * 16 + 8 * 4;
        uint64_t text_temporary = normalize_text > bits_text ? normalize_text : bits_text;
        uint64_t construct = 80 + 6 * 16 + 19 * 8 + 80 + 80 +
            2 * (3 * 96 + 4 * 39 + 2 * (43 + 128) + text_temporary);
        uint64_t decoder = parse > construct ? parse : construct;
        /* Existing immutable snapshot80 +786 code units, nested KPN32768,
         * control magic8 and metadata8 overlap the one fresh decoder. */
        uint64_t control = 80 + 2 * 786 + 32768 + 8 + 8 + decoder;
        live = 265 * ordinary + control;
    } else {
        /* One admitted operation: probe writer/result/direct9 each, direct
         * result21, metadata8 and selector's <=11 code-unit lookup string.
         * checkUpdate3 and borrowed materialization are smaller. */
        live = 3 * 9 + 21 + 8 + 2 * 11;
    }
    uint64_t total;
    if (!kvpn_production_add_v1(retained, callbacks, &total) ||
        !kvpn_production_add_v1(total, acquire > live ? acquire : live, &total) || total > capacity) return 5;
    *out = total;
    return 0;
}
int32_t kvpn_production_backing_sum_v1(uint64_t shared, uint64_t frames,
    uint64_t frame_size, uint64_t fixed, uint64_t per_frame, uint64_t capacity,
    uint64_t *out) {
    if (!out) return 2;
    *out = 0;
    if (!shared || !frames || !frame_size || frames % frame_size) return 2;
    uint64_t count = frames / frame_size, total;
    if (per_frame > UINT64_MAX / count ||
        !kvpn_production_add_v1(shared, frames, &total) ||
        !kvpn_production_add_v1(total, fixed, &total) ||
        !kvpn_production_add_v1(total, count * per_frame, &total) || total > capacity) return 5;
    *out = total;
    return 0;
}
int kvpn_production_metadata_v1(const kvpn_production_memory_v1 *scalars, size_t scalar_count,
    const kvpn_production_memory_v1 *bytes, size_t byte_count) {
    if (!scalars || scalar_count == 0 || scalar_count > 2 || byte_count > 2 || (byte_count && !bytes)) return 0;
    for (size_t i = 0; i < scalar_count; ++i) {
        size_t alignment;
        if (scalars[i].length == sizeof(uint32_t)) alignment = _Alignof(uint32_t);
        else if (scalars[i].length == sizeof(uint64_t)) alignment = _Alignof(uint64_t);
        else return 0;
        if (!address_range(scalars[i].data, scalars[i].length) || (uintptr_t)scalars[i].data % alignment) return 0;
        for (size_t j = 0; j < i; ++j)
            if (!kvpn_production_disjoint_v1(scalars[i].data, scalars[i].length, scalars[j].data, scalars[j].length)) return 0;
        for (size_t j = 0; j < byte_count; ++j) {
            /* Null/empty byte spans cannot alias. Their semantic rejection is
             * later, after structurally valid metadata has been zeroed. */
            if (!bytes[j].data || !bytes[j].length) continue;
            if (!kvpn_production_disjoint_v1(scalars[i].data, scalars[i].length, bytes[j].data, bytes[j].length)) return 0;
        }
    }
    return 1;
}
void kvpn_production_wipe_v1(void *data, size_t length) {
    volatile uint8_t *bytes = data;
    if (bytes) while (length--) *bytes++ = 0;
}

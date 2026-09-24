// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_abi.h"
#include "kvpn_production_facade_v1.h"
#include "production_scoped_exports_v1.h"
#include "kvpn_production_spans_v1.h"
#include "kvpn_android_callbacks.h"
#include <stdlib.h>
#include <string.h>
#ifdef KVPN_ANDROID_PLATFORM_INTERNAL_V1
void kvpn_task7_rejection_v1(uint8_t, uint8_t, int32_t);
#endif

int32_t kvpn_prod_run_probe_core_v1(kvpn_output_call_v1 *call, uint64_t parent, const uint8_t *request, uint32_t length, uint8_t *output, uint32_t *written) {
    int32_t status = kvpn_go_prod_run_probe_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, (uint8_t *)request, length, output, written);
    if (status < 0 || status > 26 || status == 19 || status == 20 || (!status && *written != 21) || (status && *written)) {
        kvpn_output_note_failure_v1(call, 18); return 18;
    }
    return status;
}
int32_t kvpn_prod_run_probe_v1(uint64_t parent, const uint8_t *request, uint32_t length, uint8_t *output, uint32_t capacity, uint32_t *written) {
    kvpn_production_memory_v1 scalar = {written, sizeof(*written)}, bytes[2] = {{request, length}, {output, capacity}};
    if (!kvpn_production_metadata_v1(&scalar, 1, bytes, 2)) return 2;
    *written = 0;
    if (!parent || length != 9) return 2;
    kvpn_production_span_v1 input, span;
    int32_t status = kvpn_production_span_v1_init((void *)request, length, 0, length, 0, length, 9, 9, &input);
    if (!status) status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 21, UINT32_MAX, &span);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, span.data, span.length)) return 2;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_prod_run_probe_core_v1(&call, parent, input.data, input.length, stage->bytes, &stage->written);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, 21); *written = 21; }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_open_stream_core_v1(kvpn_output_call_v1 *call, uint64_t parent, const uint8_t *request, uint32_t length, uint64_t *child) {
    int32_t status = kvpn_go_prod_open_stream_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, (uint8_t *)request, length, child);
    if (status < 0 || status > 26 || status == 19 || status == 20 || (!status && !*child) || (status && *child)) {
        kvpn_output_note_failure_v1(call, 18); return 18;
    }
    return status;
}
int32_t kvpn_prod_discard_stream_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child) {
    return kvpn_go_discard_prod_stream_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child);
}
int32_t kvpn_prod_open_stream_v1(uint64_t parent, const uint8_t *request, uint32_t length, uint64_t *child) {
    kvpn_production_memory_v1 scalar = {child, sizeof(*child)}, bytes = {request, length};
    if (!kvpn_production_metadata_v1(&scalar, 1, &bytes, 1)) return 2;
    *child = 0;
    if (!parent) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init((void *)request, length, 0, length, 0, length, 7, 259, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    uint64_t staged = 0; uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 2);
    if (!status) status = kvpn_prod_open_stream_core_v1(&call, parent, span.data, span.length, &staged);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { *child = staged; published = 1; }
    }
    if (staged && !published) {
        if (kvpn_prod_discard_stream_core_v1(&call, parent, staged)) status = 18;
        else discarded = 1;
    }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

int32_t kvpn_prod_receive_packet_core_v1(kvpn_output_call_v1 *call, uint64_t parent,
    uint8_t *stage, uint32_t capacity, uint32_t *written, uint64_t *token) {
    int32_t status = kvpn_go_prod_receive_packet_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, stage, capacity, written, token);
    if (status < 0 || status > 26 || status == 19 || status == 20 ||
        (!status && (!*written || *written > capacity || !*token)) || (status && (*written || *token))) {
        kvpn_output_note_failure_v1(call, 18);
        return 18;
    }
    return status;
}
int32_t kvpn_prod_discard_packet_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t token) {
    return kvpn_go_discard_prod_packet_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, token);
}
int32_t kvpn_prod_receive_packet_v1(uint64_t parent, uint8_t *output, uint32_t capacity, uint32_t *written, uint64_t *token) {
    kvpn_production_memory_v1 scalars[2] = {{written, sizeof(*written)}, {token, sizeof(*token)}}, bytes = {output, capacity};
    if (!kvpn_production_metadata_v1(scalars, 2, &bytes, 1)) return 2;
    *written = 0; *token = 0;
    if (!parent) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 1, 65535, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 3);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_prod_receive_packet_core_v1(&call, parent, stage->bytes, span.length, &stage->written, &stage->token);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, stage->written); *written = stage->written; *token = stage->token; published = 1; }
    }
    if (stage && stage->token && !published) {
        if (kvpn_prod_discard_packet_core_v1(&call, parent, stage->token)) status = 18;
        else discarded = 1;
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

int32_t kvpn_prod_next_control_core_v1(kvpn_output_call_v1 *call, uint64_t parent,
    uint8_t *stage, uint32_t capacity, uint32_t *written) {
    int32_t status = kvpn_go_prod_next_control_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, stage, capacity, written);
#ifdef KVPN_ANDROID_PLATFORM_INTERNAL_V1
    /* Distinguish the raw export result from this facade's shape rejection. */
    if (status < 0 || status > 26 || status == 19) kvpn_task7_rejection_v1(0, 11, status);
    else if (!status && (*written < 32 || *written > capacity)) kvpn_task7_rejection_v1(0, 12, 18);
    else if (status && *written) kvpn_task7_rejection_v1(0, 13, 18);
    else if (status && status != 20) kvpn_task7_rejection_v1(0, 10, status);
#endif
    if (status < 0 || status > 26 || status == 19 ||
        (!status && (*written < 32 || *written > capacity)) || (status && *written)) {
        kvpn_output_note_failure_v1(call, 18);
        return 18;
    }
    return status;
}
int32_t kvpn_prod_next_control_v1(uint64_t parent, uint8_t *output, uint32_t capacity, uint32_t *written) {
    kvpn_production_memory_v1 scalar = {written, sizeof(*written)}, bytes = {output, capacity};
    if (!kvpn_production_metadata_v1(&scalar, 1, &bytes, 1)) return 2;
    *written = 0;
    if (!parent) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 1, 32800, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_CONTROL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_prod_next_control_core_v1(&call, parent, stage->bytes, span.length, &stage->written);
    if (!status) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &publish);
        if (!status && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, stage->written); *written = stage->written; }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_submit_packet_core_v1(kvpn_output_call_v1 *call, uint64_t parent, const uint8_t *input, uint32_t length) {
    return kvpn_go_prod_submit_packet_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, (uint8_t *)input, length);
}
int32_t kvpn_prod_submit_packet_v1(uint64_t parent, const uint8_t *input, uint32_t length) {
    if (!parent || !input || !length) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init((void *)input, length, 0, length, 0, length, 1, 65535, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_submit_packet_core_v1(&call, parent, span.data, span.length));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_cancel_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_prod_cancel_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent);
}
int32_t kvpn_prod_close_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_prod_close_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent);
}

int32_t kvpn_prod_cancel_v1(uint64_t parent) {
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, &call, &absent);
    if (absent) return kvpn_go_prod_retired_result_v1(parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_prod_cancel_core_v1(&call, parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_close_v1(uint64_t parent) {
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, &call, &absent);
    if (absent) return kvpn_go_prod_retired_result_v1(parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_prod_close_core_v1(&call, parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    if (!status && kvpn_android_finalize_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

uint64_t kvpn_platform_call_backing_v1(void) {
    return sizeof(kvpn_android_callbacks_v1) + 4 * sizeof(kvpn_platform_borrow_v1) +
        sizeof(kvpn_platform_finalize_v1) + sizeof(kvpn_cb_capture_sizes_v1) +
        sizeof(kvpn_cb_capture_output_v1) + sizeof(kvpn_cb_socket_expectation_v1) +
        sizeof(kvpn_cb_network_snapshot_v1);
}
int32_t kvpn_prod_direct_backing_v1(uint64_t capacity, uint64_t *out) {
    if (!out) return 2;
    *out = 0;
    uint64_t shared = 0, owner = 0, frames = 0, go_overlap = 0, fixed;
    int32_t status = kvpn_output_layout_v1(KVPN_OUTPUT_PRODUCTION_V1, &shared, &owner, &frames);
    if (status) return status;
    if (!frames || frames % sizeof(kvpn_output_call_v1)) return 18;
    status = kvpn_go_output_overlap_backing_v1(frames / sizeof(kvpn_output_call_v1), &go_overlap);
    if (status) return status;
    /* Gate shared storage already contains every output/platform owner. The
     * four synchronous platform roles are ordinary, cancel and two queries;
     * finalization has one noncopyable claim after End. Java/JNI-owned backing
     * is a separate trusted caller charge, never inferred from caller arenas. */
    uint64_t platform = kvpn_platform_call_backing_v1();
    if (!kvpn_production_add_v1(platform, go_overlap, &fixed)) return 5;
    return kvpn_production_backing_sum_v1(shared, frames, sizeof(kvpn_output_call_v1),
        fixed, sizeof(kvpn_production_output_stage_v1), capacity, out);
}

int32_t kvpn_prod_open_v1(const uint8_t *request, uint32_t request_length,
    uint64_t lease, uint64_t *parent, uint8_t *snapshot, uint32_t capacity, uint32_t *written) {
    const kvpn_production_memory_v1 metadata[2] = {{parent, sizeof(*parent)}, {written, sizeof(*written)}};
    const kvpn_production_memory_v1 spans[2] = {{request, request_length}, {snapshot, capacity}};
    if (!kvpn_production_metadata_v1(metadata, 2, spans, 2)) return 2;
    *parent = 0; *written = 0;
    if (!lease || !request || !request_length || !snapshot) return 2;
    kvpn_production_span_v1 input, output;
    int32_t status = kvpn_production_span_v1_init((void *)request, request_length, 0, request_length,
        0, request_length, 1, 2721575, &input);
    if (status) return status;
    status = kvpn_production_span_v1_init(snapshot, capacity, 0, capacity, 0, capacity, 32768, UINT32_MAX, &output);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, output.data, output.length)) return 2;
    uint64_t external = 0;
    status = kvpn_prod_direct_backing_v1(128ULL << 20, &external);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_open_v1(lease, KVPN_OUTPUT_PRODUCTION_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t entered_core = 0, published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 1);
    if (!status) {
        stage = calloc(1, sizeof(*stage));
        if (!stage) status = 5;
    }
    if (!status) {
        entered_core = 1;
        status = kvpn_prod_open_core_v1(&call, kvpn_android_callbacks_table_v1(), input.data,
            input.length, stage->bytes, external, &stage->parent, &stage->written);
        if (status < 0 || status > 26 || status == 19 || status == 20 ||
            (!status && (!stage->parent || stage->written < 220 || stage->written > 32768))) {
            kvpn_output_note_failure_v1(&call, 18);
            status = 18;
        }
        if (!status) {
            uint8_t commit = 0;
            status = kvpn_output_try_commit_v1(&call, 0, &commit);
            if (!status && !commit) status = 18;
            if (!status) status = kvpn_output_opening_published_v1(&call);
            if (!status) {
                memcpy(output.data, stage->bytes, stage->written);
                *parent = stage->parent;
                *written = stage->written;
                published = 1;
            }
        }
        if (!published && stage->parent) {
            if (kvpn_prod_discard_parent_core_v1(&call, stage->parent)) status = 18;
        }
    }
    if (!entered_core && kvpn_output_opening_stage_v1(&call, 0)) status = 18;
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    if (!published && kvpn_android_finalize_failed_opening_v1(lease, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

int32_t kvpn_prod_open_core_v1(kvpn_output_call_v1 *call, const kvpn_android_callbacks_v1 *platform,
    const uint8_t *request, uint32_t request_length, uint8_t *stage, uint64_t external,
    uint64_t *parent, uint32_t *written) {
    uint8_t holder = 2;
    int32_t status = kvpn_go_prod_open_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        (kvpn_android_callbacks_v1 *)platform, call->owner, call->serial, call->epoch,
        (uint8_t *)request, request_length, stage, 32768, external, parent, written, &holder);
    if (holder > 1 || kvpn_output_opening_stage_v1(call, holder)) {
        kvpn_output_note_failure_v1(call, 18);
        return 18;
    }
    return status;
}

int32_t kvpn_prod_discard_parent_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_discard_prod_parent_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent);
}

int32_t kvpn_prod_confirm_socket_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t token, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    return kvpn_go_prod_confirm_socket_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, token, protected_ok, has_network, network);
}
int32_t kvpn_prod_confirm_socket_v1(uint64_t parent, uint64_t token, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    if (!parent || protected_ok > 1 || has_network > 1 || ((has_network == 0) != (network == 0))) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_confirm_socket_core_v1(&call, parent, token, protected_ok, has_network, network));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_confirm_packet_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t token, uint32_t length) {
    return kvpn_go_prod_confirm_packet_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, token, length);
}
int32_t kvpn_prod_confirm_packet_v1(uint64_t parent, uint64_t token, uint32_t length) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_confirm_packet_core_v1(&call, parent, token, length));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_reject_packet_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t token) {
    return kvpn_go_prod_reject_packet_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, token);
}
int32_t kvpn_prod_reject_packet_v1(uint64_t parent, uint64_t token) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_reject_packet_core_v1(&call, parent, token));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_handover_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint8_t has_network, uint64_t network) {
    return kvpn_go_prod_handover_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, has_network, network);
}
int32_t kvpn_prod_handover_v1(uint64_t parent, uint8_t has_network, uint64_t network) {
    if (!parent || has_network > 1 || ((has_network == 0) != (network == 0))) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_handover_core_v1(&call, parent, has_network, network));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_prod_reconnect_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint8_t reason) {
    return kvpn_go_prod_reconnect_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, reason);
}
int32_t kvpn_production_commit_scalar_v1(kvpn_output_call_v1 *call, int32_t native) {
    if (native < 0 || native > 26 || native == 19 || native == 20) {
        kvpn_output_note_failure_v1(call, 18);
        return 18;
    }
    uint8_t publish = 0;
    int32_t status = kvpn_output_try_commit_v1(call, native, &publish);
    if (!status && !publish) {
        kvpn_output_note_failure_v1(call, 18);
        return 18;
    }
    return status;
}
int32_t kvpn_prod_reconnect_v1(uint64_t parent, uint8_t reason) {
    if (!parent || reason < 1 || reason > 3) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_prod_reconnect_core_v1(&call, parent, reason));
    kvpn_output_end_v1(&call);
    return status;
}

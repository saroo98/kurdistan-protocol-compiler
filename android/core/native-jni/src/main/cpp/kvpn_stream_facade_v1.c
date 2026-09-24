// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_abi.h"
#include "kvpn_production_facade_v1.h"
#include "production_scoped_exports_v1.h"
#include "kvpn_production_spans_v1.h"
#include "kvpn_android_callbacks.h"
#include <stdlib.h>
#include <string.h>

int32_t kvpn_stream_receive_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child,
    uint8_t *output, uint32_t capacity, uint32_t *written, uint64_t *token) {
    int32_t status = kvpn_go_stream_receive_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child, output, capacity, written, token);
    if (status < 0 || status > 26 || status == 20 || (!status && (!*written || *written > capacity || !*token)) ||
        (status && (*written || *token))) { kvpn_output_note_failure_v1(call, 18); return 18; }
    return status;
}
int32_t kvpn_stream_discard_delivery_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child, uint64_t token) {
    return kvpn_go_discard_stream_delivery_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child, token);
}
int32_t kvpn_stream_receive_v1(uint64_t parent, uint64_t child, uint8_t *output, uint32_t capacity, uint32_t *written, uint64_t *token) {
    kvpn_production_memory_v1 scalars[2] = {{written, sizeof(*written)}, {token, sizeof(*token)}}, bytes = {output, capacity};
    if (!kvpn_production_metadata_v1(scalars, 2, &bytes, 1)) return 2;
    *written = 0; *token = 0;
    if (!parent || !child) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 1, 16384, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_production_output_stage_v1 *stage = NULL;
    uint8_t published = 0, discarded = 0;
    status = kvpn_output_expect_receipt_v1(&call, 4);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_stream_receive_core_v1(&call, parent, child, stage->bytes, span.length, &stage->written, &stage->token);
    if (status == 0 || status == 19) {
        uint8_t publish = 0;
        status = kvpn_output_try_commit_v1(&call, status, &publish);
        if ((status == 0 || status == 19) && !publish) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (publish) {
            if (!status) { memcpy(span.data, stage->bytes, stage->written); *written = stage->written; *token = stage->token; }
            published = 1;
        }
    }
    if (stage && stage->token && !published) {
        if (kvpn_stream_discard_delivery_core_v1(&call, parent, child, stage->token)) status = 18;
        else discarded = 1;
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    if (discarded && kvpn_android_finalize_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1)) status = 18;
    return status;
}

int32_t kvpn_stream_send_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child, const uint8_t *input, uint32_t length) {
    return kvpn_go_stream_send_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child, (uint8_t *)input, length);
}
int32_t kvpn_stream_send_v1(uint64_t parent, uint64_t child, const uint8_t *input, uint32_t length) {
    if (!parent || !child || !input || !length) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init((void *)input, length, 0, length, 0, length, 1, 16384, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_send_core_v1(&call, parent, child, span.data, span.length));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_stream_confirm_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child, uint64_t token, uint32_t length) {
    return kvpn_go_stream_confirm_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child, token, length);
}
int32_t kvpn_stream_confirm_v1(uint64_t parent, uint64_t child, uint64_t token, uint32_t length) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_confirm_core_v1(&call, parent, child, token, length));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_stream_reject_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child, uint64_t token) {
    return kvpn_go_stream_reject_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child, token);
}
int32_t kvpn_stream_reject_v1(uint64_t parent, uint64_t child, uint64_t token) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_reject_core_v1(&call, parent, child, token));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_stream_half_close_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child) {
    return kvpn_go_stream_half_close_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child);
}
int32_t kvpn_stream_half_close_v1(uint64_t parent, uint64_t child) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_half_close_core_v1(&call, parent, child));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_stream_cancel_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child) {
    return kvpn_go_stream_cancel_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child);
}
int32_t kvpn_stream_cancel_v1(uint64_t parent, uint64_t child) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_cancel_core_v1(&call, parent, child));
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_stream_close_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t child) {
    return kvpn_go_stream_close_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, child);
}
int32_t kvpn_stream_close_v1(uint64_t parent, uint64_t child) {
    if (!parent) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_PRODUCTION_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_production_commit_scalar_v1(&call, kvpn_stream_close_core_v1(&call, parent, child));
    kvpn_output_end_v1(&call);
    return status;
}

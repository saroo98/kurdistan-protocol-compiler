// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_abi.h"
#include "kvpn_production_facade_v1.h"
#include "production_scoped_exports_v1.h"
#include "kvpn_production_spans_v1.h"
#include "kvpn_android_callbacks.h"
#include <stdlib.h>
#include <string.h>

int32_t kvpn_maintenance_materialize_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t candidate, uint8_t *output, uint32_t capacity, uint32_t *written) {
    int32_t status = kvpn_go_maintenance_materialize_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, candidate, output, capacity, written);
    if (status < 0 || status > 26 || status == 19 || status == 20 || (!status && (!*written || *written > capacity)) || (status && *written)) {
        kvpn_output_note_failure_v1(call, 18); return 18;
    }
    return status;
}
int32_t kvpn_maintenance_release_update_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t candidate) {
    int32_t status = kvpn_go_maintenance_release_update_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, candidate);
    if (status < 0 || status > 26 || status == 19 || status == 20) { kvpn_output_note_failure_v1(call, 18); return 18; }
    return status;
}
int32_t kvpn_maintenance_run_probe_core_v1(kvpn_output_call_v1 *call, uint64_t parent, const uint8_t *request, uint32_t length, uint8_t *output, uint32_t *written) {
    int32_t status = kvpn_go_maintenance_run_probe_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, (uint8_t *)request, length, output, written);
    if (status < 0 || status > 26 || status == 19 || status == 20 || (!status && *written != 21) || (status && *written)) {
        kvpn_output_note_failure_v1(call, 18); return 18;
    }
    return status;
}
int32_t kvpn_maintenance_materialize_v1(uint64_t parent, uint64_t candidate, uint8_t *output, uint32_t capacity, uint32_t *written) {
    kvpn_production_memory_v1 scalar = {written, sizeof(*written)}, bytes = {output, capacity};
    if (!kvpn_production_metadata_v1(&scalar, 1, &bytes, 1)) return 2;
    *written = 0;
    if (!parent || !candidate) return 2;
    kvpn_production_span_v1 span;
    int32_t status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 1, UINT32_MAX, &span);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_materialize_core_v1(&call, parent, candidate, stage->bytes,
        span.length < sizeof(stage->bytes) ? span.length : sizeof(stage->bytes), &stage->written);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, stage->written); *written = stage->written; }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}
int32_t kvpn_maintenance_release_update_v1(uint64_t parent, uint64_t candidate) {
    if (!parent || !candidate) return 2;
    kvpn_output_call_v1 call = {0};
    int32_t status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_release_update_core_v1(&call, parent, candidate);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
    }
    kvpn_output_end_v1(&call);
    return status;
}
int32_t kvpn_maintenance_run_probe_v1(uint64_t parent, const uint8_t *request, uint32_t length, uint8_t *output, uint32_t capacity, uint32_t *written) {
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
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_run_probe_core_v1(&call, parent, input.data, input.length, stage->bytes, &stage->written);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, 21); *written = 21; }
    }
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_maintenance_discard_candidate_core_v1(kvpn_output_call_v1 *call, uint64_t parent, uint64_t candidate) {
    return kvpn_go_discard_maintenance_candidate_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, candidate);
}
int32_t kvpn_maintenance_check_update_core_v1(kvpn_output_call_v1 *call, uint64_t parent,
    const uint8_t *request, uint32_t length, kvpn_maintenance_output_stage_v1 *stage) {
    kvpn_maintenance_decision_v1 *d = &stage->decision;
    int32_t status = kvpn_go_maintenance_check_update_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent, (uint8_t *)request, length, d);
    stage->candidate = d->candidate;
    if (status < 0 || status > 26 || status == 19 || status == 20) goto malformed;
    if (status) return status;
    if (d->result > 23 || d->result == 3 || d->result == 4 || d->result == 8) goto malformed;
    if (!d->result) {
        if (!d->candidate || d->deployment != 1 || !d->generation || d->expiry > 1 ||
            d->rotation > 7 || (d->rotation & 2) || d->revocation || d->compatibility ||
            !d->artifact_length || d->artifact_length > 1052763) goto malformed;
        for (size_t i = 0; i < 10; ++i) if (d->changes[i] > 1) goto malformed;
    } else {
        if (d->candidate || d->generation || d->artifact_length || d->deployment || d->expiry ||
            d->rotation || d->revocation || d->compatibility) goto malformed;
        for (size_t i = 0; i < 10; ++i) if (d->changes[i]) goto malformed;
    }
    stage->bytes[0] = 1;
    stage->bytes[1] = (uint8_t)(d->result >> 8); stage->bytes[2] = (uint8_t)d->result;
    stage->written = 3;
    if (!d->result) {
        for (size_t i = 0; i < 8; ++i) {
            stage->bytes[3+i] = (uint8_t)(d->candidate >> (56-8*i));
            stage->bytes[12+i] = (uint8_t)(d->generation >> (56-8*i));
        }
        stage->bytes[11] = d->deployment; stage->bytes[20] = d->expiry;
        stage->bytes[21] = d->rotation; stage->bytes[22] = d->revocation; stage->bytes[23] = d->compatibility;
        memcpy(stage->bytes+24, d->changes, 10);
        for (size_t i = 0; i < 4; ++i) stage->bytes[34+i] = (uint8_t)(d->artifact_length >> (24-8*i));
        stage->written = 38;
    }
    return 0;
malformed:
    kvpn_output_note_failure_v1(call, 18);
    return 18;
}
int32_t kvpn_maintenance_check_update_v1(uint64_t parent, const uint8_t *request, uint32_t length,
    uint8_t *output, uint32_t capacity, uint32_t *written) {
    kvpn_production_memory_v1 scalar = {written, sizeof(*written)}, bytes[2] = {{request, length}, {output, capacity}};
    if (!kvpn_production_metadata_v1(&scalar, 1, bytes, 2)) return 2;
    *written = 0;
    if (!parent || length != 3) return 2;
    kvpn_production_span_v1 input, span;
    int32_t status = kvpn_production_span_v1_init((void *)request, length, 0, length, 0, length, 3, 3, &input);
    if (!status) status = kvpn_production_span_v1_init(output, capacity, 0, capacity, 0, capacity, 38, UINT32_MAX, &span);
    if (status) return status;
    if (!kvpn_production_disjoint_v1(input.data, input.length, span.data, span.length)) return 2;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_parent_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, KVPN_OUTPUT_NORMAL_V1, &call);
    if (status) return status;
    kvpn_maintenance_output_stage_v1 *stage = NULL;
    uint8_t published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 2);
    if (!status) { stage = calloc(1, sizeof(*stage)); if (!stage) status = 5; }
    if (!status) status = kvpn_maintenance_check_update_core_v1(&call, parent, input.data, input.length, stage);
    if (!status) {
        uint8_t commit = 0;
        status = kvpn_output_try_commit_v1(&call, 0, &commit);
        if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
        if (!status) { memcpy(span.data, stage->bytes, stage->written); *written = stage->written; published = 1; }
    }
    if (stage && !published && stage->candidate && kvpn_maintenance_discard_candidate_core_v1(&call, parent, stage->candidate)) status = 18;
    if (stage) { kvpn_production_wipe_v1(stage, sizeof(*stage)); free(stage); }
    kvpn_output_end_v1(&call);
    return status;
}

int32_t kvpn_maintenance_direct_backing_v1(uint64_t capacity, uint64_t *out) {
    if (!out) return 2;
    *out = 0;
    uint64_t shared = 0, owner = 0, frames = 0, go_overlap = 0, fixed;
    int32_t status = kvpn_output_layout_v1(KVPN_OUTPUT_MAINTENANCE_V1, &shared, &owner, &frames);
    if (status) return status;
    if (!frames || frames % sizeof(kvpn_output_call_v1)) return 18;
    status = kvpn_go_output_overlap_backing_v1(frames / sizeof(kvpn_output_call_v1), &go_overlap);
    if (status) return status;
    if (!kvpn_production_add_v1(kvpn_platform_call_backing_v1(), go_overlap, &fixed)) return 5;
    return kvpn_production_backing_sum_v1(shared, frames, sizeof(kvpn_output_call_v1),
        fixed, sizeof(kvpn_maintenance_output_stage_v1), capacity, out);
}
int32_t kvpn_maintenance_open_core_v1(kvpn_output_call_v1 *call, const kvpn_android_callbacks_v1 *platform,
    const uint8_t *request, uint32_t length, uint64_t external, uint64_t *parent) {
    uint8_t holder = 2;
    int32_t status = kvpn_go_maintenance_open_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        (kvpn_android_callbacks_v1 *)platform, call->owner, call->serial, call->epoch,
        (uint8_t *)request, length, external, parent, &holder);
    if (holder > 1 || kvpn_output_opening_stage_v1(call, holder) || status < 0 || status > 26 ||
        status == 19 || status == 20 || (!status && !*parent)) {
        kvpn_output_note_failure_v1(call, 18); return 18;
    }
    return status;
}
int32_t kvpn_maintenance_discard_parent_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_discard_maintenance_parent_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(),
        call->owner, call->serial, call->epoch, parent);
}
int32_t kvpn_maintenance_open_v1(const uint8_t *request, uint32_t length, uint64_t lease, uint64_t *parent) {
    kvpn_production_memory_v1 scalar = {parent, sizeof(*parent)}, bytes = {request, length};
    if (!kvpn_production_metadata_v1(&scalar, 1, &bytes, 1)) return 2;
    *parent = 0;
    if (!lease) return 2;
    kvpn_production_span_v1 input;
    int32_t status = kvpn_production_span_v1_init((void *)request, length, 0, length, 0, length, 1, 2721575, &input);
    if (status) return status;
    uint64_t external = 0;
    status = kvpn_maintenance_direct_backing_v1(128ULL << 20, &external);
    if (status) return status;
    kvpn_output_call_v1 call = {0};
    status = kvpn_output_begin_open_v1(lease, KVPN_OUTPUT_MAINTENANCE_V1, &call);
    if (status) return status;
    uint64_t staged = 0;
    uint8_t entered = 0, published = 0;
    status = kvpn_output_expect_receipt_v1(&call, 1);
    if (!status) {
        entered = 1;
        status = kvpn_maintenance_open_core_v1(&call, kvpn_android_callbacks_table_v1(), input.data, input.length, external, &staged);
        if (!status) {
            uint8_t commit = 0;
            status = kvpn_output_try_commit_v1(&call, 0, &commit);
            if (!status && !commit) { kvpn_output_note_failure_v1(&call, 18); status = 18; }
            if (!status) status = kvpn_output_opening_published_v1(&call);
            if (!status) { *parent = staged; published = 1; }
        }
        if (!published && staged && kvpn_maintenance_discard_parent_core_v1(&call, staged)) status = 18;
    }
    if (!entered && kvpn_output_opening_stage_v1(&call, 0)) status = 18;
    kvpn_output_end_v1(&call);
    if (!published && kvpn_android_finalize_failed_opening_v1(lease, KVPN_OUTPUT_MAINTENANCE_V1)) status = 18;
    return status;
}
int32_t kvpn_maintenance_cancel_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_maintenance_cancel_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(), call->owner, call->serial, call->epoch, parent);
}
int32_t kvpn_maintenance_close_core_v1(kvpn_output_call_v1 *call, uint64_t parent) {
    return kvpn_go_maintenance_close_v1((kvpn_output_callbacks_v1 *)kvpn_output_callbacks_table_v1(), call->owner, call->serial, call->epoch, parent);
}
int32_t kvpn_maintenance_cancel_v1(uint64_t parent) {
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, &call, &absent);
    if (absent) return kvpn_go_maintenance_retired_result_v1(parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_cancel_core_v1(&call, parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    return status;
}
int32_t kvpn_maintenance_close_v1(uint64_t parent) {
    kvpn_output_call_v1 call = {0};
    uint8_t absent = 0;
    int32_t status = kvpn_output_begin_lifecycle_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1, &call, &absent);
    if (absent) return kvpn_go_maintenance_retired_result_v1(parent);
    if (status) return status;
    status = kvpn_output_expect_receipt_v1(&call, 0);
    if (!status) status = kvpn_maintenance_close_core_v1(&call, parent);
    status = kvpn_output_retirement_drain_v1(&call, status);
    kvpn_output_end_v1(&call);
    if (!status && kvpn_android_finalize_parent_v1(parent, KVPN_OUTPUT_MAINTENANCE_V1)) status = 18;
    return status;
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "output_callbacks_v1.h"

/* By-value trampoline results keep output scratch in C, rather than making
 * a Go local escape through a cgo output pointer on every observer call. */
kvpn_output_clock_result_v1 kvpn_output_clock_sample_v1(const kvpn_output_callbacks_v1 *t) {
    kvpn_output_clock_result_v1 r = {0};
    r.status = t->monotonic_now_ns(&r.now);
    return r;
}
kvpn_output_claim_result_v1 kvpn_output_prod_claim_result_v1(const kvpn_output_callbacks_v1 *t, uint64_t o, uint64_t c, uint64_t e, uint8_t k, uint64_t p, uint64_t h, uint64_t d) {
    kvpn_output_claim_result_v1 r = {0};
    r.status = t->prod_claim_receipt(o, c, e, k, p, h, d, &r.retired);
    return r;
}
kvpn_output_claim_result_v1 kvpn_output_maint_claim_result_v1(const kvpn_output_callbacks_v1 *t, uint64_t o, uint64_t c, uint64_t e, uint8_t k, uint64_t p, uint64_t h, uint64_t d) {
    kvpn_output_claim_result_v1 r = {0};
    r.status = t->maint_claim_receipt(o, c, e, k, p, h, d, &r.retired);
    return r;
}

int32_t kvpn_output_table_valid_v1(const kvpn_output_callbacks_v1 *table) {
    return table && table->version == 1 && table->struct_size == sizeof(*table)
        && table->monotonic_now_ns
        && table->prod_validate_invocation
        && table->prod_bind_parent
        && table->prod_bind_handle
        && table->prod_bind_lane
        && table->prod_prepare
        && table->prod_parent_terminal
        && table->prod_attempt_terminal
        && table->prod_claim_receipt
        && table->prod_finish_receipt
        && table->prod_resource_retired
        && table->maint_validate_invocation
        && table->maint_bind_parent
        && table->maint_bind_handle
        && table->maint_bind_lane
        && table->maint_supersede_normal
        && table->maint_prepare
        && table->maint_parent_terminal
        && table->maint_candidate_terminal
        && table->maint_claim_receipt
        && table->maint_finish_receipt
        && table->maint_resource_retired;
}

int32_t kvpn_output_monotonic_now_ns_v1(const kvpn_output_callbacks_v1 *table, uint64_t * now) {
    return table->monotonic_now_ns(now);
}
int32_t kvpn_output_prod_validate_invocation_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch) {
    return table->prod_validate_invocation(owner, call, epoch);
}
int32_t kvpn_output_prod_bind_parent_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch) {
    return table->prod_bind_parent(owner, call, epoch);
}
int32_t kvpn_output_prod_bind_handle_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t parent) {
    return table->prod_bind_handle(owner, call, epoch, parent);
}
int32_t kvpn_output_prod_bind_lane_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint16_t lane, uint64_t attempt) {
    return table->prod_bind_lane(owner, call, epoch, lane, attempt);
}
int32_t kvpn_output_prod_prepare_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t attempt, uint64_t child, uint64_t delivery, uint8_t has_deadline, uint64_t clock_sample_ns, uint64_t remaining_ns, uint8_t terminal) {
    return table->prod_prepare(owner, call, epoch, attempt, child, delivery, has_deadline, clock_sample_ns, remaining_ns, terminal);
}
void kvpn_output_prod_parent_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, int32_t reason) {
    table->prod_parent_terminal(owner, epoch, reason);
}
void kvpn_output_prod_attempt_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint64_t identity, int32_t reason) {
    table->prod_attempt_terminal(owner, epoch, identity, reason);
}
int32_t kvpn_output_prod_claim_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, uint8_t * already_retired) {
    return table->prod_claim_receipt(owner, call, epoch, kind, parent, child, delivery, already_retired);
}
int32_t kvpn_output_prod_finish_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, int32_t cleanup) {
    return table->prod_finish_receipt(owner, call, epoch, kind, parent, child, delivery, cleanup);
}
void kvpn_output_prod_resource_retired_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t attempt, uint64_t child, uint64_t delivery, int32_t cleanup) {
    table->prod_resource_retired(owner, epoch, kind, parent, attempt, child, delivery, cleanup);
}
int32_t kvpn_output_maint_validate_invocation_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch) {
    return table->maint_validate_invocation(owner, call, epoch);
}
int32_t kvpn_output_maint_bind_parent_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch) {
    return table->maint_bind_parent(owner, call, epoch);
}
int32_t kvpn_output_maint_bind_handle_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t parent) {
    return table->maint_bind_handle(owner, call, epoch, parent);
}
int32_t kvpn_output_maint_bind_lane_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t revocation) {
    return table->maint_bind_lane(owner, call, epoch, revocation);
}
int32_t kvpn_output_maint_supersede_normal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch) {
    return table->maint_supersede_normal(owner, call, epoch);
}
int32_t kvpn_output_maint_prepare_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t candidate, uint8_t has_deadline, uint64_t clock_sample_ns, uint64_t remaining_ns, uint8_t terminal) {
    return table->maint_prepare(owner, call, epoch, candidate, has_deadline, clock_sample_ns, remaining_ns, terminal);
}
void kvpn_output_maint_parent_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, int32_t reason) {
    table->maint_parent_terminal(owner, epoch, reason);
}
void kvpn_output_maint_candidate_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint64_t identity, int32_t reason) {
    table->maint_candidate_terminal(owner, epoch, identity, reason);
}
int32_t kvpn_output_maint_claim_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, uint8_t * already_retired) {
    return table->maint_claim_receipt(owner, call, epoch, kind, parent, child, delivery, already_retired);
}
int32_t kvpn_output_maint_finish_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, int32_t cleanup) {
    return table->maint_finish_receipt(owner, call, epoch, kind, parent, child, delivery, cleanup);
}
void kvpn_output_maint_resource_retired_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, int32_t cleanup) {
    table->maint_resource_retired(owner, epoch, kind, parent, child, cleanup);
}

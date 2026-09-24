// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_OUTPUT_CALLBACKS_V1_H
#define KVPN_OUTPUT_CALLBACKS_V1_H
#include <stdint.h>

/* Private in-process ABI. Never serialized. The provider owns this immutable
 * table for the loaded-library lifetime; it contains no Java or Go pointers. */
typedef struct kvpn_output_callbacks_v1 {
    uint32_t version, struct_size;
    int32_t (*monotonic_now_ns)(uint64_t *);
    int32_t (*prod_validate_invocation)(uint64_t, uint64_t, uint64_t);
    int32_t (*prod_bind_parent)(uint64_t, uint64_t, uint64_t);
    int32_t (*prod_bind_handle)(uint64_t, uint64_t, uint64_t, uint64_t);
    int32_t (*prod_bind_lane)(uint64_t, uint64_t, uint64_t, uint16_t, uint64_t);
    int32_t (*prod_prepare)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint8_t);
    void (*prod_parent_terminal)(uint64_t, uint64_t, int32_t);
    void (*prod_attempt_terminal)(uint64_t, uint64_t, uint64_t, int32_t);
    int32_t (*prod_claim_receipt)(uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t, uint8_t *);
    int32_t (*prod_finish_receipt)(uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t, int32_t);
    void (*prod_resource_retired)(uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t, uint64_t, int32_t);
    int32_t (*maint_validate_invocation)(uint64_t, uint64_t, uint64_t);
    int32_t (*maint_bind_parent)(uint64_t, uint64_t, uint64_t);
    int32_t (*maint_bind_handle)(uint64_t, uint64_t, uint64_t, uint64_t);
    int32_t (*maint_bind_lane)(uint64_t, uint64_t, uint64_t, uint8_t);
    int32_t (*maint_supersede_normal)(uint64_t, uint64_t, uint64_t);
    int32_t (*maint_prepare)(uint64_t, uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint8_t);
    void (*maint_parent_terminal)(uint64_t, uint64_t, int32_t);
    void (*maint_candidate_terminal)(uint64_t, uint64_t, uint64_t, int32_t);
    int32_t (*maint_claim_receipt)(uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t, uint8_t *);
    int32_t (*maint_finish_receipt)(uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t, int32_t);
    void (*maint_resource_retired)(uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, int32_t);
} kvpn_output_callbacks_v1;
#if defined(__GNUC__)
#pragma GCC visibility push(hidden)
#endif
typedef struct { int32_t status; uint64_t now; } kvpn_output_clock_result_v1;
typedef struct { int32_t status; uint8_t retired; } kvpn_output_claim_result_v1;
kvpn_output_clock_result_v1 kvpn_output_clock_sample_v1(const kvpn_output_callbacks_v1 *);
kvpn_output_claim_result_v1 kvpn_output_prod_claim_result_v1(const kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t);
kvpn_output_claim_result_v1 kvpn_output_maint_claim_result_v1(const kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint8_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_output_table_valid_v1(const kvpn_output_callbacks_v1 *table);
int32_t kvpn_output_monotonic_now_ns_v1(const kvpn_output_callbacks_v1 *table, uint64_t * now);
int32_t kvpn_output_prod_validate_invocation_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch);
int32_t kvpn_output_prod_bind_parent_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch);
int32_t kvpn_output_prod_bind_handle_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t parent);
int32_t kvpn_output_prod_bind_lane_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint16_t lane, uint64_t attempt);
int32_t kvpn_output_prod_prepare_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t attempt, uint64_t child, uint64_t delivery, uint8_t has_deadline, uint64_t clock_sample_ns, uint64_t remaining_ns, uint8_t terminal);
void kvpn_output_prod_parent_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, int32_t reason);
void kvpn_output_prod_attempt_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint64_t identity, int32_t reason);
int32_t kvpn_output_prod_claim_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, uint8_t * already_retired);
int32_t kvpn_output_prod_finish_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, int32_t cleanup);
void kvpn_output_prod_resource_retired_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t attempt, uint64_t child, uint64_t delivery, int32_t cleanup);
int32_t kvpn_output_maint_validate_invocation_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch);
int32_t kvpn_output_maint_bind_parent_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch);
int32_t kvpn_output_maint_bind_handle_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t parent);
int32_t kvpn_output_maint_bind_lane_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t revocation);
int32_t kvpn_output_maint_supersede_normal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch);
int32_t kvpn_output_maint_prepare_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint64_t candidate, uint8_t has_deadline, uint64_t clock_sample_ns, uint64_t remaining_ns, uint8_t terminal);
void kvpn_output_maint_parent_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, int32_t reason);
void kvpn_output_maint_candidate_terminal_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint64_t identity, int32_t reason);
int32_t kvpn_output_maint_claim_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, uint8_t * already_retired);
int32_t kvpn_output_maint_finish_receipt_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t call, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, uint64_t delivery, int32_t cleanup);
void kvpn_output_maint_resource_retired_v1(const kvpn_output_callbacks_v1 *table, uint64_t owner, uint64_t epoch, uint8_t kind, uint64_t parent, uint64_t child, int32_t cleanup);
#if defined(__GNUC__)
#pragma GCC visibility pop
#endif
#endif

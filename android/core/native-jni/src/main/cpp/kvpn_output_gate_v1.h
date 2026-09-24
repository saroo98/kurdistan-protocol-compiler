// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_OUTPUT_GATE_V1_H
#define KVPN_OUTPUT_GATE_V1_H
#include "output_callbacks_v1.h"

enum { KVPN_OUTPUT_PRODUCTION_V1 = 1, KVPN_OUTPUT_MAINTENANCE_V1 = 2 };
enum { KVPN_OUTPUT_NORMAL_V1 = 0, KVPN_OUTPUT_CONTROL_V1 = 1, KVPN_OUTPUT_RETIREMENT_V1 = 2 };
/* Stack allocation only. Initialize to zero. Never copy, mutate, or move an
 * admitted frame. Only this C gate follows next, and only until matching End. */
typedef struct kvpn_output_call_v1 {
    struct kvpn_output_call_v1 *next;
    uint64_t owner, serial, epoch;
    uint16_t lane;
    uint8_t call_class, expectation, expected_kind, bound, opening, draining;
} kvpn_output_call_v1;

/* Synchronous noncopyable JNI borrower; C retains this stack address until leave. */
typedef struct kvpn_platform_borrow_v1 {
    void *object, *method;
    uint64_t owner, call;
    uint8_t method_index;
} kvpn_platform_borrow_v1;

/* Synchronous noncopyable post-End ownership claim. Only the gate mutates
 * these fields. object is borrowed only before actual owner-close detaches it;
 * the released receipt remains usable afterward without dereferencing object. */
typedef struct kvpn_platform_finalize_v1 {
    struct kvpn_platform_finalize_v1 *self;
    void *object;
    uint64_t owner, lease, parent;
    uint8_t kind, holder, released;
} kvpn_platform_finalize_v1;
int32_t kvpn_output_opening_stage_v1(kvpn_output_call_v1 *, uint8_t);
int32_t kvpn_output_opening_published_v1(kvpn_output_call_v1 *);
int32_t kvpn_output_failed_opening_claim_v1(uint64_t, uint8_t, kvpn_platform_finalize_v1 *);
int32_t kvpn_output_parent_finalize_claim_v1(uint64_t, uint8_t, kvpn_platform_finalize_v1 *);
int32_t kvpn_output_finalize_unclaim_v1(kvpn_platform_finalize_v1 *);
int32_t kvpn_output_finalize_finish_v1(kvpn_platform_finalize_v1 *, int32_t);

int32_t kvpn_platform_install_v1(uint64_t, void *, void *const [20]);
int32_t kvpn_platform_enter_v1(uint64_t, uint8_t, uint64_t, kvpn_platform_borrow_v1 *);
int32_t kvpn_platform_leave_v1(kvpn_platform_borrow_v1 *, int32_t);
/* Two synchronous read-only reverse queries, independent of the outgoing hook. */
int32_t kvpn_platform_query_enter_v1(uint64_t, uint64_t, kvpn_platform_borrow_v1 *);
int32_t kvpn_platform_query_leave_v1(kvpn_platform_borrow_v1 *, int32_t);
int32_t kvpn_platform_detach_v1(uint64_t, void **);
/* Child kind: revision=1, publication=2, socket=3, maintenance network=4. */
int32_t kvpn_platform_child_adopt_v1(uint64_t, uint8_t, uint64_t);
int32_t kvpn_platform_child_matches_v1(uint64_t, uint8_t, uint64_t);
int32_t kvpn_platform_child_retire_v1(uint64_t, uint8_t, uint64_t, int32_t);
int32_t kvpn_platform_abandon_owner_v1(uint64_t, uint64_t *);
int32_t kvpn_platform_unclaimed_borrow_v1(uint64_t, kvpn_platform_borrow_v1 *);
void kvpn_platform_fail_v1(uint64_t);
void *kvpn_platform_signal_object_v1(uint64_t, uint8_t, uint64_t);

int32_t kvpn_output_owner_reserve_v1(uint8_t, uint64_t *, uint64_t *);
int32_t kvpn_output_abandon_unclaimed_v1(uint64_t);
/* External producer cleanup is an additional caller precondition. This
 * primitive checks C ownership only; it does not close Java resources. */
int32_t kvpn_output_owner_release_v1(uint64_t);
int32_t kvpn_output_begin_open_v1(uint64_t, uint8_t, kvpn_output_call_v1 *);
int32_t kvpn_output_begin_parent_v1(uint64_t, uint8_t, uint8_t, kvpn_output_call_v1 *);
/* Absence is decided under the same lock as admission. Busy/failed live
 * owners never authorize a native retired-result fallback. */
int32_t kvpn_output_begin_lifecycle_v1(uint64_t, uint8_t, kvpn_output_call_v1 *, uint8_t *);
int32_t kvpn_output_expect_receipt_v1(kvpn_output_call_v1 *, uint8_t);
int32_t kvpn_output_try_commit_v1(kvpn_output_call_v1 *, int32_t, uint8_t *);
/* Before final caller-byte copy only: invalidate an undelivered commit so its
 * exact receipt can be cleaned. Never clears invariant/cleanup failures. */
int32_t kvpn_output_publication_undelivered_v1(kvpn_output_call_v1 *);
void kvpn_output_note_failure_v1(kvpn_output_call_v1 *, int32_t);
void kvpn_output_end_v1(kvpn_output_call_v1 *);
int32_t kvpn_output_revision_begin_v1(uint64_t);
/* Only the exact borrowed platform revision signal may call this pre-fence.
 * No handler is reserved here; actual invalidation still uses begin/finish. */
int32_t kvpn_output_revision_prefence_v1(uint64_t);
/* Signal kind: 1 revision, 2 production socket loss, 3 maintenance network loss.
 * Signal IDs are reserved by the fixed Go holder before Java can be invoked. */
int32_t kvpn_platform_signal_install_v1(uint64_t, uint8_t, uint64_t);
int32_t kvpn_platform_signal_borrow_v1(uint64_t, uint8_t, uint64_t);
int32_t kvpn_platform_signal_return_v1(uint64_t, uint8_t, uint64_t);
int32_t kvpn_platform_signal_retire_v1(uint64_t, uint8_t, uint64_t, int32_t);
int32_t kvpn_platform_revision_prefence_v1(uint64_t, uint64_t);
int32_t kvpn_output_revision_finish_v1(uint64_t, int32_t);
int32_t kvpn_output_retirement_drain_v1(kvpn_output_call_v1 *, int32_t);
int32_t kvpn_output_layout_v1(uint8_t, uint64_t *, uint64_t *, uint64_t *);
const kvpn_output_callbacks_v1 *kvpn_output_callbacks_table_v1(void);
#ifdef KVPN_OUTPUT_TEST_V1
uint8_t kvpn_output_test_waiting_v1(uint64_t owner);
#endif
#endif

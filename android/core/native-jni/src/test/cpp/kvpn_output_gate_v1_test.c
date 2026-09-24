// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_output_gate_v1.h"
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sched.h>

static const kvpn_output_callbacks_v1 *cb;
static uint64_t parent_serial = 1000;
typedef struct { uint64_t owner; pthread_barrier_t *before, *after; } terminal_job;
static void *run_terminal(void *arg) {
    terminal_job *j = arg;
    pthread_barrier_wait(j->before);
    cb->prod_parent_terminal(j->owner, 7, 13);
    pthread_barrier_wait(j->after);
    return NULL;
}
static uint64_t open_owner(uint8_t kind, kvpn_output_call_v1 *c) {
    uint64_t owner, lease;
    assert(kvpn_output_owner_reserve_v1(kind, &owner, &lease) == 0);
    assert(kvpn_output_begin_open_v1(lease, kind, c) == 0);
    assert(kvpn_output_expect_receipt_v1(c, 1) == 0);
    if (kind == 1) {
        assert(cb->prod_bind_parent(owner, c->serial, 7) == 0);
        assert(cb->prod_bind_handle(owner, c->serial, 7, ++parent_serial) == 0);
        assert(cb->prod_bind_lane(owner, c->serial, 7, 0, 1) == 0);
    } else {
        assert(cb->maint_bind_parent(owner, c->serial, 7) == 0);
        assert(cb->maint_bind_handle(owner, c->serial, 7, ++parent_serial) == 0);
        assert(cb->maint_bind_lane(owner, c->serial, 7, 0) == 0);
    }
    return owner;
}
static uint64_t now(void) {
    uint64_t n = 0;
    assert(cb->monotonic_now_ns(&n) == 0 && n);
    return n;
}
static int32_t prepare(kvpn_output_call_v1 *c, uint64_t child, uint64_t delivery) {
    return cb->prod_prepare(c->owner, c->serial, c->epoch, 1, child, delivery, 1, now(), 10000000000ULL, 0);
}
static void retire(uint64_t owner, uint8_t kind, uint64_t parent) {
    if (kind == 1) cb->prod_resource_retired(owner, 7, 1, parent, 0, 0, 0, 0);
    else cb->maint_resource_retired(owner, 7, 1, parent, 0, 0);
    assert(kvpn_output_owner_release_v1(owner) == 0);
}

/* An admitted control frame is finite before it binds a concrete descriptor. */
static void control_descriptor_attempt_is_exact(void) {
    kvpn_output_call_v1 c={0}, duplicate={0}; uint8_t publish=9;
    uint64_t owner=open_owner(1,&c), parent=parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent,1,1,&c)==0);
    assert(kvpn_output_expect_receipt_v1(&c,0)==0);
    assert(cb->prod_bind_lane(owner,c.serial,7,1,1)==0);
    assert(cb->prod_prepare(owner,c.serial,7,2,0,0,1,now(),10000000000ULL,0)==3);
    cb->prod_attempt_terminal(owner,7,1,7);
    assert(cb->prod_prepare(owner,c.serial,7,1,0,0,1,now(),10000000000ULL,0)==3);
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent,1,1,&c)==0);
    assert(kvpn_output_expect_receipt_v1(&c,0)==0);
    assert(cb->prod_bind_lane(owner,c.serial,7,1,2)==0);
    assert(kvpn_output_begin_parent_v1(parent,1,1,&duplicate)==0);
    assert(kvpn_output_expect_receipt_v1(&duplicate,0)==0);
    assert(cb->prod_bind_lane(owner,duplicate.serial,7,1,2)==5);
    kvpn_output_end_v1(&duplicate);
    assert(cb->prod_prepare(owner,c.serial,7,2,0,0,1,now(),10000000000ULL,0)==0);
    assert(kvpn_output_try_commit_v1(&c,0,&publish)==0 && publish==1);
    kvpn_output_end_v1(&c);
    cb->prod_parent_terminal(owner,7,7);
    assert(kvpn_output_begin_parent_v1(parent,1,1,&c)==0);
    assert(kvpn_output_expect_receipt_v1(&c,0)==0);
    assert(cb->prod_bind_lane(owner,c.serial,7,1,2)==0);
    assert(cb->prod_prepare(owner,c.serial,7,2,0,0,0,0,0,1)==0);
    assert(kvpn_output_try_commit_v1(&c,0,&publish)==0 && publish==1);
    kvpn_output_end_v1(&c);
    retire(owner,1,parent);
}

/* Catches an overflow pre-lane pool, hole admission and duplicate occupancy. */
static void saturation_and_lane_holes(void) {
    kvpn_output_call_v1 opening = {0}, calls[267] = {{0}};
    uint64_t owner = open_owner(1, &opening), parent = parent_serial;
    kvpn_output_end_v1(&opening);
    for (size_t i = 0; i < 266; ++i) {
        assert(kvpn_output_begin_parent_v1(parent, 1, 0, &calls[i]) == 0);
        assert(kvpn_output_expect_receipt_v1(&calls[i], 0) == 0);
        uint16_t lane = (uint16_t)(i + (i >= 5) + (i >= 201));
        assert(cb->prod_bind_lane(owner, calls[i].serial, 7, lane, 1) == 0);
    }
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &calls[266]) == 5);
    assert(kvpn_output_begin_parent_v1(parent, 1, 2, &calls[266]) == 0);
    for (size_t i = 0; i < 267; ++i) kvpn_output_end_v1(&calls[i]);
    retire(owner, 1, parent);
    owner = open_owner(1, &opening); parent = parent_serial;
    kvpn_output_end_v1(&opening);
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &calls[0]) == 0);
    assert(cb->prod_bind_lane(owner, calls[0].serial, 7, 6, 1) == 3);
    assert(kvpn_output_expect_receipt_v1(&calls[0], 0) == 0);
    assert(cb->prod_bind_lane(owner, calls[0].serial, 7, 5, 1) == 3);
    assert(cb->prod_bind_lane(owner, calls[0].serial, 7, 202, 1) == 3);
    assert(kvpn_output_expect_receipt_v1(&calls[0], 2) == 3);
    kvpn_output_end_v1(&calls[0]);
    retire(owner, 1, parent);
    uint64_t owners[64], leases[64], extra = 10, token = 10;
    for (size_t i = 0; i < 64; ++i) assert(kvpn_output_owner_reserve_v1(1, &owners[i], &leases[i]) == 0);
    assert(kvpn_output_owner_reserve_v1(1, &extra, &token) == 5 && !extra && !token);
    for (size_t i = 0; i < 64; ++i) assert(kvpn_output_abandon_unclaimed_v1(leases[i]) == 0);
}

/* Same native child is acquired by OpenStream, but not by EOF. */
static void open_stream_versus_eof(void) {
    kvpn_output_call_v1 c = {0};
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    for (uint8_t kind = 0; kind <= 2; kind += 2) {
        uint8_t retired = 8;
        assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, kind) == 0);
        assert(cb->prod_bind_lane(owner, c.serial, 7, 6, 1) == 0);
        assert(prepare(&c, 50, 0) == 0);
        int32_t s = cb->prod_claim_receipt(owner, c.serial, 7, 2, parent, 50, 0, &retired);
        assert(s == (kind ? 0 : 3) && retired == 0);
        if (kind) {
            assert(cb->prod_claim_receipt(owner, c.serial, 7, 2, parent, 50, 0, &retired) == 3);
            cb->prod_resource_retired(owner, 7, 2, parent, 1, 50, 0, 0);
            assert(cb->prod_finish_receipt(owner, c.serial, 7, 2, parent, 50, 0, 0) == 0);
        }
        kvpn_output_end_v1(&c);
    }
    retire(owner, 1, parent);
}

typedef struct {
    uint64_t owner, call, parent;
    pthread_barrier_t *start;
    int32_t status;
    uint8_t retired;
} claim_job;

static void expected_stream_delivery_allows_attested_eof(void) {
    kvpn_output_call_v1 c = {0};
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 4) == 0);
    assert(cb->prod_bind_lane(owner, c.serial, 7, 8, 1) == 0);
    assert(prepare(&c, 0, 0) == 3);
    assert(prepare(&c, 0, 77) == 3);
    assert(prepare(&c, 50, 0) == 0);
    uint8_t retired = 8, publish = 0;
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 4, parent, 50, 0, &retired) == 3 && !retired);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 2, parent, 50, 0, &retired) == 3 && !retired);
    assert(kvpn_output_try_commit_v1(&c, 19, &publish) == 19 && publish);
    kvpn_output_end_v1(&c);
    for (uint8_t kind = 0; kind <= 4; kind += 2) {
        assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, kind) == 0);
        assert(cb->prod_bind_lane(owner, c.serial, 7, 8, 1) == 0);
        assert(prepare(&c, 51, 0) == 0);
        assert(kvpn_output_try_commit_v1(&c, kind == 4 ? 0 : 19, &publish) == 18 && !publish);
        if (kind == 2) {
            assert(cb->prod_claim_receipt(owner, c.serial, 7, 2, parent, 51, 0, &retired) == 0);
            cb->prod_resource_retired(owner, 7, 2, parent, 1, 51, 0, 0);
            assert(cb->prod_finish_receipt(owner, c.serial, 7, 2, parent, 51, 0, 0) == 0);
        }
        kvpn_output_end_v1(&c);
    }
    retire(owner, 1, parent);
}
static void *run_claim(void *arg) {
    claim_job *j = arg;
    pthread_barrier_wait(j->start);
    j->status = cb->prod_claim_receipt(j->owner, j->call, 7, 2, j->parent, 50, 0, &j->retired);
    return NULL;
}
static void simultaneous_receipt_claim(void) {
    kvpn_output_call_v1 c = {0};
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 2) == 0);
    assert(cb->prod_bind_lane(owner, c.serial, 7, 6, 1) == 0);
    assert(prepare(&c, 50, 0) == 0);
    pthread_barrier_t start; pthread_t threads[2];
    assert(pthread_barrier_init(&start, NULL, 3) == 0);
    claim_job jobs[2] = {{owner, c.serial, parent, &start, -1, 9}, {owner, c.serial, parent, &start, -1, 9}};
    for (size_t i = 0; i < 2; ++i) assert(pthread_create(&threads[i], NULL, run_claim, &jobs[i]) == 0);
    pthread_barrier_wait(&start);
    for (size_t i = 0; i < 2; ++i) assert(pthread_join(threads[i], NULL) == 0);
    assert((jobs[0].status == 0 && jobs[1].status == 3) || (jobs[0].status == 3 && jobs[1].status == 0));
    assert(!jobs[0].retired && !jobs[1].retired);
    assert(pthread_barrier_destroy(&start) == 0);
    cb->prod_resource_retired(owner, 7, 2, parent, 1, 50, 0, 0);
    assert(cb->prod_finish_receipt(owner, c.serial, 7, 2, parent, 50, 0, 0) == 0);
    kvpn_output_end_v1(&c); retire(owner, 1, parent);
}

/* Catches publication after terminal, but preserves attested control. */
typedef struct {
    kvpn_output_call_v1 *call;
    uint64_t parent;
    uint8_t ns, finish_first, retired;
    int32_t claim_status, finish_status;
    pthread_barrier_t *before, *after;
} cleanup_job;
static void *run_cleanup(void *arg) {
    cleanup_job *j = arg;
    kvpn_output_call_v1 *c = j->call;
    pthread_barrier_wait(j->before);
    j->claim_status = j->ns == 1
        ? cb->prod_claim_receipt(c->owner, c->serial, 7, 2, j->parent, 50, 0, &j->retired)
        : cb->maint_claim_receipt(c->owner, c->serial, 7, 2, j->parent, 50, 0, &j->retired);
    if (!j->claim_status && j->finish_first) j->finish_status = j->ns == 1
        ? cb->prod_finish_receipt(c->owner, c->serial, 7, 2, j->parent, 50, 0, 0)
        : cb->maint_finish_receipt(c->owner, c->serial, 7, 2, j->parent, 50, 0, 0);
    pthread_barrier_wait(j->after);
    return NULL;
}
/* Caller barriers order the real guarded transitions, never callbacks under
 * the fence. Cleanup-first, commit-first and completed cleanup are distinct. */
static void cleanup_publication_both_winners(void) {
    for (uint8_t ns = 1; ns <= 2; ++ns) for (uint8_t mode = 0; mode < 4; ++mode) {
        kvpn_output_call_v1 c = {0}; uint8_t publish = 9;
        uint64_t owner = open_owner(ns, &c), parent = parent_serial;
        kvpn_output_end_v1(&c);
        assert(kvpn_output_begin_parent_v1(parent, ns, 0, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, 2) == 0);
        if (ns == 1) {
            assert(cb->prod_bind_lane(owner, c.serial, 7, 6, 1) == 0);
            assert(prepare(&c, 50, 0) == 0);
        } else {
            assert(cb->maint_bind_lane(owner, c.serial, 7, 0) == 0);
            assert(cb->maint_prepare(owner, c.serial, 7, 50, 1, now(), 10000000000ULL, 0) == 0);
        }
        if (mode == 1) assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 0 && publish == 1);
        if (mode == 3) {
            if (ns == 1) cb->prod_resource_retired(owner, 7, 2, parent, 1, 50, 0, 0);
            else cb->maint_resource_retired(owner, 7, 2, parent, 50, 0);
            assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 3 && publish == 0);
        }
        pthread_barrier_t before, after; pthread_t thread;
        assert(pthread_barrier_init(&before, NULL, 2) == 0);
        assert(pthread_barrier_init(&after, NULL, 2) == 0);
        cleanup_job job = { &c, parent, ns, mode == 2, 9, -1, -1, &before, &after };
        assert(pthread_create(&thread, NULL, run_cleanup, &job) == 0);
        pthread_barrier_wait(&before);
        pthread_barrier_wait(&after);
        assert(pthread_join(thread, NULL) == 0);
        assert(pthread_barrier_destroy(&before) == 0);
        assert(pthread_barrier_destroy(&after) == 0);
        if (mode == 1) {
            assert(job.claim_status == (ns == 1 ? 3 : 4) && job.retired == 0);
            /* A failed consumer explicitly revokes its undelivered commit. */
            kvpn_output_note_failure_v1(&c, 18);
            job.claim_status = ns == 1
                ? cb->prod_claim_receipt(owner, c.serial, 7, 2, parent, 50, 0, &job.retired)
                : cb->maint_claim_receipt(owner, c.serial, 7, 2, parent, 50, 0, &job.retired);
        }
        assert(job.claim_status == 0 && job.retired == (mode == 3));
        assert(kvpn_output_try_commit_v1(&c, 0, &publish) == (mode == 1 ? 18 : 3) && publish == 0);
        if (mode == 2) assert(job.finish_status == 0);
        else if (ns == 1) assert(cb->prod_finish_receipt(owner, c.serial, 7, 2, parent, 50, 0, 0) == 0);
        else assert(cb->maint_finish_receipt(owner, c.serial, 7, 2, parent, 50, 0, 0) == 0);
        assert(kvpn_output_try_commit_v1(&c, 0, &publish) == (mode == 1 ? 18 : 3) && publish == 0);
        kvpn_output_end_v1(&c);
        if (mode == 1) assert(kvpn_output_owner_release_v1(owner) == 3); /* failure stays sticky */
        else retire(owner, ns, parent);
        printf("CleanupPublication namespace=%u mode=%u zero_later_publish PASS\n", ns, mode);
    }
}
static void terminal_both_winners(void) {
    for (int commit_first = 0; commit_first < 2; ++commit_first) {
        kvpn_output_call_v1 c = {0}; uint8_t publish = 9;
        uint64_t owner = open_owner(1, &c), parent = parent_serial;
        kvpn_output_end_v1(&c);
        assert(kvpn_output_begin_parent_v1(parent, 1, 1, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, 0) == 0);
        assert(cb->prod_bind_lane(owner, c.serial, 7, 1, 1) == 0);
        assert(prepare(&c, 0, 0) == 0);
        if (commit_first) assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 0 && publish == 1);
        pthread_barrier_t before, after;
        assert(pthread_barrier_init(&before, NULL, 2) == 0);
        assert(pthread_barrier_init(&after, NULL, 2) == 0);
        terminal_job job = { owner, &before, &after }; pthread_t thread;
        assert(pthread_create(&thread, NULL, run_terminal, &job) == 0);
        pthread_barrier_wait(&before);
        pthread_barrier_wait(&after);
        assert(pthread_join(thread, NULL) == 0);
        assert(pthread_barrier_destroy(&before) == 0);
        assert(pthread_barrier_destroy(&after) == 0);
        if (!commit_first) assert(kvpn_output_try_commit_v1(&c, 0, &publish) != 0 && publish == 0);
        assert(kvpn_output_owner_release_v1(owner) != 0);
        kvpn_output_end_v1(&c);
        assert(kvpn_output_begin_parent_v1(parent, 1, 1, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, 0) == 0);
        assert(cb->prod_bind_lane(owner, c.serial, 7, 1, 1) == 0);
        assert(cb->prod_prepare(owner, c.serial, 7, 1, 0, 0, 0, 0, 0, 1) == 0);
        assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 0 && publish == 1);
        kvpn_output_end_v1(&c);
        retire(owner, 1, parent);
    }
}

static void attempt_candidate_and_clock(void) {
    kvpn_output_call_v1 c = {0}; uint8_t publish;
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 0) == 0);
    assert(cb->prod_bind_lane(owner, c.serial, 7, 6, 1) == 0);
    cb->prod_attempt_terminal(owner, 7, 1, 9);
    assert(prepare(&c, 5, 0) != 0);
    kvpn_output_end_v1(&c); retire(owner, 1, parent);
    owner = open_owner(2, &c); parent = parent_serial; kvpn_output_end_v1(&c);
    for (uint64_t i = 0; i < 2; ++i) {
        uint64_t candidate = 1 - i;
        assert(kvpn_output_begin_parent_v1(parent, 2, 0, &c) == 0);
        assert(kvpn_output_expect_receipt_v1(&c, candidate ? 2 : 0) == 0);
        assert(cb->maint_bind_lane(owner, c.serial, 7, 0) == 0);
        assert(cb->maint_prepare(owner, c.serial, 7, candidate, 1, now(), 10000000000ULL, 0) == 0);
        cb->maint_candidate_terminal(owner, 7, 1, 19);
        assert((kvpn_output_try_commit_v1(&c, 0, &publish) == 0) == (candidate == 0));
        assert(publish == (candidate == 0));
        cb->maint_resource_retired(owner, 7, 2, parent, candidate, 0);
        kvpn_output_end_v1(&c);
    }
    retire(owner, 2, parent);
    owner = open_owner(1, &c); parent = parent_serial;
    assert(cb->prod_prepare(owner, c.serial, 7, 1, 0, 0, 0, 0, 0, 0) != 0);
    assert(cb->prod_prepare(owner, c.serial, 7, 1, 0, 0, 1, UINT64_MAX, 2, 0) != 0);
    assert(cb->prod_prepare(owner, c.serial, 7, 1, 0, 0, 1, 1, 1, 0) != 0);
    kvpn_output_end_v1(&c); retire(owner, 1, parent);
}

static void receipt_shape_and_cleanup_namespace(void) {
    kvpn_output_call_v1 c = {0};
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 0, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 0) == 0);
    assert(cb->prod_bind_lane(owner, c.serial, 7, 6, 1) == 0);
    assert(prepare(&c, 20, 30) == 3); /* None cannot hide an acquired delivery. */
    kvpn_output_end_v1(&c); retire(owner, 1, parent);
    owner = open_owner(2, &c); parent = parent_serial;
    assert(cb->maint_prepare(owner, c.serial, 7, 0, 1, now(), 10000000000ULL, 0) == 0);
    uint8_t clean;
    assert(cb->maint_claim_receipt(owner, c.serial, 7, 1, parent, 0, 0, &clean) == 0);
    assert(cb->maint_finish_receipt(owner, c.serial, 7, 1, parent, 0, 0, 8) == 8);
    kvpn_output_end_v1(&c);
    assert(kvpn_output_owner_release_v1(owner) != 0);
}

static void admitted_terminal_and_supersede(void) {
    kvpn_output_call_v1 normal = {0}, control = {0}, extra = {0}; uint8_t publish;
    uint64_t owner = open_owner(1, &normal), parent = parent_serial;
    kvpn_output_end_v1(&normal);
    assert(kvpn_output_begin_parent_v1(parent, 1, 1, &control) == 0);
    assert(kvpn_output_expect_receipt_v1(&control, 0) == 0);
    assert(cb->prod_bind_lane(owner, control.serial, 7, 1, 1) == 0);
    cb->prod_parent_terminal(owner, 7, 13);
    assert(cb->prod_prepare(owner, control.serial, 7, 1, 0, 0, 0, 0, 0, 1) == 0);
    assert(kvpn_output_try_commit_v1(&control, 0, &publish) == 0 && publish);
    kvpn_output_end_v1(&control); retire(owner, 1, parent);

    owner = open_owner(2, &normal); parent = parent_serial; kvpn_output_end_v1(&normal);
    assert(kvpn_output_begin_parent_v1(parent, 2, 0, &normal) == 0);
    assert(kvpn_output_expect_receipt_v1(&normal, 0) == 0);
    assert(cb->maint_bind_lane(owner, normal.serial, 7, 0) == 0);
    assert(cb->maint_prepare(owner, normal.serial, 7, 0, 1, now(), 10000000000ULL, 0) == 0);
    assert(kvpn_output_begin_parent_v1(parent, 2, 1, &control) == 0);
    assert(kvpn_output_expect_receipt_v1(&control, 0) == 0);
    assert(cb->maint_bind_lane(owner, control.serial, 7, 1) == 0);
    assert(cb->maint_supersede_normal(owner, control.serial, 7) == 0);
    assert(kvpn_output_try_commit_v1(&normal, 0, &publish) != 0 && !publish);
    kvpn_output_end_v1(&normal);
    assert(kvpn_output_begin_parent_v1(parent, 2, 0, &extra) == 5);
    cb->maint_parent_terminal(owner, 7, 20);
    assert(cb->maint_prepare(owner, control.serial, 7, 0, 0, 0, 0, 1) == 0);
    assert(kvpn_output_try_commit_v1(&control, 0, &publish) == 0 && publish);
    kvpn_output_end_v1(&control); retire(owner, 2, parent);
}

static void deadline_expires_after_prepare(void) {
    kvpn_output_call_v1 c = {0}; uint8_t publish = 7;
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 1, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 0) == 0);
    assert(cb->prod_bind_lane(owner, c.serial, 7, 1, 1) == 0);
    uint64_t sample = now(), duration = 100000000ULL;
    cb->prod_parent_terminal(owner, 7, 13);
    assert(cb->prod_prepare(owner, c.serial, 7, 1, 0, 0, 1, sample, duration, 1) == 0);
    while (now() < sample + duration) sched_yield();
    assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 8 && publish == 0);
    kvpn_output_end_v1(&c); retire(owner, 1, parent);
}

/* Missing/terminal-only identities must never become completed receipts. */
static void retained_receipts_and_failure(void) {
    kvpn_output_call_v1 c = {0}; uint8_t clean = 4;
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    assert(prepare(&c, 0, 0) == 0);
    cb->prod_parent_terminal(owner, 7, 7);
    assert(cb->prod_claim_receipt(owner, c.serial, 8, 1, parent, 0, 0, &clean) == 3 && clean == 0);
    assert(cb->maint_claim_receipt(owner, c.serial, 7, 1, parent, 0, 0, &clean) == 4 && clean == 0);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 1, parent + 1, 0, 0, &clean) == 3);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 1, parent, 1, 0, &clean) == 3);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 1, parent, 0, 1, &clean) == 3);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 1, parent, 0, 0, &clean) == 0 && clean == 0);
    assert(cb->prod_finish_receipt(owner, c.serial, 7, 1, parent, 0, 0, 18) == 18);
    cb->prod_resource_retired(owner, 7, 1, parent, 0, 0, 0, 0);
    assert(cb->prod_claim_receipt(owner, c.serial, 7, 1, parent, 0, 0, &clean) == 3 && clean == 0);
    kvpn_output_end_v1(&c);
    assert(kvpn_output_owner_release_v1(owner) != 0);

    owner = open_owner(2, &c); parent = parent_serial;
    assert(cb->maint_prepare(owner, c.serial, 7, 0, 1, now(), 10000000000ULL, 0) == 0);
    uint64_t old_call = c.serial;
    kvpn_output_end_v1(&c); /* unresolved receipt retained, no stack pointer */
    assert(kvpn_output_owner_release_v1(owner) != 0);
    assert(cb->maint_validate_invocation(owner, old_call, 7) == 4);
    cb->maint_resource_retired(owner, 7, 1, parent, 0, 0);
    assert(cb->maint_claim_receipt(owner, old_call, 7, 1, parent, 0, 0, &clean) == 4 && clean == 0);
    assert(kvpn_output_owner_release_v1(owner) != 0); /* earlier unproven End remains sticky */
}

static void drains_and_layout(void) {
    kvpn_output_call_v1 c = {0}, retirement = {0};
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    kvpn_output_end_v1(&c);
    assert(kvpn_output_begin_parent_v1(parent, 1, 2, &retirement) == 0);
    assert(kvpn_output_retirement_drain_v1(&retirement, 0) == 0);
    assert(kvpn_output_revision_begin_v1(owner) == 25);
    assert(kvpn_output_retirement_drain_v1(&retirement, 0) == 18);
    kvpn_output_end_v1(&retirement);
    assert(kvpn_output_owner_release_v1(owner) != 0);

    owner = open_owner(1, &c);
    assert(kvpn_output_revision_begin_v1(owner) == 0);
    assert(kvpn_output_revision_finish_v1(owner, 10) == 10); /* actual legacy storage failure, no self-wait */
    assert(kvpn_output_revision_begin_v1(owner) != 0);
    kvpn_output_end_v1(&c);
    assert(kvpn_output_owner_release_v1(owner) != 0);
    for (uint8_t kind = 1; kind <= 2; ++kind) {
        uint64_t shared = 0, slot = 0, frames = 0;
        assert(kvpn_output_layout_v1(kind, &shared, &slot, &frames) == 0);
        assert(shared >= 64 * slot && slot > 0);
        assert(frames == sizeof(kvpn_output_call_v1) * (kind == 1 ? 267 : 2));
        printf("Layout kind=%u shared=%llu owner=%llu maximum_frames=%llu frame=%zu table=%zu\n", kind,
            (unsigned long long)shared, (unsigned long long)slot, (unsigned long long)frames,
            sizeof(kvpn_output_call_v1), sizeof(kvpn_output_callbacks_v1));
    }
}

#ifdef KVPN_OUTPUT_TEST_V1
typedef struct { uint64_t owner; int32_t result; } drain_job;
typedef struct { kvpn_output_call_v1 *call; int32_t result; } retirement_job;
static void *run_retirement(void *arg) {
    retirement_job *job = arg;
    job->result = kvpn_output_retirement_drain_v1(job->call, 0);
    return NULL;
}
static void *run_revision_finish(void *arg) {
    drain_job *job = arg;
    job->result = kvpn_output_revision_finish_v1(job->owner, 0);
    return NULL;
}
static void actual_revision_wait(void) {
    kvpn_output_call_v1 c = {0}; uint8_t publish;
    uint64_t owner = open_owner(1, &c), parent = parent_serial;
    assert(prepare(&c, 0, 0) == 0);
    assert(kvpn_output_try_commit_v1(&c, 0, &publish) == 0 && publish == 1);
    assert(kvpn_output_revision_begin_v1(owner) == 0);
    drain_job job = { owner, -1 }; pthread_t thread;
    assert(pthread_create(&thread, NULL, run_revision_finish, &job) == 0);
    while (!kvpn_output_test_waiting_v1(owner)) sched_yield();
    /* Actual cond_wait entered while the committed outer frame remains held. */
    assert(kvpn_output_owner_release_v1(owner) == 3);
    kvpn_output_end_v1(&c);
    assert(pthread_join(thread, NULL) == 0 && job.result == 0);
    retire(owner, 1, parent);

    owner = open_owner(1, &c);
    assert(kvpn_output_revision_begin_v1(owner) == 0);
    job.owner = owner; job.result = -1;
    assert(pthread_create(&thread, NULL, run_revision_finish, &job) == 0);
    while (!kvpn_output_test_waiting_v1(owner)) sched_yield();
    assert(kvpn_output_revision_begin_v1(owner) == 25);
    /* A duplicate handler wakes the waiting original with sticky failure,
     * without first requiring this still-held outer frame to End. */
    assert(pthread_join(thread, NULL) == 0 && job.result == 25);
    kvpn_output_end_v1(&c);

    owner = open_owner(1, &c); parent = parent_serial;
    kvpn_output_call_v1 retirement = {0};
    assert(kvpn_output_begin_parent_v1(parent, 1, 2, &retirement) == 0);
    retirement_job rjob = { &retirement, -1 };
    assert(pthread_create(&thread, NULL, run_retirement, &rjob) == 0);
    while (!kvpn_output_test_waiting_v1(owner)) sched_yield();
    assert(kvpn_output_retirement_drain_v1(&retirement, 0) == 18);
    assert(pthread_join(thread, NULL) == 0 && rjob.result == 18);
    kvpn_output_end_v1(&c); kvpn_output_end_v1(&retirement);
}
#endif

/* Catches duplicate token claim and copied-frame unlinking. */
static void owner_claim_and_abandon(void) {
    uint64_t owner = 99, lease = 99;
    kvpn_output_call_v1 call = {0}, second = {0};
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    assert(owner && lease);
    assert(kvpn_output_begin_open_v1(lease, 2, &call) == 3);
    assert(kvpn_output_begin_open_v1(lease, 1, &call) == 0);
    assert(kvpn_output_begin_open_v1(lease, 1, &second) == 3);
    assert(kvpn_output_abandon_unclaimed_v1(lease) == 3);
    second = call;
    kvpn_output_end_v1(&second);
    assert(kvpn_output_owner_release_v1(owner) == 3);
    kvpn_output_end_v1(&call);
    assert(kvpn_output_owner_release_v1(owner) == 0);
    assert(kvpn_output_owner_release_v1(owner) == 3);
    assert(kvpn_output_owner_reserve_v1(2, &owner, &lease) == 0);
    assert(kvpn_output_abandon_unclaimed_v1(lease) == 0);
    assert(kvpn_output_begin_open_v1(lease, 2, &call) == 3);
}

/* BindParent already represents native ownership even before a public handle
 * can be bound. Absence of that handle is not successful cleanup evidence. */
static void bound_epoch_requires_cleanup(void) {
    uint64_t owner, lease; kvpn_output_call_v1 c = {0};
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    assert(kvpn_output_begin_open_v1(lease, 1, &c) == 0);
    assert(kvpn_output_expect_receipt_v1(&c, 1) == 0);
    assert(cb->prod_bind_parent(owner, c.serial, 7) == 0);
    kvpn_output_end_v1(&c);
    assert(kvpn_output_owner_release_v1(owner) == 3);
}

/* This test exercises actual gate ownership only. It does not claim that the
 * dummy platform object is a JVM receiver or that Go cleanup ran. */
static void failed_opening_finalization_claim(void) {
    int object = 0;
    void *methods[20];
    for (size_t i = 0; i < 20; ++i) methods[i] = &object;
    for (uint8_t holder = 0; holder <= 1; ++holder) {
        uint64_t owner, lease;
        kvpn_output_call_v1 opening = {0};
        kvpn_platform_finalize_v1 claim = {0}, duplicate = {0};
        assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
        assert(kvpn_platform_install_v1(owner, &object, methods) == 0);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &claim) == 25);
        assert(kvpn_output_begin_open_v1(lease, 1, &opening) == 0);
        assert(kvpn_output_expect_receipt_v1(&opening, 1) == 0);
        assert(kvpn_output_opening_stage_v1(&opening, holder) == 0);
        assert(kvpn_output_opening_stage_v1(&opening, holder) == 3);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &claim) == 25);
        kvpn_output_end_v1(&opening);
        assert(kvpn_output_failed_opening_claim_v1(lease, 2, &claim) == 25);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &claim) == 0);
        assert(claim.object == &object && claim.owner == owner && claim.holder == holder && !claim.released);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &duplicate) == 25);
        duplicate = claim;
        assert(kvpn_output_finalize_unclaim_v1(&duplicate) == 25);
        assert(kvpn_output_finalize_unclaim_v1(&claim) == 0);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &claim) == 0);
        kvpn_platform_borrow_v1 callback = {0};
        assert(kvpn_platform_enter_v1(owner, 19, 0, &callback) == 0);
        assert(kvpn_platform_leave_v1(&callback, 0) == 0);
        void *retired = NULL;
        assert(kvpn_platform_detach_v1(owner, &retired) == 0 && retired == &object);
        assert(kvpn_output_owner_release_v1(owner) == 0 && claim.released == 1);
        duplicate = claim;
        assert(kvpn_output_finalize_finish_v1(&duplicate, 0) == 25);
        assert(kvpn_output_finalize_finish_v1(&claim, 0) == 0);
        assert(kvpn_output_finalize_finish_v1(&claim, 0) == 25);
        assert(kvpn_output_failed_opening_claim_v1(lease, 1, &claim) == 25);
    }
    puts("FailedOpeningClaim ExactAddress PostEnd BothHolderStages ActualReleaseReceipt PASS");
}

static void published_parent_finalization_claim(void) {
    int object = 0;
    void *methods[20];
    for (size_t i = 0; i < 20; ++i) methods[i] = &object;
    for (uint8_t kind = 1; kind <= 2; ++kind) {
        uint64_t owner, lease, parent = ++parent_serial;
        kvpn_output_call_v1 opening = {0};
        kvpn_platform_finalize_v1 claim = {0};
        assert(kvpn_output_owner_reserve_v1(kind, &owner, &lease) == 0);
        assert(kvpn_platform_install_v1(owner, &object, methods) == 0);
        assert(kvpn_output_begin_open_v1(lease, kind, &opening) == 0);
        assert(kvpn_output_expect_receipt_v1(&opening, 1) == 0);
        assert(kvpn_output_opening_stage_v1(&opening, 1) == 0);
        assert(kvpn_output_opening_published_v1(&opening) == 3);
        if (kind == 1) {
            assert(cb->prod_bind_parent(owner, opening.serial, 7) == 0);
            assert(cb->prod_bind_handle(owner, opening.serial, 7, parent) == 0);
            assert(cb->prod_bind_lane(owner, opening.serial, 7, 0, 1) == 0);
            assert(prepare(&opening, 0, 0) == 0);
        } else {
            assert(cb->maint_bind_parent(owner, opening.serial, 7) == 0);
            assert(cb->maint_bind_handle(owner, opening.serial, 7, parent) == 0);
            assert(cb->maint_bind_lane(owner, opening.serial, 7, 0) == 0);
            assert(cb->maint_prepare(owner, opening.serial, 7, 0, 1, now(), 10000000000ULL, 0) == 0);
        }
        assert(kvpn_output_opening_published_v1(&opening) == 3);
        uint8_t published = 0;
        assert(kvpn_output_try_commit_v1(&opening, 0, &published) == 0 && published == 1);
        assert(kvpn_output_opening_published_v1(&opening) == 0);
        assert(kvpn_output_parent_finalize_claim_v1(parent, kind, &claim) == 25);
        kvpn_output_end_v1(&opening);
        assert(kvpn_output_failed_opening_claim_v1(lease, kind, &claim) == 25);
        assert(kvpn_output_parent_finalize_claim_v1(parent, kind, &claim) == 25);
        if (kind == 1) cb->prod_resource_retired(owner, 7, 1, parent, 1, 0, 0, 0);
        else cb->maint_resource_retired(owner, 7, 1, parent, 0, 0);
        assert(kvpn_output_parent_finalize_claim_v1(parent, kind, &claim) == 0);
        // An arbitrary nominal success is not a cleanup receipt. Keep the
        // actual C owner failed and prevent a second destructive claim.
        assert(kvpn_output_finalize_finish_v1(&claim, 0) == 25);
        assert(kvpn_output_parent_finalize_claim_v1(parent, kind, &claim) == 25);
        assert(kvpn_output_owner_release_v1(owner) == 3);
    }
    printf("ParentFinalize RequiresCommitNativeRetirement ActualRelease StickyFailure claim=%zu PASS\n", sizeof(kvpn_platform_finalize_v1));
}

static void undelivered_publication_cleanup(void) {
    int object = 0; void *methods[20];
    for (unsigned i = 0; i < 20; ++i) methods[i] = &object;
    for (uint8_t kind = 1; kind <= 2; ++kind) for (uint8_t mode = 0; mode < 3; ++mode) {
        kvpn_output_call_v1 call = {0};
        kvpn_platform_finalize_v1 claim = {0};
        uint64_t owner, lease, parent = ++parent_serial;
        assert(kvpn_output_owner_reserve_v1(kind, &owner, &lease) == 0);
        assert(kvpn_platform_install_v1(owner, &object, methods) == 0);
        assert(kvpn_output_begin_open_v1(lease, kind, &call) == 0);
        assert(kvpn_output_expect_receipt_v1(&call, 1) == 0);
        assert(kvpn_output_opening_stage_v1(&call, 1) == 0);
        assert(kvpn_output_publication_undelivered_v1(&call) == 3);
        if (kind == 1) {
            assert(cb->prod_bind_parent(owner, call.serial, 7) == 0);
            assert(cb->prod_bind_handle(owner, call.serial, 7, parent) == 0);
            assert(cb->prod_bind_lane(owner, call.serial, 7, 0, 1) == 0);
            assert(prepare(&call, 0, 0) == 0);
        } else {
            assert(cb->maint_bind_parent(owner, call.serial, 7) == 0);
            assert(cb->maint_bind_handle(owner, call.serial, 7, parent) == 0);
            assert(cb->maint_bind_lane(owner, call.serial, 7, 0) == 0);
            assert(cb->maint_prepare(owner, call.serial, 7, 0, 1, now(), 10000000000ULL, 0) == 0);
        }
        assert(kvpn_output_publication_undelivered_v1(&call) == 3);
        uint8_t publish = 0, retired = 99;
        assert(kvpn_output_try_commit_v1(&call, 0, &publish) == 0 && publish == 1);
        kvpn_output_call_v1 copied = call;
        assert(kvpn_output_publication_undelivered_v1(&copied) == 3);
        if (mode == 2) kvpn_output_note_failure_v1(&call, 18);
        assert(kvpn_output_publication_undelivered_v1(&call) == (mode == 2 ? 3 : 0));
        assert(kvpn_output_publication_undelivered_v1(&call) == 3);
        assert(kvpn_output_try_commit_v1(&call, 0, &publish) != 0 && publish == 0);
        int32_t cleanup = mode == 1 ? (kind == 1 ? 18 : 23) : 0;
        if (kind == 1) {
            assert(cb->prod_claim_receipt(owner, call.serial, 7, 1, parent, 0, 0, &retired) == 0 && retired == 0);
            cb->prod_resource_retired(owner, 7, 1, parent, 1, 0, 0, cleanup);
            assert(cb->prod_finish_receipt(owner, call.serial, 7, 1, parent, 0, 0, cleanup) == cleanup);
        } else {
            assert(cb->maint_claim_receipt(owner, call.serial, 7, 1, parent, 0, 0, &retired) == 0 && retired == 0);
            cb->maint_resource_retired(owner, 7, 1, parent, 0, cleanup);
            assert(cb->maint_finish_receipt(owner, call.serial, 7, 1, parent, 0, 0, cleanup) == cleanup);
        }
        assert(kvpn_output_try_commit_v1(&call, 0, &publish) != 0 && publish == 0);
        assert(kvpn_output_failed_opening_claim_v1(lease, kind, &claim) == 25);
        kvpn_output_end_v1(&call);
        assert(kvpn_output_publication_undelivered_v1(&call) == 3);
        if (mode) {
            assert(kvpn_output_failed_opening_claim_v1(lease, kind, &claim) == 25);
            assert(kvpn_output_owner_release_v1(owner) == 3);
        } else {
            assert(kvpn_output_failed_opening_claim_v1(lease, kind, &claim) == 0);
            kvpn_platform_borrow_v1 callback = {0}; void *detached = NULL;
            assert(kvpn_platform_enter_v1(owner, 19, 0, &callback) == 0);
            assert(kvpn_platform_leave_v1(&callback, 0) == 0);
            assert(kvpn_platform_detach_v1(owner, &detached) == 0 && detached == &object);
            assert(kvpn_output_owner_release_v1(owner) == 0 && claim.released == 1);
            assert(kvpn_output_finalize_finish_v1(&claim, 0) == 0);
        }
    }
    puts("UndeliveredPublication BothKinds ExactFrame NoRecommit ActualCleanup PriorFailureSticky PASS");
}

static void lifecycle_absence_is_not_busy(void) {
    kvpn_output_call_v1 opening = {0}, close_call = {0}, other = {0};
    uint8_t absent = 99;
    assert(kvpn_output_begin_lifecycle_v1(0, 1, &close_call, &absent) == 2 && absent == 0);
    uint64_t owner = open_owner(1, &opening), parent = parent_serial;
    kvpn_output_end_v1(&opening);
    assert(kvpn_output_begin_lifecycle_v1(parent, 1, &close_call, &absent) == 0 && absent == 0);
    absent = 99;
    assert(kvpn_output_begin_lifecycle_v1(parent, 1, &other, &absent) == 5 && absent == 0);
    kvpn_output_end_v1(&close_call);
    retire(owner, 1, parent);
    assert(kvpn_output_begin_lifecycle_v1(parent, 1, &other, &absent) == 3 && absent == 1);
    owner = open_owner(1, &opening); parent = parent_serial;
    kvpn_output_note_failure_v1(&opening, 18);
    kvpn_output_end_v1(&opening);
    absent = 99;
    assert(kvpn_output_begin_lifecycle_v1(parent, 1, &close_call, &absent) == 0 && absent == 0);
    assert(kvpn_output_retirement_drain_v1(&close_call, 0) == 18);
    kvpn_output_end_v1(&close_call);
    assert(kvpn_output_owner_release_v1(owner) == 3);
    puts("LifecycleAbsentOnly NoBusyOrFailureFallback PASS");
}

int main(void) {
    alarm(30); /* A caller watchdog, never a scheduling oracle. */
    cb = kvpn_output_callbacks_table_v1();
    control_descriptor_attempt_is_exact();
    puts("ControlDescriptorAttemptMismatch ExactDescriptor DuplicateLane Terminal PASS");
    owner_claim_and_abandon();
    puts("OwnerClaimAndAbandon WrongKindAndSerial FrameCopyRejected PASS");
    saturation_and_lane_holes();
    puts("SaturationAndLaneHoles ExpectReceiptOnce PASS");
    bound_epoch_requires_cleanup();
    puts("BoundEpochBeforeHandleRequiresCleanup PASS");
    open_stream_versus_eof();
    expected_stream_delivery_allows_attested_eof();
    puts("OpenStreamVersusEOF ReceiptClaimFinishActualRetirement PASS");
    simultaneous_receipt_claim();
    puts("SimultaneousReceiptClaimExactlyOneWinner PASS");
    cleanup_publication_both_winners();
    undelivered_publication_cleanup();
    terminal_both_winners();
    puts("PrepareTerminalBothWinners TerminalControlDistinction PASS");
    attempt_candidate_and_clock();
    puts("AttemptRetirement CandidateExpiryVersusConsumption MonotonicConversion PASS");
    receipt_shape_and_cleanup_namespace();
    puts("NoneReceiptShape TypedCleanupFailure PASS");
    admitted_terminal_and_supersede();
    puts("AdmittedTerminalControl SupersedeNormal NoControlBypass PASS");
    deadline_expires_after_prepare();
    puts("RealDeadlineStillExpiresForTerminalResult PASS");
    retained_receipts_and_failure();
    puts("ReceiptWrongIdentity FirstFailureRetention EndUnresolved ActualRetirementAfterEnd PASS");
    drains_and_layout();
    puts("RevisionNativeFailureNoJoin RetirementExcludesSelf RetirementOverlap Layout PASS");
#ifdef KVPN_OUTPUT_TEST_V1
    actual_revision_wait();
    puts("ActualRevisionWaitEntry CommittedEndReleasesGuard PASS");
#endif
    failed_opening_finalization_claim();
    published_parent_finalization_claim();
    lifecycle_absence_is_not_busy();
    return 0;
}

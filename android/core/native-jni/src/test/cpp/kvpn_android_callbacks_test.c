// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_output_gate_v1.h"
#include "android_callbacks_v1.h"
#include "kvpn_tun_proof.h"
#include <assert.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>

/* Same read-only gate route as the actual JNI query_borrow. */
static int32_t query_enter(uint64_t owner, uint64_t call, kvpn_platform_borrow_v1 *borrow) {
    return kvpn_platform_query_enter_v1(owner, call, borrow);
}
static int32_t query_leave(kvpn_platform_borrow_v1 *borrow, int32_t failed) {
    return kvpn_platform_query_leave_v1(borrow, failed);
}
static void barrier_wait(pthread_barrier_t *barrier) {
    int result = pthread_barrier_wait(barrier);
    assert(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}
typedef struct { uint64_t owner; pthread_barrier_t entered, release; } query_overlap;
static void *ordinary_poll(void *argument) {
    query_overlap *test = argument;
    kvpn_platform_borrow_v1 query = {0};
    assert(query_enter(test->owner, UINT64_MAX, &query) == 0);
    barrier_wait(&test->entered);
    barrier_wait(&test->release);
    assert(query_leave(&query, 0) == 0);
    return NULL;
}
static void nested_cancellation_query_and_ordinary_poll_retain_exact_owner(void) {
    uint64_t owner, lease;
    void *methods[20];
    for (unsigned i=0;i<20;++i) methods[i]=&methods[i];
    assert(kvpn_output_owner_reserve_v1(1,&owner,&lease)==0);
    assert(kvpn_platform_install_v1(owner,methods,methods)==0);
    kvpn_platform_borrow_v1 ordinary={0}, hook={0}, nested={0}, extra={0};
    assert(kvpn_platform_enter_v1(owner,9,UINT64_MAX,&ordinary)==0);
    assert(kvpn_platform_enter_v1(owner,18,UINT64_MAX,&hook)==0);
    /* Java cancelCall has no Binder worker wait, so asks its original context. */
    assert(query_enter(owner,UINT64_MAX,&nested)==0);
    assert(nested.object==methods && nested.owner==owner && nested.call==UINT64_MAX);
    assert(query_enter(owner,1,&extra)==25);
    assert(query_enter(owner+1,UINT64_MAX,&extra)==25);
    assert(query_enter(owner,UINT64_MAX,&nested)==25);
    assert(kvpn_platform_enter_v1(owner,18,UINT64_MAX,&nested)==25);
    query_overlap overlap={.owner=owner};
    assert(pthread_barrier_init(&overlap.entered,NULL,2)==0);
    assert(pthread_barrier_init(&overlap.release,NULL,2)==0);
    pthread_t thread; assert(pthread_create(&thread,NULL,ordinary_poll,&overlap)==0);
    barrier_wait(&overlap.entered);
    assert(query_enter(owner,UINT64_MAX,&extra)==25); /* two read-only queries maximum */
    assert(kvpn_platform_enter_v1(owner,18,UINT64_MAX,&extra)==25); /* still one hook */
    assert(kvpn_platform_leave_v1(&ordinary,0)==0);
    assert(kvpn_platform_leave_v1(&hook,0)==0);
    assert(kvpn_platform_enter_v1(owner,19,0,&extra)==25); /* result writes still own lifetime */
    void *object=NULL;
    assert(kvpn_platform_detach_v1(owner,&object)==25 && object==NULL);
    assert(kvpn_output_abandon_unclaimed_v1(lease)!=0);
    assert(query_leave(&nested,0)==0);
    assert(kvpn_platform_enter_v1(owner,19,0,&extra)==25);
    barrier_wait(&overlap.release);
    assert(pthread_join(thread,NULL)==0);
    assert(pthread_barrier_destroy(&overlap.entered)==0);
    assert(pthread_barrier_destroy(&overlap.release)==0);
    assert(kvpn_platform_enter_v1(owner,19,0,&extra)==0);
    assert(kvpn_platform_leave_v1(&extra,0)==0);
    assert(kvpn_platform_detach_v1(owner,&object)==0 && object==methods);
    assert(kvpn_output_abandon_unclaimed_v1(lease)==0); /* no spurious UNPROVEN */
}

#ifdef KVPN_OUTPUT_TEST_V1
typedef struct { uint64_t owner; int32_t result; } query_drain;
static void *finish_query_drain(void *argument) {
    query_drain *test=argument;
    test->result=kvpn_output_revision_finish_v1(test->owner,0);
    return NULL;
}
static void reverse_query_result_write_keeps_revision_drain_pending(void) {
    uint64_t owner,lease;
    void *methods[20]; for(unsigned i=0;i<20;++i)methods[i]=&methods[i];
    assert(kvpn_output_owner_reserve_v1(1,&owner,&lease)==0);
    assert(kvpn_platform_install_v1(owner,methods,methods)==0);
    kvpn_output_call_v1 opening={0};
    assert(kvpn_output_begin_open_v1(lease,1,&opening)==0);
    kvpn_platform_borrow_v1 callback={0},query={0};
    assert(kvpn_platform_enter_v1(owner,4,7,&callback)==0);
    assert(query_enter(owner,7,&query)==0);
    assert(kvpn_output_revision_begin_v1(owner)==0);
    uint8_t publish=99;
    assert(kvpn_output_try_commit_v1(&opening,0,&publish)!=0 && publish==0);
    kvpn_output_end_v1(&opening);
    assert(kvpn_platform_leave_v1(&callback,0)==0);
    query_drain test={.owner=owner,.result=99}; pthread_t thread;
    assert(pthread_create(&thread,NULL,finish_query_drain,&test)==0);
    while(!kvpn_output_test_waiting_v1(owner))sched_yield();
    assert(query_leave(&query,0)==0); /* final JNI result write has now finished */
    assert(pthread_join(thread,NULL)==0 && test.result==0);
    assert(kvpn_platform_enter_v1(owner,19,0,&callback)==0);
    assert(kvpn_platform_leave_v1(&callback,0)==0);
    void *object=NULL; assert(kvpn_platform_detach_v1(owner,&object)==0);
    assert(kvpn_output_owner_release_v1(owner)==0);
}
#endif

static void real_query_failure_stays_unproven(void) {
    uint64_t owner,lease;
    void *methods[20]; for(unsigned i=0;i<20;++i)methods[i]=&methods[i];
    assert(kvpn_output_owner_reserve_v1(1,&owner,&lease)==0);
    assert(kvpn_platform_install_v1(owner,methods,methods)==0);
    kvpn_platform_borrow_v1 callback={0},query={0},copy={0};
    assert(kvpn_platform_enter_v1(owner,4,7,&callback)==0);
    assert(query_enter(owner,7,&query)==0);
    copy=query;
    assert(query_leave(&copy,0)==25); /* copied frame cannot return retained address */
    assert(query_leave(&query,14)==0);
    assert(kvpn_platform_leave_v1(&callback,0)==0);
    assert(kvpn_platform_enter_v1(owner,19,0,&callback)==0);
    assert(kvpn_platform_leave_v1(&callback,0)==0);
    void *object=NULL; assert(kvpn_platform_detach_v1(owner,&object)==25 && object==NULL);
    assert(kvpn_output_abandon_unclaimed_v1(lease)!=0);
}

static void non_tun_fd_never_yields_proof_or_closes_original(void) {
    uint8_t name[15]; uint32_t written=99;
    memset(name,0x5a,sizeof(name));
    assert(kvpn_tun_read_identity_v1(-1,name,sizeof(name),&written)!=0 && written==0);
    for (unsigned i=0;i<sizeof(name);++i) assert(name[i]==0);
    int descriptors[2]; assert(pipe(descriptors)==0);
    int duplicate=dup(descriptors[0]); assert(duplicate>=0);
    memset(name,0x5a,sizeof(name)); written=99;
    assert(kvpn_tun_read_identity_v1(duplicate,name,sizeof(name),&written)!=0 && written==0);
    for (unsigned i=0;i<sizeof(name);++i) assert(name[i]==0);
    assert((fcntl(duplicate,F_GETFD)&FD_CLOEXEC)!=0);
    assert(close(duplicate)==0);
    assert(fcntl(descriptors[0],F_GETFD)>=0);
    assert(close(descriptors[0])==0 && close(descriptors[1])==0);
}

/* Fencing is not handler admission. Both gates close before either sink begins. */
static void prefence_has_no_orphan_handler(void) {
    uint64_t owner[2], lease[2];
    kvpn_output_call_v1 frame[2] = {{0}};
    for (unsigned i = 0; i < 2; ++i) {
        assert(kvpn_output_owner_reserve_v1((uint8_t)(i + 1), &owner[i], &lease[i]) == 0);
        assert(kvpn_output_begin_open_v1(lease[i], (uint8_t)(i + 1), &frame[i]) == 0);
    }
    assert(kvpn_output_revision_prefence_v1(0) == 25);
    assert(kvpn_output_revision_prefence_v1(UINT64_MAX) == 25);
    for (unsigned i = 0; i < 2; ++i)
        assert(kvpn_output_revision_prefence_v1(owner[i]) == 0);
    for (unsigned i = 0; i < 2; ++i) {
        uint8_t publish = 99;
        assert(kvpn_output_try_commit_v1(&frame[i], 0, &publish) != 0 && publish == 0);
        assert(kvpn_output_revision_begin_v1(owner[i]) == 0);
        kvpn_output_end_v1(&frame[i]);
        assert(kvpn_output_revision_finish_v1(owner[i], 0) == 0);
        assert(kvpn_output_owner_release_v1(owner[i]) == 0);
    }
    assert(kvpn_output_revision_prefence_v1(owner[0]) == 25);
}

static void exact_signals_cannot_fence_replacement_or_wrong_kind(void) {
    uint64_t owner, lease;
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    assert(kvpn_platform_signal_install_v1(owner, 1, UINT64_MAX) == 0);
    assert(kvpn_platform_signal_install_v1(owner, 1, 7) == 25);
    assert(kvpn_platform_signal_install_v1(owner, 3, 8) == 25);
    assert(kvpn_platform_revision_prefence_v1(owner, 7) == 25);
    kvpn_output_call_v1 call = {0};
    assert(kvpn_output_begin_open_v1(lease, 1, &call) == 0);
    assert(kvpn_platform_signal_borrow_v1(owner, 1, UINT64_MAX) == 0);
    assert(kvpn_platform_revision_prefence_v1(owner, UINT64_MAX) == 25);
    assert(kvpn_platform_signal_return_v1(owner, 1, UINT64_MAX) == 0);
    assert(kvpn_platform_revision_prefence_v1(owner, UINT64_MAX) == 0);
    kvpn_output_end_v1(&call);
    assert(kvpn_output_owner_release_v1(owner) != 0);
    assert(kvpn_platform_signal_retire_v1(owner, 1, UINT64_MAX, 0) == 0);
    assert(kvpn_output_owner_release_v1(owner) == 0);
    uint64_t old = owner;
    assert(kvpn_output_owner_reserve_v1(2, &owner, &lease) == 0);
    assert(kvpn_platform_signal_install_v1(owner, 3, 9) == 0);
    assert(kvpn_platform_revision_prefence_v1(owner, 9) == 25);
    assert(kvpn_platform_revision_prefence_v1(old, UINT64_MAX) == 25);
    assert(kvpn_output_abandon_unclaimed_v1(lease) != 0);
    assert(kvpn_platform_signal_retire_v1(owner, 3, 9, 0) == 0);
    assert(kvpn_output_abandon_unclaimed_v1(lease) == 0);
}

static void callback_reference_and_cancel_borrows_retain_owner(void) {
    uint64_t owner, lease;
    void *methods[20];
    for (unsigned i = 0; i < 20; ++i) methods[i] = &methods[i];
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    methods[19] = NULL;
    assert(kvpn_platform_install_v1(owner, methods, methods) == 25);
    methods[19] = &methods[19];
    assert(kvpn_platform_install_v1(owner, methods, methods) == 0);
    assert(kvpn_output_abandon_unclaimed_v1(lease) != 0);
    kvpn_platform_borrow_v1 call = {0}, duplicate = {0}, cancellation = {0};
    assert(kvpn_platform_enter_v1(owner, 18, UINT64_MAX, &cancellation) == 6);
    assert(cancellation.owner == 0); /* No Java borrower, not a cleanup receipt. */
    assert(kvpn_platform_enter_v1(owner, 4, UINT64_MAX, &call) == 0);
    assert(call.object == methods && call.method == methods[4]);
    assert(kvpn_platform_enter_v1(owner, 18, UINT64_MAX, &call) == 25);
    assert(kvpn_platform_enter_v1(owner, 4, 1, &duplicate) == 25);
    assert(kvpn_platform_enter_v1(owner, 18, 1, &cancellation) == 25);
    assert(kvpn_platform_enter_v1(owner, 18, UINT64_MAX, &cancellation) == 0);
    assert(kvpn_platform_leave_v1(&call, 0) == 0);
    assert(kvpn_platform_enter_v1(owner, 19, 0, &duplicate) == 25);
    assert(kvpn_platform_leave_v1(&cancellation, 0) == 0);
    assert(kvpn_platform_enter_v1(owner, 18, UINT64_MAX, &cancellation) == 6);
    assert(kvpn_platform_enter_v1(owner, 19, 0, &duplicate) == 0);
    assert(kvpn_platform_leave_v1(&duplicate, 0) == 0);
    void *object = NULL;
    assert(kvpn_platform_detach_v1(owner, &object) == 0 && object == methods);
    assert(kvpn_output_abandon_unclaimed_v1(lease) == 0);
}

static void fixed_children_do_not_alias_or_disappear_on_failed_close(void) {
    uint64_t owner, lease;
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    assert(kvpn_platform_child_adopt_v1(owner, 1, 11) == 0);
    assert(kvpn_platform_signal_install_v1(owner, 1, 111) == 0);
    assert(kvpn_platform_child_adopt_v1(owner, 1, 12) == 25);
    assert(kvpn_platform_child_adopt_v1(owner, 2, 11) == 25);
    assert(kvpn_platform_child_adopt_v1(owner, 2, 22) == 0);
    assert(kvpn_platform_child_adopt_v1(owner, 4, 33) == 25);
    assert(kvpn_platform_child_adopt_v1(owner, 3, 33) == 0);
    assert(kvpn_platform_child_matches_v1(owner, 2, 22) == 1);
    assert(kvpn_platform_child_retire_v1(owner, 2, 23, 0) == 25);
    assert(kvpn_output_abandon_unclaimed_v1(lease) != 0);
    assert(kvpn_platform_child_retire_v1(owner, 2, 22, 0) == 0);
    assert(kvpn_platform_child_retire_v1(owner, 3, 33, 0) == 0);
    assert(kvpn_platform_child_retire_v1(owner, 1, 11, 0) == 0);
    assert(kvpn_platform_revision_prefence_v1(owner, 111) == 25);
    assert(kvpn_output_abandon_unclaimed_v1(lease) == 0);

    assert(kvpn_output_owner_reserve_v1(2, &owner, &lease) == 0);
    assert(kvpn_platform_child_adopt_v1(owner, 4, 44) == 0);
    assert(kvpn_platform_child_retire_v1(owner, 4, 44, 14) == 25);
    assert(kvpn_platform_child_retire_v1(owner, 4, 44, 0) == 25);
    assert(kvpn_platform_child_matches_v1(owner, 4, 44) == 1);
    assert(kvpn_output_abandon_unclaimed_v1(lease) != 0);
}

static kvpn_cb_bridge_v1 test_capture_sizes(kvpn_cb_owner_v1 a0, kvpn_cb_capture_sizes_v1 * out) {
    (void)a0; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_capture_copy_into(kvpn_cb_owner_v1 a0, kvpn_cb_capture_output_v1 * out) {
    (void)a0; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_production_current_register(kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    (void)a0; (void)parent_epoch; (void)invalidated; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_maintenance_current_register(kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    (void)a0; (void)parent_epoch; (void)invalidated; (void)out;
    return 14;
}
static kvpn_cb_m1 test_revision_revalidate(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2) {
    (void)a0; (void)a1; (void)a2;
    return 14;
}
static kvpn_cb_m1 test_publication_acquire(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2, kvpn_cb_publication_v1 * out) {
    (void)a0; (void)a1; (void)a2; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_publication_is_current(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2, uint8_t * out) {
    (void)a0; (void)a1; (void)a2; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_publication_close(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2) {
    (void)a0; (void)a1; (void)a2;
    return 14;
}
static kvpn_cb_bridge_v1 test_revision_close(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1) {
    (void)a0; (void)a1;
    return 14;
}
static kvpn_cb_p1 test_socket_register(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, const kvpn_cb_socket_expectation_v1 * a2, kvpn_cb_signal_v1 lost, kvpn_cb_socket_v1 * out, uint8_t * binding_required) {
    (void)a0; (void)a1; (void)a2; (void)lost; (void)out; (void)binding_required;
    return 14;
}
static kvpn_cb_p1 test_socket_confirm(kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    (void)a0; (void)a1; (void)protected_ok; (void)has_network; (void)network;
    return 14;
}
static kvpn_cb_p1 test_socket_close(kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1) {
    (void)a0; (void)a1;
    return 14;
}
static kvpn_cb_m1 test_maintenance_network_acquire(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_signal_v1 lost, kvpn_cb_network_v1 * out) {
    (void)a0; (void)a1; (void)lost; (void)out;
    return 14;
}
static kvpn_cb_m1 test_maintenance_network_snapshot(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, kvpn_cb_network_snapshot_v1 * out) {
    (void)a0; (void)a1; (void)out;
    return 14;
}
static kvpn_cb_m1 test_maintenance_network_is_current(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, uint8_t * out) {
    (void)a0; (void)a1; (void)out;
    return 14;
}
static kvpn_cb_m1 test_maintenance_network_bind_socket(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, int32_t fd) {
    (void)a0; (void)a1; (void)fd;
    return 14;
}
static kvpn_cb_bridge_v1 test_maintenance_network_close(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1) {
    (void)a0; (void)a1;
    return 14;
}
static kvpn_cb_m1 test_system_roots_into(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_output_v1 * out) {
    (void)a0; (void)a1; (void)out;
    return 14;
}
static kvpn_cb_bridge_v1 test_cancel_call(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1) {
    (void)a0; (void)a1;
    return 14;
}
static kvpn_cb_bridge_v1 test_owner_close(kvpn_cb_owner_v1 a0) {
    (void)a0;
    return 14;
}
static void complete_typed_table_is_required(void) {
    kvpn_android_callbacks_v1 table = { .version = 1, .struct_size = sizeof(table),
        .capture_sizes = test_capture_sizes,
        .capture_copy_into = test_capture_copy_into,
        .production_current_register = test_production_current_register,
        .maintenance_current_register = test_maintenance_current_register,
        .revision_revalidate = test_revision_revalidate,
        .publication_acquire = test_publication_acquire,
        .publication_is_current = test_publication_is_current,
        .publication_close = test_publication_close,
        .revision_close = test_revision_close,
        .socket_register = test_socket_register,
        .socket_confirm = test_socket_confirm,
        .socket_close = test_socket_close,
        .maintenance_network_acquire = test_maintenance_network_acquire,
        .maintenance_network_snapshot = test_maintenance_network_snapshot,
        .maintenance_network_is_current = test_maintenance_network_is_current,
        .maintenance_network_bind_socket = test_maintenance_network_bind_socket,
        .maintenance_network_close = test_maintenance_network_close,
        .system_roots_into = test_system_roots_into,
        .cancel_call = test_cancel_call,
        .owner_close = test_owner_close,
        .output = kvpn_output_callbacks_table_v1() };
    assert(kvpn_android_table_valid_v1(&table) == 1);
    assert(kvpn_android_table_valid_v1(NULL) == 0);
    table.version = 2;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.version = 1;
    table.struct_size--;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.struct_size++;
    table.capture_sizes = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.capture_sizes = test_capture_sizes;
    table.capture_copy_into = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.capture_copy_into = test_capture_copy_into;
    table.production_current_register = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.production_current_register = test_production_current_register;
    table.maintenance_current_register = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_current_register = test_maintenance_current_register;
    table.revision_revalidate = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.revision_revalidate = test_revision_revalidate;
    table.publication_acquire = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.publication_acquire = test_publication_acquire;
    table.publication_is_current = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.publication_is_current = test_publication_is_current;
    table.publication_close = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.publication_close = test_publication_close;
    table.revision_close = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.revision_close = test_revision_close;
    table.socket_register = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.socket_register = test_socket_register;
    table.socket_confirm = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.socket_confirm = test_socket_confirm;
    table.socket_close = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.socket_close = test_socket_close;
    table.maintenance_network_acquire = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_network_acquire = test_maintenance_network_acquire;
    table.maintenance_network_snapshot = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_network_snapshot = test_maintenance_network_snapshot;
    table.maintenance_network_is_current = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_network_is_current = test_maintenance_network_is_current;
    table.maintenance_network_bind_socket = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_network_bind_socket = test_maintenance_network_bind_socket;
    table.maintenance_network_close = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.maintenance_network_close = test_maintenance_network_close;
    table.system_roots_into = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.system_roots_into = test_system_roots_into;
    table.cancel_call = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.cancel_call = test_cancel_call;
    table.owner_close = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
    table.owner_close = test_owner_close;
    table.output = NULL;
    assert(kvpn_android_table_valid_v1(&table) == 0);
}

static void exact_unclaimed_receiver_borrow_does_not_close_or_claim(void) {
    uint64_t owner = 0, lease = 0, abandoned = 0;
    void *methods[20];
    for (unsigned i = 0; i < 20; ++i) methods[i] = &methods[i];
    assert(kvpn_output_owner_reserve_v1(1, &owner, &lease) == 0);
    assert(kvpn_platform_install_v1(owner, methods, methods) == 0);
    kvpn_platform_borrow_v1 borrow = {0};
    assert(kvpn_platform_unclaimed_borrow_v1(lease + 1, &borrow) == 25);
    assert(kvpn_platform_unclaimed_borrow_v1(lease, &borrow) == 0);
    assert(borrow.owner == owner && borrow.object == methods && borrow.method_index == 0);
    /* A wrong receiver returns the read-only borrow, leaving the real lease usable. */
    assert(kvpn_platform_leave_v1(&borrow, 0) == 0);
    assert(kvpn_platform_unclaimed_borrow_v1(lease, &borrow) == 0);
    kvpn_output_call_v1 opening = {0};
    assert(kvpn_output_begin_open_v1(lease, 1, &opening) == 0);
    assert(kvpn_platform_leave_v1(&borrow, 0) == 0);
    assert(kvpn_platform_abandon_owner_v1(lease, &abandoned) == 25 && abandoned == 0);
    assert(kvpn_platform_unclaimed_borrow_v1(lease, &borrow) == 25);
    kvpn_output_end_v1(&opening);
    assert(kvpn_platform_enter_v1(owner, 19, 0, &borrow) == 0);
    assert(kvpn_platform_leave_v1(&borrow, 0) == 0);
    void *object = NULL;
    assert(kvpn_platform_detach_v1(owner, &object) == 0 && object == methods);
    assert(kvpn_output_owner_release_v1(owner) == 0);
}

int main(void) {
    alarm(30); /* watchdog only, never a scheduling oracle */
    nested_cancellation_query_and_ordinary_poll_retain_exact_owner();
    real_query_failure_stays_unproven();
#ifdef KVPN_OUTPUT_TEST_V1
    reverse_query_result_write_keeps_revision_drain_pending();
#endif
    uint64_t shared = 0, owner_bytes = 0, frames = 0, maintenance_frames = 0;
    assert(kvpn_output_layout_v1(2, &shared, &owner_bytes, &maintenance_frames) == 0);
    assert(kvpn_output_layout_v1(1, &shared, &owner_bytes, &frames) == 0);
    printf("C layout: shared64=%llu owner=%llu production_frames=%llu maintenance_frames=%llu platform_table=%zu align=%zu borrower=%zu align=%zu network_snapshot=%zu socket_expectation=%zu\n",
        (unsigned long long)shared, (unsigned long long)owner_bytes, (unsigned long long)frames,
        (unsigned long long)maintenance_frames, sizeof(kvpn_android_callbacks_v1), _Alignof(kvpn_android_callbacks_v1),
        sizeof(kvpn_platform_borrow_v1), _Alignof(kvpn_platform_borrow_v1), sizeof(kvpn_cb_network_snapshot_v1), sizeof(kvpn_cb_socket_expectation_v1));
    exact_unclaimed_receiver_borrow_does_not_close_or_claim();
    non_tun_fd_never_yields_proof_or_closes_original();
    complete_typed_table_is_required();
    prefence_has_no_orphan_handler();
    exact_signals_cannot_fence_replacement_or_wrong_kind();
    callback_reference_and_cancel_borrows_retain_owner();
    fixed_children_do_not_alias_or_disappear_on_failed_close();
    puts("Android callback bookkeeping: PASS");
    return 0;
}

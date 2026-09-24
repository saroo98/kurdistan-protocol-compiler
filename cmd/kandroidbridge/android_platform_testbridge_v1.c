//go:build phase18outputtest && cgo && linux && !android

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "android_callbacks_v1.h"
#include "../../android/core/native-jni/src/main/cpp/kvpn_output_gate_v1.h"
#include <string.h>
static int32_t results[20];
static uint32_t calls[20];
static uint8_t mutate;
static uint8_t network_current = 1;
void kvpn_android_test_network_current_v1(uint8_t current) { network_current = current; }
static uint8_t captured[2721543];
static uint8_t host_roots[65536];
static uint32_t host_roots_length;
int32_t kvpn_android_test_roots_v1(const uint8_t *bytes, uint32_t length) {
    if (length > sizeof(host_roots) || (length && !bytes)) return 2;
    memset(host_roots, 0, sizeof(host_roots)); host_roots_length = length;
    if (length) memcpy(host_roots, bytes, length);
    return 0;
}
static uint32_t captured_sizes[5];
static uint64_t next_child=1000;
static uint64_t finalized_test_owner;
static uint8_t finalized_test_receiver;
int32_t kvpn_android_test_install_receiver_v1(uint64_t owner) {
    void *methods[20];
    for (unsigned i = 0; i < 20; ++i) methods[i] = &finalized_test_receiver;
    int32_t status = kvpn_platform_install_v1(owner, &finalized_test_receiver, methods);
    if (!status) finalized_test_owner = owner;
    return status;
}
static kvpn_cb_bridge_v1 test_capture_sizes(kvpn_cb_owner_v1 a0, kvpn_cb_capture_sizes_v1 * out) {
    ++calls[0];
    (void)a0; *out = (kvpn_cb_capture_sizes_v1){2,3,5,7,11};
    if (captured_sizes[0]) *out = (kvpn_cb_capture_sizes_v1){captured_sizes[0],captured_sizes[1],captured_sizes[2],captured_sizes[3],captured_sizes[4]};
    return results[0];
}
static kvpn_cb_bridge_v1 test_capture_copy_into(kvpn_cb_owner_v1 a0, kvpn_cb_capture_output_v1 * out) {
    ++calls[1];
    (void)a0; kvpn_cb_output_v1 *rows[5] = {&out->verify_request, &out->activation_record, &out->recipient_request, &out->recipient_private, &out->settings};
    uint32_t at=0;
    for (unsigned i=0; i<5; ++i) {
        if (captured_sizes[0]) { if (rows[i]->capacity != captured_sizes[i]) return 25; memcpy(rows[i]->data, captured+at, captured_sizes[i]); at+=captured_sizes[i]; }
        else memset(rows[i]->data, (int)i+1, rows[i]->capacity);
        rows[i]->written=rows[i]->capacity;
    }
    if (mutate) out->verify_request.capacity++;
    return results[1];
}
static kvpn_cb_bridge_v1 test_production_current_register(kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    ++calls[2];
    (void)a0; (void)parent_epoch; (void)invalidated; *out=++next_child;
    return results[2];
}
static kvpn_cb_bridge_v1 test_maintenance_current_register(kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    ++calls[3];
    (void)a0; (void)parent_epoch; (void)invalidated; *out=results[3] ? 0 : ++next_child;
    return results[3];
}
static kvpn_cb_m1 test_revision_revalidate(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2) {
    (void)a0; (void)a1; (void)a2;
    return results[4];
}
static kvpn_cb_m1 test_publication_acquire(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2, kvpn_cb_publication_v1 * out) {
    ++calls[5];
    (void)a0; (void)a1; (void)a2; *out=++next_child;
    return results[5];
}
static kvpn_cb_bridge_v1 test_publication_is_current(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2, uint8_t * out) {
    (void)a0; (void)a1; (void)a2; *out=1;
    return results[6];
}
static kvpn_cb_bridge_v1 test_publication_close(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2) {
    (void)a0; (void)a1; (void)a2;
    return results[7];
}
static kvpn_cb_bridge_v1 test_revision_close(kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1) {
    (void)a0; (void)a1;
    return results[8];
}
static kvpn_cb_p1 test_socket_register(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, const kvpn_cb_socket_expectation_v1 * a2, kvpn_cb_signal_v1 lost, kvpn_cb_socket_v1 * out, uint8_t * binding_required) {
    if (!a0 || !a1 || !lost || !a2 || !a2->parent_epoch || !a2->attempt || !a2->socket_token || a2->fd<0 || a2->selection_explicit>1 || a2->has_network>1) return 1;
    *out=++next_child; *binding_required=1;
    return results[9];
}
static kvpn_cb_p1 test_socket_confirm(kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    (void)a0; (void)a1; (void)protected_ok; (void)has_network; (void)network;
    return results[10];
}
static kvpn_cb_p1 test_socket_close(kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1) {
    (void)a0; (void)a1;
    return results[11];
}
static kvpn_cb_m1 test_maintenance_network_acquire(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_signal_v1 lost, kvpn_cb_network_v1 * out) {
    (void)a0; (void)a1; (void)lost; *out=++next_child;
    return results[12];
}
static kvpn_cb_m1 test_maintenance_network_snapshot(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, kvpn_cb_network_snapshot_v1 * out) {
    (void)a0; (void)a1;
    memset(out,0,sizeof(*out)); out->mode=1; out->families=1; out->dns_count=1;
    out->dns[0].family=4; out->dns[0].port=53; memset(out->dns[0].address,1,4);
    return results[13];
}
static kvpn_cb_m1 test_maintenance_network_is_current(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, uint8_t * out) {
    (void)a0; (void)a1; *out=network_current;
    return results[14];
}
static kvpn_cb_m1 test_maintenance_network_bind_socket(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, int32_t fd) {
    ++calls[15];
    (void)a0; (void)a1; (void)fd;
    return results[15];
}
static kvpn_cb_bridge_v1 test_maintenance_network_close(kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1) {
    (void)a0; (void)a1;
    return results[16];
}
static kvpn_cb_m1 test_system_roots_into(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_output_v1 * out) {
    (void)a0; (void)a1;
    const uint8_t bytes[8]={1,0,1,0,0,0,1,0x30};
    if (host_roots_length) {
        if (out->capacity < host_roots_length) return 6;
        memcpy(out->data, host_roots, host_roots_length); out->written = host_roots_length;
        return results[17];
    }
    if (out->capacity<8) return 6;
    memcpy(out->data,bytes,8); out->written=8;
    if (mutate) out->capacity++;
    return results[17];
}
static kvpn_cb_bridge_v1 test_cancel_call(kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1) {
    (void)a0; (void)a1;
    return results[18];
}
static kvpn_cb_bridge_v1 test_owner_close(kvpn_cb_owner_v1 a0) {
    if (a0 == finalized_test_owner) {
        kvpn_platform_borrow_v1 borrow = {0};
        if (kvpn_platform_enter_v1(a0, 19, 0, &borrow)) return 25;
        int32_t status = kvpn_platform_leave_v1(&borrow, results[19]);
        if (status || results[19]) return status ? status : results[19];
        void *receiver = NULL;
        if (kvpn_platform_detach_v1(a0, &receiver) || receiver != &finalized_test_receiver) return 25;
        status = kvpn_output_owner_release_v1(a0);
        if (!status) finalized_test_owner = 0;
        return status ? 25 : 0;
    }
    return results[19];
}
static kvpn_android_callbacks_v1 table = {
    .version=1, .struct_size=sizeof(kvpn_android_callbacks_v1),
    .capture_sizes=test_capture_sizes,
    .capture_copy_into=test_capture_copy_into,
    .production_current_register=test_production_current_register,
    .maintenance_current_register=test_maintenance_current_register,
    .revision_revalidate=test_revision_revalidate,
    .publication_acquire=test_publication_acquire,
    .publication_is_current=test_publication_is_current,
    .publication_close=test_publication_close,
    .revision_close=test_revision_close,
    .socket_register=test_socket_register,
    .socket_confirm=test_socket_confirm,
    .socket_close=test_socket_close,
    .maintenance_network_acquire=test_maintenance_network_acquire,
    .maintenance_network_snapshot=test_maintenance_network_snapshot,
    .maintenance_network_is_current=test_maintenance_network_is_current,
    .maintenance_network_bind_socket=test_maintenance_network_bind_socket,
    .maintenance_network_close=test_maintenance_network_close,
    .system_roots_into=test_system_roots_into,
    .cancel_call=test_cancel_call,
    .owner_close=test_owner_close
};
const kvpn_android_callbacks_v1 *kvpn_android_test_table_v1(void) {
    table.output=kvpn_output_callbacks_table_v1();
    return &table;
}
/* Only the tagged host build substitutes the explicit callback fixture.
 * Production and host still execute the same private finalization source. */
const kvpn_android_callbacks_v1 *kvpn_android_callbacks_table_v1(void) {
    return kvpn_android_test_table_v1();
}
void kvpn_android_test_reset_v1(void) { memset(results,0,sizeof(results)); memset(calls,0,sizeof(calls)); memset(captured,0,sizeof(captured)); memset(captured_sizes,0,sizeof(captured_sizes)); memset(host_roots,0,sizeof(host_roots)); host_roots_length=0; mutate=0; network_current=1; }
uint32_t kvpn_android_test_call_count_v1(uint8_t method) { return method < 20 ? calls[method] : 0; }
void kvpn_android_test_mutate_v1(void) { mutate=1; }
void kvpn_android_test_result_v1(uint8_t method,int32_t result) { if(method<20) results[method]=result; }
int32_t kvpn_android_test_capture_v1(const uint8_t *data, uint32_t size, const uint32_t *lengths) {
    uint64_t total=0;
    for (unsigned i=0;i<5;++i) total+=lengths[i];
    if (!data || total!=size || size>sizeof(captured)) return 1;
    memcpy(captured,data,size); memcpy(captured_sizes,lengths,sizeof(captured_sizes)); return 0;
}

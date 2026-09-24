// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_ANDROID_CALLBACKS_V1_H
#define KVPN_ANDROID_CALLBACKS_V1_H
#include <stdint.h>
#include "output_callbacks_v1.h"
typedef uint64_t kvpn_cb_owner_v1;
typedef uint64_t kvpn_cb_registration_v1;
typedef uint64_t kvpn_cb_publication_v1;
typedef uint64_t kvpn_cb_socket_v1;
typedef uint64_t kvpn_cb_network_v1;
typedef uint64_t kvpn_cb_signal_v1;
typedef uint64_t kvpn_cb_call_v1;

/* Return namespaces, never interchangeable despite the common storage type. */
typedef int32_t kvpn_cb_bridge_v1;  /* androidbridge.ErrorCode */
typedef int32_t kvpn_cb_m1;         /* MaintenanceResultV1 */
typedef int32_t kvpn_cb_p1;         /* production P1 */

typedef struct {
    uint8_t *data;
    uint32_t capacity;
    uint32_t written;
} kvpn_cb_output_v1;

typedef struct {
    uint32_t verify_request;
    uint32_t activation_record;
    uint32_t recipient_request;
    uint32_t recipient_private;
    uint32_t settings;
} kvpn_cb_capture_sizes_v1;

typedef struct {
    kvpn_cb_output_v1 verify_request;
    kvpn_cb_output_v1 activation_record;
    kvpn_cb_output_v1 recipient_request;
    kvpn_cb_output_v1 recipient_private;
    kvpn_cb_output_v1 settings;
} kvpn_cb_capture_output_v1;

/* Exact IdentityV1/SelectionV1 values, not a replacement OS-proof record. */
typedef struct {
    uint64_t parent_epoch;
    uint64_t attempt;
    uint64_t socket_token;
    int32_t fd;
    uint8_t selection_explicit;  /* 0 or 1 */
    uint8_t has_network;         /* 0 or 1 */
    uint64_t network;
} kvpn_cb_socket_expectation_v1;

typedef struct {
    uint8_t family;              /* 4 or 6 */
    uint8_t address[16];         /* IPv4 uses first 4 bytes; remainder zero */
    uint16_t port;               /* host-order private ABI, must be 53 */
} kvpn_cb_dns_server_v1;

typedef struct {
    uint8_t mode;                /* exact native ProbeModeV1 value */
    uint8_t families;            /* exact native 1..3 family mask */
    uint8_t dns_count;           /* 1..4 */
    kvpn_cb_dns_server_v1 dns[4]; /* unused entries completely zero */
} kvpn_cb_network_snapshot_v1;
typedef struct {
    uint32_t version;
    uint32_t struct_size;

    kvpn_cb_bridge_v1 (*capture_sizes)(kvpn_cb_owner_v1,
        kvpn_cb_capture_sizes_v1 *out);
    kvpn_cb_bridge_v1 (*capture_copy_into)(kvpn_cb_owner_v1,
        kvpn_cb_capture_output_v1 *out);

    kvpn_cb_bridge_v1 (*production_current_register)(kvpn_cb_owner_v1,
        uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated,
        kvpn_cb_registration_v1 *out);
    kvpn_cb_bridge_v1 (*maintenance_current_register)(kvpn_cb_owner_v1,
        uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated,
        kvpn_cb_registration_v1 *out);
    kvpn_cb_m1 (*revision_revalidate)(kvpn_cb_owner_v1,
        kvpn_cb_registration_v1, kvpn_cb_call_v1);
    kvpn_cb_m1 (*publication_acquire)(kvpn_cb_owner_v1,
        kvpn_cb_registration_v1, kvpn_cb_call_v1,
        kvpn_cb_publication_v1 *out);
    kvpn_cb_bridge_v1 (*publication_is_current)(kvpn_cb_owner_v1,
        kvpn_cb_registration_v1, kvpn_cb_publication_v1, uint8_t *out);
    kvpn_cb_bridge_v1 (*publication_close)(kvpn_cb_owner_v1,
        kvpn_cb_registration_v1, kvpn_cb_publication_v1);
    kvpn_cb_bridge_v1 (*revision_close)(kvpn_cb_owner_v1,
        kvpn_cb_registration_v1);

    kvpn_cb_p1 (*socket_register)(kvpn_cb_owner_v1, kvpn_cb_call_v1,
        const kvpn_cb_socket_expectation_v1 *, kvpn_cb_signal_v1 lost,
        kvpn_cb_socket_v1 *out, uint8_t *binding_required);
    kvpn_cb_p1 (*socket_confirm)(kvpn_cb_owner_v1, kvpn_cb_socket_v1,
        uint8_t protected_ok, uint8_t has_network, uint64_t network);
    kvpn_cb_p1 (*socket_close)(kvpn_cb_owner_v1, kvpn_cb_socket_v1);

    kvpn_cb_m1 (*maintenance_network_acquire)(kvpn_cb_owner_v1,
        kvpn_cb_call_v1, kvpn_cb_signal_v1 lost, kvpn_cb_network_v1 *out);
    kvpn_cb_m1 (*maintenance_network_snapshot)(kvpn_cb_owner_v1,
        kvpn_cb_network_v1, kvpn_cb_network_snapshot_v1 *out);
    kvpn_cb_m1 (*maintenance_network_is_current)(kvpn_cb_owner_v1,
        kvpn_cb_network_v1, uint8_t *out);
    kvpn_cb_m1 (*maintenance_network_bind_socket)(kvpn_cb_owner_v1,
        kvpn_cb_network_v1, int32_t fd);
    kvpn_cb_bridge_v1 (*maintenance_network_close)(kvpn_cb_owner_v1,
        kvpn_cb_network_v1);
    kvpn_cb_m1 (*system_roots_into)(kvpn_cb_owner_v1,
        kvpn_cb_call_v1, kvpn_cb_output_v1 *out);

    /* Cancellation only, no dispatchable arbitrary operation or payload. */
    kvpn_cb_bridge_v1 (*cancel_call)(kvpn_cb_owner_v1, kvpn_cb_call_v1);
    kvpn_cb_bridge_v1 (*owner_close)(kvpn_cb_owner_v1);
    const kvpn_output_callbacks_v1 *output;
} kvpn_android_callbacks_v1;
kvpn_cb_bridge_v1 kvpn_android_revision_invalidated_v1(
    kvpn_cb_owner_v1 owner, kvpn_cb_signal_v1 signal);
kvpn_cb_bridge_v1 kvpn_android_socket_lost_v1(
    kvpn_cb_owner_v1 owner, kvpn_cb_signal_v1 signal);
kvpn_cb_bridge_v1 kvpn_android_maintenance_network_lost_v1(
    kvpn_cb_owner_v1 owner, kvpn_cb_signal_v1 signal);
kvpn_cb_bridge_v1 kvpn_android_call_cancelled_v1(
    kvpn_cb_owner_v1 owner, kvpn_cb_call_v1 call, uint8_t *out);
kvpn_cb_bridge_v1 kvpn_android_call_remaining_millis_v1(
    kvpn_cb_owner_v1 owner, kvpn_cb_call_v1 call,
    uint8_t *has_deadline, uint64_t *remaining);

int32_t kvpn_android_table_valid_v1(const kvpn_android_callbacks_v1 *);
/* Forwarders are used only within the bridge; only table validation crosses
 * the JNI/bridge boundary. Match the output callback helper visibility. */
#if defined(__GNUC__)
#pragma GCC visibility push(hidden)
#endif
kvpn_cb_bridge_v1 kvpn_android_capture_sizes_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_capture_sizes_v1 * out);
kvpn_cb_bridge_v1 kvpn_android_capture_copy_into_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_capture_output_v1 * out);
kvpn_cb_bridge_v1 kvpn_android_production_current_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out);
kvpn_cb_bridge_v1 kvpn_android_maintenance_current_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out);
kvpn_cb_m1 kvpn_android_revision_revalidate_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2);
kvpn_cb_m1 kvpn_android_publication_acquire_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2, kvpn_cb_publication_v1 * out);
kvpn_cb_bridge_v1 kvpn_android_publication_is_current_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2, uint8_t * out);
kvpn_cb_bridge_v1 kvpn_android_publication_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2);
kvpn_cb_bridge_v1 kvpn_android_revision_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1);
kvpn_cb_p1 kvpn_android_socket_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, const kvpn_cb_socket_expectation_v1 * a2, kvpn_cb_signal_v1 lost, kvpn_cb_socket_v1 * out, uint8_t * binding_required);
kvpn_cb_p1 kvpn_android_socket_confirm_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1, uint8_t protected_ok, uint8_t has_network, uint64_t network);
kvpn_cb_p1 kvpn_android_socket_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1);
kvpn_cb_m1 kvpn_android_maintenance_network_acquire_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_signal_v1 lost, kvpn_cb_network_v1 * out);
kvpn_cb_m1 kvpn_android_maintenance_network_snapshot_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, kvpn_cb_network_snapshot_v1 * out);
kvpn_cb_m1 kvpn_android_maintenance_network_is_current_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, uint8_t * out);
kvpn_cb_m1 kvpn_android_maintenance_network_bind_socket_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, int32_t fd);
kvpn_cb_bridge_v1 kvpn_android_maintenance_network_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1);
kvpn_cb_m1 kvpn_android_system_roots_into_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_output_v1 * out);
kvpn_cb_bridge_v1 kvpn_android_cancel_call_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1);
kvpn_cb_bridge_v1 kvpn_android_owner_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0);
#if defined(__GNUC__)
#pragma GCC visibility pop
#endif
#endif

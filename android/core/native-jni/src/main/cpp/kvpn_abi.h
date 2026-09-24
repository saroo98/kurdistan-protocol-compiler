// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

#ifndef KVPN_ABI_H
#define KVPN_ABI_H

#include <stdint.h>

/* New P1 namespace. These definitions belong to the JNI facade DSO, not the
 * Go DSO. Explicit visibility survives the facade's default hidden build. */
#define KVPN_PRODUCTION_ABI_V1 __attribute__((visibility("default")))
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_open_v1(const uint8_t *request, uint32_t request_len,
    uint64_t private_platform_lease, uint64_t *session,
    uint8_t *snapshot, uint32_t snapshot_cap, uint32_t *snapshot_len);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_next_control_v1(uint64_t session,
    uint8_t *output, uint32_t capacity, uint32_t *written);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_confirm_socket_v1(uint64_t session, uint64_t socket_token,
    uint8_t protected_ok, uint8_t has_network, uint64_t network_handle);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_submit_packet_v1(uint64_t session,
    const uint8_t *packet, uint32_t length);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_receive_packet_v1(uint64_t session,
    uint8_t *output, uint32_t capacity, uint32_t *written, uint64_t *delivery_token);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_confirm_packet_v1(uint64_t session,
    uint64_t delivery_token, uint32_t delivered_length);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_reject_packet_v1(uint64_t session, uint64_t delivery_token);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_open_stream_v1(uint64_t session,
    const uint8_t *request, uint32_t request_len, uint64_t *stream_child);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_run_probe_v1(uint64_t session,
    const uint8_t *request, uint32_t request_len,
    uint8_t *output, uint32_t capacity, uint32_t *written);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_reconnect_v1(uint64_t session, uint8_t reason);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_handover_v1(uint64_t session,
    uint8_t has_network, uint64_t network_handle);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_cancel_v1(uint64_t session);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_prod_close_v1(uint64_t session);

KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_send_v1(uint64_t session, uint64_t stream_child,
    const uint8_t *input, uint32_t length);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_receive_v1(uint64_t session, uint64_t stream_child,
    uint8_t *output, uint32_t capacity, uint32_t *written, uint64_t *delivery_token);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_confirm_v1(uint64_t session, uint64_t stream_child,
    uint64_t delivery_token, uint32_t delivered_length);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_reject_v1(uint64_t session, uint64_t stream_child,
    uint64_t delivery_token);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_half_close_v1(uint64_t session, uint64_t stream_child);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_cancel_v1(uint64_t session, uint64_t stream_child);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_stream_close_v1(uint64_t session, uint64_t stream_child);

KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_open_v1(const uint8_t *request, uint32_t request_len,
    uint64_t private_platform_lease, uint64_t *maintenance);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_check_update_v1(uint64_t maintenance,
    const uint8_t *request, uint32_t request_len,
    uint8_t *output, uint32_t capacity, uint32_t *written);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_materialize_v1(uint64_t maintenance, uint64_t candidate_child,
    uint8_t *output, uint32_t capacity, uint32_t *written);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_release_update_v1(uint64_t maintenance, uint64_t candidate_child);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_run_probe_v1(uint64_t maintenance,
    const uint8_t *request, uint32_t request_len,
    uint8_t *output, uint32_t capacity, uint32_t *written);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_cancel_v1(uint64_t maintenance);
KVPN_PRODUCTION_ABI_V1 int32_t kvpn_maintenance_close_v1(uint64_t maintenance);

int32_t kvpn_abi_info(uint8_t *output, uint32_t capacity, uint32_t *output_length);
int32_t kvpn_verify_preview(
    uint8_t *input,
    uint32_t input_length,
    uint64_t *output_handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_recipient_create(uint32_t validity_seconds, uint64_t *output_handle);
int32_t kvpn_recipient_request(
    uint64_t handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_recipient_private_export(
    uint64_t handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_recipient_validate(
    uint8_t *recipient_request,
    uint32_t recipient_request_length,
    uint8_t *recipient_private,
    uint32_t recipient_private_length);
int32_t kvpn_verify_preview_with_recipient(
    uint8_t *input,
    uint32_t input_length,
    uint8_t *recipient_request,
    uint32_t recipient_request_length,
    uint8_t *recipient_private,
    uint32_t recipient_private_length,
    uint64_t *output_handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_activation_open(uint64_t verified, uint64_t *output_handle);
int32_t kvpn_activation_next(
    uint64_t handle,
    uint64_t *sequence,
    uint32_t *kind,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_activation_submit(
    uint64_t handle,
    uint64_t sequence,
    uint32_t kind,
    uint8_t storage_ok,
    uint8_t *active,
    uint32_t active_length,
    uint8_t *last_known_good,
    uint32_t last_known_good_length,
    uint8_t *reopened,
    uint32_t reopened_length);
int32_t kvpn_diagnostic_prepare(
    uint8_t *input,
    uint32_t input_length,
    uint64_t *output_handle);
int32_t kvpn_diagnostic_preview(
    uint64_t handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_diagnostic_confirm(
    uint64_t handle,
    uint8_t approved,
    uint8_t *preview,
    uint32_t preview_length);
int32_t kvpn_diagnostic_build(
    uint64_t handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_backup_create(
    uint8_t *payload,
    uint32_t payload_length,
    uint8_t *passphrase,
    uint32_t passphrase_length,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_backup_open_preview(
    uint8_t *input,
    uint32_t input_length,
    uint8_t *passphrase,
    uint32_t passphrase_length,
    uint64_t *output_handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_backup_restore(
    uint64_t handle,
    uint8_t *preview,
    uint32_t preview_length,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_runtime_session_open(
    uint8_t *input,
    uint32_t input_length,
    uint64_t *output_handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_runtime_session_open_v2(
    uint8_t *input,
    uint32_t input_length,
    uint64_t *output_handle,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_runtime_socket_prepare(uint64_t handle, int32_t *output_fd);
int32_t kvpn_runtime_socket_commit_protected(uint64_t handle, uint8_t protected_socket);
int32_t kvpn_runtime_tun_attach(uint64_t handle, int32_t fd);
int32_t kvpn_runtime_status(uint64_t handle, uint32_t *output_state);
int32_t kvpn_runtime_diagnostics_v1(uint64_t handle, uint64_t *output, uint32_t output_count);
int32_t kvpn_runtime_rejection_code_v1(uint64_t handle, uint32_t *output_code);
int32_t kvpn_runtime_stop(uint64_t handle);
int32_t kvpn_cancel(uint64_t handle);
int32_t kvpn_free(uint64_t handle);

#endif

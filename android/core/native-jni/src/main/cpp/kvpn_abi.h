// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

#ifndef KVPN_ABI_H
#define KVPN_ABI_H

#include <stdint.h>

int32_t kvpn_abi_info(uint8_t *output, uint32_t capacity, uint32_t *output_length);
int32_t kvpn_verify_preview(
    uint8_t *input,
    uint32_t input_length,
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
int32_t kvpn_phase11_roundtrip(
    uint8_t *input,
    uint32_t input_length,
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
int32_t kvpn_runtime_session_roundtrip(
    uint64_t handle,
    uint8_t *input,
    uint32_t input_length,
    uint8_t *output,
    uint32_t capacity,
    uint32_t *output_length);
int32_t kvpn_cancel(uint64_t handle);
int32_t kvpn_free(uint64_t handle);

#endif

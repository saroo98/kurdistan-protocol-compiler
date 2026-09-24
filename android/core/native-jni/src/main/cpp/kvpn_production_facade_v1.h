// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_PRODUCTION_FACADE_V1_H
#define KVPN_PRODUCTION_FACADE_V1_H
#include "kvpn_output_gate_v1.h"
#include "android_callbacks_v1.h"
#include "production_scoped_exports_v1.h"

/* Counted private storage for an admitted production facade call. Allocation
 * follows Begin. The largest canonical production result is a full packet. */
typedef struct {
    uint8_t bytes[65535];
    uint64_t parent, token;
    uint32_t written;
} kvpn_production_output_stage_v1;
typedef struct {
    uint8_t bytes[1052763];
    uint64_t parent, candidate;
    uint32_t written;
    kvpn_maintenance_decision_v1 decision;
} kvpn_maintenance_output_stage_v1;
int32_t kvpn_maintenance_check_update_core_v1(kvpn_output_call_v1 *, uint64_t, const uint8_t *, uint32_t, kvpn_maintenance_output_stage_v1 *);
int32_t kvpn_maintenance_discard_candidate_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_maintenance_materialize_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *);
int32_t kvpn_maintenance_release_update_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_maintenance_run_probe_core_v1(kvpn_output_call_v1 *, uint64_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
uint64_t kvpn_platform_call_backing_v1(void);
int32_t kvpn_maintenance_direct_backing_v1(uint64_t, uint64_t *);
int32_t kvpn_maintenance_open_core_v1(kvpn_output_call_v1 *, const kvpn_android_callbacks_v1 *, const uint8_t *, uint32_t, uint64_t, uint64_t *);
int32_t kvpn_maintenance_discard_parent_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_maintenance_cancel_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_maintenance_close_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_prod_direct_backing_v1(uint64_t, uint64_t *);
int32_t kvpn_prod_run_probe_core_v1(kvpn_output_call_v1 *, uint64_t, const uint8_t *, uint32_t, uint8_t *, uint32_t *);
int32_t kvpn_prod_open_stream_core_v1(kvpn_output_call_v1 *, uint64_t, const uint8_t *, uint32_t, uint64_t *);
int32_t kvpn_prod_discard_stream_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_stream_receive_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
int32_t kvpn_stream_discard_delivery_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint64_t);

int32_t kvpn_prod_open_core_v1(kvpn_output_call_v1 *, const kvpn_android_callbacks_v1 *,
    const uint8_t *, uint32_t, uint8_t *, uint64_t, uint64_t *, uint32_t *);
int32_t kvpn_prod_discard_parent_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_prod_cancel_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_prod_close_core_v1(kvpn_output_call_v1 *, uint64_t);
int32_t kvpn_prod_receive_packet_core_v1(kvpn_output_call_v1 *, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
int32_t kvpn_prod_discard_packet_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_prod_next_control_core_v1(kvpn_output_call_v1 *, uint64_t, uint8_t *, uint32_t, uint32_t *);
int32_t kvpn_prod_submit_packet_core_v1(kvpn_output_call_v1 *, uint64_t, const uint8_t *, uint32_t);
int32_t kvpn_stream_send_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, const uint8_t *, uint32_t);

int32_t kvpn_prod_reconnect_core_v1(kvpn_output_call_v1 *, uint64_t, uint8_t);
/* Shared publication bookkeeping only, never dispatches an operation. The
 * caller retains its own frame until all final result writes have completed. */
int32_t kvpn_production_commit_scalar_v1(kvpn_output_call_v1 *, int32_t);
int32_t kvpn_prod_confirm_socket_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint8_t, uint8_t, uint64_t);
int32_t kvpn_prod_confirm_packet_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint32_t);
int32_t kvpn_prod_reject_packet_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_prod_handover_core_v1(kvpn_output_call_v1 *, uint64_t, uint8_t, uint64_t);
int32_t kvpn_stream_confirm_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint64_t, uint32_t);
int32_t kvpn_stream_reject_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t, uint64_t);
int32_t kvpn_stream_half_close_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_stream_cancel_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
int32_t kvpn_stream_close_core_v1(kvpn_output_call_v1 *, uint64_t, uint64_t);
#endif

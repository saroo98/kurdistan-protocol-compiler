// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#ifndef KVPN_PRODUCTION_SCOPED_EXPORTS_V1_H
#define KVPN_PRODUCTION_SCOPED_EXPORTS_V1_H
#include "output_callbacks_v1.h"
#include "android_callbacks_v1.h"
typedef struct {
    uint64_t candidate, generation;
    uint32_t artifact_length;
    uint16_t result;
    uint8_t deployment, expiry, rotation, revocation, compatibility, changes[10];
} kvpn_maintenance_decision_v1;
int32_t kvpn_go_maintenance_materialize_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *);
int32_t kvpn_go_maintenance_release_update_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_maintenance_run_probe_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint8_t *, uint32_t *);
int32_t kvpn_go_maintenance_check_update_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, kvpn_maintenance_decision_v1 *);
int32_t kvpn_go_discard_maintenance_candidate_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_maintenance_open_v1(kvpn_output_callbacks_v1 *, kvpn_android_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint64_t, uint64_t *, uint8_t *);
int32_t kvpn_go_discard_maintenance_parent_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_maintenance_cancel_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_maintenance_close_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_run_probe_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint8_t *, uint32_t *);
int32_t kvpn_go_prod_open_stream_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint64_t *);
int32_t kvpn_go_discard_prod_stream_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_stream_receive_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
int32_t kvpn_go_discard_stream_delivery_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_android_platform_finalize_v1(uint64_t, uint8_t);
int32_t kvpn_go_output_overlap_backing_v1(uint64_t, uint64_t *);
int32_t kvpn_go_prod_retired_result_v1(uint64_t);
int32_t kvpn_go_maintenance_retired_result_v1(uint64_t);
void kvpn_go_prod_retirement_publish_v1(uint64_t, int32_t);
void kvpn_go_maintenance_retirement_publish_v1(uint64_t, int32_t);
int32_t kvpn_go_prod_cancel_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_close_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_receive_packet_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
int32_t kvpn_go_discard_prod_packet_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_next_control_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *);
int32_t kvpn_go_prod_open_v1(kvpn_output_callbacks_v1 *, kvpn_android_callbacks_v1 *,
    uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t, uint8_t *, uint32_t,
    uint64_t, uint64_t *, uint32_t *, uint8_t *);
int32_t kvpn_go_discard_prod_parent_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_submit_packet_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t);
int32_t kvpn_go_stream_send_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t *, uint32_t);

/* Typed private Go-DSO adapters. The immutable table and retained frame
 * identity are passed explicitly; no C/JNI provider reference is linked back
 * into the Go DSO. Non-const matches cgo's generated declarations. */
int32_t kvpn_go_prod_reconnect_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t,
    uint64_t, uint64_t, uint8_t);
int32_t kvpn_go_prod_confirm_socket_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t, uint8_t, uint64_t);
int32_t kvpn_go_prod_confirm_packet_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
int32_t kvpn_go_prod_reject_packet_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_prod_handover_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint8_t, uint64_t);
int32_t kvpn_go_stream_confirm_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint32_t);
int32_t kvpn_go_stream_reject_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_stream_half_close_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_stream_cancel_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int32_t kvpn_go_stream_close_v1(kvpn_output_callbacks_v1 *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
#endif

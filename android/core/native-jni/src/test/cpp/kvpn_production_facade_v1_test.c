// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_abi.h"
#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>

/* Independent canonical ABI v1 contract. A parameter/order/type change must
 * fail compilation, even if all production callers change with the header. */
#define SIGNATURE(name, ...) _Static_assert(_Generic(&(name), int32_t (*)(__VA_ARGS__): 1, default: 0), #name " signature")
SIGNATURE(kvpn_prod_open_v1, const uint8_t *, uint32_t, uint64_t, uint64_t *, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_prod_next_control_v1, uint64_t, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_prod_confirm_socket_v1, uint64_t, uint64_t, uint8_t, uint8_t, uint64_t);
SIGNATURE(kvpn_prod_submit_packet_v1, uint64_t, const uint8_t *, uint32_t);
SIGNATURE(kvpn_prod_receive_packet_v1, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
SIGNATURE(kvpn_prod_confirm_packet_v1, uint64_t, uint64_t, uint32_t);
SIGNATURE(kvpn_prod_reject_packet_v1, uint64_t, uint64_t);
SIGNATURE(kvpn_prod_open_stream_v1, uint64_t, const uint8_t *, uint32_t, uint64_t *);
SIGNATURE(kvpn_prod_run_probe_v1, uint64_t, const uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_prod_reconnect_v1, uint64_t, uint8_t);
SIGNATURE(kvpn_prod_handover_v1, uint64_t, uint8_t, uint64_t);
SIGNATURE(kvpn_prod_cancel_v1, uint64_t);
SIGNATURE(kvpn_prod_close_v1, uint64_t);
SIGNATURE(kvpn_stream_send_v1, uint64_t, uint64_t, const uint8_t *, uint32_t);
SIGNATURE(kvpn_stream_receive_v1, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *, uint64_t *);
SIGNATURE(kvpn_stream_confirm_v1, uint64_t, uint64_t, uint64_t, uint32_t);
SIGNATURE(kvpn_stream_reject_v1, uint64_t, uint64_t, uint64_t);
SIGNATURE(kvpn_stream_half_close_v1, uint64_t, uint64_t);
SIGNATURE(kvpn_stream_cancel_v1, uint64_t, uint64_t);
SIGNATURE(kvpn_stream_close_v1, uint64_t, uint64_t);
SIGNATURE(kvpn_maintenance_open_v1, const uint8_t *, uint32_t, uint64_t, uint64_t *);
SIGNATURE(kvpn_maintenance_check_update_v1, uint64_t, const uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_maintenance_materialize_v1, uint64_t, uint64_t, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_maintenance_release_update_v1, uint64_t, uint64_t);
SIGNATURE(kvpn_maintenance_run_probe_v1, uint64_t, const uint8_t *, uint32_t, uint8_t *, uint32_t, uint32_t *);
SIGNATURE(kvpn_maintenance_cancel_v1, uint64_t);
SIGNATURE(kvpn_maintenance_close_v1, uint64_t);
#undef SIGNATURE

int main(int argc, char **argv) {
    assert(argc == 2);
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) { fputs("facade library could not load\n", stderr); return 1; }
    static const char *const names[] = {
        "kvpn_prod_open_v1", "kvpn_prod_next_control_v1", "kvpn_prod_confirm_socket_v1",
        "kvpn_prod_submit_packet_v1", "kvpn_prod_receive_packet_v1", "kvpn_prod_confirm_packet_v1",
        "kvpn_prod_reject_packet_v1", "kvpn_prod_open_stream_v1", "kvpn_prod_run_probe_v1",
        "kvpn_prod_reconnect_v1", "kvpn_prod_handover_v1", "kvpn_prod_cancel_v1", "kvpn_prod_close_v1",
        "kvpn_stream_send_v1", "kvpn_stream_receive_v1", "kvpn_stream_confirm_v1",
        "kvpn_stream_reject_v1", "kvpn_stream_half_close_v1", "kvpn_stream_cancel_v1", "kvpn_stream_close_v1",
        "kvpn_maintenance_open_v1", "kvpn_maintenance_check_update_v1", "kvpn_maintenance_materialize_v1",
        "kvpn_maintenance_release_update_v1", "kvpn_maintenance_run_probe_v1",
        "kvpn_maintenance_cancel_v1", "kvpn_maintenance_close_v1"
    };
    _Static_assert(sizeof(names) / sizeof(names[0]) == 27, "canonical operation count");
    int missing = 0;
    for (size_t i = 0; i < 27; ++i) {
        if (!dlsym(library, names[i])) { fprintf(stderr, "missing canonical symbol: %s\n", names[i]); ++missing; }
    }
    assert(dlclose(library) == 0);
    return missing ? 1 : 0;
}

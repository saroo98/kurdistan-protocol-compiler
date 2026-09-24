// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "kvpn_android_callbacks.h"
#include "production_scoped_exports_v1.h"

int32_t kvpn_android_finalize_claim_v1(kvpn_platform_finalize_v1 *claim) {
    /* The claim pins the receiver until owner_close detaches it. No gate guard
     * spans Go/Java, and finish uses the release receipt, not the detached ref. */
    uint64_t parent = claim->parent;
    uint8_t kind = claim->kind;
    int32_t actual = claim->holder
        ? kvpn_go_android_platform_finalize_v1(claim->owner, claim->kind)
        : kvpn_android_callbacks_table_v1()->owner_close(claim->owner);
    int32_t finished = kvpn_output_finalize_finish_v1(claim, actual);
    /* Publication is after the exact release receipt, never native retirement
     * alone. An evicted record is not recreated by this old completion. */
    if (parent) {
        if (kind == KVPN_OUTPUT_PRODUCTION_V1)
            kvpn_go_prod_retirement_publish_v1(parent, finished ? 18 : 0);
        else if (kind == KVPN_OUTPUT_MAINTENANCE_V1)
            kvpn_go_maintenance_retirement_publish_v1(parent, finished ? 18 : 0);
    }
    return finished;
}

int32_t kvpn_android_finalize_failed_opening_v1(uint64_t lease, uint8_t kind) {
    kvpn_platform_finalize_v1 claim = {0};
    if (kvpn_output_failed_opening_claim_v1(lease, kind, &claim)) return 25;
    return kvpn_android_finalize_claim_v1(&claim);
}

int32_t kvpn_android_finalize_parent_v1(uint64_t parent, uint8_t kind) {
    kvpn_platform_finalize_v1 claim = {0};
    if (kvpn_output_parent_finalize_claim_v1(parent, kind, &claim)) return 25;
    return kvpn_android_finalize_claim_v1(&claim);
}

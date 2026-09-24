// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
#include "android_callbacks_v1.h"

int32_t kvpn_android_table_valid_v1(const kvpn_android_callbacks_v1 *table) {
    return table && table->version == 1 && table->struct_size == sizeof(*table)
        && table->capture_sizes
        && table->capture_copy_into
        && table->production_current_register
        && table->maintenance_current_register
        && table->revision_revalidate
        && table->publication_acquire
        && table->publication_is_current
        && table->publication_close
        && table->revision_close
        && table->socket_register
        && table->socket_confirm
        && table->socket_close
        && table->maintenance_network_acquire
        && table->maintenance_network_snapshot
        && table->maintenance_network_is_current
        && table->maintenance_network_bind_socket
        && table->maintenance_network_close
        && table->system_roots_into
        && table->cancel_call
        && table->owner_close
        && kvpn_output_table_valid_v1(table->output);
}

kvpn_cb_bridge_v1 kvpn_android_capture_sizes_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_capture_sizes_v1 * out) {
    return table->capture_sizes(a0, out);
}
kvpn_cb_bridge_v1 kvpn_android_capture_copy_into_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_capture_output_v1 * out) {
    return table->capture_copy_into(a0, out);
}
kvpn_cb_bridge_v1 kvpn_android_production_current_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    return table->production_current_register(a0, parent_epoch, invalidated, out);
}
kvpn_cb_bridge_v1 kvpn_android_maintenance_current_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, uint64_t parent_epoch, kvpn_cb_signal_v1 invalidated, kvpn_cb_registration_v1 * out) {
    return table->maintenance_current_register(a0, parent_epoch, invalidated, out);
}
kvpn_cb_m1 kvpn_android_revision_revalidate_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2) {
    return table->revision_revalidate(a0, a1, a2);
}
kvpn_cb_m1 kvpn_android_publication_acquire_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_call_v1 a2, kvpn_cb_publication_v1 * out) {
    return table->publication_acquire(a0, a1, a2, out);
}
kvpn_cb_bridge_v1 kvpn_android_publication_is_current_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2, uint8_t * out) {
    return table->publication_is_current(a0, a1, a2, out);
}
kvpn_cb_bridge_v1 kvpn_android_publication_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1, kvpn_cb_publication_v1 a2) {
    return table->publication_close(a0, a1, a2);
}
kvpn_cb_bridge_v1 kvpn_android_revision_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_registration_v1 a1) {
    return table->revision_close(a0, a1);
}
kvpn_cb_p1 kvpn_android_socket_register_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, const kvpn_cb_socket_expectation_v1 * a2, kvpn_cb_signal_v1 lost, kvpn_cb_socket_v1 * out, uint8_t * binding_required) {
    return table->socket_register(a0, a1, a2, lost, out, binding_required);
}
kvpn_cb_p1 kvpn_android_socket_confirm_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1, uint8_t protected_ok, uint8_t has_network, uint64_t network) {
    return table->socket_confirm(a0, a1, protected_ok, has_network, network);
}
kvpn_cb_p1 kvpn_android_socket_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_socket_v1 a1) {
    return table->socket_close(a0, a1);
}
kvpn_cb_m1 kvpn_android_maintenance_network_acquire_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_signal_v1 lost, kvpn_cb_network_v1 * out) {
    return table->maintenance_network_acquire(a0, a1, lost, out);
}
kvpn_cb_m1 kvpn_android_maintenance_network_snapshot_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, kvpn_cb_network_snapshot_v1 * out) {
    return table->maintenance_network_snapshot(a0, a1, out);
}
kvpn_cb_m1 kvpn_android_maintenance_network_is_current_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, uint8_t * out) {
    return table->maintenance_network_is_current(a0, a1, out);
}
kvpn_cb_m1 kvpn_android_maintenance_network_bind_socket_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1, int32_t fd) {
    return table->maintenance_network_bind_socket(a0, a1, fd);
}
kvpn_cb_bridge_v1 kvpn_android_maintenance_network_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_network_v1 a1) {
    return table->maintenance_network_close(a0, a1);
}
kvpn_cb_m1 kvpn_android_system_roots_into_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1, kvpn_cb_output_v1 * out) {
    return table->system_roots_into(a0, a1, out);
}
kvpn_cb_bridge_v1 kvpn_android_cancel_call_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0, kvpn_cb_call_v1 a1) {
    return table->cancel_call(a0, a1);
}
kvpn_cb_bridge_v1 kvpn_android_owner_close_v1(const kvpn_android_callbacks_v1 *table, kvpn_cb_owner_v1 a0) {
    return table->owner_close(a0);
}

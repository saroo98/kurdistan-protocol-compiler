// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

enum class LiveTunnelStage {
    VERIFIED,
    SOCKET_PREPARED,
    SOCKET_PROTECTED,
    AUTHENTICATED,
    TUN_ESTABLISHED,
    RUNNING,
    STOPPED,
}

enum class LiveTunnelFailure {
    DUPLICATE_START,
    AUTHORITY_REJECTED,
    SOCKET_PREPARE_FAILED,
    SOCKET_PROTECT_FAILED,
    NETWORK_AUTHENTICATION_FAILED,
    INVALID_TUN_POLICY,
    TUN_ESTABLISH_FAILED,
    TUN_ATTACH_FAILED,
    NATIVE_STATE_MISMATCH,
    NETWORK_UNAVAILABLE,
    NETWORK_CHANGED,
    CANCELLED,
}

data class LiveIpPrefix(
    val address: String,
    val prefixLength: Int,
)

data class LiveTunConfiguration(
    val addresses: List<LiveIpPrefix>,
    val routes: List<LiveIpPrefix>,
    val dnsServers: List<String>,
    val mtu: Int,
    val metered: Boolean,
    val routingPolicy: VpnRoutingPolicy,
)

sealed interface LiveTunnelStartResult {
    data class Running(val stage: LiveTunnelStage = LiveTunnelStage.RUNNING) : LiveTunnelStartResult
    data class Failure(val category: LiveTunnelFailure) : LiveTunnelStartResult
}

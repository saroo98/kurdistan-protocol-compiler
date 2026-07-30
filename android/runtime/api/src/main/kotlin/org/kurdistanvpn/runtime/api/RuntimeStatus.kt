// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import org.kurdistanvpn.core.model.RuntimeAvailability

data class UnavailableRuntime(
    val reason: RuntimeAvailability = RuntimeAvailability.PHASE_9_NO_RUNTIME,
)

enum class VpnRuntimeState {
    IDLE,
    PREPARING,
    ACTIVE_LOCAL_ONLY,
    ACTIVE_KURD_LOOPBACK,
    STOPPING,
    REVOKED,
    FAILED,
}

data class VpnRuntimeSnapshot(
    val state: VpnRuntimeState = VpnRuntimeState.IDLE,
    val packetsRead: Long = 0,
    val packetsWritten: Long = 0,
    val alwaysOn: Boolean = false,
    val lockdown: Boolean = false,
    val failure: String? = null,
    val packetDisposition: String? = null,
    val perAppRoutingMode: PerAppRoutingMode = PerAppRoutingMode.ALL_APPS,
)

object VpnRuntimeContract {
    const val ACTION_START = "org.kurdistanvpn.runtime.action.START"
    const val ACTION_STOP = "org.kurdistanvpn.runtime.action.STOP"
    const val ACTION_QUERY_STATUS = "org.kurdistanvpn.runtime.action.QUERY_STATUS"
    const val ACTION_STATUS = "org.kurdistanvpn.runtime.action.STATUS"
    const val EXTRA_STATE = "state"
    const val EXTRA_PACKETS = "packets"
    const val EXTRA_PACKETS_WRITTEN = "packets_written"
    const val EXTRA_ALWAYS_ON = "always_on"
    const val EXTRA_LOCKDOWN = "lockdown"
    const val EXTRA_FAILURE = "failure"
    const val EXTRA_PACKET_DISPOSITION = "packet_disposition"
    const val EXTRA_PER_APP_MODE = "per_app_mode"
    const val EXTRA_PACKAGES = "packages"
}

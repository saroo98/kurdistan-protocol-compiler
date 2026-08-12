// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

internal object VpnNetworkTeardownBarrier {
    suspend fun awaitNoRegisteredVpn(
        timeoutMillis: Long,
        pollMillis: Long,
        vpnTransportSnapshot: () -> Iterable<Boolean>,
        wait: suspend (Long) -> Unit = { delay(it) },
    ): Boolean {
        require(timeoutMillis > 0) { "VPN_TEARDOWN_TIMEOUT_REJECTED" }
        require(pollMillis > 0) { "VPN_TEARDOWN_POLL_REJECTED" }
        return withTimeoutOrNull(timeoutMillis) {
            while (vpnTransportSnapshot().any { present -> present }) {
                wait(pollMillis)
            }
            true
        } ?: false
    }

    fun failedSnapshot(): List<Boolean> = listOf(true)

    @Suppress("DEPRECATION")
    fun snapshot(connectivity: ConnectivityManager): List<Boolean> = runCatching {
        connectivity.allNetworks.map { network ->
            connectivity.getNetworkCapabilities(network)
                ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }.getOrElse { failedSnapshot() }
}

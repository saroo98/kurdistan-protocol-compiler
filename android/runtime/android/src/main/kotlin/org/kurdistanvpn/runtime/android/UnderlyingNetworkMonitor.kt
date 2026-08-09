// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal data class NetworkTransition<T>(
    val previous: T?,
    val current: T?,
)

internal class UnderlyingNetworkAvailability<T> {
    private val lock = ReentrantLock()
    private val changed = lock.newCondition()
    private var current: T? = null
    private var bound = false

    fun update(value: T?, isBound: Boolean) {
        lock.withLock {
            current = value
            bound = value != null && isBound
            changed.signalAll()
        }
    }

    fun awaitUsable(timeoutMillis: Long): T? {
        require(timeoutMillis >= 0)
        var remaining = TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        lock.withLock {
            while (current == null || !bound) {
                if (remaining <= 0) return null
                remaining = changed.awaitNanos(remaining)
            }
            return current
        }
    }
}

internal class CurrentNetworkTracker<T>(
    private val onTransition: (NetworkTransition<T>) -> Unit,
) {
    private val available = linkedSetOf<T>()
    private var current: T? = null

    fun available(value: T) {
        if (!available.add(value) || current != null) return
        current = value
        onTransition(NetworkTransition(null, value))
    }

    fun lost(value: T) {
        if (!available.remove(value) || current != value) return
        val previous = current
        current = available.firstOrNull()
        onTransition(NetworkTransition(previous, current))
    }
}

internal class UnderlyingNetworkMonitor(
    private val connectivity: ConnectivityManager,
    onTransition: (NetworkTransition<Network>) -> Unit,
) : AutoCloseable {
    private val tracker = CurrentNetworkTracker(onTransition)
    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = tracker.available(network)
        override fun onLost(network: Network) = tracker.lost(network)
    }
    private var registered = false

    fun start() {
        if (registered) return
        connectivity.registerNetworkCallback(request, callback)
        registered = true
        connectivity.activeNetwork?.takeIf { network ->
            connectivity.getNetworkCapabilities(network)?.hasCapability(
                NetworkCapabilities.NET_CAPABILITY_NOT_VPN,
            ) == true
        }?.let(tracker::available)
    }

    override fun close() {
        if (!registered) return
        registered = false
        runCatching { connectivity.unregisterNetworkCallback(callback) }
    }
}

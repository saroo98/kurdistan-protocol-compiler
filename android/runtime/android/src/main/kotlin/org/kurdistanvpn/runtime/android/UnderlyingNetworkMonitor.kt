// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
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

    @Synchronized fun available(value: T) {
        if (!available.add(value) || current != null) return
        current = value
        onTransition(NetworkTransition(null, value))
    }

    @Synchronized fun lost(value: T) {
        if (!available.remove(value) || current != value) return
        val previous = current
        current = available.firstOrNull()
        onTransition(NetworkTransition(previous, current))
    }
}

/** Owns possible platform registration before the fallible registration call. A failed
 * close is sticky; an ambiguous callback handle is never unregistered twice. */
internal class NetworkCallbackOwnership(private val register: () -> Unit,
    private val unregister: () -> Unit) : AutoCloseable {
    private enum class State { NEW, ACQUIRING, REGISTERED, CLEAN, UNPROVEN }
    private var state = State.NEW
    @Synchronized fun start() {
        check(state == State.NEW)
        state = State.ACQUIRING
        try { register(); state = State.REGISTERED }
        catch (failure: Throwable) { try { close() } catch (_: Throwable) { }; throw failure }
    }
    @Synchronized fun acceptsCallbacks(): Boolean = state == State.ACQUIRING || state == State.REGISTERED
    @Synchronized override fun close() {
        if (state == State.NEW || state == State.CLEAN) { state = State.CLEAN; return }
        check(state != State.UNPROVEN) { "NETWORK_CALLBACK_CLEANUP_UNPROVEN" }
        state = State.UNPROVEN
        unregister()
        state = State.CLEAN
    }
}

internal data class UnderlyingNetworkState(val handle: Long = 0, val validated: Boolean = false,
    val captive: Boolean = false, val metered: Boolean = true, val suspended: Boolean = false,
    val vpn: Boolean = false) {
    // Failed public validation alone is not proof that the admitted relay is unreachable.
    fun permits(policy: org.kurdistanvpn.core.model.NetworkMeteredPolicy): Boolean =
        handle != 0L && !vpn && !captive && !suspended && policy.permits(metered, false, false)
}

internal fun NetworkCapabilities.runtimeState(handle: Long) = UnderlyingNetworkState(handle,
    hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
    hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
    !hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
    Build.VERSION.SDK_INT >= 28 && !hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED),
    !hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))

internal class DefaultNetworkStateTracker(private val changed: (UnderlyingNetworkState) -> Unit) {
    private var handle = 0L
    @Synchronized fun available(value: Long) { require(value != 0L); handle = value }
    @Synchronized fun capabilities(value: UnderlyingNetworkState) { if (value.handle == handle && handle != 0L) changed(value) }
    @Synchronized fun lost(value: Long) { if (handle == value) { handle = 0; changed(UnderlyingNetworkState()) } }
}

internal class UnderlyingNetworkMonitor(private val connectivity: ConnectivityManager,
    onState: (UnderlyingNetworkState) -> Unit) : AutoCloseable {
    private val tracker = DefaultNetworkStateTracker(onState)
    private val callback: ConnectivityManager.NetworkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { if (ownership.acceptsCallbacks()) tracker.available(network.networkHandle) }
        override fun onLost(network: Network) { if (ownership.acceptsCallbacks()) tracker.lost(network.networkHandle) }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (!ownership.acceptsCallbacks()) return
            tracker.capabilities(capabilities.runtimeState(network.networkHandle))
        }
    }
    private val ownership: NetworkCallbackOwnership = NetworkCallbackOwnership(
        { connectivity.registerDefaultNetworkCallback(callback) },
        { connectivity.unregisterNetworkCallback(callback) })

    fun start() = ownership.start()

    override fun close() {
        ownership.close()
    }
}

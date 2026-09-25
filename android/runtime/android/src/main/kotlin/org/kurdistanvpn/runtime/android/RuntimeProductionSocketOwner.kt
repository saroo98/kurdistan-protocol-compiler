// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.Closeable

internal data class RuntimeSocketIdentityV1(val epoch: Long, val attempt: Long, val token: Long,
    val fd: Int, val explicit: Int, val hasNetwork: Int, val network: Long)
internal interface RuntimeSocketPlatformV1 : Closeable {
    fun duplicate(fd: Int)
    fun observe(lost: () -> Unit)
    fun select(explicit: Int, has: Int, handle: Long): Long
    fun current(): Boolean
    fun protect(): Boolean
    fun bind()
}

/** The containing native callback child adopts this owner before acquire. */
internal class RuntimeProductionSocketOwner(private val platform: RuntimeSocketPlatformV1,
    private val startCurrent: () -> Boolean, private val lost: () -> Unit) : Closeable {
    private val monitor = Any()
    private var identity: RuntimeSocketIdentityV1? = null
    private var handle = 0L
    private var busy = false
    private var terminal = false
    private var confirmed = false
    private var bound = false
    private var signalled = false
    private var closeRequested = false
    private var closeStarted = false
    private var clean = false
    private var unproven = false

    /** False is unavailable, not cleanup: the adopted resources still require close. */
    fun acquire(value: RuntimeSocketIdentityV1): Boolean {
        synchronized(monitor) { check(identity == null && !terminal); identity = value; busy = true }
        try {
            platform.duplicate(value.fd)
            check(value.epoch != 0L && value.attempt != 0L && value.token != 0L && value.fd >= 0 &&
                value.explicit in 0..1 && value.hasNetwork in 0..1 &&
                (value.hasNetwork != 0 || value.network == 0L) &&
                (value.hasNetwork != 1 || value.network != 0L) && startCurrent())
            platform.observe(::signalLoss)
            val selected = platform.select(value.explicit, value.hasNetwork, value.network)
            if (selected == 0L) return false
            check(value.hasNetwork == 0 || selected == value.network)
            if (!startCurrent() || !platform.current()) return false
            synchronized(monitor) { check(!unproven); if (terminal) return false; handle = selected }
            return true
        } finally { finishCall() }
    }

    fun selectedHandle(): Long = synchronized(monitor) { if (terminal || unproven) 0 else handle }
    fun boundNetworkHandle(): Long {
        val candidate = synchronized(monitor) { if (terminal || unproven || busy || !bound) 0 else handle }
        return if (candidate != 0L && startCurrent() && platform.current() &&
            synchronized(monitor) { !terminal && !unproven && bound && handle == candidate }) candidate else 0
    }
    fun confirm(protected: Int, hasNetwork: Int, network: Long): Int {
        if (protected !in 0..1 || hasNetwork !in 0..1 || (hasNetwork == 0 && network != 0L)) return 1
        synchronized(monitor) {
            if (terminal || unproven || handle == 0L) return 9
            if (busy || confirmed) return 3
            confirmed = true; busy = true
        }
        try {
            if (!startCurrent() || !platform.current()) { signalLoss(); return 9 }
            if (protected == 0) { signalLoss(); return 16 }
            val expected = synchronized(monitor) { checkNotNull(identity) }
            if (hasNetwork != expected.hasNetwork || network != expected.network ||
                (hasNetwork == 1 && network != selectedHandle())) { signalLoss(); return 9 }
            val protectedActual = try { platform.protect() } catch (_: Throwable) { false }
            if (!protectedActual) { signalLoss(); return 16 }
            try { platform.bind() } catch (_: Throwable) { signalLoss(); return 9 }
            if (!startCurrent() || !platform.current() || synchronized(monitor) { terminal || unproven }) {
                signalLoss(); return 9
            }
            synchronized(monitor) { if (terminal || unproven) return 9; bound = true }
            return 0
        } finally { finishCall() }
    }

    private fun signalLoss() {
        val notify = synchronized(monitor) {
            terminal = true
            if (signalled) false else { signalled = true; true }
        }
        if (notify) try { lost() } catch (failure: Throwable) {
            synchronized(monitor) { unproven = true }; throw failure
        }
    }
    private fun finishCall() {
        val close = synchronized(monitor) { busy = false; closeRequested }
        if (close) close()
    }
    override fun close() {
        synchronized(monitor) {
            closeRequested = true; terminal = true
            if (busy) { unproven = true; throw RuntimeAuthorityCleanupUnprovenException() }
            if (closeStarted) { if (!clean || unproven) throw RuntimeAuthorityCleanupUnprovenException(); return }
            closeStarted = true
        }
        var failure: Throwable? = null
        try { signalLoss() } catch (caught: Throwable) { failure = caught }
        try { platform.close() } catch (caught: Throwable) { if (failure == null) failure = caught }
        if (failure != null) { synchronized(monitor) { unproven = true }; throw failure }
        synchronized(monitor) { clean = true }
        if (synchronized(monitor) { unproven }) throw RuntimeAuthorityCleanupUnprovenException()
    }

    companion object {
        fun forService(service: VpnService, policy: org.kurdistanvpn.core.model.NetworkMeteredPolicy,
            startCurrent: () -> Boolean, lost: () -> Unit) =
            RuntimeProductionSocketOwner(AndroidSocketPlatformV1(service, policy), startCurrent, lost)
    }
}

/** Called only under AndroidSocketPlatformV1's monitor; no framework state or authority. */
internal class RuntimeSocketSelectionRevisionV1 {
    private var value = 0L
    fun snapshot(): Long = value
    fun unchanged(before: Long): Boolean = value != Long.MAX_VALUE && value == before
    fun observe(invalid: Boolean): Boolean {
        if (value == Long.MAX_VALUE) return false
        // Initial availability/capability/link notifications are not invalidations.
        if (invalid) value++
        return true
    }
}

/** Actual service capability, never a caller's protect Boolean or raw Network provider. */
private class AndroidSocketPlatformV1(private val service: VpnService,
    private val policy: org.kurdistanvpn.core.model.NetworkMeteredPolicy) : RuntimeSocketPlatformV1 {
    private val connectivity = service.getSystemService(ConnectivityManager::class.java)
    private val monitor = Any()
    private var descriptor: ParcelFileDescriptor? = null
    private var selected: Network? = null
    private var interfaceName: String? = null
    private var observed = false
    private var closed = false
    private val revision = RuntimeSocketSelectionRevisionV1()
    private var lost: (() -> Unit)? = null
    private val callback = object : ConnectivityManager.NetworkCallback() {
        private fun event(network: Network, invalid: Boolean) {
            val notify = synchronized(monitor) {
                if (closed) return
                // Once selected, a different network cannot invalidate this socket.
                if (selected != null && selected != network) return
                if (!revision.observe(invalid)) lost else if (selected == network && invalid) lost else null
            }
            notify?.invoke()
        }
        override fun onAvailable(network: Network) = event(network, false)
        override fun onLost(network: Network) = event(network, true)
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) =
            event(network, !capabilities.runtimeState(network.networkHandle).permits(policy) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) =
            event(network, synchronized(monitor) { selected == network && interfaceName != properties.interfaceName })
    }
    override fun duplicate(fd: Int) { check(descriptor == null); descriptor = ParcelFileDescriptor.fromFd(fd) }
    override fun observe(lost: () -> Unit) {
        synchronized(monitor) { check(!observed && !closed); this.lost = lost; observed = true }
        val request = NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build()
        connectivity.registerNetworkCallback(request, callback)
    }
    @Suppress("DEPRECATION") // Public bounded API26 visible-network scan; no hidden replacement.
    override fun select(explicit: Int, has: Int, handle: Long): Long {
        check(explicit in 0..1 && has in 0..1 && (has != 0 || handle == 0L))
        if (explicit == 1) check(has == 1 && handle != 0L)
        var candidate: Network? = null
        var candidateName: String? = null
        fun usable(network: Network): Boolean {
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
            return capabilities.runtimeState(network.networkHandle).permits(policy) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        // Initial callbacks may overlap a read. Re-read boundedly, never accept
        // unstable facts or switch candidates during the same acquisition.
        repeat(3) {
            val before = synchronized(monitor) { check(observed); if (closed) return 0; revision.snapshot() }
            val networks = connectivity.allNetworks
            check(networks.size <= 64)
            val currentDefault = connectivity.activeNetwork
            val chosen = if (has == 1) networks.firstOrNull { it.networkHandle == handle && usable(it) }
                else currentDefault?.takeIf(::usable) ?: networks.firstOrNull(::usable)
            if (chosen == null) return 0
            val name = connectivity.getLinkProperties(chosen)?.interfaceName
            if (name.isNullOrEmpty() || (candidate != null && (candidate != chosen || candidateName != name))) return 0
            candidate = chosen; candidateName = name
            synchronized(monitor) {
                if (closed) return 0
                if (revision.unchanged(before)) {
                    selected = chosen; interfaceName = name
                    return chosen.networkHandle
                }
            }
        }
        return 0
    }
    override fun current(): Boolean {
        val before: Long; val network: Network; val name: String?
        synchronized(monitor) { if (closed) return false; before = revision.snapshot(); network = selected ?: return false; name = interfaceName }
        val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
        val properties = connectivity.getLinkProperties(network) ?: return false
        return capabilities.runtimeState(network.networkHandle).permits(policy) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && properties.interfaceName == name &&
            synchronized(monitor) { !closed && revision.unchanged(before) && selected == network }
    }
    override fun protect(): Boolean = service.protect(checkNotNull(descriptor).fd)
    override fun bind() = checkNotNull(selected).bindSocket(checkNotNull(descriptor).fileDescriptor)
    override fun close() {
        synchronized(monitor) { check(!closed); closed = true }
        var failure: Throwable? = null
        if (observed) try { connectivity.unregisterNetworkCallback(callback) } catch (caught: Throwable) { failure = caught }
        try { descriptor?.close() } catch (caught: Throwable) { if (failure == null) failure = caught }
        if (failure != null) throw failure
        descriptor = null; selected = null; lost = null
    }
}

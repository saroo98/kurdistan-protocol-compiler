// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import java.io.Closeable
import java.net.Inet6Address
import java.nio.ByteBuffer

internal data class RuntimeMaintenanceNetworkSnapshotV1(val handle: Long, val vpn: Boolean,
    val ownerUid: Int, val interfaceName: String?, val families: Int, val dns: Array<ByteArray>,
    val privateDnsActive: Boolean, val privateDnsName: String?, val visibleCount: Int, val visibleVpn: Boolean) {
    fun sameSelection(other: RuntimeMaintenanceNetworkSnapshotV1): Boolean = handle == other.handle && vpn == other.vpn &&
        ownerUid == other.ownerUid && interfaceName == other.interfaceName && families == other.families &&
        privateDnsActive == other.privateDnsActive && privateDnsName == other.privateDnsName && visibleVpn == other.visibleVpn &&
        dns.size == other.dns.size && dns.indices.all { dns[it].contentEquals(other.dns[it]) }
}
internal class RuntimeMaintenanceNetworkFailureV1(val status: Int) : IllegalStateException("MAINTENANCE_NETWORK_UNAVAILABLE")
/** Accessed only under the platform monitor; callbacks themselves perform no platform reads. */
internal class RuntimeMaintenanceObservationV1 {
    var revision = 0L; private set
    private var frozen: RuntimeMaintenanceNetworkSnapshotV1? = null
    private var lost = false
    fun event(invalid: (RuntimeMaintenanceNetworkSnapshotV1) -> Boolean): Boolean {
        val value = frozen
        if (value == null || invalid(value)) {
            if (revision == Long.MAX_VALUE) lost = true else revision++
            if (value != null) lost = true
        }
        return lost
    }
    fun capture(before: Long, value: RuntimeMaintenanceNetworkSnapshotV1): RuntimeMaintenanceNetworkSnapshotV1? {
        if (lost) throw RuntimeMaintenanceNetworkFailureV1(10)
        // Seed the comparison even on overlap. The next bounded read verifies it;
        // duplicate initial notifications no longer masquerade as mutations.
        val previous = frozen
        if (previous != null && !previous.sameSelection(value)) {
            lost = true
            throw RuntimeMaintenanceNetworkFailureV1(10)
        }
        if (previous == null) frozen = value
        if (before != revision) return null
        return value
    }
}
/** Initial callback delivery can overlap observation. Retry only that overlap,
 * without waiting, changing the selected network or accepting unstable facts. */
internal fun maintenanceStableSnapshotV1(current: () -> Boolean, read: () -> RuntimeMaintenanceNetworkSnapshotV1?): RuntimeMaintenanceNetworkSnapshotV1 {
    repeat(3) {
        if (!current()) throw RuntimeMaintenanceNetworkFailureV1(10)
        read()?.let {
            if (!current()) throw RuntimeMaintenanceNetworkFailureV1(10)
            return it
        }
    }
    throw RuntimeMaintenanceNetworkFailureV1(10)
}
internal interface RuntimeMaintenanceNetworkPlatformV1 : Closeable {
    val apiLevel: Int
    val ownUid: Int
    fun observeDefault(lost: () -> Unit)
    fun observeVisible(lost: () -> Unit)
    fun snapshot(): RuntimeMaintenanceNetworkSnapshotV1
    fun bind(fd: Int)
}

/** One selected network, two pre-adopted observers, no re-selection after acquisition. */
internal class VpnMaintenanceNetworkLease(private val platform: RuntimeMaintenanceNetworkPlatformV1,
    private val mode: Int, private val startCurrent: () -> Boolean, private val tunName: () -> String?,
    private val noOwnActivation: () -> Boolean, private val lost: () -> Unit) : Closeable {
    private val monitor = Any()
    private var facts: RuntimeMaintenanceNetworkSnapshotV1? = null
    private var started = false
    private var busy = false
    private var terminal = false
    private var signalled = false
    private var unproven = false
    private var closeRequested = false
    private var closeStarted = false
    private var clean = false

    fun acquire(): Int {
        synchronized(monitor) { if (started || terminal) return 3; started = true; busy = true }
        try {
            platform.observeDefault(::signalLoss)
            platform.observeVisible(::signalLoss)
            val snapshot = platform.snapshot()
            val status = validate(snapshot)
            if (status != 0) { signalLoss(); return status }
            synchronized(monitor) { if (terminal || unproven) return 10; facts = snapshot }
            return 0
        } catch (failure: Throwable) {
            if (failure is RuntimeAuthorityCleanupUnprovenException) synchronized(monitor) { unproven = true }
            signalLoss()
            return if (failure is RuntimeMaintenanceNetworkFailureV1) failure.status else 10
        } finally { finishCall() }
    }
    private fun validate(value: RuntimeMaintenanceNetworkSnapshotV1): Int {
        if (value.visibleCount > 64 || value.dns.size > 4) return 6
        if (mode !in 1..2 || value.handle == 0L || value.visibleCount <= 0 || !startCurrent() ||
            value.families !in 1..3 || value.dns.isEmpty()) return 10
        if (platform.apiLevel >= 28 && (value.privateDnsActive || !value.privateDnsName.isNullOrEmpty())) return 10
        if (mode == 1) {
            if (value.vpn || value.visibleVpn || !noOwnActivation()) return 10
        } else {
            if (!value.vpn || value.interfaceName == null || tunName() != value.interfaceName ||
                (platform.apiLevel >= 30 && value.ownerUid != platform.ownUid)) return 10
        }
        for ((index, address) in value.dns.withIndex()) {
            if (address.size != 4 && address.size != 16) return 10
            if (address.all { it == 0.toByte() } || (address.size == 4 && address[0].toInt() and 0xff in 224..239) ||
                (address.size == 16 && address[0] == 0xff.toByte())) return 10
            if (address.size == 4 && value.families and 1 == 0 || address.size == 16 && value.families and 2 == 0) return 10
            if (address.size == 16) {
                if (address[0] == 0xfe.toByte() && address[1].toInt() and 0xc0 == 0x80) return 10
                var mapped = address[10] == 0xff.toByte() && address[11] == 0xff.toByte()
                for (i in 0 until 10) if (address[i] != 0.toByte()) mapped = false
                if (mapped) return 10
            }
            for (previous in 0 until index) if (address.contentEquals(value.dns[previous])) return 10
        }
        return 0
    }
    fun isCurrent(): Boolean {
        val expected = synchronized(monitor) {
            if (terminal || unproven || busy) return false
            val value = facts ?: return false
            busy = true; value
        }
        try {
            val observed = platform.snapshot()
            val valid = validate(observed) == 0 && expected.sameSelection(observed) &&
                synchronized(monitor) { !terminal && !unproven }
            if (!valid) signalLoss()
            return valid
        } catch (_: Throwable) { signalLoss(); return false }
        finally { finishCall() }
    }
    fun copySnapshot(destination: ByteBuffer, metadata: IntArray): Int {
        metadata.fill(0)
        if (metadata.size != 3 || !destination.isDirect || destination.isReadOnly || destination.capacity() != 76 ||
            destination.position() != 0 || destination.limit() != 76) return 1
        for (i in 0 until 76) destination.put(i, 0)
        if (!isCurrent()) return 10
        val value = synchronized(monitor) { facts ?: return 10 }
        for (i in value.dns.indices) {
            val address = value.dns[i]
            val base = i * 19
            destination.put(base, if (address.size == 4) 4 else 6)
            for (j in address.indices) destination.put(base + 1 + j, address[j])
            destination.put(base + 18, 53)
        }
        if (synchronized(monitor) { terminal || unproven } || !startCurrent()) {
            for (i in 0 until 76) destination.put(i, 0)
            return 10
        }
        metadata[0] = mode; metadata[1] = value.families; metadata[2] = value.dns.size
        return 0
    }
    fun bindSocket(fd: Int): Int {
        if (fd < 0) return 1
        if (!isCurrent()) return 10
        synchronized(monitor) { if (busy || terminal || unproven) return 10; busy = true }
        try { platform.bind(fd) }
        catch (failure: Throwable) {
            if (failure is RuntimeAuthorityCleanupUnprovenException) synchronized(monitor) { unproven = true }
            signalLoss(); return 10
        } finally { finishCall() }
        return if (isCurrent()) 0 else 10
    }
    private fun signalLoss() {
        val notify = synchronized(monitor) { terminal = true; if (signalled) false else { signalled = true; true } }
        if (notify) try { lost() } catch (failure: Throwable) { synchronized(monitor) { unproven = true }; throw failure }
    }
    private fun finishCall() {
        val close = synchronized(monitor) { busy = false; closeRequested }
        if (close) close()
    }
    override fun close() {
        synchronized(monitor) {
            terminal = true; closeRequested = true
            if (busy) { unproven = true; throw RuntimeAuthorityCleanupUnprovenException() }
            if (closeStarted) { if (!clean || unproven) throw RuntimeAuthorityCleanupUnprovenException(); return }
            closeStarted = true
        }
        var failure: Throwable? = null
        try { signalLoss() } catch (caught: Throwable) { failure = caught }
        try { platform.close() } catch (caught: Throwable) { if (failure == null) failure = caught }
        if (failure != null) { synchronized(monitor) { unproven = true }; throw failure }
        synchronized(monitor) { clean = true; if (unproven) throw RuntimeAuthorityCleanupUnprovenException() }
    }
    companion object {
        fun forService(service: VpnService, mode: Int, startCurrent: () -> Boolean,
            proof: RuntimeTunProofOwner?, noOwnActivation: () -> Boolean, lost: () -> Unit) =
            VpnMaintenanceNetworkLease(AndroidMaintenanceNetworkPlatformV1(service, mode), mode,
                startCurrent, { proof?.interfaceName() }, noOwnActivation, lost)
    }
}

private fun maintenanceVisibleNetworkRequestV1(): NetworkRequest {
    val builder = NetworkRequest.Builder()
    if (Build.VERSION.SDK_INT >= 30) builder.clearCapabilities()
    else {
        // AOSP API26-29 defaults. Remove all three, including NOT_VPN, so
        // visible VPN/restricted/untrusted networks are not silently filtered.
        builder.removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }
    return builder.build()
}

private class AndroidMaintenanceNetworkPlatformV1(service: VpnService, private val mode: Int) : RuntimeMaintenanceNetworkPlatformV1 {
    override val apiLevel: Int get() = Build.VERSION.SDK_INT
    override val ownUid: Int get() = Process.myUid()
    private val connectivity = service.getSystemService(ConnectivityManager::class.java)
    private val monitor = Any()
    private var defaultOwned = false
    private var visibleOwned = false
    private var closed = false
    private val observation = RuntimeMaintenanceObservationV1()
    private var selected: Network? = null
    private var loss: (() -> Unit)? = null
    private var binding: ParcelFileDescriptor? = null

    private fun callback(default: Boolean) = object : ConnectivityManager.NetworkCallback() {
        private fun event(network: Network, invalid: (RuntimeMaintenanceNetworkSnapshotV1) -> Boolean) {
            val notify = synchronized(monitor) {
                if (closed) return
                if (observation.event(invalid)) loss else null
            }
            notify?.invoke()
        }
        override fun onAvailable(network: Network) = event(network) { default && it.handle != network.networkHandle }
        override fun onLost(network: Network) = event(network) { it.handle == network.networkHandle }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) = event(network) {
            val vpn = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            (mode == 1 && vpn) || (it.handle == network.networkHandle && (it.vpn != vpn ||
                (Build.VERSION.SDK_INT >= 30 && it.ownerUid != capabilities.ownerUid)))
        }
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) = event(network) {
            it.handle == network.networkHandle && !sameLink(it, properties)
        }
    }
    private val defaultCallback = callback(true)
    private val visibleCallback = callback(false)
    override fun observeDefault(lost: () -> Unit) {
        synchronized(monitor) { check(!defaultOwned && !closed); defaultOwned = true; loss = lost }
        connectivity.registerDefaultNetworkCallback(defaultCallback)
    }
    override fun observeVisible(lost: () -> Unit) {
        synchronized(monitor) { check(defaultOwned && !visibleOwned && !closed); visibleOwned = true }
        connectivity.registerNetworkCallback(maintenanceVisibleNetworkRequestV1(), visibleCallback)
    }
    @Suppress("DEPRECATION") // Accepted public API26 bounded visible-network observation.
    override fun snapshot(): RuntimeMaintenanceNetworkSnapshotV1 {
        val network = connectivity.activeNetwork ?: throw RuntimeMaintenanceNetworkFailureV1(10)
        return maintenanceStableSnapshotV1({ connectivity.activeNetwork == network }) { snapshotAttempt(network) }
    }
    private fun snapshotAttempt(network: Network): RuntimeMaintenanceNetworkSnapshotV1? {
        val before = synchronized(monitor) { check(!closed && defaultOwned && visibleOwned); observation.revision }
        synchronized(monitor) { if (selected != null && selected != network) throw RuntimeMaintenanceNetworkFailureV1(10) }
        val capabilities = connectivity.getNetworkCapabilities(network) ?: throw RuntimeMaintenanceNetworkFailureV1(10)
        val properties = connectivity.getLinkProperties(network) ?: throw RuntimeMaintenanceNetworkFailureV1(10)
        val visible = connectivity.allNetworks
        if (visible.size > 64) throw RuntimeMaintenanceNetworkFailureV1(6)
        var anyVpn = false
        var selectedVisible = false
        for (item in visible) {
            if (item == network) selectedVisible = true
            val observation = connectivity.getNetworkCapabilities(item) ?: throw RuntimeMaintenanceNetworkFailureV1(10)
            if (observation.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) anyVpn = true
        }
        if (!selectedVisible) throw RuntimeMaintenanceNetworkFailureV1(10)
        val dns = properties.dnsServers
        if (dns.size > 4) throw RuntimeMaintenanceNetworkFailureV1(6)
        val addresses = Array(dns.size) { index ->
            val address = dns[index]
            if (address is Inet6Address && address.scopeId != 0) throw RuntimeMaintenanceNetworkFailureV1(10)
            address.address
        }
        val value = RuntimeMaintenanceNetworkSnapshotV1(network.networkHandle,
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            if (Build.VERSION.SDK_INT >= 30) capabilities.ownerUid else -1, properties.interfaceName, families(properties), addresses,
            if (Build.VERSION.SDK_INT >= 28) properties.isPrivateDnsActive else false,
            if (Build.VERSION.SDK_INT >= 28) properties.privateDnsServerName else null, visible.size, anyVpn)
        if (connectivity.activeNetwork != network) throw RuntimeMaintenanceNetworkFailureV1(10)
        synchronized(monitor) {
            if (closed || (selected != null && selected != network)) throw RuntimeMaintenanceNetworkFailureV1(10)
            val captured = observation.capture(before, value) ?: return null
            if (selected == null) selected = network
            return captured
        }
    }
    private fun families(properties: LinkProperties): Int {
        var mask = 0
        for (item in properties.linkAddresses) {
            val size = item.address.address.size
            if (size == 4) mask = mask or 1 else if (size == 16) mask = mask or 2
        }
        return mask
    }
    private fun sameLink(expected: RuntimeMaintenanceNetworkSnapshotV1, properties: LinkProperties): Boolean {
        if (expected.interfaceName != properties.interfaceName || expected.families != families(properties)) return false
        if (Build.VERSION.SDK_INT >= 28 && (expected.privateDnsActive != properties.isPrivateDnsActive || expected.privateDnsName != properties.privateDnsServerName)) return false
        val dns = properties.dnsServers
        if (dns.size != expected.dns.size) return false
        for (i in dns.indices) {
            if (dns[i] is Inet6Address && (dns[i] as Inet6Address).scopeId != 0) return false
            if (!dns[i].address.contentEquals(expected.dns[i])) return false
        }
        return true
    }
    override fun bind(fd: Int) {
        check(binding == null)
        binding = ParcelFileDescriptor.fromFd(fd)
        try {
            val network = synchronized(monitor) { check(!closed); checkNotNull(selected) }
            check(connectivity.activeNetwork == network)
            network.bindSocket(checkNotNull(binding).fileDescriptor)
        } finally {
            try { binding?.close(); binding = null }
            catch (_: Throwable) { throw RuntimeAuthorityCleanupUnprovenException() }
        }
    }
    override fun close() {
        synchronized(monitor) { check(!closed); closed = true }
        var failure: Throwable? = null
        if (defaultOwned) try { connectivity.unregisterNetworkCallback(defaultCallback) } catch (caught: Throwable) { failure = caught }
        if (visibleOwned) try { connectivity.unregisterNetworkCallback(visibleCallback) } catch (caught: Throwable) { if (failure == null) failure = caught }
        // A failed duplicate close is not retried against a possibly reused FD.
        if (binding != null && failure == null) failure = RuntimeAuthorityCleanupUnprovenException()
        if (failure != null) throw failure
        selected = null; loss = null
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.net.InetAddress
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeDiagnostics
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeRuntimeState
import org.kurdistanvpn.runtime.api.LiveIpPrefix
import org.kurdistanvpn.runtime.api.LiveTunConfiguration
import org.kurdistanvpn.runtime.api.LiveTunnelFailure
import org.kurdistanvpn.runtime.api.LiveTunnelStage
import org.kurdistanvpn.runtime.api.LiveTunnelStartResult
import org.kurdistanvpn.runtime.api.PerAppRoutingMode
import org.kurdistanvpn.runtime.api.VpnRoutingPolicy

internal fun interface SocketProtector {
    fun protect(fileDescriptor: Int): Boolean
}

internal fun interface SocketNetworkBinder {
    fun bind(fileDescriptor: Int): Boolean
}

internal fun interface TunEstablisher {
    fun establish(configuration: LiveTunConfiguration): DetachableTun?
}

internal interface DetachableTun : AutoCloseable {
    fun detachFileDescriptor(): Int
}

internal fun interface DetachedFileDescriptorCloser {
    fun close(fileDescriptor: Int)
}

internal class NativeTunnelController(
    private val protector: SocketProtector,
    private val networkBinder: SocketNetworkBinder,
    private val tunEstablisher: TunEstablisher,
    private val detachedCloser: DetachedFileDescriptorCloser,
    private val onStage: (LiveTunnelStage) -> Unit = {},
) : AutoCloseable {
    private val lock = Any()
    private var activeSession: NativeLiveRuntimeSession? = null

    fun start(session: NativeLiveRuntimeSession): LiveTunnelStartResult = synchronized(lock) {
        if (activeSession != null) {
            session.close()
            return@synchronized LiveTunnelStartResult.Failure(LiveTunnelFailure.DUPLICATE_START)
        }
        onStage(LiveTunnelStage.VERIFIED)
        while (true) {
            val socket = when (val prepared = session.prepareSocket()) {
                is NativeResult.Failure -> return@synchronized fail(
                    session,
                    prepared.error.toLiveTunnelFailure(LiveTunnelFailure.SOCKET_PREPARE_FAILED),
                )
                is NativeResult.Success -> prepared.value
            }
            onStage(LiveTunnelStage.SOCKET_PREPARED)
            val protected = runCatching { protector.protect(socket) }.getOrDefault(false)
            if (!protected) {
                session.commitProtected(false)
                return@synchronized fail(session, LiveTunnelFailure.SOCKET_PROTECT_FAILED)
            }
            onStage(LiveTunnelStage.SOCKET_PROTECTED)
            val bound = runCatching { networkBinder.bind(socket) }.getOrDefault(false)
            if (!bound) {
                session.commitProtected(false)
                return@synchronized fail(session, LiveTunnelFailure.SOCKET_BIND_FAILED)
            }
            when (val committed = session.commitProtected(true)) {
                is NativeResult.Failure -> {
                    if (committed.error == OperationError.ENDPOINT_UNAVAILABLE) continue
                    return@synchronized fail(
                        session,
                        committed.error.toLiveTunnelFailure(LiveTunnelFailure.NETWORK_AUTHENTICATION_FAILED),
                    )
                }
                is NativeResult.Success -> break
            }
        }
        if (session.status() != NativeResult.Success(NativeRuntimeState.KURD_AUTHENTICATED)) {
            return@synchronized fail(session, LiveTunnelFailure.NATIVE_STATE_MISMATCH)
        }
        onStage(LiveTunnelStage.AUTHENTICATED)
        val configuration = runCatching { session.snapshot.toLiveTunConfiguration() }
            .getOrElse {
                return@synchronized fail(session, LiveTunnelFailure.INVALID_TUN_POLICY)
            }
        val tun = runCatching { tunEstablisher.establish(configuration) }.getOrNull()
            ?: return@synchronized fail(session, LiveTunnelFailure.TUN_ESTABLISH_FAILED)
        val tunFileDescriptor = try {
            tun.detachFileDescriptor()
        } catch (_: Throwable) {
            tun.close()
            return@synchronized fail(session, LiveTunnelFailure.TUN_ESTABLISH_FAILED)
        } finally {
            runCatching { tun.close() }
        }
        if (tunFileDescriptor < 0) {
            return@synchronized fail(session, LiveTunnelFailure.TUN_ESTABLISH_FAILED)
        }
        onStage(LiveTunnelStage.TUN_ESTABLISHED)
        val attached = try {
            session.attachTun(tunFileDescriptor)
        } finally {
            // The native runtime duplicates the descriptor synchronously. Android
            // retains ownership of the detached original and closes it exactly once.
            runCatching { detachedCloser.close(tunFileDescriptor) }
        }
        when (attached) {
            is NativeResult.Failure -> {
                return@synchronized fail(
                    session,
                    attached.error.toLiveTunnelFailure(LiveTunnelFailure.TUN_ATTACH_FAILED),
                )
            }
            is NativeResult.Success -> Unit
        }
        if (session.status() != NativeResult.Success(NativeRuntimeState.RUNNING)) {
            return@synchronized fail(session, LiveTunnelFailure.NATIVE_STATE_MISMATCH)
        }
        activeSession = session
        onStage(LiveTunnelStage.RUNNING)
        LiveTunnelStartResult.Running()
    }

    fun isRunning(): Boolean = synchronized(lock) { activeSession != null }

    fun diagnostics(): NativeResult<NativeLiveRuntimeDiagnostics> = synchronized(lock) {
        activeSession?.diagnostics() ?: NativeResult.Failure(OperationError.CANCELLED)
    }

    fun checkHealth(): LiveTunnelFailure? = synchronized(lock) {
        val session = activeSession ?: return@synchronized null
        val failure = when (val status = session.status()) {
            is NativeResult.Success -> if (status.value == NativeRuntimeState.RUNNING) {
                null
            } else {
                LiveTunnelFailure.NATIVE_STATE_MISMATCH
            }
            is NativeResult.Failure -> status.error.toLiveTunnelFailure(
                LiveTunnelFailure.INTERNAL_FAILURE,
            )
        }
        if (failure == null) return@synchronized null
        activeSession = null
        runCatching { session.stop() }
        runCatching { session.close() }
        onStage(LiveTunnelStage.STOPPED)
        failure
    }

    fun stop() = synchronized(lock) {
        val session = activeSession ?: return@synchronized
        activeSession = null
        runCatching { session.stop() }
        runCatching { session.close() }
        onStage(LiveTunnelStage.STOPPED)
    }

    override fun close() = stop()

    private fun fail(
        session: NativeLiveRuntimeSession,
        failure: LiveTunnelFailure,
    ): LiveTunnelStartResult.Failure {
        runCatching { session.stop() }
        runCatching { session.close() }
        return LiveTunnelStartResult.Failure(failure)
    }
}

private fun OperationError.toLiveTunnelFailure(fallback: LiveTunnelFailure): LiveTunnelFailure =
    when (this) {
        OperationError.TRUST_REJECTED,
        OperationError.AUTHORITY_UNAVAILABLE,
        OperationError.POLICY_REJECTED,
        OperationError.INCOMPATIBLE_NATIVE_CORE
        -> LiveTunnelFailure.AUTHORITY_REJECTED
        OperationError.CANCELLED -> LiveTunnelFailure.CANCELLED
        OperationError.ENDPOINT_UNAVAILABLE -> LiveTunnelFailure.ENDPOINT_UNAVAILABLE
        OperationError.TLS_REJECTED -> LiveTunnelFailure.TLS_REJECTED
        OperationError.KURD_AUTH_REJECTED -> LiveTunnelFailure.KURD_AUTH_REJECTED
        OperationError.TUN_IO_FAILED -> LiveTunnelFailure.TUN_IO_FAILED
        OperationError.DNS_UNAVAILABLE -> LiveTunnelFailure.DNS_UNAVAILABLE
        OperationError.NETWORK_LOST -> LiveTunnelFailure.NETWORK_LOST
        OperationError.FALLBACK_EXHAUSTED -> LiveTunnelFailure.FALLBACK_EXHAUSTED
        OperationError.NODE_DRAINED -> LiveTunnelFailure.NODE_DRAINED
        OperationError.DEPLOYMENT_DISABLED -> LiveTunnelFailure.DEPLOYMENT_DISABLED
        OperationError.RESOURCE_LIMIT -> LiveTunnelFailure.RESOURCE_LIMIT
        OperationError.STATE_CORRUPT -> LiveTunnelFailure.STATE_CORRUPT
        OperationError.RECOVERY_REQUIRED,
        OperationError.KEY_INVALIDATED,
        OperationError.STORAGE_FAILURE,
        OperationError.QUARANTINED
        -> LiveTunnelFailure.RECOVERY_REQUIRED
        OperationError.INTERNAL_FAILURE -> LiveTunnelFailure.INTERNAL_FAILURE
        OperationError.INVALID_INPUT,
        OperationError.SIZE_LIMIT,
        OperationError.DUPLICATE
        -> fallback
    }

internal fun NativeLiveRuntimeSessionSnapshot.toLiveTunConfiguration(): LiveTunConfiguration {
    require(mtu == 1280) { "INVALID_LIVE_MTU" }
    val addresses = buildList {
        clientIpv4.nonZeroAddressOrNull()?.let { add(LiveIpPrefix(it, 32)) }
        clientIpv6.nonZeroAddressOrNull()?.let { add(LiveIpPrefix(it, 128)) }
    }
    val dnsServers = buildList {
        dnsIpv4.nonZeroAddressOrNull()?.let(::add)
        dnsIpv6.nonZeroAddressOrNull()?.let(::add)
    }
    require(addresses.isNotEmpty() && dnsServers.isNotEmpty()) { "MISSING_LIVE_NETWORK" }
    require(addresses.map { it.address.contains(':') } == dnsServers.map { it.contains(':') }) {
        "DNS_FAMILY_MISMATCH"
    }
    val resolvedRoutes = routes.map { route ->
        val address = route.address.toNumericAddress()
        val maximum = if (route.address.size == 4) 32 else 128
        require(route.prefixLength in 0..maximum) { "INVALID_ROUTE_PREFIX" }
        require(route.prefixLength == 0 && route.address.all { it == 0.toByte() }) {
            "LAN_BYPASS_NOT_AUTHORIZED"
        }
        LiveIpPrefix(address, route.prefixLength)
    }
    require(resolvedRoutes.map { it.address.contains(':') }.toSet() ==
        addresses.map { it.address.contains(':') }.toSet()) { "ROUTE_FAMILY_MISMATCH" }
    val mode = when (perAppMode) {
        PerAppSelectionMode.ALL_APPS -> PerAppRoutingMode.ALL_APPS
        PerAppSelectionMode.INCLUDE_ONLY -> PerAppRoutingMode.INCLUDE_ONLY
        PerAppSelectionMode.EXCLUDE_SELECTED -> PerAppRoutingMode.EXCLUDE_SELECTED
    }
    return LiveTunConfiguration(
        addresses = addresses,
        routes = resolvedRoutes,
        dnsServers = dnsServers,
        mtu = mtu,
        metered = metered,
        routingPolicy = VpnRoutingPolicy(mode, packages.toSet()).validate(),
    )
}

private fun ByteArray.nonZeroAddressOrNull(): String? =
    takeIf { it.any { value -> value != 0.toByte() } }?.toNumericAddress()

private fun ByteArray.toNumericAddress(): String {
    require(size == 4 || size == 16) { "INVALID_ADDRESS_LENGTH" }
    return requireNotNull(InetAddress.getByAddress(this).hostAddress) { "INVALID_ADDRESS" }
}

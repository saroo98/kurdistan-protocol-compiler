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

/** Allocated before the framework acquisition starts. A returned platform resource is assigned
 * directly into this owner before validation or any wrapper allocation. Framework-internal
 * acquisitions which throw without returning remain explicitly unproven, never guessed clean. */
internal class PlatformTunOwner<T : AutoCloseable>(
    private val acquire: () -> T?, private val validate: (T) -> Unit,
    private val detach: (T) -> Int,
) : DetachableTun {
    private var resource: T? = null
    private var started = false
    private var detached = false
    private var closed = false
    private var unproven = false

    @Synchronized fun establish(): DetachableTun? {
        check(!started && !closed)
        started = true
        try {
            resource = acquire()
            val acquired = resource
            if (acquired == null) { closed = true; return null }
            validate(acquired)
            return this
        } catch (failure: Throwable) {
            if (resource == null) unproven = true
            try { close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
    }

    @Synchronized override fun detachFileDescriptor(): Int {
        check(started && !closed && !detached && !unproven)
        return try {
            val descriptor = detach(checkNotNull(resource))
            check(descriptor >= 0) { "TUN_DETACH_INVALID" }
            detached = true
            descriptor
        } catch (failure: Throwable) { unproven = true; throw failure }
    }

    @Synchronized override fun close() {
        if (!closed) {
            closed = true
            val owned = resource
            resource = null
            try { owned?.close() } catch (_: Throwable) { unproven = true }
        }
        check(!unproven) { "TUN_PLATFORM_CLEANUP_UNPROVEN" }
    }
}

internal fun interface DetachedFileDescriptorCloser {
    fun close(fileDescriptor: Int)
}

/** Resource acquisition callbacks must register each owner immediately after acquisition. */
internal class ActivationResourceRegistrar internal constructor(
    private val register: (String, AutoCloseable) -> Unit,
) {
    fun notification(resource: AutoCloseable) = register("notification", resource)
    fun healthMonitor(resource: AutoCloseable) = register("health", resource)
}

internal class NativeTunnelController(
    private val protector: SocketProtector,
    private val networkBinder: SocketNetworkBinder,
    private val tunEstablisher: TunEstablisher,
    private val detachedCloser: DetachedFileDescriptorCloser,
    private val onStage: (LiveTunnelStage) -> Unit = {},
    private val preTunValidation: () -> Boolean = { false },
    private val prepareRequiredActivationResources: (ActivationResourceRegistrar) -> Unit = {},
    /** Side-effect-free final validation. The service publishes ACTIVE only via its coordinator. */
    private val finalPublicationCheck: () -> Boolean = { false },
    /** Service composition uses one guard for required activation-resource ownership.
     * Unit compositions without it retain the controller's existing local owners. */
    private val activationOwner: RuntimeActivationGuard? = null,
) : AutoCloseable {
    private enum class CloseState { OWNED, CLOSING, CLEAN, UNPROVEN }
    private class Owner(val identity: Any, private val release: () -> Boolean) {
        var state = CloseState.OWNED
            private set
        fun closeOnce(): CloseState {
            if (state != CloseState.OWNED) return state
            state = CloseState.CLOSING
            state = try { if (release()) CloseState.CLEAN else CloseState.UNPROVEN }
                catch (_: Throwable) { CloseState.UNPROVEN }
            return state
        }
    }
    private class Rejected(val category: LiveTunnelFailure) : RuntimeException()
    /** Produced only after the registrar has attempted its internally owned fallback cleanup. */
    private class OwnershipRegistrationFailure : RuntimeException()
    private val lock = Any()
    private val owners = mutableListOf<Owner>()
    private var claimedSession: NativeLiveRuntimeSession? = null
    private var starting = false
    private var running = false
    private var unproven = false
    private var stoppedNotified = false
    private var terminalFailure: LiveTunnelFailure? = null
    @Volatile private var cancelled = false

    /** Ownership transfers at entry, including rejected starts. Callers must never close it again. */
    fun start(session: NativeLiveRuntimeSession): LiveTunnelStartResult = synchronized(lock) {
        if (claimedSession != null || cancelled) {
            if (session !== claimedSession && findOwner(session) == null) {
                try {
                    val rejected = takeSession(session)
                    if (rejected.closeOnce() == CloseState.UNPROVEN) {
                        unproven = true
                        terminalFailure = LiveTunnelFailure.RECOVERY_REQUIRED
                        cancelLocked()
                    }
                } catch (_: Throwable) {
                    terminalFailure = LiveTunnelFailure.INTERNAL_FAILURE
                    cancelLocked()
                }
            }
            return@synchronized LiveTunnelStartResult.Failure(LiveTunnelFailure.DUPLICATE_START, cleanupStateLocked())
        }
        claimedSession = session
        starting = true
        var captured: NativeLiveRuntimeSessionSnapshot? = null
        var failure: LiveTunnelFailure? = null
        var completed: LiveTunnelStartResult.Running? = null
        try {
            // takeSession owns its fallback before owner allocation/registration can fail.
            takeSession(session)
            captured = session.snapshot.ownedSnapshot()
            stage(LiveTunnelStage.VERIFIED)
            val socket = value(session.prepareSocket(), LiveTunnelFailure.SOCKET_PREPARE_FAILED)
            requireNotCancelled()
            if (socket < 0) reject(LiveTunnelFailure.SOCKET_PREPARE_FAILED)
            stage(LiveTunnelStage.SOCKET_PREPARED)
            if (!protector.protect(socket)) {
                session.commitProtected(false)
                reject(LiveTunnelFailure.SOCKET_PROTECT_FAILED)
            }
            requireNotCancelled()
            stage(LiveTunnelStage.SOCKET_PROTECTED)
            if (!networkBinder.bind(socket)) {
                session.commitProtected(false)
                reject(LiveTunnelFailure.SOCKET_BIND_FAILED)
            }
            requireNotCancelled()
            // A retry belongs to the coordinator and requires a fresh armed authority.
            value(session.commitProtected(true), LiveTunnelFailure.NETWORK_AUTHENTICATION_FAILED)
            requireNotCancelled()
            if (value(session.status(), LiveTunnelFailure.NATIVE_STATE_MISMATCH) != NativeRuntimeState.KURD_AUTHENTICATED) {
                reject(LiveTunnelFailure.NATIVE_STATE_MISMATCH)
            }
            stage(LiveTunnelStage.AUTHENTICATED)
            val configuration = try { captured.toLiveTunConfiguration() }
                catch (_: Throwable) { reject(LiveTunnelFailure.INVALID_TUN_POLICY) }
            if (!preTunValidation()) reject(LiveTunnelFailure.AUTHORITY_REJECTED)
            requireNotCancelled()
            val tun = try { tunEstablisher.establish(configuration) } catch (_: Throwable) {
                // This legacy interface cannot expose a TUN acquired internally before throwing.
                // Do not certify that unseen partial acquisition as clean.
                unproven = true
                reject(LiveTunnelFailure.TUN_ESTABLISH_FAILED)
            } ?: reject(LiveTunnelFailure.TUN_ESTABLISH_FAILED)
            val tunOwner = takeTun(tun)
            requireNotCancelled()
            val descriptor = try { tun.detachFileDescriptor() } catch (_: Throwable) {
                // A throwing detach may already have transferred a descriptor without returning it.
                unproven = true
                reject(LiveTunnelFailure.TUN_ESTABLISH_FAILED)
            }
            if (descriptor < 0) { unproven = true; reject(LiveTunnelFailure.TUN_ESTABLISH_FAILED) }
            val detached = takeDetached(descriptor)
            if (tunOwner.closeOnce() != CloseState.CLEAN) reject(LiveTunnelFailure.RECOVERY_REQUIRED)
            stage(LiveTunnelStage.TUN_ESTABLISHED)
            val attached = try { session.attachTun(descriptor) } finally { detached.closeOnce() }
            if (detached.state != CloseState.CLEAN) reject(LiveTunnelFailure.RECOVERY_REQUIRED)
            value(attached, LiveTunnelFailure.TUN_ATTACH_FAILED)
            requireNotCancelled()
            if (value(session.status(), LiveTunnelFailure.NATIVE_STATE_MISMATCH) != NativeRuntimeState.RUNNING) {
                reject(LiveTunnelFailure.NATIVE_STATE_MISMATCH)
            }
            val kinds = mutableSetOf<String>()
            var registering = true
            val registrar = ActivationResourceRegistrar { kind, resource ->
                synchronized(lock) {
                    if (findOwner(resource) != null) reject(LiveTunnelFailure.INTERNAL_FAILURE)
                    if (activationOwner != null) {
                        if (resource !is RuntimeActivationResource) {
                            takeActivationResource(resource).closeOnce()
                            reject(LiveTunnelFailure.INTERNAL_FAILURE)
                        }
                        try {
                            activationOwner.prepareActivationResource(
                                if (kind == "notification") RuntimeResourceKind.NOTIFICATION else RuntimeResourceKind.HEALTH_MONITOR,
                                resource,
                            )
                        } catch (_: Throwable) { throw OwnershipRegistrationFailure() }
                        if (!registering || cancelled || !kinds.add(kind)) {
                            activationOwner.markCancellation()
                            reject(LiveTunnelFailure.CANCELLED)
                        }
                        return@synchronized
                    }
                    val owner = takeActivationResource(resource)
                    if (!registering || cancelled || !kinds.add(kind)) {
                        owner.closeOnce()
                        terminalFailure = LiveTunnelFailure.CANCELLED
                        cancelLocked()
                        reject(LiveTunnelFailure.CANCELLED)
                    }
                }
            }
            try { prepareRequiredActivationResources(registrar) }
            catch (failure: Throwable) {
                // An arbitrary callback throw may hide a resource created before registration.
                // A controller-origin registration failure instead retains its actual owner state.
                if (failure !is OwnershipRegistrationFailure && failure !is Rejected) unproven = true
                throw failure
            } finally { registering = false }
            requireNotCancelled()
            val ready = LiveTunnelStartResult.Running()
            if (kinds != setOf("notification", "health") || !finalPublicationCheck()) {
                reject(LiveTunnelFailure.AUTHORITY_REJECTED)
            }
            requireNotCancelled()
            // RUNNING is a return value, never a fallible external observer publication.
            // Only the coordinator may turn this native-ready result into external ACTIVE.
            running = true
            requireNotCancelled()
            completed = ready
        } catch (error: Rejected) {
            failure = error.category
            terminalFailure = failure
            cancelLocked()
        } catch (_: Throwable) {
            failure = if (cancelled) LiveTunnelFailure.CANCELLED else LiveTunnelFailure.INTERNAL_FAILURE
            terminalFailure = failure
            cancelLocked()
        } finally {
            captured?.wipeOwnedSnapshot()
            starting = false
        }
        if (failure == null) requireNotNull(completed)
        else LiveTunnelStartResult.Failure(failure, cleanupStateLocked())
    }

    fun isRunning(): Boolean = synchronized(lock) { running && !cancelled && !unproven }

    fun diagnostics(): NativeResult<NativeLiveRuntimeDiagnostics> = synchronized(lock) {
        if (!isRunning()) return@synchronized NativeResult.Failure(OperationError.CANCELLED)
        try { requireNotNull(claimedSession).diagnostics() }
        catch (_: Throwable) {
            terminalFailure = LiveTunnelFailure.INTERNAL_FAILURE
            cancelLocked()
            NativeResult.Failure(OperationError.INTERNAL_FAILURE)
        }
    }

    fun checkHealth(): LiveTunnelFailure? = synchronized(lock) {
        if (!running) return@synchronized terminalFailure
        val failure = try {
            when (val result = requireNotNull(claimedSession).status()) {
                is NativeResult.Success -> if (result.value == NativeRuntimeState.RUNNING) null else LiveTunnelFailure.NATIVE_STATE_MISMATCH
                is NativeResult.Failure -> result.error.toLiveTunnelFailure(LiveTunnelFailure.INTERNAL_FAILURE)
            }
        } catch (_: Throwable) { LiveTunnelFailure.INTERNAL_FAILURE }
        if (failure != null) {
            terminalFailure = failure
            cancelLocked()
            emitStopped()
        }
        failure
    }

    /** Cancellation is visible before waiting for an in-flight synchronous native call. */
    fun stopResult(): org.kurdistanvpn.runtime.api.LiveTunnelCleanupState {
        cancelled = true
        return synchronized(lock) {
            val wasLive = running || starting
            cancelLocked()
            if (wasLive) emitStopped()
            cleanupStateLocked()
        }
    }

    fun cleanupState(): org.kurdistanvpn.runtime.api.LiveTunnelCleanupState = synchronized(lock) { cleanupStateLocked() }
    fun stop() { stopResult() }
    override fun close() { stopResult() }

    private fun emitStopped() {
        if (stoppedNotified) return
        stoppedNotified = true
        try { onStage(LiveTunnelStage.STOPPED) } catch (_: Throwable) { unproven = true }
    }
    private fun cancelLocked() {
        cancelled = true
        running = false
        var index = owners.size - 1
        while (index >= 0) {
            if (owners[index].closeOnce() == CloseState.UNPROVEN) unproven = true
            index--
        }
    }
    private fun cleanupStateLocked(): org.kurdistanvpn.runtime.api.LiveTunnelCleanupState {
        if (unproven) return org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN
        var required = starting || running
        var index = 0
        while (index < owners.size) {
            when (owners[index].state) {
                CloseState.UNPROVEN -> return org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN
                CloseState.OWNED, CloseState.CLOSING -> required = true
                CloseState.CLEAN -> Unit
            }
            index++
        }
        return if (required) org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.CLEANUP_REQUIRED
            else org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.CLEAN
    }
    private fun findOwner(identity: Any): Owner? {
        var index = 0
        while (index < owners.size) {
            val owner = owners[index]
            if (owner.identity === identity) return owner
            index++
        }
        return null
    }
    private fun takeSession(session: NativeLiveRuntimeSession): Owner {
        var owner: Owner? = null
        try {
            owner = Owner(session) { releaseSession(session) }
            owners.add(owner)
            return owner
        } catch (failure: Throwable) {
            if (owner != null) rememberClose(owner) else if (!releaseSession(session)) unproven = true
            throw failure
        }
    }
    private fun takeTun(tun: DetachableTun): Owner {
        var owner: Owner? = null
        try {
            owner = Owner(tun) { tun.close(); true }
            owners.add(owner)
            return owner
        } catch (failure: Throwable) {
            if (owner != null) rememberClose(owner) else try { tun.close() } catch (_: Throwable) { unproven = true }
            throw failure
        }
    }
    private fun takeDetached(descriptor: Int): Owner {
        var owner: Owner? = null
        try {
            owner = Owner(Any()) { detachedCloser.close(descriptor); true }
            owners.add(owner)
            return owner
        } catch (failure: Throwable) {
            if (owner != null) rememberClose(owner)
            else try { detachedCloser.close(descriptor) } catch (_: Throwable) { unproven = true }
            throw failure
        }
    }
    private fun takeActivationResource(resource: AutoCloseable): Owner {
        var owner: Owner? = null
        try {
            owner = Owner(resource) { resource.close(); true }
            owners.add(owner)
            return owner
        } catch (failure: Throwable) {
            if (owner != null) rememberClose(owner) else try { resource.close() } catch (_: Throwable) { unproven = true }
            throw OwnershipRegistrationFailure()
        }
    }
    private fun rememberClose(owner: Owner) {
        if (owner.closeOnce() == CloseState.UNPROVEN) unproven = true
    }
    private fun releaseSession(session: NativeLiveRuntimeSession): Boolean {
        val stopped = try { session.stop() is NativeResult.Success } catch (_: Throwable) { false }
        val closed = try { session.close(); true } catch (_: Throwable) { false }
        return stopped && closed
    }
    private fun stage(stage: LiveTunnelStage) { onStage(stage); requireNotCancelled() }
    private fun requireNotCancelled() { if (cancelled) reject(LiveTunnelFailure.CANCELLED) }
    private fun reject(failure: LiveTunnelFailure): Nothing = throw Rejected(failure)
    private fun <T> value(result: NativeResult<T>, fallback: LiveTunnelFailure): T = when (result) {
        is NativeResult.Success -> result.value
        is NativeResult.Failure -> reject(result.error.toLiveTunnelFailure(fallback))
    }
}

private fun NativeLiveRuntimeSessionSnapshot.ownedSnapshot(): NativeLiveRuntimeSessionSnapshot {
    // Allocate bookkeeping before cloning anything. Every subsequent clone is owned before
    // validation or another allocation; partial construction wipes only controller-owned data.
    val buffers = arrayOfNulls<ByteArray>(8)
    val routeCopies = ArrayList<org.kurdistanvpn.core.nativeapi.NativeRoute>(2)
    var transferred = false
    try {
        buffers[0] = planDigest.clone(); buffers[1] = profileFingerprint.clone()
        buffers[2] = strategyFingerprint.clone(); buffers[3] = relayFingerprint.clone()
        buffers[4] = clientIpv4.clone(); buffers[5] = dnsIpv4.clone()
        buffers[6] = clientIpv6.clone(); buffers[7] = dnsIpv6.clone()
        val packageCopies = packages.toList()
        val protocolCopies = payloadProtocols.toSet()
        for (route in routes) {
            val address = route.address.clone()
            try {
                require(routeCopies.size < 2)
                routeCopies.add(route.copy(address = address))
            } catch (failure: Throwable) { address.fill(0); throw failure }
        }
        val owned = copy(planDigest = requireNotNull(buffers[0]), profileFingerprint = requireNotNull(buffers[1]),
            strategyFingerprint = requireNotNull(buffers[2]), relayFingerprint = requireNotNull(buffers[3]),
            clientIpv4 = requireNotNull(buffers[4]), dnsIpv4 = requireNotNull(buffers[5]),
            clientIpv6 = requireNotNull(buffers[6]), dnsIpv6 = requireNotNull(buffers[7]),
            packages = packageCopies, routes = routeCopies, payloadProtocols = protocolCopies)
        require(owned.generation > 0 && owned.planDigest.size == 32 && owned.profileFingerprint.size == 16 &&
            owned.strategyFingerprint.size == 16 && owned.relayFingerprint.size == 16)
        require(owned.clientIpv4.size == 4 && owned.dnsIpv4.size == 4 && owned.clientIpv6.size == 16 && owned.dnsIpv6.size == 16)
        require(owned.packages.size <= 64 && owned.packages.all { it.length <= 255 } && owned.routes.size in 1..2)
        require(owned.routes.all { it.address.size == 4 || it.address.size == 16 })
        transferred = true
        return owned
    } finally {
        if (!transferred) {
            var index = 0
            while (index < buffers.size) { buffers[index]?.fill(0); index++ }
            index = 0
            while (index < routeCopies.size) { routeCopies[index].address.fill(0); index++ }
        }
    }
}

private fun NativeLiveRuntimeSessionSnapshot.wipeOwnedSnapshot() {
    planDigest.fill(0); profileFingerprint.fill(0); strategyFingerprint.fill(0); relayFingerprint.fill(0)
    clientIpv4.fill(0); dnsIpv4.fill(0); clientIpv6.fill(0); dnsIpv6.fill(0)
    var index = 0
    while (index < routes.size) { routes[index].address.fill(0); index++ }
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

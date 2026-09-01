// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativePayloadProtocol
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeRoute
import org.kurdistanvpn.core.nativeapi.NativeRuntimeState
import org.kurdistanvpn.runtime.api.LiveTunnelFailure
import org.kurdistanvpn.runtime.api.LiveTunnelStage
import org.kurdistanvpn.runtime.api.LiveTunnelStartResult

/** Internal-build controller model. No real TUN, socket, authority, or ACTIVE publication
 * occurs here. This source set is absent from release APKs. */
object LiveTunnelInvariantProbe {
    data class Result(
        val events: List<String>,
        val runningBeforeStop: Boolean,
        val runningAfterStop: Boolean,
        val failure: LiveTunnelFailure?,
    )

    fun exercise(protectSucceeds: Boolean): Result {
        val events = mutableListOf<String>()
        val session = ProbeSession(events)
        val controller = NativeTunnelController(
            protector = SocketProtector { descriptor ->
                events += "protect:$descriptor"
                protectSucceeds
            },
            networkBinder = SocketNetworkBinder { descriptor ->
                events += "bind:$descriptor"
                true
            },
            tunEstablisher = TunEstablisher {
                events += "builder"
                ProbeTun(events)
            },
            detachedCloser = DetachedFileDescriptorCloser { events += "close-detached:$it" },
            onStage = { events += "stage:${it.name}" },
            preTunValidation = { events += "model:PRE_TUN"; true },
            prepareRequiredActivationResources = { registrar ->
                registrar.notification(AutoCloseable { events += "model:NOTIFICATION_CLOSED" })
                events += "model:NOTIFICATION_READY"
                registrar.healthMonitor(AutoCloseable { events += "model:HEALTH_CLOSED" })
                events += "model:HEALTH_READY"
            },
            finalPublicationCheck = { events += "model:PRE_ACTIVE"; true },
        )
        val start = controller.start(session)
        if (start is LiveTunnelStartResult.Running) events += "model:NATIVE_READY"
        val before = controller.isRunning()
        controller.stop()
        val after = controller.isRunning()
        return Result(
            events = events.toList(),
            runningBeforeStop = before,
            runningAfterStop = after,
            failure = (start as? LiveTunnelStartResult.Failure)?.category,
        )
    }
}

private class ProbeTun(private val events: MutableList<String>) : DetachableTun {
    init { events += "establish" }
    override fun detachFileDescriptor(): Int = 71.also { events += "detach" }
    override fun close() = Unit
}

private class ProbeSession(private val events: MutableList<String>) : NativeLiveRuntimeSession {
    private var state = NativeRuntimeState.VERIFIED
    override val snapshot = NativeLiveRuntimeSessionSnapshot(
        generation = 7,
        planDigest = ByteArray(32) { 1 },
        profileFingerprint = ByteArray(16) { 2 },
        strategyFingerprint = ByteArray(16) { 3 },
        relayFingerprint = ByteArray(16) { 4 },
        selectionMode = SelectionMode.AUTOMATIC,
        perAppMode = PerAppSelectionMode.ALL_APPS,
        packages = emptyList(),
        ipMode = IpMode.IPV4_ONLY,
        dnsMode = DnsMode.INTERNAL_TUN,
        mtu = 1280,
        metered = false,
        clientIpv4 = byteArrayOf(10, 77, 0, 2),
        dnsIpv4 = byteArrayOf(10, 77, 0, 1),
        clientIpv6 = ByteArray(16),
        dnsIpv6 = ByteArray(16),
        routes = listOf(NativeRoute(ByteArray(4), 0)),
        payloadProtocols = setOf(NativePayloadProtocol.TCP, NativePayloadProtocol.UDP),
        maxQueuePackets = 100,
        maxIncompleteOperations = 32,
        maxReconnectAttempts = 3,
        dialTimeoutMillis = 5_000,
        idleTimeoutMillis = 60_000,
    )

    override fun prepareSocket(): NativeResult<Int> {
        events += "prepare"
        state = NativeRuntimeState.SOCKET_PREPARED
        return NativeResult.Success(37)
    }

    override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> {
        if (!protectedSocket) {
            events += "commit-false"
            return NativeResult.Failure(org.kurdistanvpn.core.model.OperationError.POLICY_REJECTED)
        }
        events += listOf("connect", "tls", "kurd")
        state = NativeRuntimeState.KURD_AUTHENTICATED
        return NativeResult.Success(Unit)
    }

    override fun attachTun(fileDescriptor: Int): NativeResult<Unit> {
        events += "attach:$fileDescriptor"
        state = NativeRuntimeState.RUNNING
        return NativeResult.Success(Unit)
    }

    override fun status(): NativeResult<NativeRuntimeState> {
        events += "status:${state.name}"
        return NativeResult.Success(state)
    }

    override fun stop(): NativeResult<Unit> {
        events += "stop"
        state = NativeRuntimeState.STOPPING
        return NativeResult.Success(Unit)
    }

    override fun close() {
        events += "close"
    }
}

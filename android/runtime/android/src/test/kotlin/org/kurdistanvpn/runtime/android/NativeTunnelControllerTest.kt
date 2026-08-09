// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSession
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeDiagnostics
import org.kurdistanvpn.core.nativeapi.NativeLiveRuntimeSessionSnapshot
import org.kurdistanvpn.core.nativeapi.NativePayloadProtocol
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeRoute
import org.kurdistanvpn.core.nativeapi.NativeRuntimeState
import org.kurdistanvpn.runtime.api.LiveTunnelFailure
import org.kurdistanvpn.runtime.api.LiveTunnelStage
import org.kurdistanvpn.runtime.api.LiveTunnelStartResult

class NativeTunnelControllerTest {
    @Test
    fun exactOrderProtectsBeforeConnectAndPublishesRunningOnlyAfterTunAttachment() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = NativeTunnelController(
            protector = SocketProtector { events += "protect"; true },
            tunEstablisher = TunEstablisher {
                events += "builder"
                FakeTun(events)
            },
            detachedCloser = DetachedFileDescriptorCloser { events += "close-detached:$it" },
            onStage = { events += "stage:${it.name}" },
        )

        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        assertEquals(
            listOf(
                "stage:VERIFIED", "prepare", "stage:SOCKET_PREPARED", "protect",
                "stage:SOCKET_PROTECTED", "connect", "tls", "kurd", "status:KURD_AUTHENTICATED",
                "stage:AUTHENTICATED", "builder", "establish", "detach",
                "stage:TUN_ESTABLISHED", "attach:71", "close-detached:71",
                "status:RUNNING", "stage:RUNNING",
            ),
            events,
        )
        assertTrue(controller.isRunning())
        controller.stop()
        assertFalse(controller.isRunning())
    }

    @Test
    fun diagnosticsReturnsOnlyTheActiveNativeSessionAggregateSnapshot() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = NativeTunnelController(
            protector = SocketProtector { true },
            tunEstablisher = TunEstablisher { FakeTun(events) },
            detachedCloser = DetachedFileDescriptorCloser {},
        )

        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        assertEquals(NativeResult.Success(liveDiagnostics()), controller.diagnostics())
        controller.stop()
        assertEquals(NativeResult.Failure(OperationError.CANCELLED), controller.diagnostics())
    }

    @Test
    fun protectFailureFailsClosedWithoutConnecting() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = NativeTunnelController(
            SocketProtector { events += "protect"; false },
            TunEstablisher { error("must not establish") },
            DetachedFileDescriptorCloser {},
        )

        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.SOCKET_PROTECT_FAILED),
            controller.start(session),
        )
        assertFalse(events.contains("connect"))
        assertTrue(events.contains("commit-false"))
        assertTrue(events.contains("stop"))
        assertTrue(events.contains("close"))
    }

    @Test
    fun endpointFallbackProtectsEveryFreshSocketBeforeRetrying() {
        val events = mutableListOf<String>()
        val session = FallbackLiveSession(events, listOf(OperationError.ENDPOINT_UNAVAILABLE, null))
        val controller = NativeTunnelController(
            SocketProtector { events += "protect:$it"; true },
            TunEstablisher { FakeTun(events) },
            DetachedFileDescriptorCloser {},
        )

        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        assertEquals(2, events.count { it.startsWith("prepare:") })
        assertEquals(listOf("protect:40", "protect:41"), events.filter { it.startsWith("protect:") })
        assertEquals(2, events.count { it == "connect" })
        assertEquals(1, events.count { it == "tls" })
        assertEquals(1, events.count { it == "kurd" })
    }

    @Test
    fun exhaustedEndpointFallbackFailsClosedWithoutTun() {
        val events = mutableListOf<String>()
        val session = FallbackLiveSession(events, listOf(OperationError.FALLBACK_EXHAUSTED))
        val controller = NativeTunnelController(
            SocketProtector { events += "protect:$it"; true },
            TunEstablisher { error("must not establish") },
            DetachedFileDescriptorCloser {},
        )

        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.FALLBACK_EXHAUSTED),
            controller.start(session),
        )
        assertTrue(events.contains("stop"))
        assertTrue(events.contains("close"))
        assertFalse(events.contains("establish"))
    }

    @Test
    fun prepareAndAuthenticationFailuresNeverEstablishTun() {
        listOf(
            FakeLiveSession.Options(prepareError = OperationError.INTERNAL_FAILURE) to LiveTunnelFailure.INTERNAL_FAILURE,
            FakeLiveSession.Options(commitError = OperationError.INTERNAL_FAILURE) to LiveTunnelFailure.INTERNAL_FAILURE,
            FakeLiveSession.Options(authenticatedState = NativeRuntimeState.TLS_AUTHENTICATED) to
                LiveTunnelFailure.NATIVE_STATE_MISMATCH,
        ).forEach { (options, expected) ->
            val events = mutableListOf<String>()
            val controller = NativeTunnelController(
                SocketProtector { true },
                TunEstablisher { error("must not establish") },
                DetachedFileDescriptorCloser {},
            )

            assertEquals(
                LiveTunnelStartResult.Failure(expected),
                controller.start(FakeLiveSession(events, options)),
            )
            assertFalse(events.contains("establish"))
            assertTrue(events.contains("close"))
        }
    }

    @Test
    fun nativeFailureCategoriesRemainActionableAndFailClosed() {
        val cases = listOf(
            FakeLiveSession.Options(prepareError = OperationError.ENDPOINT_UNAVAILABLE) to LiveTunnelFailure.ENDPOINT_UNAVAILABLE,
            FakeLiveSession.Options(commitError = OperationError.TLS_REJECTED) to LiveTunnelFailure.TLS_REJECTED,
            FakeLiveSession.Options(commitError = OperationError.KURD_AUTH_REJECTED) to LiveTunnelFailure.KURD_AUTH_REJECTED,
            FakeLiveSession.Options(commitError = OperationError.NODE_DRAINED) to LiveTunnelFailure.NODE_DRAINED,
            FakeLiveSession.Options(commitError = OperationError.DEPLOYMENT_DISABLED) to LiveTunnelFailure.DEPLOYMENT_DISABLED,
            FakeLiveSession.Options(attachError = OperationError.TUN_IO_FAILED) to LiveTunnelFailure.TUN_IO_FAILED,
            FakeLiveSession.Options(attachError = OperationError.RESOURCE_LIMIT) to LiveTunnelFailure.RESOURCE_LIMIT,
            FakeLiveSession.Options(prepareError = OperationError.STATE_CORRUPT) to LiveTunnelFailure.STATE_CORRUPT,
            FakeLiveSession.Options(prepareError = OperationError.RECOVERY_REQUIRED) to LiveTunnelFailure.RECOVERY_REQUIRED,
            FakeLiveSession.Options(prepareError = OperationError.CANCELLED) to LiveTunnelFailure.CANCELLED,
        )
        cases.forEach { (options, expected) ->
            val events = mutableListOf<String>()
            val controller = NativeTunnelController(
                SocketProtector { true },
                TunEstablisher { FakeTun(events) },
                DetachedFileDescriptorCloser { events += "closed:$it" },
            )

            assertEquals(
                LiveTunnelStartResult.Failure(expected),
                controller.start(FakeLiveSession(events, options)),
            )
            assertFalse(controller.isRunning())
            assertTrue(events.contains("close"))
        }
    }

    @Test
    fun asynchronousNativeFailureClearsFalseRunningState() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = NativeTunnelController(
            SocketProtector { true },
            TunEstablisher { FakeTun(events) },
            DetachedFileDescriptorCloser {},
        )
        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        session.failStatus(OperationError.TUN_IO_FAILED)

        assertEquals(LiveTunnelFailure.TUN_IO_FAILED, controller.checkHealth())
        assertFalse(controller.isRunning())
        assertTrue(events.contains("stop"))
        assertTrue(events.contains("close"))
    }

    @Test
    fun nullTunAndDuplicateStartFailClosed() {
        val firstEvents = mutableListOf<String>()
        val controller = NativeTunnelController(
            SocketProtector { true },
            TunEstablisher { null },
            DetachedFileDescriptorCloser {},
        )
        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.TUN_ESTABLISH_FAILED),
            controller.start(FakeLiveSession(firstEvents)),
        )
        assertFalse(controller.isRunning())

        val runningEvents = mutableListOf<String>()
        val running = NativeTunnelController(
            SocketProtector { true },
            TunEstablisher { FakeTun(runningEvents) },
            DetachedFileDescriptorCloser {},
        )
        assertEquals(LiveTunnelStartResult.Running(), running.start(FakeLiveSession(runningEvents)))
        val duplicateEvents = mutableListOf<String>()
        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.DUPLICATE_START),
            running.start(FakeLiveSession(duplicateEvents)),
        )
        assertTrue(duplicateEvents.contains("close"))
        running.close()
    }

    @Test
    fun attachFailureClosesDetachedDescriptorAndNeverPublishesRunning() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events, failAttach = true)
        val controller = NativeTunnelController(
            SocketProtector { true },
            TunEstablisher { FakeTun(events) },
            DetachedFileDescriptorCloser { events += "closed:$it" },
            onStage = { events += "stage:${it.name}" },
        )

        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE),
            controller.start(session),
        )
        assertEquals(1, events.count { it == "closed:71" })
        assertFalse(events.contains("stage:${LiveTunnelStage.RUNNING.name}"))
    }

    @Test
    fun snapshotBuildsExactDualStackDefaultsAndOnlyInTunnelDns() {
        val configuration = snapshot(dualStack = true).toLiveTunConfiguration()

        assertEquals(
            listOf("10.77.0.2", "fd4b:7572:6400:0:0:0:0:2"),
            configuration.addresses.map { it.address },
        )
        assertEquals(listOf(32, 128), configuration.addresses.map { it.prefixLength })
        assertEquals(listOf(0, 0), configuration.routes.map { it.prefixLength })
        assertEquals(listOf("10.77.0.1", "fd4b:7572:6400:0:0:0:0:1"), configuration.dnsServers)
        assertEquals(1280, configuration.mtu)
    }

    @Test(expected = IllegalArgumentException::class)
    fun snapshotRejectsAnyLanBypassRoute() {
        snapshot().copy(
            routes = listOf(NativeRoute(byteArrayOf(10, 0, 0, 0), 8)),
        ).toLiveTunConfiguration()
    }

    @Test
    fun snapshotPreservesVerifiedIpv6PerAppAndMeteredPolicy() {
        val ipv6 = snapshot().copy(
            perAppMode = PerAppSelectionMode.INCLUDE_ONLY,
            packages = listOf("org.example.one", "org.example.two"),
            ipMode = IpMode.IPV6_ONLY,
            metered = true,
            clientIpv4 = ByteArray(4),
            dnsIpv4 = ByteArray(4),
            clientIpv6 = byteArrayOf(0xfd.toByte(), 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2),
            dnsIpv6 = byteArrayOf(0xfd.toByte(), 0, 0, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1),
            routes = listOf(NativeRoute(ByteArray(16), 0)),
        ).toLiveTunConfiguration()

        assertEquals(listOf(128), ipv6.addresses.map { it.prefixLength })
        assertEquals(listOf(0), ipv6.routes.map { it.prefixLength })
        assertEquals(PerAppSelectionMode.INCLUDE_ONLY.name, ipv6.routingPolicy.perAppMode.name)
        assertEquals(setOf("org.example.one", "org.example.two"), ipv6.routingPolicy.packages)
        assertTrue(ipv6.metered)
    }
}

private class FakeTun(private val events: MutableList<String>) : DetachableTun {
    init { events += "establish" }
    override fun detachFileDescriptor(): Int = 71.also { events += "detach" }
    override fun close() = Unit
}

private class FakeLiveSession(
    private val events: MutableList<String>,
    private val options: Options = Options(),
) : NativeLiveRuntimeSession {
    constructor(events: MutableList<String>, failAttach: Boolean) : this(
        events,
        Options(attachError = if (failAttach) OperationError.INTERNAL_FAILURE else null),
    )

    data class Options(
        val prepareError: OperationError? = null,
        val commitError: OperationError? = null,
        val attachError: OperationError? = null,
        val authenticatedState: NativeRuntimeState = NativeRuntimeState.KURD_AUTHENTICATED,
    )

    private var state = NativeRuntimeState.VERIFIED
    private var statusError: OperationError? = null
    override val snapshot = snapshot()

    override fun prepareSocket(): NativeResult<Int> {
        events += "prepare"
        options.prepareError?.let { return NativeResult.Failure(it) }
        state = NativeRuntimeState.SOCKET_PREPARED
        return NativeResult.Success(37)
    }

    override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> {
        if (!protectedSocket) {
            events += "commit-false"
            return NativeResult.Failure(OperationError.POLICY_REJECTED)
        }
        events += listOf("connect", "tls", "kurd")
        options.commitError?.let { return NativeResult.Failure(it) }
        state = options.authenticatedState
        return NativeResult.Success(Unit)
    }

    override fun attachTun(fileDescriptor: Int): NativeResult<Unit> {
        events += "attach:$fileDescriptor"
        options.attachError?.let { return NativeResult.Failure(it) }
        state = NativeRuntimeState.RUNNING
        return NativeResult.Success(Unit)
    }

    override fun status(): NativeResult<NativeRuntimeState> {
        events += "status:${state.name}"
        statusError?.let { return NativeResult.Failure(it) }
        return NativeResult.Success(state)
    }

    override fun diagnostics(): NativeResult<NativeLiveRuntimeDiagnostics> =
        NativeResult.Success(liveDiagnostics())

    fun failStatus(error: OperationError) {
        statusError = error
    }

    override fun stop(): NativeResult<Unit> {
        events += "stop"
        state = NativeRuntimeState.STOPPING
        return NativeResult.Success(Unit)
    }

    override fun close() { events += "close" }
}

private class FallbackLiveSession(
    private val events: MutableList<String>,
    private val commitErrors: List<OperationError?>,
) : NativeLiveRuntimeSession {
    private var attempt = 0
    private var state = NativeRuntimeState.VERIFIED
    override val snapshot = snapshot()

    override fun prepareSocket(): NativeResult<Int> {
        events += "prepare:$attempt"
        state = NativeRuntimeState.SOCKET_PREPARED
        return NativeResult.Success(40 + attempt)
    }

    override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> {
        if (!protectedSocket) return NativeResult.Failure(OperationError.POLICY_REJECTED)
        events += "connect"
        val error = commitErrors.getOrNull(attempt++)
        if (error != null) {
            state = NativeRuntimeState.VERIFIED
            return NativeResult.Failure(error)
        }
        events += listOf("tls", "kurd")
        state = NativeRuntimeState.KURD_AUTHENTICATED
        return NativeResult.Success(Unit)
    }

    override fun attachTun(fileDescriptor: Int): NativeResult<Unit> {
        events += "attach:$fileDescriptor"
        state = NativeRuntimeState.RUNNING
        return NativeResult.Success(Unit)
    }

    override fun status(): NativeResult<NativeRuntimeState> = NativeResult.Success(state)
    override fun stop(): NativeResult<Unit> {
        events += "stop"
        return NativeResult.Success(Unit)
    }
    override fun close() { events += "close" }
}

private fun snapshot(dualStack: Boolean = false) = NativeLiveRuntimeSessionSnapshot(
    generation = 7,
    planDigest = ByteArray(32) { 1 },
    profileFingerprint = ByteArray(16) { 2 },
    strategyFingerprint = ByteArray(16) { 3 },
    relayFingerprint = ByteArray(16) { 4 },
    selectionMode = SelectionMode.AUTOMATIC,
    perAppMode = PerAppSelectionMode.ALL_APPS,
    packages = emptyList(),
    ipMode = if (dualStack) IpMode.DUAL_STACK else IpMode.IPV4_ONLY,
    dnsMode = DnsMode.INTERNAL_TUN,
    mtu = 1280,
    metered = false,
    clientIpv4 = byteArrayOf(10, 77, 0, 2),
    dnsIpv4 = byteArrayOf(10, 77, 0, 1),
    clientIpv6 = if (dualStack) byteArrayOf(0xfd.toByte(), 0x4b, 0x75, 0x72, 0x64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2) else ByteArray(16),
    dnsIpv6 = if (dualStack) byteArrayOf(0xfd.toByte(), 0x4b, 0x75, 0x72, 0x64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) else ByteArray(16),
    routes = buildList {
        add(NativeRoute(ByteArray(4), 0))
        if (dualStack) add(NativeRoute(ByteArray(16), 0))
    },
    payloadProtocols = setOf(NativePayloadProtocol.TCP, NativePayloadProtocol.UDP),
    maxQueuePackets = 100,
    maxIncompleteOperations = 32,
    maxReconnectAttempts = 3,
    dialTimeoutMillis = 5_000,
    idleTimeoutMillis = 60_000,
)

private fun liveDiagnostics() = NativeLiveRuntimeDiagnostics(
    tunPacketsRead = 1,
    outboundPacketsAccepted = 2,
    carrierRecordsWritten = 3,
    carrierRecordsRead = 4,
    authenticatedOperations = 5,
    innerPacketsAccepted = 6,
    innerPacketsRejected = 7,
    tunWriteAttempts = 8,
    tunWriteFailures = 9,
    tunWriteFailureCode = 10,
    tunWriteErrno = 11,
    tunPacketsWritten = 12,
    rejectedTunPackets = 13,
)

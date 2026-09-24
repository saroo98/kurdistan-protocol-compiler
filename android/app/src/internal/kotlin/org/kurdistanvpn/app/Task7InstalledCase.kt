// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import java.io.File
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.runtime.android.*
import org.kurdistanvpn.runtime.api.RuntimeAuthorityTrigger
import org.kurdistanvpn.core.nativejni.Task7InstalledFixtureNative

/** Internal snapshot v1: no sign bits; legacy low fields retain explicit -1 sentinels. */
internal fun task7PackRejectionV1(kind: Long, detail: Long, owner: Int, callback: Int, native: LongArray, socket: Int = 0): LongArray {
    require(kind in -1..10 && detail in -1..0xffffe && owner in 0..7 && callback in 0..127)
    require(native.size == 3 && native.all { it in 0..4095 })
    require(socket in 0..0x7ffff)
    return longArrayOf((1L shl 62) or (if (kind == -1L) 255 else kind) or (owner.toLong() shl 8) or
        (callback.toLong() shl 11) or (native[1] shl 18) or (native[2] shl 30) or (socket.toLong() shl 42),
        (if (detail == -1L) 0xfffff else detail) or (native[0] shl 20))
}

internal fun task7ControlWithinDeadlineV1(deadline: Long, now: () -> Long,
    cancelled: () -> Boolean, poll: () -> NativeProductResult<NativeControlEvent>
): NativeProductResult<NativeControlEvent> {
    while (!cancelled() && now() < deadline) {
        val result = poll()
        // P1 timeout does not consume the queued event or terminate the owner.
        // Retain the fixture's original outer deadline, never restart the case.
        if (result !is NativeProductResult.Failure || result.code != ProductFailureCode.OPERATION_TIMED_OUT)
            return result
    }
    return NativeProductResult.Failure(if (cancelled()) ProductFailureCode.CANCELLED else ProductFailureCode.OPERATION_TIMED_OUT)
}

/** One finite operation, with real owners retained until all cleanup returns. */
internal class Task7InstalledCase(private val service: Task7InstalledDriverService,
    val epoch: Long, val sequence: Long, val caseId: Int, val level: Int) {
    private val monitor = Any()
    private val values = LongArray(32) { -1 }.apply {
        this[0] = epoch; this[1] = sequence; this[2] = 1; this[3] = 0; this[4] = caseId.toLong(); this[5] = level.toLong()
        this[6] = SystemClock.elapsedRealtime()
    }
    private val cancelled = AtomicBoolean(false)
    private val cancellationStarted = AtomicBoolean(false)
    private val cancellationFinished = CountDownLatch(1)
    private var cancellationClosed = false
    @Volatile private var stopProven = false
    @Volatile private var owner: RuntimeProductionPlatformOwner? = null
    @Volatile private var session: ProductionNativeSession? = null
    private val native = Task7InstalledFixtureNative()
    private val tunPage = if(caseId in 2..7) task7InstalledTunPageV1(epoch,sequence,1,caseId) else null
    @Volatile private var tun: Task7InstalledTunCase? = null
    private val maintenance = if(caseId in 8..11 || caseId in 301..304) Task7InstalledMaintenanceCase(service,epoch,sequence,caseId,cancelled,level) else null
    private val maintenanceDns = if(caseId in 12..14) Task7InstalledMaintenanceDnsCase(service,epoch,sequence,caseId,cancelled) else null
    fun snapshot(): LongArray = synchronized(monitor) { values.copyOf() }
    fun tunSnapshot(): LongArray = synchronized(monitor) { checkNotNull(tunPage).copyOf().also { it[4]=values[2] } }
    fun maintenanceSnapshot(): LongArray = checkNotNull(maintenance).snapshot(synchronized(monitor){values[2]})
    fun maintenanceDnsSnapshot():LongArray=checkNotNull(maintenanceDns).snapshot(synchronized(monitor){values[2]})
    fun publicationSnapshot(): LongArray {
        fun field(instance: Any, name: String): Any? = instance.javaClass.getDeclaredField(name)
            .apply { isAccessible = true }.get(instance)
        fun scalars(instance: Any): LongArray {
            val values = field(instance, "publicationDiagnostic") as LongArray
            return synchronized(values) { values.copyOf() }
        }
        val retained = owner
        val client = runCatching { scalars(checkNotNull(retained)) }.getOrNull()
        val delegate = runCatching {
            val binding = field(checkNotNull(retained), "production")
            scalars(checkNotNull(field(checkNotNull(binding), "delegate")))
        }.getOrNull()
        return task7InstalledPublicationPageV1(epoch, sequence, synchronized(monitor) { values[2] }, client, delegate)
    }
    private fun record(index: Int, value: Long) = synchronized(monitor) { values[index] = value }
    // Fixed internal diagnostic IDs, not native status values or enum ordinals.
    private fun recordControlFailure(kind: Long, code: ProductFailureCode) {
        val diagnosticCode = when (code) {
            ProductFailureCode.INVALID_INPUT -> 1L
            ProductFailureCode.SIZE_LIMIT -> 2L
            ProductFailureCode.PROFILE_UNTRUSTED -> 3L
            ProductFailureCode.PROFILE_EXPIRED -> 4L
            ProductFailureCode.PROFILE_REVOKED -> 5L
            ProductFailureCode.PROFILE_ROLLBACK -> 6L
            ProductFailureCode.PROFILE_WRONG_DEVICE -> 7L
            ProductFailureCode.PROFILE_INCOMPATIBLE -> 8L
            ProductFailureCode.STORAGE_LOCKED -> 9L
            ProductFailureCode.STORAGE_KEY_INVALIDATED -> 10L
            ProductFailureCode.STORAGE_DEGRADED -> 11L
            ProductFailureCode.MIGRATION_REQUIRED -> 12L
            ProductFailureCode.VPN_CONSENT_REQUIRED -> 13L
            ProductFailureCode.VPN_CONSENT_DENIED -> 14L
            ProductFailureCode.NETWORK_UNAVAILABLE -> 15L
            ProductFailureCode.NETWORK_IDENTITY_UNAVAILABLE -> 16L
            ProductFailureCode.CAPTIVE_PORTAL -> 17L
            ProductFailureCode.NODE_UNREACHABLE -> 18L
            ProductFailureCode.SESSION_AUTHENTICATION_FAILED -> 19L
            ProductFailureCode.NO_PERMITTED_STRATEGY -> 20L
            ProductFailureCode.SOCKET_PROTECTION_FAILED -> 21L
            ProductFailureCode.TUN_ESTABLISH_FAILED -> 22L
            ProductFailureCode.ROUTE_POLICY_REJECTED -> 23L
            ProductFailureCode.DNS_POLICY_REJECTED -> 24L
            ProductFailureCode.DNS_HEALTH_FAILED -> 25L
            ProductFailureCode.APP_POLICY_DRIFT -> 26L
            ProductFailureCode.FOREGROUND_START_BLOCKED -> 27L
            ProductFailureCode.RECONNECT_EXHAUSTED -> 28L
            ProductFailureCode.UPDATE_SIGNATURE_INVALID -> 29L
            ProductFailureCode.UPDATE_ROLLBACK -> 30L
            ProductFailureCode.UPDATE_INCOMPATIBLE -> 31L
            ProductFailureCode.PROXY_BIND_FAILED -> 32L
            ProductFailureCode.PROXY_AUTHENTICATION_FAILED -> 33L
            ProductFailureCode.LOW_MEMORY -> 34L
            ProductFailureCode.THERMAL_LIMIT -> 35L
            ProductFailureCode.CANCELLED -> 36L
            ProductFailureCode.INTERNAL_FAILURE -> 37L
            ProductFailureCode.OPERATION_ALREADY_ACTIVE -> 38L
            ProductFailureCode.OPERATION_INTERRUPTED -> 39L
            ProductFailureCode.RESOURCE_LIMIT -> 40L
            ProductFailureCode.RATE_LIMITED -> 41L
            ProductFailureCode.OPERATION_TIMED_OUT -> 42L
            ProductFailureCode.UPDATE_FETCH_REJECTED -> 43L
        }
        synchronized(monitor) { values[14] = kind; values[31] = diagnosticCode }
    }
    private fun recordProbeResult(kind: Long, result: NativeProbeResult) {
        val path = when (result.path) {
            NativeProbePath.DISCONNECTED_TCP_CONNECT -> 1L
            NativeProbePath.ACTIVE_RELAY_END_TO_END -> 2L
        }
        val completion = when (result.completion) {
            NativeProbeCompletion.COMPLETE -> 1L
            NativeProbeCompletion.TIMED_OUT -> 2L
            NativeProbeCompletion.RATE_LIMITED -> 3L
        }
        // Four bounded 0..10 counters use one nibble each, then two bits per enum.
        val detail = result.attempted.toLong() or (result.succeeded.toLong() shl 4) or
            (result.failed.toLong() shl 8) or (result.unstarted.toLong() shl 12) or
            (path shl 16) or (completion shl 18)
        synchronized(monitor) { values[14] = kind; values[31] = detail }
    }
    private fun recordFailureOrigin(failure: Exception) {
        var origin: Throwable = failure
        repeat(4) { origin.cause?.let { origin = it } }
        for (frame in origin.stackTrace.take(32)) {
            // Exact own-source allowlist, including compiler-generated nested classes.
            // Only a fixed code and bounded numeric line cross the internal Binder.
            val code = when (frame.className.substringBefore('$') + "#" + frame.fileName) {
                "org.kurdistanvpn.runtime.android.RuntimeProductionAuthorityClientV1#RuntimeProductionAuthorityClientV1.kt" -> 1L
                "org.kurdistanvpn.runtime.android.RuntimeProductionCallOwnerV1#RuntimeProductionAuthorityClientV1.kt" -> 2L
                "org.kurdistanvpn.runtime.android.RuntimeProductionBootstrapBorrowV1#RuntimeProductionPlatformOwner.kt" -> 3L
                "org.kurdistanvpn.runtime.android.RuntimeProductionPlatformOwner#RuntimeProductionPlatformOwner.kt" -> 4L
                "org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner#RuntimeAuthorityReissueClient.kt" -> 5L
                "org.kurdistanvpn.runtime.android.RuntimeProductionAuthorityFrameCodecV1#RuntimeProductionAuthorityFrameCodecV1.kt" -> 6L
                "org.kurdistanvpn.runtime.api.RuntimeCaptureSnapshotV1#RuntimeProductionCapture.kt" -> 7L
                "org.kurdistanvpn.runtime.api.RuntimeCaptureCodecV1#RuntimeProductionCapture.kt" -> 8L
                "org.kurdistanvpn.core.nativejni.NativeBridge#NativeBridge.kt" -> 9L
                "org.kurdistanvpn.core.nativejni.AndroidProductionCallbacks#AndroidProductionCallbacks.kt" -> 10L
                "org.kurdistanvpn.runtime.android.RuntimeProductionGuardOwnershipV1#RuntimeProductionPlatformOwner.kt" -> 11L
                "org.kurdistanvpn.runtime.android.RuntimeReissuePipeIo#RuntimeAuthorityReissueClient.kt" -> 12L
                "org.kurdistanvpn.core.nativejni.ProductionNativeSessionV1#ProductionNativeSessionV1.kt" -> 13L
                "org.kurdistanvpn.core.nativejni.ProductionNativeParentV1#ProductionNativeOpenV1.kt" -> 14L
                else -> continue
            }
            record(12, code)
            record(13, if (frame.lineNumber in 1..10_000) frame.lineNumber.toLong() else -1)
            return
        }
    }
    private fun recordInitialRejection() {
        // Fixed own-instance fields only. Missing observation stays zero; never traverse
        // arbitrary objects, expose identifiers, or turn diagnostic failure into success.
        fun field(instance: Any, name: String): Any? = instance.javaClass.getDeclaredField(name)
            .apply { isAccessible = true }.get(instance)
        val retained = owner
        val admission = runCatching {
            val client = field(checkNotNull(retained), "client")
            val calls = field(checkNotNull(client), "calls")
            field(checkNotNull(calls), "firstAdmissionRejection") as Int
        }.getOrDefault(0)
        val callback = runCatching {
            val binding = field(checkNotNull(retained), "production")
            val delegate = field(checkNotNull(binding), "delegate")
            field(checkNotNull(delegate), "firstRevalidationRejection") as Int
        }.getOrDefault(0)
        val nativeFailure = runCatching { native.snapshot().sliceArray(13..15) }.getOrElse { LongArray(3) }
        val socket = runCatching {
            val binding = field(checkNotNull(retained), "production")
            val delegate = field(checkNotNull(binding), "delegate")
            field(checkNotNull(delegate), "firstSocketRejection") as Int
        }.getOrDefault(0)
        synchronized(monitor) {
            val packed = task7PackRejectionV1(values[14], values[31], admission, callback, nativeFailure, socket)
            values[14] = packed[0]; values[31] = packed[1]
        }
    }
    fun requestCancellation(): Boolean = synchronized(monitor) {
        if (cancellationClosed || values[2] != 1L || !cancellationStarted.compareAndSet(false, true)) return false
        cancelled.set(true)
        true
    }
    fun cancel() {
        try {
            maintenance?.let { it.cancel(); return }
            maintenanceDns?.let { it.cancel(); return }
            tun?.let { it.cancel(); return }
            if (owner?.stop(RuntimeStopReason.CANCEL) == RuntimeStartDecision.Idle) stopProven = true
            native.cancel()
        } finally { cancellationFinished.countDown() }
    }
    fun run() {
        var started = false
        var success = false
        var joined = false
        try {
            record(11, 1)
            check(task7InstalledCaseAllowedV1(caseId,level))
            if(maintenance!=null){success=maintenance.run();joined=maintenance.cleanupProven;return}
            if(maintenanceDns!=null){success=maintenanceDns.run();joined=maintenanceDns.cleanupProven;return}
            val connectivity = service.getSystemService(ConnectivityManager::class.java)
            check(connectivity.allNetworks.none { connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true })
            check(!cancelled.get())
            record(11, 2)
            check(native.startRelay(File(service.filesDir, "task7-installed-v1").absolutePath, level) == 0)
            started = true
            record(11, 3)
            val before = native.snapshot(); for (i in 0..8) record(16 + i, before[i])
            check(before[0] == level.toLong() * 1048576 && before[2] == 1L)
            record(11, 4)
            RuntimeProductionPlatformOwner.acquireIfIdle(service, RuntimeAuthorityTrigger.MANUAL, 1,
                onAdmitted = { admitted -> record(11, 5); owner = admitted; if (cancelled.get()) admitted.stop(RuntimeStopReason.CANCEL) }) { admitted ->
                record(11, 6)
                check(!cancelled.get())
                val opened = admitted.openProductionSession()
                if (opened is NativeProductResult.Failure) recordControlFailure(5, opened.code)
                check(opened is NativeProductResult.Success)
                session = opened.value
            }
            record(11, 7)
            val parent = checkNotNull(session)
            val until = values[6] + 40_000
            var routeReady = false
            var routeEvent: NativeControlEvent.RoutePlanReady? = null
            val buffer = ByteBuffer.allocateDirect(32776).apply { position(4); limit(32772) }
            while (!routeReady && SystemClock.elapsedRealtime() < until && !cancelled.get()) {
                record(11, 8)
                val control = try { task7ControlWithinDeadlineV1(until, SystemClock::elapsedRealtime,
                    cancelled::get) { parent.nextControl(buffer) } }
                    catch (failure: Exception) { record(14, 4); throw failure }
                when (val event = control) {
                    is NativeProductResult.Failure -> {
                        recordControlFailure(1, event.code)
                        error("TASK7_CONTROL_REJECTED")
                    }
                    is NativeProductResult.Success -> when (val value = event.value) {
                        is NativeControlEvent.SocketProtectionRequired -> {
                            record(11, 9)
                            // Wait while confirmation is withheld, then sample the actual native listener.
                            SystemClock.sleep(50)
                            check(native.snapshot()[9] == 0L)
                            record(10, 1)
                            record(11, 10)
                            val confirmed = parent.confirmSocketProtection(value.token, true, null)
                            if (confirmed is NativeProductResult.Failure) recordControlFailure(6, confirmed.code)
                            check(confirmed is NativeProductResult.Success)
                        }
                        is NativeControlEvent.RoutePlanReady -> { routeReady = true; routeEvent = value }
                        is NativeControlEvent.Failed -> {
                            recordControlFailure(2, value.code)
                            error("TASK7_AUTHENTICATION_REJECTED")
                        }
                        is NativeControlEvent.Stopped -> {
                            record(14, 3)
                            error("TASK7_PREMATURE_STOP")
                        }
                        else -> Unit
                    }
                }
            }
            record(11, 11)
            check(routeReady && !cancelled.get())
            if(caseId in 2..7) {
                val packets=Task7InstalledTunCase(service,caseId,native,cancelled,monitor,checkNotNull(tunPage),until) { owner=it }
                tun=packets
                packets.run(checkNotNull(owner),parent,checkNotNull(routeEvent))
                success=true
                return
            }
            record(11, 12)
            val delegate = checkNotNull(checkNotNull(owner).selectedSessionProbe())
            record(11, 13)
            val result = delegate.runSelected(Task7InstalledFixturePreparation.selectedProbe())
            if (result is NativeProductResult.Failure) recordControlFailure(7, result.code)
            if (result is NativeProductResult.Success && (result.value.path != NativeProbePath.ACTIVE_RELAY_END_TO_END ||
                    result.value.attempted != 1 || result.value.succeeded != 1 || result.value.failed != 0 ||
                    result.value.unstarted != 0 || result.value.completion != NativeProbeCompletion.COMPLETE))
                recordProbeResult(10, result.value)
            check(result is NativeProductResult.Success && result.value.path == NativeProbePath.ACTIVE_RELAY_END_TO_END)
            check(result.value.attempted == 1 && result.value.succeeded == 1 && result.value.failed == 0 &&
                result.value.unstarted == 0 && result.value.completion == NativeProbeCompletion.COMPLETE)
            record(11, 14)
            check(native.snapshot()[10] > 0)
            record(7, 1)
            record(11, 15)
            check(checkNotNull(owner).stop(RuntimeStopReason.STOP) == RuntimeStartDecision.Idle)
            stopProven = true
            joined = true
            record(11, 16)
            val stale = delegate.runSelected(Task7InstalledFixturePreparation.selectedProbe())
            when (stale) {
                is NativeProductResult.Failure -> recordControlFailure(8, stale.code)
                is NativeProductResult.Success -> recordProbeResult(9, stale.value)
            }
            check(stale is NativeProductResult.Failure)
            record(8, 1)
            success = true
        } catch (failure: Exception) {
            recordFailureOrigin(failure)
            record(3, if (cancelled.get()) 2 else 1)
            // Observation must never alter the original exception/cleanup path.
            runCatching { recordInitialRejection() }
        } finally {
            try {
                if (maintenanceDns != null) {
                    joined=maintenanceDns.cleanupProven
                    if(cancelled.get())record(3,2)
                } else if (maintenance != null) {
                    joined=maintenance.cleanupProven
                    if(cancelled.get())record(3,2)
                } else if (tun != null) {
                    joined=checkNotNull(tun).cleanupProven
                    if(cancelled.get())record(3,2)
                } else if (!joined) {
                    val stopping = owner?.stop(RuntimeStopReason.STOP)
                    if (stopping == RuntimeStartDecision.Idle) stopProven = true
                    joined = stopping == null || stopProven
                }
                // Seal cancellation admission before joining it. A late death/timeout must
                // never run the process-global native cancel after FINISH admits a successor.
                val cancellationPending = synchronized(monitor) {
                    cancellationClosed = true
                    cancellationStarted.get()
                }
                if (cancellationPending) check(cancellationFinished.await(5, TimeUnit.SECONDS))
                if (started && tun == null) {
                    native.cancel()
                    val until = SystemClock.elapsedRealtime() + 5_000
                    while (native.snapshot()[11] != 1L && SystemClock.elapsedRealtime() < until) SystemClock.sleep(10)
                    check(native.snapshot()[11] == 1L)
                    check(joined)
                    check(native.finish() == 0)
                    val after = native.snapshot()
                    check(after[0] == 0L && after[2] == 0L)
                    for (i in 3..8) record(22 + i, after[i])
                }
                record(9, if (joined) 1 else 0)
            } catch (_: Exception) { joined = false; record(9, 0); record(3, 3) }
            record(15, SystemClock.elapsedRealtime())
            record(2, if (success && joined && !cancelled.get()) 2 else 3)
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
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
    @Test fun debugInvariantProbeUsesRequiredBarriersWithoutClaimingExternalActive() {
        val result = LiveTunnelInvariantProbe.exercise(protectSucceeds = true)
        assertTrue(result.runningBeforeStop)
        assertFalse(result.runningAfterStop)
        assertEquals(null, result.failure)
        for (event in listOf("model:PRE_TUN", "model:NOTIFICATION_READY", "model:HEALTH_READY",
                "model:PRE_ACTIVE", "model:NATIVE_READY", "model:NOTIFICATION_CLOSED", "model:HEALTH_CLOSED")) {
            assertEquals(event, 1, result.events.count { it == event })
        }
        assertTrue(result.events.indexOf("model:PRE_TUN") < result.events.indexOf("establish"))
        assertTrue(result.events.indexOf("model:HEALTH_READY") < result.events.indexOf("model:PRE_ACTIVE"))
        assertFalse(result.events.contains("stage:RUNNING"))
        val rejected = LiveTunnelInvariantProbe.exercise(protectSucceeds = false)
        assertEquals(LiveTunnelFailure.SOCKET_PROTECT_FAILED, rejected.failure)
        assertFalse(rejected.events.contains("establish"))
        assertFalse(rejected.events.contains("model:NATIVE_READY"))
    }

    @Test fun platformTunReturnedResourceIsOwnedBeforeValidationOrWrapperTransfer() {
        for (point in listOf("valid", "validate", "close", "detach", "negative")) {
            var acquisitions = 0
            var closes = 0
            val resource = AutoCloseable { closes++; check(point != "close") }
            val owner = PlatformTunOwner(acquire = { acquisitions++; resource },
                validate = { check(point != "validate") },
                detach = { check(point != "detach"); if (point == "negative") -1 else 71 })
            if (point == "validate") {
                assertThrows(IllegalStateException::class.java) { owner.establish() }
            } else {
                assertTrue(owner.establish() === owner)
                if (point == "detach" || point == "negative")
                    assertThrows(IllegalStateException::class.java) { owner.detachFileDescriptor() }
                else assertEquals(71, owner.detachFileDescriptor())
                if (point == "valid") { owner.close(); owner.close() }
                else {
                    assertThrows(IllegalStateException::class.java) { owner.close() }
                    assertThrows(IllegalStateException::class.java) { owner.close() }
                }
            }
            assertEquals(point, 1, acquisitions)
            assertEquals(point, 1, closes)
            assertThrows(IllegalStateException::class.java) { owner.establish() }
        }
    }

    @Test fun nullOrThrowingFrameworkEstablishmentCannotInventAnOwnedDescriptor() {
        val absent = PlatformTunOwner<AutoCloseable>({ null }, {}, { error("no resource") })
        assertEquals(null, absent.establish())
        absent.close(); absent.close()
        val unknown = PlatformTunOwner<AutoCloseable>({ error("framework acquisition threw") }, {}, { error("no resource") })
        assertThrows(IllegalStateException::class.java) { unknown.establish() }
        assertThrows(IllegalStateException::class.java) { unknown.close() }
        assertThrows(IllegalStateException::class.java) { unknown.establish() }
    }

    @Test fun nativeOpenValidatesFullWidthLengthBeforeNarrowingAndWipesTemporaryBytes() {
        for (length in listOf(Long.MIN_VALUE, -1L, 0L, 9L, Int.MAX_VALUE.toLong() + 1, Long.MAX_VALUE)) {
            var retired = 0
            var decoded = 0
            lateinit var output: java.nio.ByteBuffer
            val result = openBoundary(8, { buffer, metadata ->
                output = buffer; buffer.put(0, 77); metadata[0] = 7; metadata[1] = length; 0
            }, { retired++; NativeResult.Success(Unit) }, { decoded++; NativeResult.Success(snapshot()) })
            assertTrue("length $length", result is NativeResult.Failure)
            assertEquals(1, retired); assertEquals(0, decoded)
            assertTrue((0 until output.capacity()).all { output.get(it) == 0.toByte() })
        }
        for (length in listOf(1L, 8L)) {
            var decodedLength = 0
            val result = openBoundary(8, { buffer, metadata ->
                buffer.put(0, 77); metadata[0] = 7; metadata[1] = length; 0
            }, { error("transferred handle must not be retired") }, { bytes ->
                decodedLength = bytes.size; NativeResult.Success(snapshot())
            })
            assertTrue(result is NativeResult.Success); assertEquals(length.toInt(), decodedLength)
        }
    }

    @Test fun nativeOpenOwnsHandleAcrossDecodeConstructionAndNativeExceptions() {
        for (point in listOf("native", "decode", "construct")) {
            var retired = 0
            var material: ByteArray? = null
            val result = openBoundary(8, { _, metadata ->
                metadata[0] = 7; metadata[1] = 1
                if (point == "native") error("partial native publication")
                0
            }, { retired++; NativeResult.Success(Unit) }, { bytes ->
                material = bytes
                if (point == "decode") error("decode failure")
                NativeResult.Success(snapshot())
            }, { _, value ->
                if (point == "construct") error("partial construction")
                FakeLiveSession(mutableListOf())
            })
            assertTrue(point, result is NativeResult.Failure); assertEquals(point, 1, retired)
            assertTrue(material?.all { it == 0.toByte() } ?: true)
        }
    }

    @Test fun nativeOpenCleanupFailureCannotBecomeAnOrdinaryCleanFailure() {
        var retired = 0
        val failure = assertThrows(java.lang.reflect.InvocationTargetException::class.java) {
            openBoundary(8, { _, metadata -> metadata[0] = 7; metadata[1] = 99; 0 },
                { retired++; NativeResult.Failure(OperationError.TUN_IO_FAILED) },
                { error("invalid native length cannot decode") })
        }
        assertEquals("NATIVE_OPEN_CLEANUP_UNPROVEN", failure.cause?.message)
        assertEquals(1, retired)
    }

    @Test fun nativeStopRetiresItsHandleAndKotlinDoesNotFreeItAgain() {
        var calls = 0
        val type = Class.forName("org.kurdistanvpn.core.nativejni.NativeLiveSessionRelease")
        val constructor = type.declaredConstructors.single { it.parameterCount == 1 }.apply { isAccessible = true }
        val owner = constructor.newInstance({ calls++; NativeResult.Success(Unit) })
        val stop = type.getDeclaredMethod("stop").apply { isAccessible = true }
        val close = type.getDeclaredMethod("close").apply { isAccessible = true }
        assertTrue(stop.invoke(owner) is NativeResult.Success<*>)
        assertTrue(stop.invoke(owner) is NativeResult.Success<*>)
        close.invoke(owner); close.invoke(owner)
        assertEquals(1, calls)
    }

    @Test fun retiredNativeHandleKeepsCleanupFailureWithoutRetryOrSuccess() {
        var calls = 0
        val type = Class.forName("org.kurdistanvpn.core.nativejni.NativeLiveSessionRelease")
        val constructor = type.declaredConstructors.single { it.parameterCount == 1 }.apply { isAccessible = true }
        val owner = constructor.newInstance({ calls++; NativeResult.Failure(OperationError.TUN_IO_FAILED) })
        val stop = type.getDeclaredMethod("stop").apply { isAccessible = true }
        val close = type.getDeclaredMethod("close").apply { isAccessible = true }
        assertEquals(NativeResult.Failure(OperationError.TUN_IO_FAILED), stop.invoke(owner))
        repeat(2) { assertThrows(java.lang.reflect.InvocationTargetException::class.java) { close.invoke(owner) } }
        assertEquals(1, calls)
    }

    @Test fun registrationFailureAfterEachAcquisitionStillClosesTheFallbackOwnerExactlyOnce() {
        for (failureAt in 1..5) for (afterInsertion in listOf(false, true)) {
            val events = mutableListOf<String>()
            val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
                TunEstablisher { object : DetachableTun {
                    override fun detachFileDescriptor() = 71
                    override fun close() { events += "close-wrapper" }
                } }, DetachedFileDescriptorCloser { events += "close-detached" },
                prepareRequiredActivationResources = { scope ->
                    scope.notification(AutoCloseable { events += "close-notification" })
                    scope.healthMonitor(AutoCloseable { events += "close-health" })
                })
            var registrations = 0
            replaceOwners(controller, object : java.util.ArrayList<Any>() {
                override fun add(element: Any): Boolean {
                    registrations++
                    if (registrations == failureAt) {
                        if (afterInsertion) super.add(element)
                        error("synthetic owner registration failure")
                    }
                    return super.add(element)
                }
            })
            val result = controller.start(FakeLiveSession(events))
            assertEquals("registration $failureAt", LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE), result)
            controller.close()
            assertEquals("registration $failureAt", 1, events.count { it == "stop" })
            assertEquals("registration $failureAt", 1, events.count { it == "close" })
            if (failureAt >= 2) assertEquals(1, events.count { it == "close-wrapper" })
            if (failureAt >= 3) assertEquals(1, events.count { it == "close-detached" })
            if (failureAt >= 4) assertEquals(1, events.count { it == "close-notification" })
            if (failureAt >= 5) assertEquals(1, events.count { it == "close-health" })
            assertFalse(controller.isRunning())
        }
    }

    @Test fun failedRegistrationAndFallbackCloseRemainUnprovenWithoutRetryingNativeCleanup() {
        val events = mutableListOf<String>()
        var closes = 0
        val base = FakeLiveSession(events)
        val session = object : NativeLiveRuntimeSession by base {
            override fun close() { closes++; error("synthetic ambiguous free") }
        }
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { error("not reached") }, DetachedFileDescriptorCloser {})
        replaceOwners(controller, object : java.util.ArrayList<Any>() {
            override fun add(element: Any): Boolean = error("synthetic registration allocation failure")
        })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE,
            org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN), controller.start(session))
        controller.close()
        controller.close()
        assertEquals(1, closes)
        assertEquals(1, events.count { it == "stop" })
        assertFalse(controller.isRunning())
    }

    @Test fun runningIsReturnedOnlyAndNeverSentToAFallibleStageObserver() {
        val events = mutableListOf<String>()
        lateinit var controller: NativeTunnelController
        controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {}, onStage = {
                events += "stage:${it.name}"
                assertFalse("no observer callback may publish an uncommitted RUNNING", it == LiveTunnelStage.RUNNING)
                assertFalse(controller.isRunning())
            })
        assertEquals(LiveTunnelStartResult.Running(), controller.start(FakeLiveSession(events)))
        assertFalse(events.contains("stage:RUNNING"))
        assertTrue(controller.isRunning())
        controller.close()
    }

    @Test fun snapshotCopiesArraysBeforeConsultingCallerOwnedCollections() {
        val events = mutableListOf<String>()
        val base = FakeLiveSession(events)
        val supplied = snapshot()
        val mutatingPackages = object : AbstractList<String>() {
            override val size: Int get() { supplied.clientIpv4.fill(0); return 0 }
            override fun get(index: Int): String = error("empty")
        }
        val session = object : NativeLiveRuntimeSession by base {
            override val snapshot = supplied.copy(packages = mutatingPackages)
        }
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { configuration ->
                assertEquals("10.77.0.2", configuration.addresses.single().address)
                FakeTun(events)
            }, DetachedFileDescriptorCloser {})
        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        assertTrue(supplied.clientIpv4.all { it == 0.toByte() })
        assertTrue(supplied.planDigest.all { it == 1.toByte() })
        controller.close()
    }

    @Test fun throwingEstablishmentCannotClaimCleanupOfAnUnreturnedResource() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { error("synthetic throw after possible internal TUN acquisition") },
            DetachedFileDescriptorCloser { error("no descriptor was returned") })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.TUN_ESTABLISH_FAILED,
            org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN), controller.start(FakeLiveSession(events)))
        assertEquals(1, events.count { it == "stop" })
        assertEquals(1, events.count { it == "close" })
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN, controller.stopResult())
    }

    @Test fun hiddenPartialActivationResourceCannotBeCertifiedCleanOrActive() {
        val events = mutableListOf<String>()
        var hidden: AutoCloseable? = null
        var hiddenCloses = 0
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {},
            prepareRequiredActivationResources = { scope ->
                scope.notification(AutoCloseable { events += "close-notification" })
                hidden = AutoCloseable { hiddenCloses++ }
                error("synthetic partial health construction before ownership transfer")
            })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE,
            org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN), controller.start(FakeLiveSession(events)))
        assertEquals(1, events.count { it == "close-notification" })
        assertEquals(1, events.count { it == "close" })
        assertEquals(0, hiddenCloses)
        assertFalse(controller.isRunning())
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN, controller.stopResult())
        assertEquals(0, hiddenCloses)
        // The test creator still owns this synthetic object; the controller never received it.
        requireNotNull(hidden).close()
        assertEquals(1, hiddenCloses)
    }

    @Test fun rejectedSessionResubmissionCannotStopOrCloseTheSameOwnerAgain() {
        val events = mutableListOf<String>()
        val rejectedEvents = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertEquals(LiveTunnelStartResult.Running(), controller.start(FakeLiveSession(events)))
        val rejected = FakeLiveSession(rejectedEvents)
        repeat(2) { assertTrue(controller.start(rejected) is LiveTunnelStartResult.Failure) }
        assertEquals(1, rejectedEvents.count { it == "stop" })
        assertEquals(1, rejectedEvents.count { it == "close" })
        controller.stop()
        assertEquals(1, events.count { it == "close" })
    }

    @Test fun cleanupDoesNotRequireAnAllocatingIteratorOrCopiedOwnerCollection() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertEquals(LiveTunnelStartResult.Running(), controller.start(FakeLiveSession(events)))
        val original = currentOwners(controller)
        replaceOwners(controller, object : AbstractMutableList<Any>() {
            override val size get() = original.size
            override fun get(index: Int) = original[index]
            override fun add(index: Int, element: Any) = error("no growth during cleanup")
            override fun removeAt(index: Int): Any = error("no removal during cleanup")
            override fun set(index: Int, element: Any): Any = error("no replacement during cleanup")
            override fun iterator(): MutableIterator<Any> = error("synthetic allocation failure")
            override fun listIterator(index: Int): MutableListIterator<Any> = error("synthetic allocation failure")
        })
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.CLEAN, controller.stopResult())
        assertEquals(1, events.count { it == "close" })
        assertEquals(1, events.count { it == "stop" })
    }

    @Test fun finalValidationExceptionAndReentrantStopNeverReturnOrPublishRunning() {
        for (stop in listOf(false, true)) {
            val events = mutableListOf<String>()
            lateinit var controller: NativeTunnelController
            controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
                TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser { events += "close-detached" },
                onStage = { events += "stage:${it.name}" },
                prepareRequiredActivationResources = { scope ->
                    scope.notification(AutoCloseable { events += "close-notification" })
                    scope.healthMonitor(AutoCloseable { events += "close-health" })
                }, finalPublicationCheck = {
                    assertFalse(controller.isRunning())
                    if (stop) { controller.stop(); true } else error("synthetic final validation failure")
                })
            assertEquals(LiveTunnelStartResult.Failure(if (stop) LiveTunnelFailure.CANCELLED else LiveTunnelFailure.INTERNAL_FAILURE),
                controller.start(FakeLiveSession(events)))
            assertFalse(events.contains("stage:RUNNING"))
            assertEquals(1, events.count { it == "close" })
            assertEquals(1, events.count { it == "close-detached" })
            assertEquals(1, events.count { it == "close-notification" })
            assertEquals(1, events.count { it == "close-health" })
            assertFalse(controller.isRunning())
        }
    }

    @Test fun duplicateCleanupUncertaintyTerminatesTheExistingSessionAndRemainsVisible() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true }, TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertTrue(controller.start(FakeLiveSession(events)) is LiveTunnelStartResult.Running)
        val rejected = object : NativeLiveRuntimeSession by FakeLiveSession(mutableListOf()) {
            override fun close() = error("ambiguous native free")
        }
        val result = controller.start(rejected) as LiveTunnelStartResult.Failure
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN, result.cleanup)
        assertEquals(LiveTunnelFailure.RECOVERY_REQUIRED, controller.checkHealth())
        assertFalse(controller.isRunning())
        assertEquals(1, events.count { it == "close" })
    }

    @Test fun concurrentStopBecomesVisibleBeforeBlockedNativePreparationReturns() {
        val events = mutableListOf<String>()
        val entered = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        val base = FakeLiveSession(events)
        val session = object : NativeLiveRuntimeSession by base {
            override fun prepareSocket(): NativeResult<Int> {
                entered.countDown()
                check(resume.await(5, java.util.concurrent.TimeUnit.SECONDS))
                return base.prepareSocket()
            }
        }
        val controller = permittedController(SocketProtector { events += "protect"; true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        val result = java.util.concurrent.atomic.AtomicReference<LiveTunnelStartResult>()
        val starter = Thread { result.set(controller.start(session)) }.apply { isDaemon = true; start() }
        assertTrue(entered.await(3, java.util.concurrent.TimeUnit.SECONDS))
        val stopper = Thread { controller.stopResult() }.apply { isDaemon = true; start() }
        try {
            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(3)
            while (stopper.state != Thread.State.BLOCKED && System.nanoTime() < deadline) Thread.yield()
            assertEquals(Thread.State.BLOCKED, stopper.state)
        } finally { resume.countDown() }
        starter.join(3000); stopper.join(3000)
        assertFalse(starter.isAlive); assertFalse(stopper.isAlive)
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.CANCELLED), result.get())
        assertFalse(events.contains("protect"))
        assertEquals(1, events.count { it == "close" })
    }
    @Test fun everyStageFailureClosesAllPreviouslyAcquiredResources() {
        // RUNNING is now solely a result after the final barrier. Its former fallible
        // observer case is covered by finalValidationExceptionAndReentrantStop... above.
        for (point in LiveTunnelStage.entries.filter { it != LiveTunnelStage.STOPPED && it != LiveTunnelStage.RUNNING }) {
            val events = mutableListOf<String>()
            val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
                TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser { events += "close-detached" },
                onStage = { if (it == point) error("stage failure") })
            assertEquals(point.name, LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE), controller.start(FakeLiveSession(events)))
            controller.close()
            assertEquals(point.name, 1, events.count { it == "close" })
            if (point == LiveTunnelStage.TUN_ESTABLISHED) assertEquals(1, events.count { it == "close-detached" })
            assertFalse(controller.isRunning())
        }
    }

    @Test fun explicitNativeStopIsNotRetriedByCloseAndFreeCannotReenterAnInflightStop() {
        var stops = 0
        lateinit var release: AutoCloseable
        release = nativeRelease({
            stops++
            assertThrows(IllegalStateException::class.java) { release.close() }
            NativeResult.Success(Unit)
        })
        val stop = release.javaClass.getDeclaredMethod("stop").apply { isAccessible = true }
        assertEquals(NativeResult.Success(Unit), stop.invoke(release))
        release.close(); release.close()
        assertEquals(1, stops)
    }
    @Test fun diagnosticsExceptionIsTerminalAndVisibleToHealthChecks() {
        val events = mutableListOf<String>()
        val base = FakeLiveSession(events)
        val session = object : NativeLiveRuntimeSession by base {
            override fun diagnostics(): NativeResult<NativeLiveRuntimeDiagnostics> = error("diagnostics callback failed")
        }
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true }, TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertTrue(controller.start(session) is LiveTunnelStartResult.Running)
        assertEquals(NativeResult.Failure(OperationError.INTERNAL_FAILURE), controller.diagnostics())
        assertEquals(LiveTunnelFailure.INTERNAL_FAILURE, controller.checkHealth())
        assertEquals(1, events.count { it == "close" })
        assertFalse(controller.isRunning())
    }

    @Test fun stopAndCloseUncertaintyIsRetainedWithoutRetryingEitherOperation() {
        val events = mutableListOf<String>()
        val base = FakeLiveSession(events)
        var stops = 0; var closes = 0
        val session = object : NativeLiveRuntimeSession by base {
            override fun stop(): NativeResult<Unit> { stops++; return NativeResult.Failure(OperationError.INTERNAL_FAILURE) }
            override fun close() { closes++; error("EINTR") }
        }
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true }, TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertTrue(controller.start(session) is LiveTunnelStartResult.Running)
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN, controller.stopResult())
        assertEquals(org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN, controller.stopResult())
        assertEquals(1, stops); assertEquals(1, closes)
        assertFalse(controller.isRunning())
    }
    @Test fun requiredActivationResourcesAreOwnedBeforeFinalCheckAndClosedOnRejection() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {},
            prepareRequiredActivationResources = { scope ->
                events += "notification"; scope.notification(AutoCloseable { events += "close-notification" })
                events += "health"; scope.healthMonitor(AutoCloseable { events += "close-health" })
            }, finalPublicationCheck = { events += "final-check"; false })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.AUTHORITY_REJECTED), controller.start(FakeLiveSession(events)))
        assertTrue(events.indexOf("health") < events.indexOf("final-check"))
        assertEquals(listOf("close-health", "close-notification", "stop", "close"), events.takeLast(4))
        assertFalse(controller.isRunning())
    }

    @Test fun partialRequiredResourceAcquisitionCleansTheAlreadyTransferredOwner() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {},
            prepareRequiredActivationResources = { scope -> scope.notification(AutoCloseable { events += "close-notification" }); error("health setup failed") },
            finalPublicationCheck = { error("must not validate incomplete resources") })
        // Known transferred resources close once, but the throwing callback cannot prove
        // that its unreturned partial health construction acquired no hidden resource.
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE,
            org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN), controller.start(FakeLiveSession(events)))
        assertEquals(1, events.count { it == "close-notification" })
        controller.close()
        assertEquals(1, events.count { it == "close-notification" })
    }

    @Test fun missingActivationOwnerNeverPublishesRunning() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {}, prepareRequiredActivationResources = {},
            finalPublicationCheck = { error("must not validate incomplete owners") })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.AUTHORITY_REJECTED), controller.start(FakeLiveSession(events)))
    }

    @Test fun everyNativeCallExceptionCleansOwnershipWithoutEscaping() {
        for (point in listOf("snapshot", "prepare", "commit", "status", "attach")) {
            val events = mutableListOf<String>()
            val base = FakeLiveSession(events)
            val session = object : NativeLiveRuntimeSession by base {
                override val snapshot: NativeLiveRuntimeSessionSnapshot get() = if (point == "snapshot") error(point) else base.snapshot
                override fun prepareSocket(): NativeResult<Int> = if (point == "prepare") error(point) else base.prepareSocket()
                override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> = if (point == "commit") error(point) else base.commitProtected(protectedSocket)
                override fun status(): NativeResult<NativeRuntimeState> = if (point == "status") error(point) else base.status()
                override fun attachTun(fileDescriptor: Int): NativeResult<Unit> = if (point == "attach") error(point) else base.attachTun(fileDescriptor)
            }
            val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
                TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser { events += "detached-close" })
            assertTrue(point, controller.start(session) is LiveTunnelStartResult.Failure)
            controller.stop()
            assertEquals(point, 1, events.count { it == "close" })
            assertFalse(controller.isRunning())
            if (point == "attach") assertEquals(1, events.count { it == "detached-close" })
        }
    }

    @Test fun nativeStopAndFreeFailuresAreStickyAndNeverRetried() {
        // RuntimeStop now includes registry retirement and every native free. Its
        // terminal error is the sole cleanup result; a second free must never run.
        var stops = 0
        val release = nativeRelease(
            { stops++; NativeResult.Failure(OperationError.INTERNAL_FAILURE) },
        )
        assertThrows(IllegalStateException::class.java) { release.close() }
        assertThrows(IllegalStateException::class.java) { release.close() }
        assertEquals(1, stops)
        var throwingStops = 0
        val failed = nativeRelease({ throwingStops++; error("EINTR") })
        assertThrows(IllegalStateException::class.java) { failed.close() }
        assertThrows(IllegalStateException::class.java) { failed.close() }
        assertEquals(1, throwingStops)
    }

    @Test fun stoppedStageReentrancyDoesNotRepeatNotificationOrClose() {
        val events = mutableListOf<String>()
        var stoppedCallbacks = 0
        lateinit var controller: NativeTunnelController
        controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {}, onStage = {
                if (it == LiveTunnelStage.TUN_ESTABLISHED) controller.stop()
                if (it == LiveTunnelStage.STOPPED) { stoppedCallbacks++; if (stoppedCallbacks < 3) controller.stop() }
            })
        assertTrue(controller.start(FakeLiveSession(events)) is LiveTunnelStartResult.Failure)
        assertEquals(1, stoppedCallbacks)
        assertEquals(1, events.count { it == "close" })
    }
    @Test fun unwiredPreTunValidationNeverEstablishesATun() {
        val events = mutableListOf<String>()
        var established = 0
        val controller = NativeTunnelController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { established++; FakeTun(events) }, DetachedFileDescriptorCloser {})
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.AUTHORITY_REJECTED), controller.start(FakeLiveSession(events)))
        assertEquals(0, established)
        assertEquals(1, events.count { it == "close" })
    }

    @Test fun detachedDescriptorCloseFailureIsNotReportedAsRunning() {
        val events = mutableListOf<String>()
        var closes = 0
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser { closes++; error("EINTR") })
        assertTrue(controller.start(FakeLiveSession(events)) is LiveTunnelStartResult.Failure)
        assertFalse(controller.isRunning())
        controller.stop()
        assertEquals(1, closes)
        assertEquals(1, events.count { it == "close" })
    }

    @Test fun cancellationDuringStageCallbackWinsBeforeTunAttachment() {
        val events = mutableListOf<String>()
        lateinit var controller: NativeTunnelController
        controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser { events += "closed:$it" },
            onStage = { if (it == LiveTunnelStage.TUN_ESTABLISHED) controller.stop() })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.CANCELLED), controller.start(FakeLiveSession(events)))
        assertFalse(events.any { it.startsWith("attach:") })
        assertEquals(1, events.count { it == "close" })
        assertEquals(1, events.count { it == "closed:71" })
    }

    @Test fun nativeSnapshotIsCapturedBeforeAnyExternalCallback() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { config -> assertEquals("10.77.0.2", config.addresses.single().address); FakeTun(events) },
            DetachedFileDescriptorCloser {}, onStage = { if (it == LiveTunnelStage.VERIFIED) session.snapshot.clientIpv4.fill(0) })
        assertEquals(LiveTunnelStartResult.Running(), controller.start(session))
        controller.stop()
    }
    @Test fun stageCallbackExceptionStillClosesTheSessionOwnedFromEntry() {
        val events = mutableListOf<String>()
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { FakeTun(events) }, DetachedFileDescriptorCloser {}, onStage = { error("callback failure") })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.INTERNAL_FAILURE), controller.start(FakeLiveSession(events)))
        assertEquals(1, events.count { it == "close" })
        assertFalse(controller.isRunning())
    }

    @Test fun detachExceptionClosesWrapperExactlyOnceAndNeverAttaches() {
        val events = mutableListOf<String>()
        var wrapperCloses = 0
        val controller = permittedController(SocketProtector { true }, SocketNetworkBinder { true },
            TunEstablisher { object : DetachableTun {
                override fun detachFileDescriptor(): Int = error("detach failure")
                override fun close() { wrapperCloses++ }
            } }, DetachedFileDescriptorCloser { error("no detached descriptor") })
        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.TUN_ESTABLISH_FAILED, org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.UNPROVEN), controller.start(FakeLiveSession(events)))
        assertEquals(1, wrapperCloses)
        assertEquals(1, events.count { it == "close" })
        assertFalse(events.any { it.startsWith("attach:") })
    }
    @Test
    fun exactOrderProtectsBeforeConnectAndPublishesRunningOnlyAfterTunAttachment() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = permittedController(
            protector = SocketProtector { events += "protect"; true },
            networkBinder = SocketNetworkBinder { events += "bind"; true },
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
                "stage:SOCKET_PROTECTED", "bind", "connect", "tls", "kurd", "status:KURD_AUTHENTICATED",
                "stage:AUTHENTICATED", "builder", "establish", "detach",
                "stage:TUN_ESTABLISHED", "attach:71", "close-detached:71",
                "status:RUNNING",
            ),
            events,
        )
        assertFalse(events.contains("stage:RUNNING"))
        assertTrue(controller.isRunning())
        controller.stop()
        assertFalse(controller.isRunning())
    }

    @Test
    fun diagnosticsReturnsOnlyTheActiveNativeSessionAggregateSnapshot() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = permittedController(
            protector = SocketProtector { true },
            networkBinder = SocketNetworkBinder { true },
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
        val controller = permittedController(
            SocketProtector { events += "protect"; false },
            SocketNetworkBinder { error("must not bind") },
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
    fun underlyingNetworkBindFailureFailsClosedBeforeNativeConnect() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events)
        val controller = permittedController(
            protector = SocketProtector { events += "protect:$it"; true },
            networkBinder = SocketNetworkBinder { events += "bind:$it"; false },
            tunEstablisher = TunEstablisher { error("must not establish") },
            detachedCloser = DetachedFileDescriptorCloser {},
        )

        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.SOCKET_BIND_FAILED),
            controller.start(session),
        )
        assertEquals(listOf("prepare", "protect:37", "bind:37", "commit-false", "stop", "close"), events)
        assertFalse(events.contains("connect"))
    }

    @Test
    fun endpointFailureReturnsForFreshAuthorityInsteadOfReusingArmedSession() {
        val events = mutableListOf<String>()
        val session = FallbackLiveSession(events, listOf(OperationError.ENDPOINT_UNAVAILABLE, null))
        val controller = permittedController(
            SocketProtector { events += "protect:$it"; true },
            SocketNetworkBinder { events += "bind:$it"; true },
            TunEstablisher { FakeTun(events) },
            DetachedFileDescriptorCloser {},
        )

        assertEquals(LiveTunnelStartResult.Failure(LiveTunnelFailure.ENDPOINT_UNAVAILABLE), controller.start(session))
        assertEquals(1, events.count { it.startsWith("prepare:") })
        assertEquals(listOf("protect:40"), events.filter { it.startsWith("protect:") })
        assertEquals(listOf("bind:40"), events.filter { it.startsWith("bind:") })
        assertEquals(1, events.count { it == "connect" })
        assertEquals(0, events.count { it == "tls" })
        assertEquals(0, events.count { it == "kurd" })
    }

    @Test
    fun exhaustedEndpointFallbackFailsClosedWithoutTun() {
        val events = mutableListOf<String>()
        val session = FallbackLiveSession(events, listOf(OperationError.FALLBACK_EXHAUSTED))
        val controller = permittedController(
            SocketProtector { events += "protect:$it"; true },
            SocketNetworkBinder { true },
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
            val controller = permittedController(
                SocketProtector { true },
                SocketNetworkBinder { true },
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
            val controller = permittedController(
                SocketProtector { true },
                SocketNetworkBinder { true },
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
        val controller = permittedController(
            SocketProtector { true },
            SocketNetworkBinder { true },
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
        val controller = permittedController(
            SocketProtector { true },
            SocketNetworkBinder { true },
            TunEstablisher { null },
            DetachedFileDescriptorCloser {},
        )
        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.TUN_ESTABLISH_FAILED),
            controller.start(FakeLiveSession(firstEvents)),
        )
        assertFalse(controller.isRunning())

        val runningEvents = mutableListOf<String>()
        val running = permittedController(
            SocketProtector { true },
            SocketNetworkBinder { true },
            TunEstablisher { FakeTun(runningEvents) },
            DetachedFileDescriptorCloser {},
        )
        assertEquals(LiveTunnelStartResult.Running(), running.start(FakeLiveSession(runningEvents)))
        val duplicateEvents = mutableListOf<String>()
        assertEquals(
            LiveTunnelStartResult.Failure(LiveTunnelFailure.DUPLICATE_START, org.kurdistanvpn.runtime.api.LiveTunnelCleanupState.CLEANUP_REQUIRED),
            running.start(FakeLiveSession(duplicateEvents)),
        )
        assertTrue(duplicateEvents.contains("close"))
        running.close()
    }

    @Test
    fun attachFailureClosesDetachedDescriptorAndNeverPublishesRunning() {
        val events = mutableListOf<String>()
        val session = FakeLiveSession(events, failAttach = true)
        val controller = permittedController(
            SocketProtector { true },
            SocketNetworkBinder { true },
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

@Suppress("UNCHECKED_CAST")
private fun currentOwners(controller: NativeTunnelController): MutableList<Any> =
    controller.javaClass.getDeclaredField("owners").apply { isAccessible = true }.get(controller) as MutableList<Any>

private fun replaceOwners(controller: NativeTunnelController, replacement: MutableList<Any>) {
    controller.javaClass.getDeclaredField("owners").apply { isAccessible = true }.set(controller, replacement)
}

private fun nativeRelease(stop: () -> NativeResult<Unit>): AutoCloseable {
    // Exercise the private production close owner without loading/executing a native library.
    val type = Class.forName("org.kurdistanvpn.core.nativejni.NativeLiveSessionRelease")
    val constructor = type.declaredConstructors.single().apply { isAccessible = true }
    return constructor.newInstance(stop) as AutoCloseable
}

@Suppress("UNCHECKED_CAST")
private fun openBoundary(maximum: Int,
    open: (java.nio.ByteBuffer, LongArray) -> Int,
    retire: (Long) -> NativeResult<Unit>,
    decode: (ByteArray) -> NativeResult<NativeLiveRuntimeSessionSnapshot>,
    construct: (Long, NativeLiveRuntimeSessionSnapshot) -> NativeLiveRuntimeSession = { _, _ -> FakeLiveSession(mutableListOf()) },
): NativeResult<NativeLiveRuntimeSession> {
    val type = Class.forName("org.kurdistanvpn.core.nativejni.NativeLiveOpenOwner")
    val constructor = type.declaredConstructors.single().apply { isAccessible = true }
    val owner = constructor.newInstance(maximum, open, retire, decode, construct,
        { _: Int -> OperationError.INTERNAL_FAILURE })
    return type.getDeclaredMethod("open").apply { isAccessible = true }.invoke(owner) as NativeResult<NativeLiveRuntimeSession>
}

private fun permittedController(
    protector: SocketProtector, networkBinder: SocketNetworkBinder, tunEstablisher: TunEstablisher,
    detachedCloser: DetachedFileDescriptorCloser, onStage: (LiveTunnelStage) -> Unit = {},
    preTunValidation: () -> Boolean = { true },
    prepareRequiredActivationResources: (ActivationResourceRegistrar) -> Unit = {
        it.notification(AutoCloseable {}); it.healthMonitor(AutoCloseable {})
    },
    finalPublicationCheck: () -> Boolean = { true },
) = NativeTunnelController(protector, networkBinder, tunEstablisher, detachedCloser, onStage,
    preTunValidation, prepareRequiredActivationResources, finalPublicationCheck)

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
    rejectedTunPacketCode = 4,
)

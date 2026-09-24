// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.*

class RuntimeProductionPlatformOwnerTest {
    @Test fun explicitStopWinsOverANetworkFailureDuringAcquisition() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.acceptProductionAuthority(admission.token, 1))
        val failure = assertThrows(Exception::class.java) {
            runProductionAcquisitionV1(coordinator, admission, {}, {
                coordinator.stop(RuntimeStopReason.STOP)
                throw RuntimeProductionNetworkUnavailableV1()
            })
        }
        assertFalse("Network result must not replace the explicit stop outcome", failure is RuntimeProductionNetworkOutcomeV1)
        assertNull(coordinator.currentToken())
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
    }
    @Test fun exhaustedNetworkAcquisitionReturnsItsTerminalDecisionToTheService() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.acceptProductionAuthority(admission.token, 0))
        val failure = assertThrows(Exception::class.java) {
            runProductionAcquisitionV1(coordinator, admission, {}, { throw RuntimeProductionNetworkUnavailableV1() })
        }
        assertTrue("Terminal reconnect reason was lost", failure is RuntimeProductionNetworkOutcomeV1)
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED),
            (failure as RuntimeProductionNetworkOutcomeV1).decision)
        assertNull(coordinator.currentToken())
    }
    @Test fun transientNetworkAcquisitionRetriesOnlyAfterProvenCleanupWithinSignedBudget() {
        for (clean in listOf(true, false)) {
            var id = 1
            val coordinator = RuntimeStartCoordinator("1".repeat(32)) { (++id).toString().repeat(32) }
            val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
            assertTrue(coordinator.acceptProductionAuthority(admission.token, 1))
            admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable {
                if (!clean) throw java.io.IOException("retirement not proven")
            })
            val failure = assertThrows(Exception::class.java) {
                runProductionAcquisitionV1(coordinator, admission, {}, { throw RuntimeProductionNetworkUnavailableV1() })
            }
            if (clean) {
                assertTrue("Network failure lost the admitted retry: ${failure.javaClass.simpleName}", failure is RuntimeProductionNetworkOutcomeV1)
                val retry = (failure as RuntimeProductionNetworkOutcomeV1).decision as RuntimeStartDecision.RequestAuthority
                assertEquals(1, retry.token.retryAttempt)
                assertEquals(1, retry.retryBudgetCeiling)
                assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
                assertEquals(retry.token, coordinator.currentToken())
                assertTrue(coordinator.acceptProductionAuthority(retry.token, 1))
                assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED),
                    coordinator.failed(retry.token, RuntimeStartFailure.NETWORK_UNAVAILABLE))
            } else {
                assertTrue(failure is RuntimeProductionNetworkOutcomeV1)
                assertTrue((failure as RuntimeProductionNetworkOutcomeV1).decision is RuntimeStartDecision.CleanupPending)
                assertNotEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
                assertEquals(admission.token, coordinator.currentToken())
            }
        }
    }
    @Test fun publicationDiagnosticsRetainAcquisitionAndActualCloseOutcomesIndependently() {
        for (mode in 0..4) {
            val source = Source(capture())
            var releases = 0
            val authority = object : RuntimeProductionCallbackAuthorityV1 by source {
                override fun acquireInitial(call: Long): Boolean = when (mode) {
                    0 -> false
                    1 -> throw java.io.IOException("not emitted")
                    else -> source.acquireInitial(call)
                }
                override fun releaseInitial(): Boolean {
                    releases++
                    return when (mode) {
                        2 -> false
                        3 -> throw java.io.IOException("not emitted")
                        else -> source.releaseInitial()
                    }
                }
            }
            val signals = object : RuntimeProductionCallbackSignalsV1 {
                override fun cancelled(owner: Long, call: Long) = false
                override fun remainingMillis(owner: Long, call: Long): Long? = 500
                override fun socketLost(owner: Long, signal: Long) = 0
                override fun networkLost(owner: Long, signal: Long) = 0
            }
            val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
                override fun fence(owner: Long, signal: Long) = 0
                override fun invalidate(owner: Long, signal: Long) = 0
            })
            val delegate = RuntimeProductionCallbackDelegateV1(1, authority, registration, signals, { _, _ -> true },
                { _, _ -> error("not requested") }, { error("not requested") }, { 1000L })
            delegate.adoptOwner(11)
            val revision = LongArray(1); val publication = LongArray(1)
            assertEquals(0, delegate.productionCurrentRegister(11, 7, 111, revision))
            assertEquals(if (mode < 2) 3 else 0, delegate.publicationAcquire(11, revision[0], 1, publication))
            assertTrue(publication[0] != 0L)
            fun snapshot(): LongArray {
                val values = delegate.javaClass.getDeclaredField("publicationDiagnostic").apply { isAccessible = true }.get(delegate) as LongArray
                return synchronized(values) { values.copyOf() }
            }
            val acquire = snapshot().copyOfRange(0, 8)
            assertEquals(listOf(5L, 4L, 6L, 6L, 6L)[mode], acquire[0])
            assertEquals(listOf(1L, 2L, 0L, 0L, 0L)[mode], acquire[1])
            assertEquals(if (mode == 4) 0 else 25, delegate.publicationClose(11, revision[0], publication[0]))
            assertEquals(1, releases)
            assertArrayEquals(acquire, snapshot().copyOfRange(0, 8))
            assertEquals(listOf(2L, 2L, 3L, 2L, 5L)[mode], snapshot()[8])
            if (mode != 4) {
                val failure = snapshot()
                assertEquals(25, delegate.publicationClose(12, revision[0], publication[0]))
                assertArrayEquals(failure, snapshot())
            }
            source.capture.close()
        }
    }
    @Test fun unavailableSocketRemainsOwnedUntilActualCloseProvesCleanup() {
        for (failClose in listOf(false, true)) {
            val source = Source(capture())
            var closes = 0
            val signals = object : RuntimeProductionCallbackSignalsV1 {
                override fun cancelled(owner: Long, call: Long) = false
                override fun remainingMillis(owner: Long, call: Long): Long? = 500
                override fun socketLost(owner: Long, signal: Long) = 0
                override fun networkLost(owner: Long, signal: Long) = 0
            }
            val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
                override fun fence(owner: Long, signal: Long) = 0
                override fun invalidate(owner: Long, signal: Long) = 0
            })
            val platform = object : RuntimeSocketPlatformV1 {
                override fun duplicate(fd: Int) { }
                override fun observe(lost: () -> Unit) { }
                override fun select(explicit: Int, has: Int, handle: Long) = 0L
                override fun current() = true
                override fun protect() = error("unavailable socket protected")
                override fun bind() = error("unavailable socket bound")
                override fun close() { closes++; check(!failClose) }
            }
            val delegate = RuntimeProductionCallbackDelegateV1(1, source, registration, signals, { _, _ -> true },
                { _, lost -> RuntimeProductionSocketOwner(platform, { true }, lost) }, { error("no network") }, { 1000L })
            delegate.adoptOwner(11)
            assertEquals(0, delegate.productionCurrentRegister(11, 7, 111, LongArray(1)))
            val socket = LongArray(1)
            val binding = IntArray(1)
            assertEquals(9, delegate.socketRegister(11, 1, 7, 1, 2, 3, 0, 0, 0, 222, socket, binding))
            assertTrue(socket[0] != 0L)
            assertEquals(0, binding[0])
            assertEquals(0, closes)
            assertTrue(delegate.owns(11))
            assertEquals(if (failClose) 25 else 0, delegate.socketClose(11, socket[0]))
            assertEquals(1, closes)
            assertEquals(!failClose, delegate.owns(11))
            if (failClose) {
                assertEquals(25, delegate.socketClose(11, socket[0]))
                assertEquals(1, closes)
            }
            source.capture.close()
        }
    }
    @Test fun socketAcquisitionOriginSurvivesActualCloseAndLaterGuardRejection() {
        val source = Source(capture())
        var closes = 0
        val signals = object : RuntimeProductionCallbackSignalsV1 {
            override fun cancelled(owner: Long, call: Long) = false
            override fun remainingMillis(owner: Long, call: Long): Long? = 500
            override fun socketLost(owner: Long, signal: Long) = 0
            override fun networkLost(owner: Long, signal: Long) = 0
        }
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long) = 0
            override fun invalidate(owner: Long, signal: Long) = 0
        })
        val platform = object : RuntimeSocketPlatformV1 {
            override fun duplicate(fd: Int) { }
            override fun observe(lost: () -> Unit) { }
            override fun select(explicit: Int, has: Int, handle: Long) = 9L
            override fun current() = true
            override fun protect() = true
            override fun bind() { }
            override fun close() { closes++ }
        }
        val delegate = RuntimeProductionCallbackDelegateV1(1, source, registration, signals, { _, _ -> true },
            { _, lost -> RuntimeProductionSocketOwner(platform, { true }, lost) }, { error("no network") }, { 1000L })
        delegate.adoptOwner(11)
        assertEquals(0, delegate.productionCurrentRegister(11, 7, 111, LongArray(1)))
        val socket = LongArray(1)
        // A mismatched explicit handle remains a contract violation, unlike no selection.
        assertEquals(18, delegate.socketRegister(11, 1, 7, 1, 2, 3, 1, 1, 8, 222, socket, IntArray(1)))
        fun diagnostic(): Int = runCatching {
            delegate.javaClass.getDeclaredField("firstSocketRejection").apply { isAccessible = true }.getInt(delegate)
        }.getOrDefault(0)
        val first = diagnostic()
        assertEquals(1, first and 15)
        assertEquals(4, (first ushr 4) and 7)
        assertEquals(2, (first ushr 7) and 3)
        assertTrue((first ushr 9) in 1..1023)
        assertEquals(25, delegate.socketClose(11, socket[0]))
        assertEquals(1, closes)
        assertEquals(first, diagnostic())
        assertEquals(25, delegate.socketClose(12, socket[0]))
        assertEquals(first, diagnostic())
        source.capture.close()
    }
    @Test fun scopedStopDuringCaptureDefersCleanupUntilTheActualAcquisitionReturns() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val calls = RuntimeProductionCallOwnerV1 { !admission.guard.isAcquisitionCurrent() }
        val entered = CountDownLatch(1)
        val returnCapture = CountDownLatch(1)
        val closed = AtomicInteger()
        val failure = AtomicReference<Throwable?>()
        admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable {
            calls.runCleanup { closed.incrementAndGet() }
            calls.close()
        })
        val acquisition = Thread {
            try {
                runProductionAcquisitionV1(coordinator, admission, {}, {
                    calls.run(1) { entered.countDown(); check(returnCapture.await(5, TimeUnit.SECONDS)) }
                })
            } catch (caught: Throwable) { failure.set(caught) }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(calls.cancel(1))
            val stopped = coordinator.stopIfCurrent(admission.token, RuntimeStopReason.CANCEL)
            assertTrue(stopped is RuntimeStartDecision.CleanupPending)
            assertEquals(RuntimeCleanupState.CLEANUP_REQUIRED, admission.guard.cleanupState())
            assertEquals(0, closed.get())
            assertEquals(admission.token, coordinator.currentToken())
            assertTrue(coordinator.stopIfCurrent(admission.token, RuntimeStopReason.CANCEL) is RuntimeStartDecision.CleanupPending)
            assertEquals(0, closed.get())
        } finally { returnCapture.countDown(); acquisition.join(5000) }
        assertFalse(acquisition.isAlive)
        assertTrue(failure.get() is RuntimeAuthorityCleanupUnprovenException)
        assertTrue(failure.get()?.cause is java.util.concurrent.CancellationException)
        assertEquals(1, closed.get())
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
        assertNull(coordinator.currentToken())
    }

    @Test fun cancelledSuccessfulAcquisitionReturnStillDrainsAfterUnwind() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val entered = CountDownLatch(1); val finish = CountDownLatch(1)
        val closed = AtomicInteger(); val failure = AtomicReference<Throwable?>()
        admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed.incrementAndGet() })
        val acquisition = Thread {
            try { runProductionAcquisitionV1(coordinator, admission, {}, { entered.countDown(); check(finish.await(5, TimeUnit.SECONDS)) }) }
            catch (caught: Throwable) { failure.set(caught) }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertTrue(coordinator.stopIfCurrent(admission.token, RuntimeStopReason.CANCEL) is RuntimeStartDecision.CleanupPending)
            assertEquals(0, closed.get())
        } finally { finish.countDown(); acquisition.join(5000) }
        assertFalse(acquisition.isAlive)
        assertTrue(failure.get() is RuntimeAuthorityCleanupUnprovenException)
        assertNull(failure.get()?.cause)
        assertEquals(1, closed.get())
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
        assertNull(coordinator.currentToken())
    }

    @Test fun cancellationBeforeCallbackCannotRunAcquisitionOrInterfereWithSuccessor() {
        var id = 1
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { (++id).toString().repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        var closed = 0
        var callbackRan = false
        var captureRan = false
        admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
        assertEquals(RuntimeStartDecision.Idle, coordinator.stopIfCurrent(admission.token, RuntimeStopReason.CANCEL))
        val successor = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val failure = assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) {
            runProductionAcquisitionV1(coordinator, admission, { callbackRan = true }, { captureRan = true })
        }
        assertNull(failure.cause)
        assertFalse(callbackRan)
        assertFalse(captureRan)
        assertEquals(RuntimeStartDecision.Stale, coordinator.stopIfCurrent(admission.token, RuntimeStopReason.STOP))
        assertEquals(1, closed)
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
        assertEquals(successor.token, coordinator.currentToken())
        assertTrue(successor.guard.isAcquisitionCurrent())
        coordinator.stop(RuntimeStopReason.STOP)
    }

    @Test fun admittedCallbackFailureClosesOwnedResourcesBeforeAnyCaptureWork() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        var closed = 0
        var captureStarted = false
        admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
        val original = IllegalStateException("callback failed")
        val failure = assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) {
            runProductionAcquisitionV1(coordinator, admission, { throw original }, { captureStarted = true })
        }
        assertSame(original, failure.cause)
        assertEquals("AUTHORITY_CLEANUP_UNPROVEN", failure.message)
        assertFalse(captureStarted)
        assertEquals(1, closed)
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
        assertNull(coordinator.currentToken())
    }
    @Test fun acquisitionFailureRetainsOriginalCauseAfterTheSameCleanup() {
        val coordinator = RuntimeStartCoordinator("1".repeat(32)) { "2".repeat(32) }
        val admission = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        var closed = 0
        var admitted = false
        val original = IllegalArgumentException("acquisition failed")
        admission.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
        val failure = assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) {
            runProductionAcquisitionV1(coordinator, admission, { admitted = true }, { throw original })
        }
        assertTrue(admitted)
        assertSame(original, failure.cause)
        assertEquals("AUTHORITY_CLEANUP_UNPROVEN", failure.message)
        assertEquals(1, closed)
        assertEquals(RuntimeCleanupState.CLEAN, admission.guard.cleanupState())
        assertNull(coordinator.currentToken())
    }
    @Test fun boundSelectorLiveFenceExceptionBecomesStickyUnavailable() {
        val source=Source(capture())
        var valid=true
        source.selector=object:org.kurdistanvpn.core.nativejni.AndroidProductionProbeBindingV1 {
            override fun isCurrent()=valid
            override fun permits(target:Int)=valid
            override fun observe(event:NativeControlEvent){}
            override fun invalidate(){valid=false}
        }
        val signals=object:RuntimeProductionCallbackSignalsV1 {
            override fun cancelled(owner:Long,call:Long)=false
            override fun remainingMillis(owner:Long,call:Long):Long?=500
            override fun socketLost(owner:Long,signal:Long)=0
            override fun networkLost(owner:Long,signal:Long)=0
        }
        val registration=RuntimeProductionRegistrationV1(object:RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner:Long,signal:Long)=0
            override fun invalidate(owner:Long,signal:Long)=0
        })
        val delegate=RuntimeProductionCallbackDelegateV1(1,source,registration,signals,{_,_->true},
            {_,_->error("no socket")},{_->error("no network")},{1000L})
        delegate.adoptOwner(11)
        val revision=LongArray(1)
        assertEquals(0,delegate.productionCurrentRegister(11,7,111,revision))
        val binding=delegate.bindActiveSelectors(11,1,ByteArray(32))
        assertTrue(binding.permits(7))
        source.throwLive=true
        assertFalse(binding.isCurrent())
        source.throwLive=false
        assertFalse(binding.permits(7))
        assertEquals(0,delegate.revisionClose(11,revision[0]))
        source.capture.close()
    }
    @Test fun selectorBindingRejectsChangedOpeningAndNeverRevivesAfterAttemptReplacement() {
        val digest=ByteArray(32){1};val facts=NativeProductionBootstrapFactsV1(9uL,digest,1280,1,1)
        var live=true
        val contains:(Int)->Boolean={it==7}
        val binding=RuntimeCapturedProbeBindingV1(facts,{live},contains,9uL,digest)
        assertTrue(binding.permits(7));assertFalse(binding.permits(8))
        binding.observe(NativeControlEvent.TransportReady(1uL,1uL))
        assertTrue(binding.permits(7))
        binding.observe(NativeControlEvent.ReconnectStarted(2uL,2uL,NativeReconnectReason.USER_REQUEST,1,1))
        assertFalse(binding.permits(7))
        binding.observe(NativeControlEvent.TransportReady(2uL,3uL));assertFalse(binding.isCurrent())
        val replacement=RuntimeCapturedProbeBindingV1(facts,{live},contains,9uL,digest)
        assertTrue(replacement.permits(7));assertFalse(binding.permits(7))
        live=false;assertFalse(replacement.permits(7));live=true;assertFalse(replacement.permits(7))
        for(mode in 0..1) {
            val rejected=RuntimeCapturedProbeBindingV1(facts,{true},contains,if(mode==0)8uL else 9uL,if(mode==0)digest else ByteArray(32){2})
            assertFalse(rejected.permits(7))
        }
    }
    @Test fun trustedGenerationReadsSameFactsOnlyAcrossBothLiveFences() {
        val expected=Long.MIN_VALUE.toULong()
        var reads=0;var fences=0
        assertEquals(expected,readCapturedGenerationV1({fences++;true}){reads++;expected})
        assertEquals(1,reads);assertEquals(2,fences)
        for (loss in listOf(1,2)) {
            reads=0;fences=0
            try { readCapturedGenerationV1({++fences!=loss}){reads++;expected};fail("lost capture accepted") }
            catch (_:IllegalStateException){}
            assertEquals(if(loss==1)0 else 1,reads)
        }
        try { readCapturedGenerationV1({true}){0uL};fail("zero generation") }
        catch (_:IllegalStateException){}
    }
    @Test fun nativeOpeningRevalidatesBeforeInitialPublicationForBothKinds() {
        for (kind in 1..2) {
            val source = Source(capture())
            val signals = object : RuntimeProductionCallbackSignalsV1 {
                override fun cancelled(owner: Long, call: Long) = false
                override fun remainingMillis(owner: Long, call: Long): Long? = 500
                override fun socketLost(owner: Long, signal: Long) = 0
                override fun networkLost(owner: Long, signal: Long) = 0
            }
            val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
                override fun fence(owner: Long, signal: Long) = 0
                override fun invalidate(owner: Long, signal: Long) = 0
            })
            val delegate = RuntimeProductionCallbackDelegateV1(kind, source, registration, signals, { _, _ -> true },
                { _, _ -> error("no socket") }, { _ -> error("no network") }, { 1000L })
            delegate.adoptOwner(11)
            assertEquals(Long.MIN_VALUE,delegate.capturedGeneration(11))
            try { delegate.capturedGeneration(12);fail("wrong capture owner") }catch(_:IllegalStateException){}
            val revision = LongArray(1); val publication = LongArray(1)
            assertEquals(0, if (kind == 1) delegate.productionCurrentRegister(11, 7, 111, revision)
                else delegate.maintenanceCurrentRegister(11, 7, 111, revision))
            assertEquals("initial native Revalidate kind=$kind", 0, delegate.revisionRevalidate(11, revision[0], 1))
            assertEquals(0, source.initialAcquisitions)
            assertEquals(0, delegate.publicationAcquire(11, revision[0], 2, publication))
            assertEquals(0, delegate.revisionRevalidate(11, revision[0], 3))
            assertEquals(0, delegate.publicationClose(11, revision[0], publication[0]))
            assertEquals(0, delegate.revisionRevalidate(11, revision[0], 4))
            assertEquals(1, source.initialAcquisitions); assertEquals(1, source.initialReleases)
            assertEquals(8, delegate.revisionRevalidate(12, revision[0], 5))
            val diagnostic = runCatching {
                delegate.javaClass.getDeclaredField("firstRevalidationRejection").apply { isAccessible = true }.getInt(delegate)
            }.getOrDefault(0)
            assertEquals(1, diagnostic)
            assertEquals(0, delegate.revisionRevalidate(11, revision[0], 6))
            assertEquals(diagnostic, delegate.javaClass.getDeclaredField("firstRevalidationRejection").apply { isAccessible = true }.getInt(delegate))
            assertEquals(0, delegate.revisionClose(11, revision[0]))
            source.capture.close()
        }
    }

    @Test fun establishedTunWrapperIsOwnedBeforeAcquisitionAndCancellationPreventsDetach() {
        var current = true
        var closes = 0
        var detaches = 0
        val original = object : AutoCloseable { override fun close() { closes++ } }
        val platform = PlatformTunOwner({ original }, { assertEquals(0, detaches) }, { detaches++; 7 })
        val tun = RuntimeProductionEstablishedTunV1(platform, { current }) { error("detach-only fixture") }
        val guard = RuntimeActivationGuard()
        assertNotNull(guard.own(RuntimeResourceKind.TUN, tun))
        assertTrue(guard.acquire { assertNotNull(platform.establish()) })
        current = false
        assertThrows(IllegalStateException::class.java) { tun.detachFileDescriptor() }
        assertEquals(0, detaches)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(1, closes)
    }

    @Test fun revalidationExceptionRecordsActualPhaseWithoutReplacingItsFailureStatus() {
        val source = Source(capture())
        val signals = object : RuntimeProductionCallbackSignalsV1 {
            override fun cancelled(owner: Long, call: Long) = false
            override fun remainingMillis(owner: Long, call: Long): Long? = 500
            override fun socketLost(owner: Long, signal: Long) = 0
            override fun networkLost(owner: Long, signal: Long) = 0
        }
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long) = 0
            override fun invalidate(owner: Long, signal: Long) = 0
        })
        val delegate = RuntimeProductionCallbackDelegateV1(1, source, registration, signals, { _, _ -> true },
            { _, _ -> error("no socket") }, { _ -> error("no network") }, { 1000L })
        delegate.adoptOwner(11)
        val revision = LongArray(1)
        assertEquals(0, delegate.productionCurrentRegister(11, 7, 111, revision))
        source.revalidationFailure = IllegalStateException("not emitted")
        assertEquals(3, delegate.revisionRevalidate(11, revision[0], 1))
        val field = delegate.javaClass.getDeclaredField("firstRevalidationRejection").apply { isAccessible = true }
        assertEquals(67, field.getInt(delegate))
        assertEquals(0, source.observations)
        assertEquals(8, delegate.revisionRevalidate(12, revision[0], 2))
        assertEquals(67, field.getInt(delegate))
        source.capture.close()
    }

    @Test fun serviceCapabilityRejectsWrongProcessUidPermissionOrExportedComponent() {
        assertTrue(RuntimeProductionServiceIdentityV1.accepts("app", "app:vpn", "app:vpn", 123, 123,
            "android.permission.BIND_VPN_SERVICE", false, false))
        assertFalse(RuntimeProductionServiceIdentityV1.accepts("app", "app", "app:vpn", 123, 123,
            "android.permission.BIND_VPN_SERVICE", false, false))
        assertFalse(RuntimeProductionServiceIdentityV1.accepts("app", "app:vpn", "app:vpn", 124, 123,
            "android.permission.BIND_VPN_SERVICE", false, false))
        assertFalse(RuntimeProductionServiceIdentityV1.accepts("app", "app:vpn", "app:vpn", 123, 123,
            null, false, false))
        assertFalse(RuntimeProductionServiceIdentityV1.accepts("app", "app:vpn", "app:vpn", 123, 123,
            "android.permission.BIND_VPN_SERVICE", true, false))
        assertFalse(RuntimeProductionServiceIdentityV1.accepts("app", "app:vpn", "app:vpn", 123, 123,
            "android.permission.BIND_VPN_SERVICE", false, true))
    }

    @Test fun delegateUsesOneInitialLeaseThenOnlyFreshLocalMaintenancePublications() {
        val source = Source(capture())
        val signals = object : RuntimeProductionCallbackSignalsV1 {
            override fun cancelled(owner: Long, call: Long) = false
            override fun remainingMillis(owner: Long, call: Long): Long? = 500
            override fun socketLost(owner: Long, signal: Long) = 0
            override fun networkLost(owner: Long, signal: Long) = 0
        }
        val registration = RuntimeProductionRegistrationV1(object : RuntimeProductionRevisionSignalsV1 {
            override fun fence(owner: Long, signal: Long) = 0
            override fun invalidate(owner: Long, signal: Long) = 0
        })
        val production = RuntimeProductionCallbackDelegateV1(1, source, registration, signals, { _, _ -> true },
            { _, _ -> error("socket not requested") }, { _ -> error("network not requested") }, { 1000L })
        val maintenance = RuntimeProductionCallbackDelegateV1(2, source, registration, signals, { _, _ -> true },
            { _, _ -> error("socket not requested") }, { _ -> error("network not requested") }, { 1000L })
        production.adoptOwner(11)
        maintenance.adoptOwner(22)
        val revision = LongArray(1)
        assertEquals(0, production.productionCurrentRegister(11, 7, 111, revision))
        val productionRevision = revision[0]
        val publication = LongArray(1)
        assertEquals(0, production.publicationAcquire(11, productionRevision, 1, publication))
        assertEquals(1, source.initialAcquisitions)
        assertEquals(0, production.publicationClose(11, productionRevision, publication[0]))
        assertEquals(1, source.initialReleases)
        assertEquals(0, maintenance.maintenanceCurrentRegister(22, 8, 222, revision))
        assertEquals(0, maintenance.publicationAcquire(22, revision[0], 2, publication))
        assertTrue(source.observations > 0)
        assertEquals(1, source.initialAcquisitions)
        val current = IntArray(1)
        assertEquals(0, maintenance.publicationIsCurrent(22, revision[0], publication[0], current))
        assertEquals(1, current[0])
        assertTrue(registration.invalidate())
        assertEquals(0, maintenance.publicationIsCurrent(22, revision[0], publication[0], current))
        assertEquals(0, current[0])
        assertEquals(0, maintenance.publicationClose(22, revision[0], publication[0]))
        assertEquals(0, maintenance.revisionClose(22, revision[0]))
        assertEquals(0, production.revisionClose(11, productionRevision))
        assertEquals(1, source.initialReleases)
        source.capture.close()
    }

    private class Source(override val capture: RuntimeCaptureSnapshotV1) : RuntimeProductionCallbackAuthorityV1 {
        var selector:org.kurdistanvpn.core.nativejni.AndroidProductionProbeBindingV1?=null
        var throwLive=false
        override fun capturedGeneration() = Long.MIN_VALUE.toULong()
        override fun bindActive(generation:ULong,digest:ByteArray):org.kurdistanvpn.core.nativejni.AndroidProductionProbeBindingV1=checkNotNull(selector)
        override fun bindDisconnected():org.kurdistanvpn.core.nativejni.AndroidProductionProbeBindingV1=error("no selection")
        private val lease = RuntimeProductionInitialLeaseV1()
        var initialAcquisitions = 0
        var initialReleases = 0
        var observations = 0
        var revalidationFailure: Throwable? = null
        override var initialAcquired = false
        override fun live():Boolean {check(!throwLive);return true}
        override fun acquireInitial(call: Long): Boolean { initialAcquisitions++; lease.install(2000); initialAcquired = true; return true }
        override fun initialCurrent() = lease.isCurrent(1000)
        override fun releaseInitial(): Boolean = lease.release { initialReleases++; true }
        override fun revalidateCurrent(call: Long, deadline: Long): Boolean {
            revalidationFailure?.let { throw it }
            return lease.observeCurrent({1000},
                { observations++; initialAcquisitions == 0 }, { observations++; initialReleases == 1 })
        }
        override fun cancel(call: Long) = true
    }

    @Test fun pendingNativeReservationRetainsSharedCaptureAcrossStopAndRetiresItsLateLease() {
        val guard = RuntimeActivationGuard()
        var sharedClosed = false
        var abandoned = 0
        val ownership = RuntimeProductionGuardOwnershipV1(guard) { sharedClosed = true }
        guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership)
        assertFalse(guard.acquire {
            ownership.beginReservation(1)
            assertEquals(RuntimeCleanupState.UNPROVEN, guard.cancel())
            try {
                ownership.reserve(1, 11, 101) {
                    abandoned++
                    assertTrue(ownership.nativeOwnerClosed(1, 11))
                    0
                }
                fail("late reservation published")
            } catch (_: RuntimeAuthorityCleanupUnprovenException) { }
        })
        assertFalse(sharedClosed)
        assertEquals(1, abandoned)
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cleanupState())
    }

    @Test fun nativeParentsRetireLifoBeforeSharedOwnerAndFailureCannotReleaseSharedCapture() {
        for (failNative in listOf(false, true)) {
            val events = mutableListOf<String>()
            val guard = RuntimeActivationGuard()
            val ownership = RuntimeProductionGuardOwnershipV1(guard) { events += "shared" }
            assertNotNull(guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership))
            ownership.beginReservation(1)
            ownership.reserve(1, 11, 101) { error("claimed production abandoned") }
            ownership.beginReservation(2)
            ownership.reserve(2, 22, 202) { error("claimed maintenance abandoned") }
            assertTrue(guard.acquire {
                ownership.adoptNativeParent(1, Closeable {
                    events += "production"
                    check(ownership.nativeOwnerClosed(1, 11))
                })
                ownership.adoptNativeParent(2, Closeable {
                    events += "maintenance"
                    if (failNative) throw IllegalStateException("native close unproven")
                    check(ownership.nativeOwnerClosed(2, 22))
                })
            })
            assertEquals(if (failNative) RuntimeCleanupState.UNPROVEN else RuntimeCleanupState.CLEAN, guard.cancel())
            assertEquals(if (failNative) listOf("maintenance", "production") else listOf("maintenance", "production", "shared"), events)
            guard.cancel()
            assertEquals(if (failNative) 2 else 3, events.size)
        }
    }

    @Test fun retiredMaintenanceSlotCanBeReusedWithoutRetiringProductionOrRepeatingClose() {
        val events = mutableListOf<String>()
        val guard = RuntimeActivationGuard()
        val ownership = RuntimeProductionGuardOwnershipV1(guard) { events += "shared" }
        guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership)
        ownership.beginReservation(1)
        ownership.reserve(1, 11, 101) { error("production abandoned") }
        ownership.adoptNativeParent(1, Closeable {
            events += "production"; check(ownership.nativeOwnerClosed(1, 11))
        })
        for (id in listOf(22L, 33L)) {
            ownership.beginReservation(2)
            ownership.reserve(2, id, id + 100) { error("maintenance abandoned") }
            ownership.adoptNativeParent(2, Closeable {
                events += "maintenance-$id"; check(ownership.nativeOwnerClosed(2, id))
            })
            ownership.retireMaintenance()
        }
        assertEquals(listOf("maintenance-22", "maintenance-33"), events)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(listOf("maintenance-22", "maintenance-33", "production", "shared"), events)
        assertThrows(IllegalStateException::class.java) { ownership.beginReservation(2) }
    }

    @Test fun stopBeforeReturnedParentAdoptionNeverMistakesClaimedLeaseForCleanAbandon() {
        val guard = RuntimeActivationGuard()
        var sharedClosed = false
        var abandoned = 0
        var nativeClosed = 0
        val ownership = RuntimeProductionGuardOwnershipV1(guard) { sharedClosed = true }
        assertNotNull(guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership))
        ownership.beginReservation(1)
        ownership.reserve(1, 11, 101) { abandoned++; 25 }
        assertFalse(guard.acquire {
            assertEquals(RuntimeCleanupState.UNPROVEN, guard.cancel())
            ownership.adoptNativeParent(1, Closeable { nativeClosed++; ownership.nativeOwnerClosed(1, 11) })
        })
        assertEquals(1, abandoned)
        assertEquals(1, nativeClosed)
        assertFalse(sharedClosed)
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cleanupState())
    }

    @Test fun genuinelyUnclaimedAbandonMustReturnCleanAfterExactOwnerCallbackBeforeSharedRelease() {
        val guard = RuntimeActivationGuard()
        var sharedClosed = false
        val ownership = RuntimeProductionGuardOwnershipV1(guard) { sharedClosed = true }
        guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership)
        ownership.beginReservation(1)
        ownership.reserve(1, Long.MIN_VALUE, Long.MIN_VALUE) {
            assertFalse(ownership.nativeOwnerClosed(1, 3))
            assertTrue(ownership.nativeOwnerClosed(1, Long.MIN_VALUE))
            0
        }
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertTrue(sharedClosed)
    }

    @Test fun failedClaimedOpeningNeedsExactFinalizationAndCallbackBeforeSharedRelease() {
        for (kind in listOf(1, 2)) for (callback in listOf(false, true)) for (result in listOf(0, 25)) {
            val guard = RuntimeActivationGuard()
            var sharedClosed = false
            var finalizations = 0
            val ownership = RuntimeProductionGuardOwnershipV1(guard) { sharedClosed = true }
            guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, ownership)
            ownership.beginReservation(kind)
            ownership.reserve(kind, Long.MIN_VALUE, -2) { 25 }
            val clean = callback && result == 0
            try {
                ownership.finalizeFailedOpening(kind, Long.MIN_VALUE, -2) {
                    finalizations++
                    if (callback) assertTrue(ownership.nativeOwnerClosed(kind, Long.MIN_VALUE))
                    result
                }
                assertTrue(clean)
            } catch (_: RuntimeAuthorityCleanupUnprovenException) { assertFalse(clean) }
            assertEquals(1, finalizations)
            try {
                ownership.finalizeFailedOpening(kind, Long.MIN_VALUE, -2) { finalizations++; 0 }
                fail("finalization repeated")
            } catch (_: RuntimeAuthorityCleanupUnprovenException) { }
            assertEquals(1, finalizations)
            assertEquals(if (clean) RuntimeCleanupState.CLEAN else RuntimeCleanupState.UNPROVEN, guard.cancel())
            assertEquals(clean, sharedClosed)
        }
    }

    @Test fun failedOpeningFinalizerRejectsWrongOwnerAndAdoptedParentWithoutNativeWork() {
        for (adopted in listOf(false, true)) {
            val guard = RuntimeActivationGuard()
            val ownership = RuntimeProductionGuardOwnershipV1(guard) { }
            ownership.beginReservation(1)
            ownership.reserve(1, 11, 101) { 25 }
            if (adopted) ownership.adoptNativeParent(1, Closeable { })
            try {
                ownership.finalizeFailedOpening(1, if (adopted) 11 else 12, 101) { fail("native work"); 0 }
                fail("invalid ownership accepted")
            } catch (_: RuntimeAuthorityCleanupUnprovenException) { }
        }
    }

    private fun capture(): RuntimeCaptureSnapshotV1 {
        val parts = RuntimeCapturePartsV1(ByteBuffer.wrap(byteArrayOf(1)), ByteBuffer.wrap(byteArrayOf(2, 3)),
            ByteBuffer.wrap(byteArrayOf(4, 5, 6)), ByteBuffer.wrap(byteArrayOf(7, 8, 9, 10)),
            ByteBuffer.wrap(byteArrayOf(11, 12, 13, 14, 15)))
        val encoded = ByteBuffer.allocate(47)
        RuntimeCaptureCodecV1.encode(parts, encoded)
        return RuntimeCaptureCodecV1.decode(encoded)
    }

    @Test fun sameCaptureFiveSpanBorrowReachesValidatorAndWipesEveryTemporaryOnFailure() {
        val borrowed = mutableListOf<ByteBuffer>()
        val validator = object : NativeBootstrapValidator {
            override fun readLegacyBinding(material: NativeBootstrapMaterialV1, legacyPolicy: ByteBuffer): NativeResult<NativeLegacyBootstrapFactsV1> = error("legacy")
            override fun readProductionBinding(material: NativeBootstrapMaterialV1, settings: ByteBuffer): NativeProductResult<NativeProductionBootstrapReadV1> {
                borrowed += listOf(material.verifyRequest, material.activationRecord, material.recipientRequest, material.recipientPrivate, settings)
                assertEquals(listOf(1, 2, 3, 4, 5), borrowed.map { it.capacity() })
                assertEquals(listOf(1, 2, 4, 7, 11), borrowed.map { it.get(0).toInt() })
                assertTrue(borrowed.all { it.isDirect })
                throw IllegalStateException("actual verifier boundary failure")
            }
        }
        capture().use { capture ->
            try { RuntimeProductionBootstrapBorrowV1.read(capture, validator); fail("accepted failed verifier") }
            catch (_: IllegalStateException) { }
            assertEquals(5, borrowed.size)
            borrowed.forEach { buffer -> for (i in 0 until buffer.capacity()) assertEquals(0, buffer.get(i).toInt()) }
            val original = ByteBuffer.allocate(4)
            assertEquals(4, capture.copyRecipientPrivateTo(original))
            assertArrayEquals(byteArrayOf(7, 8, 9, 10), original.array())
        }
    }
}

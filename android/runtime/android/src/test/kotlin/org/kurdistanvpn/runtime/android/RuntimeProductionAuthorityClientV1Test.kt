// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test

class RuntimeProductionAuthorityClientV1Test {
    @Test fun aDeadPublishedProviderDoesNotRequireAnImpossibleRemoteAcknowledgement() {
        assertTrue(retireProductionProviderV1(true, true) { error("dead provider cannot acknowledge") })
        assertFalse(retireProductionProviderV1(false, true) { false })
        assertFalse(retireProductionProviderV1(true, false) { false })
        assertTrue(retireProductionProviderV1(false, true) { true })
    }
    @Test fun beforeInstallRetirementRequiresActualJoinedCancelAcknowledgement() {
        val lease = RuntimeProductionInitialLeaseV1()
        var cancellations = 0
        val action = { cancellations++; 1 }
        val clean = lease.cancelBeforeInstall(action)
        assertTrue(clean)
        assertEquals(1, cancellations)
        assertFalse(lease.wasInstalled())
        assertFalse(lease.isCurrent(100))
        assertFalse(lease.observeCurrent({ 100 }, { true }, { true }))
        assertThrows(IllegalStateException::class.java) { lease.install(2000) }
        assertTrue(lease.cancelBeforeInstall { error("already acknowledged") })
        assertEquals(1, cancellations)
    }
    @Test fun exactProviderDeadlineAllowsDelayedPreTunButNeverExtendsActualExpiry() {
        // Local operation began at1000; real provider lease began at1500 and expires at3500.
        val lease = RuntimeProductionInitialLeaseV1()
        assertTrue(lease.installIfCurrent(3500, 3296))
        assertTrue(lease.isCurrent(3499)); assertFalse(lease.isCurrent(3500))
        val late = RuntimeProductionInitialLeaseV1()
        assertFalse(late.installIfCurrent(3500, 3500)); assertFalse(late.wasInstalled())
        assertTrue(late.cancelBeforeInstall { 1 })
        assertThrows(IllegalStateException::class.java) { late.installIfCurrent(5500, 3501) }
    }
    @Test fun beforeInstallCancelFailurePendingThrowAndOverlapStayUnproven() {
        for (status in listOf(0, 2)) {
            val lease = RuntimeProductionInitialLeaseV1()
            assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { lease.cancelBeforeInstall { status } }
            assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { lease.cancelBeforeInstall { 1 } }
            assertFalse(lease.isCurrent(100))
        }
        val failed = RuntimeProductionInitialLeaseV1()
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { failed.cancelBeforeInstall { throw java.io.IOException() } }
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { failed.cancelBeforeInstall { 1 } }
        val pending = RuntimeProductionInitialLeaseV1()
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) {
            pending.cancelBeforeInstall {
                assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { pending.cancelBeforeInstall { 1 } }
                1
            }
        }
    }
    @Test fun realCallOwnerLateCancellationKeepsInstalledPhaseSixAndNoStalePredicate() {
        val values = LongArray(16) { -1 }
        val lease = RuntimeProductionInitialLeaseV1(values)
        val calls = RuntimeProductionCallOwnerV1()
        try {
            assertThrows(CancellationException::class.java) {
                runProductionPublicationCallV1(lease, values, { 25 }) {
                    calls.run(1) {
                        assertTrue(lease.installIfCurrent(2100, 100))
                        assertTrue(calls.cancel(1))
                        true
                    }
                }
            }
            assertEquals(6L, values[0]); assertEquals(2L, values[1])
            assertEquals(-1L, values[3]); assertEquals(1L, values[4]); assertEquals(0L, values[5])
        } finally { calls.close() }
        val success = LongArray(16) { -1 }
        val installed = RuntimeProductionInitialLeaseV1(success)
        assertTrue(runProductionPublicationCallV1(installed, success, { 25 }) { installed.installIfCurrent(2100, 100) })
        assertEquals(7L, success[0]); assertEquals(-1L, success[3]); assertEquals(1L, success[5])
    }
    @Test fun actualLeaseRetainsOnlySharedScalarsAndCannotReplaceAcquisitionFailure() {
        val scalars = LongArray(16) { -1 }
        recordProductionPublicationV1(scalars, 0, 5, 1, 2001, 0, 0, failure = IllegalStateException())
        val acquisition = scalars.copyOfRange(0, 8)
        val lease = RuntimeProductionInitialLeaseV1(scalars)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { lease.release { error("not installed") } }
        recordProductionPublicationV1(scalars, 0, 7, 0, 0, 1, 1, 1)
        assertArrayEquals(acquisition, scalars.copyOfRange(0, 8))
        assertEquals(2L, scalars[8]); assertEquals(3L, scalars[9])
        assertEquals(2001L, scalars[2]); assertEquals(-1L, scalars[10])
    }
    @Test fun initialLeaseDiagnosticDistinguishesNoInstallFromActualFailedRelease() {
        fun observed(lease: RuntimeProductionInitialLeaseV1): LongArray = runCatching {
            val values = lease.javaClass.getDeclaredField("publicationDiagnostic").apply { isAccessible = true }.get(lease) as LongArray
            synchronized(values) { values.copyOfRange(8, 16) }
        }.getOrElse { LongArray(8) { -1 } }
        val absent = RuntimeProductionInitialLeaseV1()
        var releases = 0
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { absent.release { releases++; true } }
        assertEquals(0, releases)
        assertEquals(2L, observed(absent)[0]); assertEquals(3L, observed(absent)[1])
        assertEquals(0L, observed(absent)[4])
        val failed = RuntimeProductionInitialLeaseV1().apply { install(2000) }
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { failed.release { releases++; false } }
        assertEquals(1, releases)
        assertEquals(3L, observed(failed)[0]); assertEquals(1L, observed(failed)[1])
        assertEquals(0L, observed(failed)[3]); assertEquals(1L, observed(failed)[4])
        val first = observed(failed)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { failed.release { error("must not retry") } }
        assertArrayEquals(first, observed(failed))
        val thrown = RuntimeProductionInitialLeaseV1().apply { install(2000) }
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { thrown.release { throw java.io.IOException("not emitted") } }
        assertEquals(2L, observed(thrown)[1]); assertEquals(5L, observed(thrown)[6])
        val clean = RuntimeProductionInitialLeaseV1().apply { install(2000) }
        assertTrue(clean.release { true }); assertTrue(clean.isReleased())
        assertEquals(1L, observed(clean)[5])
    }
    @Test fun admissionDiagnosticPreservesFirstOverlapBeforeLaterClose() {
        val calls = RuntimeProductionCallOwnerV1()
        val entered = CountDownLatch(1); val release = CountDownLatch(1)
        val failed = AtomicReference<Throwable?>()
        val caller = Thread {
            try { calls.run(1) { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) } }
            catch (failure: Throwable) { failed.set(failure) }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            assertThrows(IllegalStateException::class.java) { calls.run(2) { error("must not execute") } }
            val observed = runCatching {
                calls.javaClass.getDeclaredField("firstAdmissionRejection").apply { isAccessible = true }.getInt(calls)
            }.getOrDefault(0)
            assertEquals(2, observed)
        } finally { release.countDown(); caller.join(5000); calls.close() }
        assertFalse(caller.isAlive); assertNull(failed.get())
        assertThrows(IllegalStateException::class.java) { calls.run(3) { error("closed") } }
        assertEquals(2, calls.javaClass.getDeclaredField("firstAdmissionRejection").apply { isAccessible = true }.getInt(calls))
    }

    @Test fun completedRunnableHandoffAdmitsNextCallBeforeWorkerReturnsToItsQueue() {
        completedRunnableHandoff(0)
    }

    @Test fun cancellationRetainsTheQueuedAdmittedCallUntilItsActualWorkerReturns() {
        completedRunnableHandoff(1)
    }

    @Test fun shutdownDrainsTheQueuedAdmittedCallWithoutClaimingCleanEarly() {
        completedRunnableHandoff(2)
    }

    private fun completedRunnableHandoff(mode: Int) {
        val calls = RuntimeProductionCallOwnerV1()
        val field = RuntimeProductionCallOwnerV1::class.java.getDeclaredField("worker").apply { isAccessible = true }
        val original = field.get(calls) as ThreadPoolExecutor
        val completed = CountDownLatch(1); val retire = CountDownLatch(1)
        val paused = AtomicBoolean(false)
        // Same real queue/factory/admission policy. Pause after the actual owner runnable,
        // which has notified its caller but has not returned to the executor's take loop.
        val worker = object : ThreadPoolExecutor(original.corePoolSize, original.maximumPoolSize,
            original.getKeepAliveTime(TimeUnit.NANOSECONDS), TimeUnit.NANOSECONDS, original.queue,
            original.threadFactory, original.rejectedExecutionHandler) {
            override fun afterExecute(task: Runnable, failure: Throwable?) {
                if (paused.compareAndSet(false, true)) {
                    completed.countDown()
                    check(retire.await(5, TimeUnit.SECONDS))
                }
                super.afterExecute(task, failure)
            }
        }
        original.shutdown()
        field.set(calls, worker)
        val secondFinished = CountDownLatch(1)
        val secondError = AtomicReference<Throwable?>()
        val secondThread = AtomicReference<Thread?>()
        var second: Thread? = null
        try {
            val firstThread = calls.run(1) { Thread.currentThread() }
            assertTrue(completed.await(5, TimeUnit.SECONDS))
            second = Thread {
                try { calls.run(2) { secondThread.set(Thread.currentThread()); 7 } }
                catch (failure: Throwable) { secondError.set(failure) }
                finally { secondFinished.countDown() }
            }.apply { isDaemon = true; start() }
            val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (worker.queue.isEmpty() && secondFinished.count != 0L && System.nanoTime() < until)
                secondFinished.await(1, TimeUnit.MILLISECONDS)
            if (worker.queue.isEmpty()) assertTrue(secondError.get() is java.util.concurrent.RejectedExecutionException)
            assertEquals("one admitted call waits; observed ${secondError.get()?.javaClass?.simpleName}", 1, worker.queue.size)
            assertEquals(0, worker.queue.remainingCapacity())
            assertThrows(IllegalStateException::class.java) { calls.run(3) { error("overlapping call") } }
            when (mode) {
                1 -> assertTrue(calls.cancel(2))
                2 -> assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { calls.close() }
            }
            assertEquals(1L, secondFinished.count)
            retire.countDown()
            assertTrue(secondFinished.await(5, TimeUnit.SECONDS))
            assertSame(firstThread, secondThread.get())
            if (mode == 0) assertNull(secondError.get()) else assertTrue(secondError.get() is CancellationException)
            if (mode == 2) assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { calls.close() }
            else calls.close()
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
        } finally {
            retire.countDown()
            second?.join(5000)
            try { calls.close() } catch (_: RuntimeAuthorityCleanupUnprovenException) { }
            assertTrue(worker.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    @Test fun ownerCancellationBeforeRegistrationPreventsWorkButAllowsCleanup() {
        val cancelled = java.util.concurrent.atomic.AtomicBoolean(true)
        val calls = RuntimeProductionCallOwnerV1(cancelled::get)
        var invoked = false
        assertThrows(java.util.concurrent.CancellationException::class.java) { calls.run(1) { invoked = true } }
        assertFalse(invoked)
        assertEquals(7, calls.runCleanup { 7 })
        calls.close()
    }

    @Test fun ownerCancellationDuringRegistrationIsObservedByActualWorker() {
        val cancelled = java.util.concurrent.atomic.AtomicBoolean(false)
        val entered = CountDownLatch(1); val finish = CountDownLatch(1)
        val calls = RuntimeProductionCallOwnerV1(cancelled::get)
        val error = AtomicReference<Throwable?>()
        val caller = Thread {
            try { calls.run(1) { entered.countDown(); check(finish.await(5, TimeUnit.SECONDS)); assertTrue(calls.isCancelled(1)); 7 } }
            catch (failure: Throwable) { error.set(failure) }
        }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        cancelled.set(true)
        assertTrue(calls.cancel(1))
        finish.countDown(); caller.join(5000)
        assertFalse(caller.isAlive)
        assertTrue(error.get() is java.util.concurrent.CancellationException)
        calls.close()
    }
    @Test fun actualLeaseStateRejectsObservationStageRacesExpiryAndFailedRelease() {
        val before = RuntimeProductionInitialLeaseV1()
        assertFalse(before.observeCurrent({100}, { before.install(200); true }, { error("not released") }))
        assertTrue(before.observeCurrent({100}, { error("already installed") }, { error("not released") }))
        assertFalse(before.observeCurrent({200}, { error("already installed") }, { error("not released") }))
        assertTrue(before.release {
            assertFalse(before.observeCurrent({100}, { error("release in flight") }, { error("not clean") }))
            true
        })
        var reads = 0
        assertTrue(before.observeCurrent({300}, { error("no renewal") }, { reads++; true }))
        assertEquals(1, reads)
        val failed = RuntimeProductionInitialLeaseV1(); failed.install(200)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { failed.release { false } }
        assertFalse(failed.observeCurrent({100}, { error("failed") }, { error("failed") }))
        assertFalse(RuntimeProductionInitialLeaseV1().observeCurrent({100}, { false }, { error("not released") }))
    }

    @Test fun expiredInitialLeaseStillReleasesOnceOnActualCleanupWorkerWithoutAReplacementCall() {
        val calls = RuntimeProductionCallOwnerV1()
        val lease = RuntimeProductionInitialLeaseV1()
        lease.install(100)
        assertTrue(lease.isCurrent(99))
        assertFalse(lease.isCurrent(100))
        var releases = 0
        assertTrue(calls.runCleanup { lease.release { releases++; true } })
        assertTrue(lease.isReleased())
        assertFalse(lease.isCurrent(99))
        assertTrue(calls.runCleanup { lease.release { releases++; false } })
        assertEquals(1, releases)
        calls.close()
    }

    @Test fun failedInitialLeaseReleaseCannotHealOrAcquireAnotherProtectedLease() {
        val lease = RuntimeProductionInitialLeaseV1()
        lease.install(100)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { lease.release { false } }
        assertFalse(lease.isReleased())
        assertFalse(lease.isCurrent(99))
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { lease.release { true } }
        assertThrows(IllegalStateException::class.java) { lease.install(200) }
    }

    @Test fun externalCleanupUsesTheSameOwnedWorkerAndCannotBeCancelledAsNativeCallZero() {
        val calls = RuntimeProductionCallOwnerV1()
        val original = calls.run(1) { Thread.currentThread() }
        val cleanup = calls.runCleanup { assertFalse(calls.cancel(0)); Thread.currentThread() }
        assertSame(original, cleanup)
        calls.close()
    }

    @Test fun failedCleanupCannotReopenTheWorkerAdmission() {
        val calls = RuntimeProductionCallOwnerV1()
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) {
            calls.run(1) { throw RuntimeAuthorityCleanupUnprovenException() }
        }
        assertThrows(IllegalStateException::class.java) { calls.run(2) { 1 } }
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { calls.close() }
    }

    @Test fun cancelledInflightCallKeepsWorkerAndCallUntilActualReturn() {
        val entered = CountDownLatch(1); val finish = CountDownLatch(1)
        val result = AtomicReference<Throwable?>()
        val calls = RuntimeProductionCallOwnerV1()
        val caller = Thread {
            try { calls.run(0x8000000000000001UL.toLong()) { entered.countDown(); check(finish.await(5, TimeUnit.SECONDS)); 7 } }
            catch (failure: Throwable) { result.set(failure) }
        }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertFalse(calls.cancel(1))
        assertTrue(calls.cancel(0x8000000000000001UL.toLong()))
        assertTrue(caller.isAlive)
        assertThrows(IllegalStateException::class.java) { calls.run(2) { error("replacement worker") } }
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { calls.close() }
        finish.countDown(); caller.join(5000); assertFalse(caller.isAlive)
        assertTrue(result.get() is java.util.concurrent.CancellationException)
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { calls.close() }
    }

    @Test fun synchronousWorkerCannotQueueAndWaitForItself() {
        val calls = RuntimeProductionCallOwnerV1()
        assertEquals(7, calls.run(1) {
            assertThrows(IllegalStateException::class.java) { calls.run(2) { 8 } }
            7
        })
        assertFalse(calls.cancel(1))
        assertEquals(9, calls.run(2) { 9 })
        calls.close()
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.io.Closeable
import java.io.IOException
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.*

/** Host execution covers the real provider state machine, not Android Binder or pipe syscalls. */
class RuntimeAuthorityReissueServiceTest {
    private data class QuiescenceTrace(
        var poisoned: Int = 0,
        var futureBegan: Boolean = false,
        var replied: Boolean = false,
        var repliedLate: Boolean = false,
        var cleanup: String = "NOT_REQUIRED",
        var lateAuthorization: Boolean = false,
        var timedOut: Boolean = false,
        var interrupted: Boolean = false,
        var elapsedWaitMillis: Long = 0,
    ) {
        fun diagnostic(outcome: String): String =
            "KURDISTAN_QUIESCENCE_DIAGNOSTIC poisoned=$poisoned outcome=$outcome timeout=$timedOut " +
                "interruption=$interrupted thread_interrupted=${Thread.currentThread().isInterrupted} " +
                "elapsed_ms=$elapsedWaitMillis future_began=$futureBegan replied=$replied " +
                "replied_late=$repliedLate cleanup=$cleanup late_authorization=$lateAuthorization"
    }

    private enum class ControlledGet { COMPLETE, TIMEOUT, INTERRUPT }

    private class ControlledFuture<T>(
        private val callable: Callable<T>,
        private val getMode: ControlledGet,
        private val onBegin: () -> Unit,
        private val onReply: () -> Unit,
    ) : Future<T> {
        private var done = false
        private var cancelled = false
        private var value: T? = null
        private var failure: Throwable? = null

        fun runPending(): T? {
            if (!done && !cancelled) {
                onBegin()
                try { value = callable.call() } catch (caught: Throwable) { failure = caught }
                done = true
                onReply()
            }
            failure?.let { throw ExecutionException(it) }
            return value
        }

        override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
            if (done) return false
            cancelled = true
            done = true
            return true
        }
        override fun isCancelled(): Boolean = cancelled
        override fun isDone(): Boolean = done
        override fun get(): T = valueOrThrow(runPending())
        override fun get(timeout: Long, unit: TimeUnit): T = when (getMode) {
            ControlledGet.COMPLETE -> valueOrThrow(runPending())
            ControlledGet.TIMEOUT -> throw TimeoutException("synthetic bounded timeout")
            ControlledGet.INTERRUPT -> throw InterruptedException("synthetic bounded interruption")
        }

        @Suppress("UNCHECKED_CAST")
        private fun valueOrThrow(result: T?): T {
            failure?.let { throw ExecutionException(it) }
            return result as T
        }
    }

    private class ControlledExecutor : AbstractExecutorService() {
        var nextGet = ControlledGet.COMPLETE
        var onBegin: () -> Unit = {}
        var onReply: () -> Unit = {}
        var last: ControlledFuture<*>? = null
        private var shutdown = false

        override fun <T> submit(task: Callable<T>): Future<T> {
            check(!shutdown)
            return ControlledFuture(task, nextGet, onBegin, onReply).also { last = it }
        }
        override fun execute(command: Runnable) = error("test executor accepts Callable submissions only")
        override fun shutdown() { shutdown = true }
        override fun shutdownNow(): MutableList<Runnable> { shutdown = true; return mutableListOf() }
        override fun isShutdown(): Boolean = shutdown
        override fun isTerminated(): Boolean = shutdown
        override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean = shutdown
    }

    private fun assertTrace(condition: Boolean, trace: QuiescenceTrace, outcome: String) {
        assertTrue(trace.diagnostic(outcome), condition)
    }

    @Test fun boundedQuiescenceImmediatePrebindRejectionDoesNotPoison() {
        val trace = QuiescenceTrace()
        val executor = ControlledExecutor().also {
            it.onBegin = { trace.futureBegan = true }
            it.onReply = { trace.replied = true }
        }
        val admission = BoundedMutationQuiescenceAdmission({ 100L }, executor, { trace.poisoned++ }, 20L) { "a".repeat(32) }
        val started = System.nanoTime()
        val result = admission.acquire { _, _, _ -> false }
        trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrace(result == null && trace.poisoned == 0 && trace.futureBegan && trace.replied, trace, "IMMEDIATE_REJECT")
    }

    @Test fun boundedQuiescenceActualTimeoutPoisonsAndLateReplyOnlyReleases() {
        val trace = QuiescenceTrace(timedOut = true)
        val executor = ControlledExecutor().also {
            it.nextGet = ControlledGet.TIMEOUT
            it.onBegin = { trace.futureBegan = true }
            it.onReply = { trace.replied = true; trace.repliedLate = true }
        }
        val admission = BoundedMutationQuiescenceAdmission({ 100L }, executor, { trace.poisoned++ }, 20L) { "b".repeat(32) }
        val started = System.nanoTime()
        val result = admission.acquire { code, _, _ ->
            if (code == RuntimeMutationQuiescenceWire.ACQUIRE) true else {
                trace.cleanup = "RELEASED"
                true
            }
        }
        trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrace(result == null && trace.poisoned == 1 && !trace.futureBegan && !trace.replied, trace, "TIMEOUT")
        val late = checkNotNull(executor.last).runPending()
        trace.lateAuthorization = late != null
        assertTrace(late == null && trace.cleanup == "RELEASED" && !trace.lateAuthorization && trace.futureBegan && trace.repliedLate, trace, "LATE_REPLY_RELEASED")
    }

    @Test fun boundedQuiescenceInterruptionPoisonsAndPreservesThreadInterruption() {
        val trace = QuiescenceTrace(interrupted = true)
        val executor = ControlledExecutor().also { it.nextGet = ControlledGet.INTERRUPT }
        val admission = BoundedMutationQuiescenceAdmission({ 100L }, executor, { trace.poisoned++ }, 20L) { "c".repeat(32) }
        val started = System.nanoTime()
        try {
            val result = admission.acquire { _, _, _ -> true }
            trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrace(result == null && trace.poisoned == 1 && Thread.currentThread().isInterrupted, trace, "INTERRUPTED")
        } finally {
            Thread.interrupted()
        }
    }

    @Test fun boundedQuiescenceLeaseCleanupIsExactAndPreventsLateAuthorization() {
        val trace = QuiescenceTrace()
        val executor = ControlledExecutor().also {
            it.onBegin = { trace.futureBegan = true }
            it.onReply = { trace.replied = true }
        }
        val admission = BoundedMutationQuiescenceAdmission({ 100L }, executor, { trace.poisoned++ }, 20L) { "d".repeat(32) }
        var releases = 0
        val lease = admission.acquire { code, _, _ ->
            if (code == RuntimeMutationQuiescenceWire.RELEASE) releases++
            true
        }
        assertTrace(lease != null && trace.poisoned == 0, trace, "LEASE_ACQUIRED")
        checkNotNull(lease).close()
        lease.close()
        trace.cleanup = if (releases == 1) "RELEASED" else "UNPROVEN"
        assertTrace(releases == 1 && trace.poisoned == 0, trace, "LEASE_RELEASED")
    }

    @Test fun quiescenceTransportOrReleaseFailurePoisonsTheDefaultProcessAdmission() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            var poisoned = 0
            val admission = BoundedMutationQuiescenceAdmission({ 100L }, executor, { poisoned++ }, 100L) {
                "c".repeat(32)
            }
            assertThrows(IllegalStateException::class.java) {
                admission.acquire { _, _, _ -> throw java.io.IOException("peer died") }
            }
            assertEquals(1, poisoned)

            val accepted = BoundedMutationQuiescenceAdmission({ 100L }, executor, { poisoned++ }, 100L) {
                "d".repeat(32)
            }.acquire { code, _, _ -> code == RuntimeMutationQuiescenceWire.ACQUIRE }
            assertNotNull(accepted)
            assertThrows(IllegalStateException::class.java) { checkNotNull(accepted).close() }
            assertEquals(2, poisoned)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test fun defaultBackendChecksUnlockBeforeOpeningAndNeverCachesRuntimeAuthority() {
        var unlocked = false
        var opens = 0; var preparations = 0; var materialCloses = 0; var readerCloses = 0
        val backend = DefaultProcessAuthorityBackend({ unlocked }, { true }, { 100L }, {
            opens++
            object : ExistingRestorationReadOwner {
                override fun prepare(): RuntimeReissueMaterial {
                    preparations++
                    return object : RuntimeReissueMaterial {
                        override val revision = 2L
                        override val signedRetryBudget = 2
                        override val payloadLength = 1
                        override fun writeTo(output: OutputStream) { output.write(7) }
                        override fun close() { materialCloses++ }
                    }
                }
                override fun close() { readerCloses++ }
            }
        }, { _, _ -> null })
        val start = Fixture().start()
        assertNull(backend.prepare(start)); assertNull(backend.observe(start)); assertEquals(0, opens)
        unlocked = true
        assertEquals(2L, backend.observe(start)?.revision)
        val material = checkNotNull(backend.prepare(start))
        assertEquals(2, preparations); assertEquals(2, opens)
        assertEquals(1, materialCloses); assertEquals(1, readerCloses)
        material.close(); material.close()
        assertEquals(2, materialCloses); assertEquals(2, readerCloses)
    }

    @Test fun defaultBackendRetainsCleanupFailureAndStillClosesEveryOwnedReader() {
        var materialCloses = 0; var readerCloses = 0
        val backend = DefaultProcessAuthorityBackend({ true }, { true }, { 100L }, {
            object : ExistingRestorationReadOwner {
                override fun prepare(): RuntimeReissueMaterial = object : RuntimeReissueMaterial {
                    override val revision = 2L; override val signedRetryBudget = 1; override val payloadLength = 1
                    override fun writeTo(output: OutputStream) { output.write(1) }
                    override fun close() { materialCloses++; throw IOException("synthetic cleanup failure") }
                }
                override fun close() { readerCloses++ }
            }
        }, { _, _ -> null })
        val material = checkNotNull(backend.prepare(Fixture().start()))
        repeat(2) {
            try { material.close(); fail("cleanup uncertainty became clean") }
            catch (_: RuntimeAuthorityCleanupUnprovenException) { }
        }
        assertEquals(1, materialCloses); assertEquals(1, readerCloses)
        try { material.writeTo(java.io.ByteArrayOutputStream()); fail("closed authority reused") }
        catch (_: IllegalStateException) { }
    }

    @Test fun defaultBackendClosesPartialReadAndChecksAdmissionAgainBeforeTransfer() {
        var prepared = true; var readerCloses = 0; var materialCloses = 0
        val backend = DefaultProcessAuthorityBackend({ true }, { prepared }, { 100L }, {
            object : ExistingRestorationReadOwner {
                override fun prepare(): RuntimeReissueMaterial {
                    prepared = false
                    return object : RuntimeReissueMaterial {
                        override val revision = 2L; override val signedRetryBudget = 0; override val payloadLength = 1
                        override fun writeTo(output: OutputStream) { output.write(1) }
                        override fun close() { materialCloses++ }
                    }
                }
                override fun close() { readerCloses++ }
            }
        }, { _, _ -> null })
        assertNull(backend.prepare(Fixture().start()))
        assertEquals(1, materialCloses); assertEquals(1, readerCloses)
    }

    @Test fun wrongCallerAndLockedStateCannotReconstructAuthority() {
        val fixture = Fixture()
        assertFalse(fixture.adapter.bind("1".repeat(32), 1001, 20, fixture.peer) {} )
        assertTrue(fixture.bind())
        assertNull(fixture.adapter.offer(fixture.start(), 1001, 20, fixture.peer))
        fixture.backend.state = fixture.backend.state.copy(unlocked = false)
        assertNull(fixture.offer())
        assertEquals(0, fixture.backend.prepared)
    }

    @Test fun singleArmFreshRequestAndPeerIdentityCannotBeSubstituted() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        assertNull(f.adapter.offer(f.start(), 1000, 21, f.peer))
        assertNull(f.adapter.offer(f.start(), 1000, 20, Any()))
        f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
        assertNull(f.offer())
        assertEquals(1, f.backend.prepared)
    }

    @Test fun fullAndOrderedLeasesBindBothPipeRolesAndRetainActiveInvalidation() {
        val f = Fixture(); assertTrue(f.bind()); val offer = checkNotNull(f.offer())
        assertEquals(0, f.adapter.completedFullAuthorityCount())
        val full = f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30)
        assertTrue(full.accepted)
        assertEquals(1, f.adapter.completedFullAuthorityCount())
        val request = offer.request(RuntimeAuthorityPurpose.FULL_AUTHORITY, full.output.identity.descriptor("4".repeat(32), 216))
        val verified = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
            .verifyAndConsume(full.output.bytes(), request.descriptor, 100)
        assertArrayEquals(byteArrayOf(8, 9, 10), (verified as RuntimeFrameVerification.Verified).authority.takePayload())
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertEquals(1, f.backend.leaseAcquisitions)
        assertEquals(0, f.backend.leaseRegistrations)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        assertEquals(1, f.backend.leaseAcquisitions)
        assertEquals(1, f.backend.leaseRegistrations)
        assertEquals(0, f.backend.leaseCloses)
        assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
        assertFalse(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
        assertEquals(0, f.backend.leaseCloses)
        assertTrue(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
        assertTrue(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
        assertEquals(1, f.backend.leaseCloses)
        assertEquals(0, f.backend.registrationCloses)
        assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        f.backend.invalidate!!()
        assertEquals(1, f.invalidations)
        assertEquals(1, f.backend.registrationCloses)
        assertNull(f.offer())
        assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
    }

    @Test fun activeUnreleasedLeaseExpiryCancelsTheRegistrationAndLease() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))

        f.backend.leaseCurrent = false
        f.adapter.expire()

        assertEquals(1, f.invalidations)
        assertEquals(1, f.backend.registrationCloses)
        assertEquals(1, f.backend.leaseCloses)
        assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
    }

    @Test fun prematureLeaseOrChangedRevisionCannotEmitAnAuthenticatedFrame() {
        for (changed in listOf(false, true)) {
            val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
            if (changed) f.backend.state = f.backend.state.copy(revision = 4)
            val response = f.respond(if (changed) RuntimeAuthorityPurpose.FULL_AUTHORITY else RuntimeAuthorityPurpose.PRE_ACTIVE, 30)
            assertFalse(response.accepted)
            assertEquals(0, response.output.bytes().size)
            assertEquals(1, response.input.closes)
            assertEquals(1, response.output.closes)
            assertEquals(1, f.backend.materialCloses)
        }
    }

    @Test fun shortOrTrailingCapabilityAndPhysicalAliasFailClosed() {
        for (case in 0..3) {
            val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
            val input = ReadPipe(ByteArray(if (case == 0) 31 else if (case == 1) 33 else 32) { 7 },
                RuntimePipeIdentity(1, 30, 1000, 4480, 0))
            val output = WritePipe(RuntimePipeIdentity(1, if (case == 2) 30 else 31, 1000, 4480, if (case == 3) 0 else 1))
            assertFalse(f.adapter.respond("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY, "4".repeat(32), 1000, 20, f.peer, input, output))
            assertEquals(0, f.adapter.completedFullAuthorityCount())
            assertEquals(0, output.bytes().size)
            assertEquals(1, input.closes); assertEquals(1, output.closes)
        }
    }

    @Test fun timeoutAndPeerDeathInvalidateArmAndCloseOwnedMaterial() {
        for (death in listOf(false, true)) {
            val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
            if (death) f.adapter.peerDied(f.peer) else { f.time = 1000; f.adapter.expire() }
            assertEquals(1, f.backend.materialCloses)
            assertFalse(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertNull(f.offer())
            assertEquals(1, f.invalidations)
        }
    }

    @Test fun invalidMetadataNeverEscapesAndItsMaterialIsClosed() {
        val f = Fixture(); f.backend.length = 0; assertTrue(f.bind())
        assertNull(f.offer()); assertEquals(1, f.backend.materialCloses)
        assertEquals(0, f.backend.writes)
    }

    @Test fun cleanupFailurePoisonsProviderAndDoesNotAbandonRemainingOwners() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        f.backend.throwLeaseClose = true
        assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
        assertFalse(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
        assertEquals(1, f.backend.registrationCloses)
        assertTrue(f.adapter.cleanupUnproven())
        assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        f.adapter.peerDied(f.peer)
        assertEquals(1, f.backend.leaseCloses)
    }

    @Test fun activeInvalidationCleanupUnprovenKeepsSharedRevisionOwnerBlockingMutation() {
        val f = Fixture()
        val process = ProtectedStateProcessOwner { f.time }
        val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
        val finalLease = checkNotNull(registration.acquireFinalLease(2_000))
        f.backend.revisionLeaseFactory = {
            object : RuntimeProviderRevisionLease {
                override val revision: Long = finalLease.revision
                override fun isCurrent(): Boolean = finalLease.isCurrent()
                override fun registerActive(onInvalidated: () -> Unit): Closeable = finalLease.registerActive(onInvalidated)
                override fun close() = finalLease.close()
            }
        }
        f.invalidation = { throw RuntimeAuthorityCleanupUnprovenException() }
        assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)

        assertThrows(IllegalStateException::class.java) { registration.close() }

        assertTrue(f.adapter.cleanupUnproven())
        assertNull(process.registerRuntimeRevision("3".repeat(32), 2, 2))
    }

    @Test fun cancellationCannotOpenAnotherArmBeforePartialConstructionUnwinds() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        val entered = CountDownLatch(1); val resume = CountDownLatch(1)
        f.backend.beforeWrite = { entered.countDown(); check(resume.await(5, TimeUnit.SECONDS)) }
        var result: Response? = null
        val worker = Thread { result = f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30) }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        try {
            f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
            assertEquals(2, f.adapter.cancellationStatus("2".repeat(32), 1000, 20, f.peer))
            assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        } finally { resume.countDown(); worker.join(5000) }
        assertFalse(worker.isAlive)
        assertFalse(checkNotNull(result).accepted)
        assertEquals(0, checkNotNull(result).output.bytes().size)
        assertEquals(1, f.backend.materialCloses)
        assertFalse(f.adapter.cleanupUnproven())
        assertEquals(1, f.adapter.cancellationStatus("2".repeat(32), 1000, 20, f.peer))
        assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
    }

    @Test fun responseIsNotReadyUntilItsFinalPipeClosureIsProven() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        val closing = CountDownLatch(1); val finish = CountDownLatch(1)
        val input = ReadPipe(ByteArray(32) { 7 }, RuntimePipeIdentity(1, 30, 1000, 4480, 0))
        val output = WritePipe(RuntimePipeIdentity(1, 31, 1000, 4480, 1)) {
            closing.countDown(); check(finish.await(5, TimeUnit.SECONDS))
        }
        var success = false
        val thread = Thread {
            success = f.adapter.respond("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY, "4".repeat(32),
                1000, 20, f.peer, input, output)
        }.apply { isDaemon = true; start() }
        assertTrue(closing.await(5, TimeUnit.SECONDS))
        try { assertEquals(2, f.adapter.responseStatus("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY, 1000, 20, f.peer)) }
        finally { finish.countDown(); thread.join(5000) }
        assertFalse(thread.isAlive); assertTrue(success)
        assertEquals(1, f.adapter.responseStatus("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY, 1000, 20, f.peer))
    }

    @Test fun invalidationDuringFinalLeaseReleaseCannotPublishOrStrandAnArm() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        f.backend.beforeLeaseClose = { f.backend.invalidate!!() }
        assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
        assertFalse(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
        assertEquals(1, f.backend.leaseCloses); assertEquals(1, f.backend.registrationCloses)
        assertTrue(f.adapter.cleanupUnproven())
        assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
    }

    @Test fun wrongRequestCannotBorrowTheCurrentArmsPipesOrDeadline() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertNull(f.adapter.expectedDeadline("9".repeat(32), 1000, 20, f.peer))
        val input = ReadPipe(ByteArray(32) { 7 }, RuntimePipeIdentity(1, 30, 1000, 4480, 0))
        val output = WritePipe(RuntimePipeIdentity(1, 31, 1000, 4480, 1))
        assertFalse(f.adapter.respond("9".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY,
            "4".repeat(32), 1000, 20, f.peer, input, output))
        assertEquals(0, output.bytes().size)
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 40).accepted)
    }

    @Test fun cancellationBeforeOfferConsumesThatGenerationWithoutCreatingAuthority() {
        val f = Fixture(); assertTrue(f.bind())
        assertEquals(1, f.adapter.cancelStart(f.start(), 1000, 20, f.peer))
        assertNull(f.offer()); assertEquals(0, f.backend.prepared)
        assertEquals(1, f.adapter.cancelStart(f.start(), 1000, 20, f.peer))
        assertEquals(0, f.adapter.cancelStart(f.start(generation = 2), 1001, 20, f.peer))
        assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
    }

    private class Fixture {
        val backend = Backend(); val peer = Any(); var time = 100L; var invalidations = 0
        var invalidation: () -> Unit = { invalidations++ }
        private var id = 10
        val adapter = RuntimeAuthorityReissueIpcAdapter(1000, "5".repeat(32), backend, { time }) {
            (id++).toString(16).padStart(32, '0')
        }
        fun bind() = adapter.bind("1".repeat(32), 1000, 20, peer) { invalidation() }
        fun start(generation: Long = 1) = RuntimeReissueStart("1".repeat(32),
            if (generation == 1L) "2".repeat(32) else "3".repeat(32), generation, RuntimeAuthorityTrigger.MANUAL, 0, 1000)
        fun offer() = adapter.offer(start(), 1000, 20, peer)
        fun respond(purpose: RuntimeAuthorityPurpose, inode: Long): Response {
            val input = ReadPipe(ByteArray(32) { 7 }, RuntimePipeIdentity(1, inode, 1000, 4480, 0))
            val output = WritePipe(RuntimePipeIdentity(1, inode + 1, 1000, 4480, 1))
            return Response(adapter.respond("2".repeat(32), purpose, "4".repeat(32), 1000, 20, peer, input, output), input, output)
        }
    }
    private data class Response(val accepted: Boolean, val input: ReadPipe, val output: WritePipe)
    private class Backend : RuntimeAuthorityReissueBackend {
        var state = RuntimeAuthorityProviderState(true, true, true, 2, 2)
        var length = 3; var prepared = 0; var writes = 0; var materialCloses = 0
        var leaseCloses = 0; var leaseRegistrations = 0; var registrationCloses = 0; var leaseAcquisitions = 0
        var throwLeaseClose = false; var leaseCurrent = true; var invalidate: (() -> Unit)? = null
        var revisionLeaseFactory: (() -> RuntimeProviderRevisionLease)? = null
        var beforeWrite: (() -> Unit)? = null
        var beforeLeaseClose: (() -> Unit)? = null
        override fun observe(start: RuntimeReissueStart) = state
        override fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial {
            prepared++
            return object : RuntimeReissueMaterial {
                override val revision = 2L
                override val signedRetryBudget = 2
                override val payloadLength get() = length
                override fun writeTo(output: OutputStream) { writes++; beforeWrite?.invoke(); output.write(byteArrayOf(8, 9, 10)) }
                override fun close() { materialCloses++ }
            }
        }
        override fun acquireRevisionLease(request: RuntimeAuthorityRequest): RuntimeProviderRevisionLease {
            revisionLeaseFactory?.let { return it() }
            leaseAcquisitions++
            return object : RuntimeProviderRevisionLease {
            override val revision = 2L
            override fun isCurrent() = leaseCurrent && state.revision == revision
            override fun registerActive(onInvalidated: () -> Unit): Closeable {
                leaseRegistrations++; invalidate = onInvalidated
                return Closeable { registrationCloses++ }
            }
            override fun close() { leaseCloses++; beforeLeaseClose?.invoke(); if (throwLeaseClose) throw IOException("synthetic close uncertainty") }
            }
        }
    }
    private class ReadPipe(private val bytes: ByteArray, override val identity: RuntimePipeIdentity) : RuntimeReissueReadPipe {
        var closes = 0; private var cursor = 0
        override fun read(target: ByteArray, offset: Int, count: Int): Int {
            if (cursor == bytes.size) return -1
            val n = minOf(3, count, bytes.size - cursor); bytes.copyInto(target, offset, cursor, cursor + n); cursor += n; return n
        }
        override fun close() { closes++ }
    }
    private class WritePipe(override val identity: RuntimePipeIdentity, private val beforeClose: () -> Unit = {}) : RuntimeReissueWritePipe {
        private val written = java.io.ByteArrayOutputStream(); var closes = 0
        fun bytes() = written.toByteArray()
        override fun write(source: ByteArray, offset: Int, count: Int): Int {
            val n = minOf(7, count); written.write(source, offset, n); return n
        }
        override fun close() { closes++; beforeClose() }
    }
}

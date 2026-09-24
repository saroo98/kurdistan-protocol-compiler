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
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner
import org.kurdistanvpn.data.protectedstate.AuthorityReadFailure
import org.kurdistanvpn.data.protectedstate.AuthorityReadResult
import org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.*

/** Host execution covers the real provider state machine, not Android Binder or pipe syscalls. */
class RuntimeAuthorityReissueServiceTest {
    @Test fun publicationExpiryPendingCleanupKeepsRegistrationUntilActualRetirement() {
        for (completed in listOf(false, true)) ProductionRegistrationFixture().use { p ->
            assertTrue(p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            if (completed) assertEquals(3000L, p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            p.f.invalidation = { throw RuntimeAuthorityPeerCleanupPendingException() }
            p.f.time = 3000
            if (completed) p.f.adapter.expire()
            else assertNull(p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            assertFalse(p.f.adapter.cleanupUnproven())
            assertEquals(1, p.registrations())
            assertEquals(2, p.f.adapter.cancellationStatus("2".repeat(32), 1000, 20, p.f.peer))
            assertNull(p.f.adapter.offer(p.f.start(2), 1000, 20, p.f.peer))
            assertEquals(2, p.f.adapter.releaseProductionLease("2".repeat(32), 1000, 20, p.f.peer))
            assertEquals(2, p.f.adapter.cancelStart(p.f.start(), 1000, 20, p.f.peer))
            assertEquals(0, p.f.adapter.cancelStart(p.f.start(), 1000, 21, Any(), retired = true))
            assertEquals(1, p.registrations())
            assertEquals(1, p.f.adapter.cancelStart(p.f.start(), 1000, 20, p.f.peer, retired = true))
            assertEquals(0, p.registrations())
            assertFalse(p.f.adapter.cleanupUnproven())
            assertNotNull(p.f.adapter.offer(p.f.start(2), 1000, 20, p.f.peer))
            p.f.adapter.cancel("3".repeat(32), 1000, 20, p.f.peer)
        }
    }
    @Test fun pendingReplyCannotHideOwnedFailureOrDeferPublishedSessionCleanup() {
        for (published in listOf(false, true)) {
            val p = ProductionRegistrationFixture()
            try {
                assertTrue(p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
                assertEquals(3000L, p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
                if (published) assertTrue(p.f.adapter.releaseLease("2".repeat(32), 1000, 20, p.f.peer))
                else p.failFacadeClose = true
                p.f.invalidation = { throw RuntimeAuthorityPeerCleanupPendingException() }
                p.f.adapter.connectionClosed(p.f.peer)
                assertTrue(p.f.adapter.cleanupUnproven())
                assertEquals(0, p.f.adapter.releaseProductionLease("2".repeat(32), 1000, 20, p.f.peer))
                assertEquals(0, p.f.adapter.cancelStart(p.f.start(), 1000, 20, p.f.peer, retired = true))
                assertTrue(p.f.adapter.cleanupUnproven())
            } finally { runCatching { p.close() } }
        }
    }
    @Test fun expirySelectedBeforeSuccessfulReleaseDoesNotCancelActiveRegistration() {
        ProductionRegistrationFixture().use { p ->
            assertTrue(p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(3000L, p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            val selected = CountDownLatch(1)
            val resume = CountDownLatch(1)
            val expiry = java.util.concurrent.FutureTask { p.f.adapter.expire() }
            val timer = Thread(expiry, "selected-expiry")
            p.f.clock = {
                if (Thread.currentThread() === timer) {
                    selected.countDown()
                    check(resume.await(5, TimeUnit.SECONDS))
                    3000L
                } else p.f.time
            }
            try {
                timer.start()
                assertTrue(selected.await(5, TimeUnit.SECONDS))
                assertTrue(p.f.adapter.releaseLease("2".repeat(32), 1000, 20, p.f.peer))
                resume.countDown()
                expiry.get(5, TimeUnit.SECONDS)
                assertEquals(0, p.f.invalidations)
                assertEquals(1, p.registrations())
                assertEquals(1, p.facadeCloses)
                assertFalse(p.f.adapter.cleanupUnproven())
                p.f.adapter.cancel("2".repeat(32), 1000, 20, p.f.peer)
                assertEquals(0, p.registrations())
            } finally {
                resume.countDown()
                timer.join(5000)
            }
        }
    }

    @Test fun confirmedPeerDeathRetiresAuthorityWithoutCallingTheDeadProcess() {
        val f = Fixture()
        assertTrue(f.bind()); assertNotNull(f.offer())
        f.invalidation = { throw IOException("Dead peer") }
        f.adapter.peerDied(f.peer)
        assertEquals(1, f.backend.materialCloses)
        assertFalse(f.adapter.cleanupUnproven())
        assertTrue(f.adapter.bind("9".repeat(32), 1000, 21, Any()) { })
        assertFalse(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
    }
    @Test fun productionExpiryTimerDoesNotRepeatPublicationValidation() {
        for (expireAtDeadline in listOf(false, true)) ProductionRegistrationFixture().use { p ->
            assertTrue(p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(3000L, p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            assertEquals(1, p.validations)
            for (time in listOf(1100L, 1200L, 2999L)) {
                p.f.time = time
                p.f.adapter.expire()
                assertEquals(1, p.validations)
                assertEquals(0, p.facadeCloses)
            }
            if (expireAtDeadline) {
                p.f.time = 3000
                p.f.adapter.expire()
                assertEquals(1, p.validations)
                assertEquals(1, p.f.invalidations)
                assertEquals(0, p.registrations())
            } else {
                assertTrue(p.f.adapter.releaseLease("2".repeat(32), 1000, 20, p.f.peer))
                assertEquals(2, p.validations)
                p.f.adapter.cancel("2".repeat(32), 1000, 20, p.f.peer)
            }
            assertEquals(1, p.facadeCloses)
            assertFalse(p.f.adapter.cleanupUnproven())
        }
    }

    @Test fun productionFreshRegistrationAvoidsDuplicateValidationWithinActualLease() {
        val f = Fixture().apply { time = 1000; deadline = 60000 }
        val process = ProtectedStateProcessOwner { f.time }
        var validations = 0; var facadeCloses = 0
        f.productionBackend.payload = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,12,13,14,15)
        f.productionBackend.length = 37
        f.productionBackend.revisionLeaseFactory = {
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(3000))
            ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ },
                publicationDeadlineElapsedMillis = 3000) {
                validations++; f.time += 600; lease.isCurrent()
            }
        }
        try {
            assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) { f.invalidation() })
            assertNotNull(f.offer()); assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            val observations = f.productionBackend.observations
            f.productionBackend.beforeObserve = { f.time += 600 }
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(observations + 1, f.productionBackend.observations)
            assertEquals(3000L, f.adapter.completeProduction("2".repeat(32), 1000, 20, f.peer))
            // With a duplicate PRE_ACTIVE reconstruction, this real release expires at 3400.
            assertTrue(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
            assertEquals(2800L, f.time); assertEquals(2, validations)
            assertEquals(1, facadeCloses)
            f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
            assertEquals(0, (reflected(process, "registrations") as Set<*>).size)
            assertFalse(f.adapter.cleanupUnproven())
        } finally { process.close() }
    }

    @Test fun productionFreshRegistrationRejectsExpiredOrInvalidatedLeaseAfterObservation() {
        for (expired in listOf(false, true)) ProductionRegistrationFixture().use { p ->
            val observed = p.f.productionBackend.observations
            val result = p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50) {
                assertEquals(observed + 1, p.f.productionBackend.observations)
                if (expired) p.f.time = 3000 else checkNotNull(p.registration).close()
            }
            assertFalse(result.accepted); assertEquals(0, result.output.bytes().size)
            assertEquals(0, p.validations); assertEquals(1, p.facadeCloses)
            assertEquals(1, result.input.closes); assertEquals(1, result.output.closes)
            assertEquals(0, p.registrations()); assertFalse(p.f.adapter.cleanupUnproven())
            assertNull(p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
        }
    }

    @Test fun productionFreshRegistrationExternalChangeCannotPassComplete() {
        ProductionRegistrationFixture().use { p ->
            val result = p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50) { p.externalCurrent = false }
            // Callback registration is not usable publication. COMPLETE must still reread trust.
            assertTrue(result.accepted); assertEquals(0, p.validations)
            assertNull(p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            assertEquals(1, p.validations); assertEquals(1, p.facadeCloses)
            assertEquals(0, p.registrations()); assertFalse(p.f.adapter.cleanupUnproven())
            assertFalse(p.f.adapter.releaseLease("2".repeat(32), 1000, 20, p.f.peer))
        }
    }

    @Test fun productionFreshRegistrationStillRequiresFreshRelease() {
        ProductionRegistrationFixture().use { p ->
            assertTrue(p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(3000L, p.f.adapter.completeProduction("2".repeat(32), 1000, 20, p.f.peer))
            assertEquals(1, p.validations)
            p.externalCurrent = false
            assertFalse(p.f.adapter.releaseLease("2".repeat(32), 1000, 20, p.f.peer))
            assertEquals(2, p.validations); assertEquals(1, p.facadeCloses)
            assertEquals(0, p.registrations()); assertFalse(p.f.adapter.cleanupUnproven())
        }
    }

    @Test fun productionFreshRegistrationObservationFailureNeverRegisters() {
        for (unclean in listOf(false, true)) ProductionRegistrationFixture().use { p ->
            p.failFacadeClose = unclean
            p.f.productionBackend.beforeObserve = {
                if (unclean) throw RuntimeAuthorityCleanupUnprovenException()
                p.f.productionBackend.state = p.f.productionBackend.state.copy(revision = 3)
            }
            val result = p.f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50)
            assertFalse(result.accepted); assertEquals(0, result.output.bytes().size)
            assertEquals(0, p.validations); assertEquals(1, p.facadeCloses)
            assertEquals(0, p.registrations())
            assertEquals(unclean, p.f.adapter.cleanupUnproven())
            if (unclean) assertNull(p.f.adapter.offer(p.f.start(generation = 2), 1000, 20, p.f.peer))
        }
    }

    @Test fun productionFreshRegistrationGenericImplementationKeepsFullFallback() {
        for (reject in listOf(false, true)) {
            val f = Fixture().apply { deadline = 60000 }
            var registrations = 0; var closes = 0
            f.productionBackend.payload = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,12,13,14,15)
            f.productionBackend.length = 37
            f.productionBackend.revisionLeaseFactory = {
                object : RuntimeProviderRevisionLease {
                    override val revision = 2L
                    override fun isCurrent() = true
                    override fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable {
                        registrations++
                        check(!reject)
                        return Closeable { onRetired(true) }
                    }
                    override fun close() { closes++ }
                }
            }
            assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) { f.invalidation() })
            assertNotNull(f.offer()); assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertEquals(!reject, f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(1, registrations)
            f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
            assertEquals(1, closes); assertEquals(reject, f.adapter.cleanupUnproven())
        }
    }

    @Test fun cancelAcknowledgementRequiresActualLeaseAndRegistrationCleanupBeforeLocalInstall() {
        for (failClose in listOf(false, true)) {
            val f = Fixture()
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
            assertEquals(0, f.backend.leaseCloses); assertEquals(0, f.backend.registrationCloses)
            f.backend.throwLeaseClose = failClose
            assertEquals(if (failClose) 0 else 1, f.adapter.cancelStart(f.start(), 1000, 20, f.peer))
            assertEquals(1, f.backend.leaseCloses)
            assertEquals(failClose, f.adapter.cleanupUnproven())
            if (!failClose) {
                assertEquals(1, f.backend.registrationCloses)
                assertEquals(1, f.adapter.cancelStart(f.start(), 1000, 20, f.peer))
                assertEquals(1, f.backend.leaseCloses); assertEquals(1, f.backend.registrationCloses)
            } else assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        }
    }
    @Test fun productionCompletionCarriesTheSameActualProtectedDeadlineAfterDelayedPreTun() {
        val f = Fixture().apply { time = 1000; deadline = 60000 }
        val process = ProtectedStateProcessOwner { f.time }
        var actualLease: RuntimeProviderRevisionLease? = null
        var validations = 0; var facadeCloses = 0
        f.productionBackend.payload = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,12,13,14,15)
        f.productionBackend.length = 37
        f.productionBackend.revisionLeaseFactory = {
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val deadline = f.time + 2000
            val lease = checkNotNull(registration.acquireFinalLease(deadline))
            ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ },
                publicationDeadlineElapsedMillis = deadline) { validations++; lease.isCurrent() }.also { actualLease = it }
        }
        try {
            assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) { f.invalidation() })
            assertNotNull(f.offer()); assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            f.productionBackend.beforeObserve = { f.time = 1500 }
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            f.productionBackend.beforeObserve = null
            assertEquals(3500L, actualLease?.publicationDeadlineElapsedMillis)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(0, validations)
            f.time = 3296
            assertNull(f.adapter.completeProduction("9".repeat(32), 1000, 20, f.peer))
            assertNull(f.adapter.completeProduction("2".repeat(32), 1001, 20, f.peer))
            assertEquals(3500L, f.adapter.completeProduction("2".repeat(32), 1000, 20, f.peer))
            assertEquals(1, validations)
            assertNull(f.adapter.completeProduction("2".repeat(32), 1000, 20, f.peer))
            f.time = 3500
            assertFalse(checkNotNull(actualLease).isCurrent())
            assertFalse(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
            assertEquals(1, facadeCloses)
            assertFalse(f.adapter.cleanupUnproven())
        } finally { process.close() }
    }

    @Test fun productionRejectedCleanupRemainsUnprovenAtFinalTransfer() {
        rejectedResultAtFinalTransfer(true, AuthorityReadFailure.CLEANUP_UNPROVEN)
    }

    @Test fun legacyRejectedCleanupRemainsUnprovenAtFinalTransfer() {
        rejectedResultAtFinalTransfer(false, AuthorityReadFailure.CLEANUP_UNPROVEN)
    }

    @Test fun ordinaryRejectedResultsRemainDefiniteAtFinalTransfer() {
        for (production in listOf(false, true)) {
            for (category in AuthorityReadFailure.entries.filter { it != AuthorityReadFailure.CLEANUP_UNPROVEN }) {
                rejectedResultAtFinalTransfer(production, category)
            }
        }
    }

    private fun rejectedResultAtFinalTransfer(production: Boolean, category: AuthorityReadFailure) {
        val f = Fixture().apply { deadline = 60_000 }
        val process = ProtectedStateProcessOwner { f.time }
        var validations = 0; var facadeCloses = 0
        f.backend.revisionLeaseFactory = {
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(f.time + 2_000))
            ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ }) {
                validations++
                if (production) ProductionCaptureReadResult.Rejected(category).readyForFinalValidation() != null
                else AuthorityReadResult.Rejected(category).readyForFinalValidation() != null
            }
        }
        try {
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertEquals(0, validations)
            val result = f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50)
            assertFalse(result.accepted)
            assertEquals(1, validations)
            assertEquals(11L, f.adapter.responseDiagnosticSnapshot()[0])
            assertEquals(0, result.output.bytes().size)
            assertEquals(1, result.input.closes); assertEquals(1, result.output.closes)
            assertEquals(1, facadeCloses)
            assertEquals(0, (reflected(process, "registrations") as Set<*>).size)
            val uncertain = category == AuthorityReadFailure.CLEANUP_UNPROVEN
            assertEquals(uncertain, f.adapter.cleanupUnproven())
            if (uncertain) {
                f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
                assertTrue(f.adapter.cleanupUnproven())
                assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
            }
        } finally { process.close() }
    }

    @Test fun freshResponseObservationAvoidsDuplicateCaptureButFinalCompleteAndReleaseStayFresh() {
        val f = Fixture().apply { deadline = 60_000 }
        val process = ProtectedStateProcessOwner { f.time }
        var validations = 0
        f.backend.revisionLeaseFactory = {
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(f.time + 2_000))
            ApplicationRevisionLease(registration, lease, AutoCloseable {}) { validations++; true }
        }
        try {
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            val observations = f.backend.observations
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertEquals(0, validations)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertEquals(1, validations)
            assertEquals(observations + 2, f.backend.observations)
            assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
            assertEquals(2, validations)
            assertTrue(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
            assertEquals(3, validations)
            f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
            assertFalse(f.adapter.cleanupUnproven())
        } finally { process.close() }
    }

    @Test fun definiteFinalValidationRejectionProvesCleanupWithoutInstalling() {
        for (expired in listOf(false, true)) {
            val f = Fixture().apply { deadline = 60_000 }
            val process = ProtectedStateProcessOwner { f.time }
            var reject = false; var facadeCloses = 0
            f.backend.revisionLeaseFactory = {
                val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
                val lease = checkNotNull(registration.acquireFinalLease(f.time + 2_000))
                ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ }) {
                    if (reject && expired) { f.time += 2_001; true } else !reject
                }
            }
            try {
                assertTrue(f.bind()); assertNotNull(f.offer())
                assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
                assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
                reject = true
                val result = f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50)
                assertFalse(result.accepted)
                assertEquals(2L, f.adapter.responseDiagnosticSnapshot()[1])
                assertEquals(0, result.output.bytes().size)
                assertEquals(1, result.input.closes); assertEquals(1, result.output.closes)
                assertEquals(1, facadeCloses)
                assertEquals(0, (reflected(process, "registrations") as Set<*>).size)
                assertFalse(f.adapter.cleanupUnproven())
            } finally { process.close() }
        }
    }

    @Test fun replayedForeignOrUnprovenValidationCannotHideUncertainRegistration() {
        for (mode in 0..2) {
            val foreign = mode == 1
            val f = Fixture().apply { deadline = 60_000 }
            val process = ProtectedStateProcessOwner { f.time }
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(f.time + 2_000))
            var allowed = false; var replay: Throwable? = null
            val wrapper = ApplicationRevisionLease(registration, lease, AutoCloseable {}) {
                replay?.let { throw it }; allowed
            }
            val first = assertThrows(IllegalStateException::class.java) { wrapper.registerActive({}) }
            allowed = true
            f.backend.revisionLeaseFactory = {
                if (foreign) object : RuntimeProviderRevisionLease by wrapper {
                    override fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable = throw first
                } else wrapper
            }
            try {
                assertTrue(f.bind()); assertNotNull(f.offer())
                assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
                assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
                if (!foreign) replay = if (mode == 2) RuntimeAuthorityCleanupUnprovenException() else first
                assertFalse(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
                assertTrue(f.adapter.cleanupUnproven())
                assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
            } finally { process.close() }
        }
    }

    @Test fun responseFailureObservationIsBoundedAndPreservesClosure() {
        for (boundary in listOf(6L, 8L, 12L, 13L)) {
            val f = Fixture()
            val production = boundary == 12L
            val backend = if (production) f.productionBackend else f.backend
            if (production) { backend.length = 37; backend.payload = ByteArray(37) }
            assertTrue(if (production) f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {} else f.bind())
            assertNotNull(f.offer())
            if (boundary == 8L) backend.beforeWrite = { throw IOException("synthetic material failure") }
            val input = ReadPipe(ByteArray(if (boundary == 6L) 31 else 32) { 7 }, RuntimePipeIdentity(1, 30, 1000, 4480, 0))
            val output = WritePipe(RuntimePipeIdentity(1, 31, 1000, 4480, 1))
            val actualOutput = if (boundary == 13L) object : RuntimeReissueWritePipe by output {
                override fun write(source: ByteArray, offset: Int, count: Int): Int = throw IOException("synthetic output failure")
            } else output
            assertFalse(f.adapter.respond("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY,
                "4".repeat(32), 1000, 20, f.peer, input, actualOutput))
            val observed = f.adapter.responseDiagnosticSnapshot()
            assertEquals(10, observed.size)
            assertArrayEquals(longArrayOf(0, 0, 0), observed.drop(7).toLongArray())
            assertEquals(-1L, observed[6])
            assertEquals(boundary, observed[0])
            assertEquals(if (boundary == 6L) 1L else if (boundary == 12L) 2L else 3L, observed[1])
            assertTrue(observed[2] in 1L..6L)
            assertTrue(observed[3] in 1L..10_000L)
            assertEquals(1L, observed[4]); assertEquals(0L, observed[5])
            observed.fill(999)
            assertEquals(boundary, f.adapter.responseDiagnosticSnapshot()[0])
            assertEquals(1, input.closes); assertEquals(1, output.closes)
            assertEquals(1, backend.materialCloses)
            assertFalse(f.adapter.cleanupUnproven())
        }
    }

    @Test fun successfulResponseObservationDoesNotManufactureAFailure() {
        val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertArrayEquals(longArrayOf(17, 0, -1, -1, 1, 0, -1, 0, 0, 0), f.adapter.responseDiagnosticSnapshot())
        assertEquals(1, f.adapter.completedFullAuthorityCount())
    }

    @Test fun realFinalLeaseExpiryDuringPreActiveObservationRecordsItsAgeWithoutRenewal() {
        val f = Fixture().apply { deadline = 60_000 }
        val process = ProtectedStateProcessOwner { f.time }
        var facadeCloses = 0
        f.backend.revisionLeaseFactory = {
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(f.time + 2_000))
            ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ }) { true }
        }
        try {
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            f.backend.beforeObserve = { f.time += 2_001 }
            val rejected = f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50)
            assertFalse(rejected.accepted)
            val diagnostic = f.adapter.responseDiagnosticSnapshot()
            assertEquals(11L, diagnostic[0]); assertEquals(1L, diagnostic[1])
            assertEquals(2_001L, diagnostic[6])
            assertEquals(1L, diagnostic[4]); assertEquals(0L, diagnostic[5])
            assertEquals(1, rejected.input.closes); assertEquals(1, rejected.output.closes)
            assertEquals(1, facadeCloses)
            assertFalse(f.adapter.cleanupUnproven())
        } finally { process.close() }
    }

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

    private data class QuiescenceOutcome<T>(
        val completedNormally: Boolean,
        val value: T?,
        val failure: Throwable?,
    ) {
        fun category(): String = when {
            !completedNormally -> "THREW_${failure?.javaClass?.simpleName ?: "UNKNOWN"}"
            value == null -> "NORMAL_NULL"
            else -> "NORMAL_VALUE"
        }
    }

    private fun <T> captureQuiescenceOutcome(block: () -> T): QuiescenceOutcome<T> = try {
        QuiescenceOutcome(completedNormally = true, value = block(), failure = null)
    } catch (failure: Throwable) {
        QuiescenceOutcome(completedNormally = false, value = null, failure = failure)
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
        val outcome = captureQuiescenceOutcome { admission.acquire { _, _, _ -> false } }
        trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrace(
            outcome.completedNormally && outcome.value == null && outcome.failure == null &&
                trace.poisoned == 0 && trace.futureBegan && trace.replied,
            trace,
            outcome.category(),
        )
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
        val outcome = captureQuiescenceOutcome {
            admission.acquire { code, _, _ ->
                if (code == RuntimeMutationQuiescenceWire.ACQUIRE) true else {
                    trace.cleanup = "RELEASED"
                    true
                }
            }
        }
        trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
        assertTrace(
            outcome.completedNormally && outcome.value == null && outcome.failure == null &&
                trace.poisoned == 1 && !trace.futureBegan && !trace.replied,
            trace,
            outcome.category(),
        )
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
            val outcome = captureQuiescenceOutcome { admission.acquire { _, _, _ -> true } }
            trace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
            assertTrace(
                outcome.completedNormally && outcome.value == null && outcome.failure == null &&
                    trace.poisoned == 1 && Thread.currentThread().isInterrupted,
                trace,
                outcome.category(),
            )
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
        val transportTrace = QuiescenceTrace()
        val transportExecutor = ControlledExecutor().also {
            it.onBegin = { transportTrace.futureBegan = true }
            it.onReply = { transportTrace.replied = true }
        }
        val transportAdmission = BoundedMutationQuiescenceAdmission(
            { 100L },
            transportExecutor,
            { transportTrace.poisoned++ },
            20L,
        ) { "c".repeat(32) }
        val transportStarted = System.nanoTime()
        val transportOutcome = captureQuiescenceOutcome {
            transportAdmission.acquire { _, _, _ -> throw IOException("peer died") }
        }
        transportTrace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - transportStarted)
        val transportFailure = transportOutcome.failure
        assertTrace(
            !transportOutcome.completedNormally && transportOutcome.value == null &&
                transportFailure is IllegalStateException &&
                transportFailure.message == "MUTATION_QUIESCENCE_TRANSPORT_UNPROVEN" &&
                transportFailure.cause is IOException && transportFailure.cause?.message == "peer died" &&
                transportTrace.poisoned == 1 && transportTrace.futureBegan && transportTrace.replied &&
                !transportTrace.timedOut && !transportTrace.interrupted && !transportTrace.repliedLate &&
                transportTrace.cleanup == "NOT_REQUIRED" && !transportTrace.lateAuthorization,
            transportTrace,
            transportOutcome.category(),
        )

        val releaseTrace = QuiescenceTrace()
        val releaseExecutor = ControlledExecutor().also {
            it.onBegin = { releaseTrace.futureBegan = true }
            it.onReply = { releaseTrace.replied = true }
        }
        var releaseCalls = 0
        val acceptedOutcome = captureQuiescenceOutcome {
            BoundedMutationQuiescenceAdmission(
                { 100L },
                releaseExecutor,
                { releaseTrace.poisoned++ },
                20L,
            ) { "d".repeat(32) }.acquire { code, _, _ ->
                if (code == RuntimeMutationQuiescenceWire.RELEASE) {
                    releaseCalls++
                    releaseTrace.cleanup = "RELEASE_REJECTED"
                    false
                } else {
                    true
                }
            }
        }
        assertTrace(
            acceptedOutcome.completedNormally && acceptedOutcome.value != null && acceptedOutcome.failure == null &&
                releaseTrace.poisoned == 0,
            releaseTrace,
            acceptedOutcome.category(),
        )
        val releaseStarted = System.nanoTime()
        val releaseOutcome = captureQuiescenceOutcome { checkNotNull(acceptedOutcome.value).close() }
        releaseTrace.elapsedWaitMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - releaseStarted)
        val releaseFailure = releaseOutcome.failure
        assertTrace(
            !releaseOutcome.completedNormally && releaseOutcome.value == null &&
                releaseFailure is IllegalStateException &&
                releaseFailure.message == "MUTATION_QUIESCENCE_RELEASE_UNPROVEN" &&
                releaseCalls == 1 && releaseTrace.poisoned == 1 && releaseTrace.futureBegan && releaseTrace.replied &&
                !releaseTrace.timedOut && !releaseTrace.interrupted && !releaseTrace.repliedLate &&
                releaseTrace.cleanup == "RELEASE_REJECTED" && !releaseTrace.lateAuthorization,
            releaseTrace,
            releaseOutcome.category(),
        )
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

    @Test fun productionProtocolCannotRenegotiateAnExistingBinderOrArm() {
        val f = Fixture()
        assertTrue(f.bind())
        assertFalse(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {})
        assertFalse(f.adapter.bindProduction("6".repeat(32), 1000, 20, f.peer) {})
        assertNotNull(f.offer())
        assertFalse(f.adapter.bindProduction("6".repeat(32), 1000, 20, Any()) {})
        assertTrue(f.adapter.acceptsProtocol(1000, 20, f.peer, 2))
        assertFalse(f.adapter.acceptsProtocol(1000, 20, f.peer, 3))
    }

    @Test fun productionPrepublicationCurrentIsExactFreshAndNeverAcquiresOrRenews() {
        fun prepared(): Pair<Fixture, RuntimeProductionAuthorityOfferV1> {
            val f = Fixture()
            f.productionBackend.payload = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,12,13,14,15)
            f.productionBackend.length = 37
            assertTrue(f.adapter.bindProduction("1".repeat(32),1000,20,f.peer){f.invalidation()})
            val offer = RuntimeProductionAuthorityOfferV1(checkNotNull(f.offer()))
            assertFalse(f.adapter.prepublicationCurrent(offer,500,1000,20,f.peer))
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY,30).accepted)
            return f to offer
        }
        val (f, offer) = prepared()
        val before = f.productionBackend.observations
        assertTrue(f.adapter.prepublicationCurrent(offer,500,1000,20,f.peer))
        assertTrue(f.adapter.prepublicationCurrent(offer,600,1000,20,f.peer))
        assertEquals(before+2,f.productionBackend.observations)
        assertEquals(0,f.productionBackend.leaseAcquisitions)
        assertFalse(f.adapter.registeredCurrent(offer,500,1000,20,f.peer))
        assertFalse(f.adapter.prepublicationCurrent(offer,500,1001,20,f.peer))
        assertFalse(f.adapter.prepublicationCurrent(offer,500,1000,21,f.peer))
        assertFalse(f.adapter.prepublicationCurrent(offer,500,1000,20,Any()))
        assertFalse(f.adapter.prepublicationCurrent(RuntimeProductionAuthorityOfferV1(offer.offer.copy(revision=4)),500,1000,20,f.peer))
        assertFalse(f.adapter.prepublicationCurrent(offer,100,1000,20,f.peer))
        assertFalse(f.adapter.prepublicationCurrent(offer,60101,1000,20,f.peer))
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN,40).accepted)
        assertFalse(f.adapter.prepublicationCurrent(offer,500,1000,20,f.peer))
        assertEquals(1,f.productionBackend.leaseAcquisitions)
        for (change in 0..4) {
            val (changed, exact) = prepared()
            changed.productionBackend.beforeObserve = {
                when(change) {
                    0 -> changed.time=1000
                    1 -> changed.productionBackend.state=changed.productionBackend.state.copy(revision=4)
                    2 -> changed.productionBackend.state=changed.productionBackend.state.copy(signedRetryBudget=3)
                    3 -> changed.productionBackend.state=changed.productionBackend.state.copy(unlocked=false)
                    else -> changed.adapter.cancelStart(changed.start(),1000,20,changed.peer)
                }
            }
            assertFalse("race $change",changed.adapter.prepublicationCurrent(exact,1500,1000,20,changed.peer))
            assertEquals(0,changed.productionBackend.leaseAcquisitions)
        }
    }

    @Test fun productionRegisteredCurrentRequiresCleanReleaseAndFreshBoundedDeadline() {
        var time = 100L; var reads = 0; var freshDeadline = 0L
        val process = ProtectedStateProcessOwner { time }
        val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
        val lease = checkNotNull(registration.acquireFinalLease(200))
        val wrapper = ApplicationRevisionLease(registration, lease, AutoCloseable {},
            { deadline -> reads++; freshDeadline = deadline; true }) { true }
        assertFalse(wrapper.isRegisteredCurrent(300))
        val active = wrapper.registerActive({})
        assertFalse(wrapper.isRegisteredCurrent(300))
        wrapper.close()
        assertFalse(wrapper.isCurrent())
        time = 1000
        assertTrue(wrapper.isRegisteredCurrent(2000))
        assertEquals(1, reads); assertEquals(2000L, freshDeadline)
        active.close()
        assertFalse(wrapper.isRegisteredCurrent(2000))
        assertEquals(1, reads)
        process.close()
    }

    @Test fun productionArmSelectsKctBackendAndAuthenticatesVersionThreeOnly() {
        val f = Fixture()
        f.productionBackend.payload = byteArrayOf(75, 67, 84, 49, 1, 0, 0, 0,
            0, 0, 0, 37, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
            11, 12, 13, 14, 15)
        f.productionBackend.length = 37
        assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {})
        assertFalse(f.bind())
        val offer = checkNotNull(f.offer())
        assertEquals(37, offer.payloadLength)
        assertEquals("profile-1", checkNotNull(offer.presentation).profileId)
        assertTrue(offer.sameAuthority(offer.copy(presentation = null)))
        assertFalse(offer.sameAuthority(offer.copy(revision = 4, presentation = null)))
        val full = f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30)
        assertTrue(full.accepted)
        assertEquals(0, f.backend.prepared)
        assertEquals(1, f.productionBackend.prepared)
        val request = offer.request(RuntimeAuthorityPurpose.FULL_AUTHORITY,
            full.output.identity.descriptor("4".repeat(32), 251))
        val verified = RuntimeProductionAuthorityFrameCodecV1.verifier(ByteArray(32) { 7 },
            RuntimeProductionAuthorityRequestV1(request)).verifyAndConsume(full.output.bytes(), request.descriptor, 100)
        assertTrue(verified is RuntimeProductionFrameVerificationV1.Verified)
        (verified as RuntimeProductionFrameVerificationV1.Verified).authority.close()
        assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
            .verifyAndConsume(full.output.bytes(), request.descriptor, 100) is RuntimeFrameVerification.Rejected)
    }

    @Test fun productionRegisteredCurrentBracketsExactReleasedArmWithFreshDeadline() {
        val f = Fixture()
        f.productionBackend.payload = byteArrayOf(75, 67, 84, 49, 1, 0, 0, 0,
            0, 0, 0, 37, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
            11, 12, 13, 14, 15)
        f.productionBackend.length = 37
        assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {})
        val offer = checkNotNull(f.offer())
        val exact = RuntimeProductionAuthorityOfferV1(offer)
        assertFalse(f.adapter.registeredCurrent(exact, 2000, 1000, 20, f.peer))
        assertArrayEquals(longArrayOf(1, 32, 0), f.adapter.responseDiagnosticSnapshot().drop(7).toLongArray())
        for (purpose in RuntimeAuthorityPurpose.entries) assertTrue(f.respond(purpose, 30L + purpose.wire * 2).accepted)
        assertTrue(f.adapter.complete(offer.start.requestId, 1000, 20, f.peer))
        assertFalse(f.adapter.registeredCurrent(exact, 2000, 1000, 20, f.peer))
        assertTrue(f.adapter.releaseLease(offer.start.requestId, 1000, 20, f.peer))
        f.time = 1500
        assertTrue(f.adapter.registeredCurrent(exact, 2000, 1000, 20, f.peer))
        assertEquals(1, f.productionBackend.leaseAcquisitions)
        assertFalse(f.adapter.registeredCurrent(exact, 1500, 1000, 20, f.peer))
        assertFalse(f.adapter.registeredCurrent(exact, 61501, 1000, 20, f.peer))
        assertFalse(f.adapter.registeredCurrent(RuntimeProductionAuthorityOfferV1(offer.copy(revision = 4)), 2000, 1000, 20, f.peer))
        assertFalse(f.adapter.registeredCurrent(exact, 2000, 1000, 21, f.peer))
        f.productionBackend.beforeRegisteredRead = { f.productionBackend.invalidate!!() }
        assertFalse(f.adapter.registeredCurrent(exact, 2000, 1000, 20, f.peer))
        assertFalse(f.adapter.registeredCurrent(exact, 2000, 1000, 20, f.peer))
        assertArrayEquals(longArrayOf(1, 32, 0), f.adapter.responseDiagnosticSnapshot().drop(7).toLongArray())
    }

    @Test fun productionRegisteredCurrentCleanupFailureCannotBecomeCleanCancellation() {
        val f = Fixture()
        f.productionBackend.payload = byteArrayOf(75, 67, 84, 49, 1, 0, 0, 0,
            0, 0, 0, 37, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
            11, 12, 13, 14, 15)
        f.productionBackend.length = 37
        assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {})
        val offer = checkNotNull(f.offer())
        for (purpose in RuntimeAuthorityPurpose.entries) assertTrue(f.respond(purpose, 40L + purpose.wire * 2).accepted)
        assertTrue(f.adapter.complete(offer.start.requestId, 1000, 20, f.peer))
        assertTrue(f.adapter.releaseLease(offer.start.requestId, 1000, 20, f.peer))
        f.productionBackend.beforeRegisteredRead = { throw RuntimeAuthorityCleanupUnprovenException() }
        assertFalse(f.adapter.registeredCurrent(RuntimeProductionAuthorityOfferV1(offer), 500, 1000, 20, f.peer))
        assertTrue(f.adapter.cleanupUnproven())
        assertArrayEquals(longArrayOf(3, 0, 1), f.adapter.responseDiagnosticSnapshot().drop(7).toLongArray())
        assertNull(f.adapter.offer(f.start(2), 1000, 20, f.peer))
    }

    @Test fun registeredDiagnosticSeparatesBusyFromActualObservationException() {
        for (exception in listOf(false, true)) {
            val f = Fixture()
            f.productionBackend.payload = byteArrayOf(75, 67, 84, 49, 1, 0, 0, 0,
                0, 0, 0, 37, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0,
                11, 12, 13, 14, 15)
            f.productionBackend.length = 37
            assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) {})
            val offer = checkNotNull(f.offer())
            for (purpose in RuntimeAuthorityPurpose.entries) assertTrue(f.respond(purpose, 60L + purpose.wire * 2).accepted)
            assertTrue(f.adapter.complete(offer.start.requestId, 1000, 20, f.peer))
            assertTrue(f.adapter.releaseLease(offer.start.requestId, 1000, 20, f.peer))
            val exact = RuntimeProductionAuthorityOfferV1(offer)
            f.productionBackend.beforeRegisteredRead = {
                if (exception) throw IllegalStateException("not emitted")
                assertFalse(f.adapter.registeredCurrent(exact, 500, 1000, 20, f.peer))
            }
            assertEquals(!exception, f.adapter.registeredCurrent(exact, 500, 1000, 20, f.peer))
            assertArrayEquals(if (exception) longArrayOf(3, 0, 4) else longArrayOf(1, 64, 0),
                f.adapter.responseDiagnosticSnapshot().drop(7).toLongArray())
            f.adapter.cancel(offer.start.requestId, 1000, 20, f.peer)
            assertArrayEquals(if (exception) longArrayOf(3, 0, 4) else longArrayOf(1, 64, 0),
                f.adapter.responseDiagnosticSnapshot().drop(7).toLongArray())
        }
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
            assertEquals(if (death) 0 else 1, f.invalidations)
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
        assertEquals(0, f.backend.registrationCloses)
        assertTrue(f.adapter.cleanupUnproven())
        assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        f.adapter.peerDied(f.peer)
        assertEquals(1, f.backend.leaseCloses)
    }

    @Test fun synchronousInvalidationDuringApplicationTransferReconcilesTheLateHandle() {
        for (failPeer in listOf(false, true)) {
            val f = Fixture()
            // Response status, fresh transfer pre/post checks, then protected install check.
            val validated = CountDownLatch(4)
            val installing = java.util.concurrent.atomic.AtomicBoolean(false)
            val process = ProtectedStateProcessOwner {
                if (installing.get()) validated.countDown()
                f.time
            }
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(2_000))
            var facadeCloses = 0
            val wrapper = ApplicationRevisionLease(registration, lease, AutoCloseable { facadeCloses++ }) { true }
            f.backend.revisionLeaseFactory = { wrapper }
            f.invalidation = {
                f.invalidations++
                // Cross-thread call must finish: installation cannot hold the wrapper lock
                // across the real synchronous callback, even before the handle is returned.
                val released = CountDownLatch(1)
                val observer = Thread { assertFalse(wrapper.isCurrent()); released.countDown() }
                    .apply { isDaemon = true; start() }
                check(released.await(5, TimeUnit.SECONDS)); observer.join(5000)
                if (failPeer) throw RuntimeAuthorityCleanupUnprovenException()
            }
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            val invalidationOwner = reflected(registration, "invalidation")
            var response: Response? = null
            val worker = Thread { response = f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50) }
                .apply { isDaemon = true }
            synchronized(reflected(invalidationOwner, "monitor")) {
                installing.set(true); worker.start()
                assertTrue(validated.await(5, TimeUnit.SECONDS))
                // Real retirement wins after the protected final validation but before
                // callback installation. The existing late-install branch must fire.
                lease.close()
                val policy = reflected(process, "policy")
                val writer = policy.javaClass.getDeclaredMethod("beginMutation").invoke(policy) as AutoCloseable?
                checkNotNull(writer).close()
            }
            worker.join(5000); assertFalse(worker.isAlive)
            assertFalse(checkNotNull(response).accepted)
            assertEquals(0, checkNotNull(response).output.bytes().size)
            assertEquals(1, facadeCloses); assertEquals(1, f.invalidations)
            assertEquals(failPeer, f.adapter.cleanupUnproven())
            if (failPeer) assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
            else assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
            assertEquals(0, (reflected(process, "registrations") as Set<*>).size)
            wrapper.close(); process.close()
        }
    }

    @Test fun realProtectedWriterWaitsForPeerReturnAndFailedPeerKeepsItBlocked() {
        for (failPeer in listOf(false, true)) for (secondCancel in listOf(false, true)) {
            val f = Fixture(); val process = ProtectedStateProcessOwner { f.time }
            val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
            val lease = checkNotNull(registration.acquireFinalLease(2_000))
            f.backend.revisionLeaseFactory = { ApplicationRevisionLease(registration, lease, AutoCloseable { }) { true } }
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
            assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
            assertTrue(f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
            val entered = CountDownLatch(1); val release = CountDownLatch(1); val returned = CountDownLatch(1)
            f.invalidation = {
                f.invalidations++; entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
                if (failPeer) throw RuntimeAuthorityCleanupUnprovenException()
            }
            val policy = reflected(process, "policy")
            var writer: AutoCloseable? = null
            val worker = Thread {
                writer = policy.javaClass.getDeclaredMethod("beginMutation").invoke(policy) as AutoCloseable?
                returned.countDown()
            }.apply { isDaemon = true; start() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            try {
                assertEquals(1L, returned.count)
                assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
                assertEquals(1, (reflected(process, "registrations") as Set<*>).size)
                if (secondCancel) {
                    f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
                    assertTrue(f.adapter.cleanupUnproven())
                    assertNotNull(reflected(f.adapter, "arm"))
                    assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
                }
            } finally { release.countDown(); worker.join(5000) }
            assertFalse(worker.isAlive); assertEquals(1, f.invalidations)
            if (failPeer || secondCancel) {
                assertNull(writer); assertTrue(f.adapter.cleanupUnproven())
                assertEquals(1, (reflected(policy, "owners") as Map<*, *>).size)
                assertThrows(IllegalStateException::class.java) { registration.close() }
            } else {
                assertNotNull(writer); writer!!.close(); assertFalse(f.adapter.cleanupUnproven())
                assertEquals(0, (reflected(policy, "owners") as Map<*, *>).size)
                assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
                registration.close()
            }
            process.close()
        }
    }

    private fun reflected(value: Any, name: String): Any = checkNotNull(value.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.get(value))

    @Test fun successfulRealProtectedInvalidationRetiresRegistrationWithoutSelfClose() {
        val f = Fixture()
        val process = ProtectedStateProcessOwner { f.time }
        val registration = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2))
        val lease = checkNotNull(registration.acquireFinalLease(2_000))
        f.backend.revisionLeaseFactory = {
            ApplicationRevisionLease(registration, lease, AutoCloseable { }) { true }
        }
        assertTrue(f.bind()); assertNotNull(f.offer())
        assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        registration.close()
        assertEquals(1, f.invalidations)
        assertFalse(f.adapter.cleanupUnproven())
        assertNotNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
        registration.close(); process.close()
    }

    @Test fun peerNotificationMustReturnBeforeAnotherArmCanBeAdmitted() {
        for (failPeer in listOf(false, true)) {
            val f = Fixture(); assertTrue(f.bind()); assertNotNull(f.offer())
            val entered = CountDownLatch(1); val release = CountDownLatch(1)
            f.invalidation = {
                entered.countDown(); check(release.await(5, TimeUnit.SECONDS))
                if (failPeer) throw RuntimeAuthorityCleanupUnprovenException()
            }
            val worker = Thread { f.adapter.connectionClosed(f.peer) }.apply { isDaemon = true; start() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            try {
                assertEquals(2, f.adapter.cancellationStatus("2".repeat(32), 1000, 20, f.peer))
                assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
                f.adapter.cancel("2".repeat(32), 1000, 20, f.peer)
                assertNull(f.adapter.offer(f.start(generation = 2), 1000, 20, f.peer))
            } finally { release.countDown(); worker.join(5000) }
            assertFalse(worker.isAlive)
            assertTrue(f.adapter.cleanupUnproven())
        }
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
                override fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable =
                    finalLease.registerActive(onInvalidated, onRetired)
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
        try {
            assertEquals(2, f.adapter.responseStatus("2".repeat(32), RuntimeAuthorityPurpose.FULL_AUTHORITY, 1000, 20, f.peer))
            assertEquals(0L, f.adapter.responseDiagnosticSnapshot()[4])
        }
        finally { finish.countDown(); thread.join(5000) }
        assertFalse(thread.isAlive); assertTrue(success)
        assertEquals(1L, f.adapter.responseDiagnosticSnapshot()[4])
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
        assertEquals(1, f.backend.leaseCloses); assertEquals(0, f.backend.registrationCloses)
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

    @Test fun publicationDiagnosticKeepsCompleteAndReleaseFailuresSeparate() {
        fun page(f: Fixture): LongArray = runCatching {
            val method = f.adapter.javaClass.declaredMethods.single { it.name.startsWith("responseDiagnosticSnapshot") && it.parameterCount == 1 }
            method.isAccessible = true
            method.invoke(f.adapter, 1) as LongArray
        }.getOrElse { LongArray(24) { -1 } }
        fun prepared(): Fixture = Fixture().also { f ->
            assertTrue(f.bind()); assertNotNull(f.offer())
            assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_ACTIVE, 50).accepted)
        }
        val complete = prepared()
        complete.backend.leaseCurrent = false
        assertFalse(complete.adapter.complete("2".repeat(32), 1000, 20, complete.peer))
        val failedComplete = page(complete)
        assertEquals(4L, failedComplete[4]); assertEquals(1L, failedComplete[5])
        assertEquals(0L, failedComplete[7]); assertEquals(-1L, failedComplete[8])
        assertEquals(1, complete.backend.leaseCloses)
        for (mode in 0..3) {
            val f = prepared()
            assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
            when (mode) {
                1 -> {
                    f.backend.leaseCurrent = false
                    // The only close happens later in cancelArm, after the false-current record.
                    f.backend.beforeLeaseClose = { assertEquals(4L, page(f)[12]) }
                }
                2 -> f.backend.throwLeaseClose = true
                3 -> f.backend.beforeLeaseClose = { f.adapter.cancel("2".repeat(32), 1000, 20, f.peer) }
            }
            assertEquals(mode == 0, f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer))
            val result = page(f)
            assertEquals(24, result.size)
            assertEquals(7L, result[4]); assertEquals(1L, result[9])
            assertEquals(listOf(7L, 4L, 5L, 6L)[mode], result[12])
            assertEquals(if (mode == 0) 0L else 1L, result[13])
            assertEquals(if (mode == 1) -1L else if (mode == 2) 2L else 0L, result[16])
            assertEquals(1, f.backend.leaseCloses)
            assertTrue(result.copyOfRange(20, 24).all { it == -1L })
        }
        for (release in listOf(false, true)) {
            val f = prepared()
            if (release) assertTrue(f.adapter.complete("2".repeat(32), 1000, 20, f.peer))
            f.backend.beforeLeaseCurrent = { throw IOException("not emitted") }
            val result = if (release) f.adapter.releaseLease("2".repeat(32), 1000, 20, f.peer)
                else f.adapter.complete("2".repeat(32), 1000, 20, f.peer)
            assertFalse(result)
            val offset = if (release) 12 else 4
            val observed = page(f)
            assertEquals(4L, observed[offset]); assertEquals(2L, observed[offset + 1])
            assertEquals(5L, observed[offset + 6]); assertEquals(-1L, observed[offset + 4])
            assertEquals(1, f.backend.leaseCloses)
        }
        val expiredBeforeTransition = prepared()
        expiredBeforeTransition.backend.beforeLeaseCurrent = { expiredBeforeTransition.time = 1001 }
        assertFalse(expiredBeforeTransition.adapter.complete("2".repeat(32), 1000, 20, expiredBeforeTransition.peer))
        assertEquals(6L, page(expiredBeforeTransition)[4])
        assertEquals(1L, page(expiredBeforeTransition)[7])
        assertEquals(901L, page(expiredBeforeTransition)[6])
    }

    /** Real protected lease/registration; only external reconstruction is controlled here. */
    private inner class ProductionRegistrationFixture : AutoCloseable {
        val f = Fixture().apply { time = 1000; deadline = 60000 }
        val process = ProtectedStateProcessOwner { f.time }
        var registration: org.kurdistanvpn.data.protectedstate.ProtectedRuntimeRevisionRegistration? = null
        var validations = 0; var facadeCloses = 0
        var externalCurrent = true; var failFacadeClose = false
        init {
            f.productionBackend.payload = byteArrayOf(75,67,84,49,1,0,0,0,0,0,0,37,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,1,0,0,0,0,11,12,13,14,15)
            f.productionBackend.length = 37
            f.productionBackend.revisionLeaseFactory = {
                val owned = checkNotNull(process.registerRuntimeRevision("1".repeat(32), 1, 2)).also { registration = it }
                val lease = checkNotNull(owned.acquireFinalLease(3000))
                ApplicationRevisionLease(owned, lease, AutoCloseable {
                    facadeCloses++; if (failFacadeClose) throw IOException("owned cleanup failure")
                }, publicationDeadlineElapsedMillis = 3000) { validations++; externalCurrent && lease.isCurrent() }
            }
            assertTrue(f.adapter.bindProduction("1".repeat(32), 1000, 20, f.peer) { f.invalidation() })
            assertNotNull(f.offer()); assertTrue(f.respond(RuntimeAuthorityPurpose.FULL_AUTHORITY, 30).accepted)
            assertTrue(f.respond(RuntimeAuthorityPurpose.PRE_TUN, 40).accepted)
        }
        fun registrations() = (reflected(process, "registrations") as Set<*>).size
        override fun close() = process.close()
    }

    private class Fixture {
        val backend = Backend(); val productionBackend = Backend(); val peer = Any(); var time = 100L; var invalidations = 0
        var deadline = 1000L
        var clock: () -> Long = { time }
        var invalidation: () -> Unit = { invalidations++ }
        private var id = 10
        val adapter = RuntimeAuthorityReissueIpcAdapter(1000, "5".repeat(32), backend, { clock() }, productionBackend) {
            (id++).toString(16).padStart(32, '0')
        }
        fun bind() = adapter.bind("1".repeat(32), 1000, 20, peer) { invalidation() }
        fun start(generation: Long = 1) = RuntimeReissueStart("1".repeat(32),
            if (generation == 1L) "2".repeat(32) else "3".repeat(32), generation, RuntimeAuthorityTrigger.MANUAL, 0, deadline)
        fun offer() = adapter.offer(start(), 1000, 20, peer)
        fun respond(purpose: RuntimeAuthorityPurpose, inode: Long, beforeRead: () -> Unit = {}): Response {
            val input = ReadPipe(ByteArray(32) { 7 }, RuntimePipeIdentity(1, inode, 1000, 4480, 0), beforeRead)
            val output = WritePipe(RuntimePipeIdentity(1, inode + 1, 1000, 4480, 1))
            return Response(adapter.respond("2".repeat(32), purpose, "4".repeat(32), 1000, 20, peer, input, output), input, output)
        }
    }
    private data class Response(val accepted: Boolean, val input: ReadPipe, val output: WritePipe)
    private class Backend : RuntimeAuthorityReissueBackend {
        var beforeObserve: (() -> Unit)? = null
        var observations = 0
        var state = RuntimeAuthorityProviderState(true, true, true, 2, 2)
        var length = 3; var prepared = 0; var writes = 0; var materialCloses = 0
        var payload = byteArrayOf(8, 9, 10)
        var leaseCloses = 0; var leaseRegistrations = 0; var registrationCloses = 0; var leaseAcquisitions = 0
        var throwLeaseClose = false; var leaseCurrent = true; var invalidate: (() -> Unit)? = null
        var revisionLeaseFactory: (() -> RuntimeProviderRevisionLease)? = null
        var beforeWrite: (() -> Unit)? = null
        var beforeLeaseClose: (() -> Unit)? = null
        var beforeLeaseCurrent: (() -> Unit)? = null
        var beforeRegisteredRead: (() -> Unit)? = null
        override fun observe(start: RuntimeReissueStart): RuntimeAuthorityProviderState { observations++; beforeObserve?.invoke(); return state }
        override fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial {
            prepared++
            return object : RuntimeReissueMaterial {
                override val revision = 2L
                override val signedRetryBudget = 2
                override val payloadLength get() = length
                override val presentation = RuntimeProfilePresentation("profile-1", 3u, 2, 1)
                override fun writeTo(output: OutputStream) { writes++; beforeWrite?.invoke(); output.write(payload) }
                override fun close() { materialCloses++ }
            }
        }
        override fun acquireRevisionLease(request: RuntimeAuthorityRequest): RuntimeProviderRevisionLease {
            revisionLeaseFactory?.let { return it() }
            leaseAcquisitions++
            return object : RuntimeProviderRegisteredRevisionLease {
            override val revision = 2L
            override fun isCurrent(): Boolean { beforeLeaseCurrent?.invoke(); return leaseCurrent && state.revision == revision }
            override fun isRegisteredCurrent(observationDeadlineElapsedMillis: Long): Boolean {
                beforeRegisteredRead?.invoke()
                return state.revision == revision
            }
            override fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable {
                var retired = false
                val retire = { if (!retired) { retired = true; registrationCloses++; onRetired(true) } }
                leaseRegistrations++; invalidate = {
                    try { onInvalidated(); retire() } catch (failure: Throwable) { onRetired(false); throw failure }
                }
                return Closeable { retire() }
            }
            override fun close() { leaseCloses++; beforeLeaseClose?.invoke(); if (throwLeaseClose) throw IOException("synthetic close uncertainty") }
            }
        }
    }
    private class ReadPipe(private val bytes: ByteArray, override val identity: RuntimePipeIdentity,
        private val beforeRead: () -> Unit = {}) : RuntimeReissueReadPipe {
        var closes = 0; private var cursor = 0; private var started = false
        override fun read(target: ByteArray, offset: Int, count: Int): Int {
            if (!started) { started = true; beforeRead() }
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

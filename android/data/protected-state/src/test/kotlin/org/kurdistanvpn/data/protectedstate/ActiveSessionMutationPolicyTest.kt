// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test

class ActiveSessionMutationPolicyTest {
    @Test fun quiescenceCleanupUncertaintyPermanentlyRejectsFurtherMutationAdmission() {
        var acquires = 0
        val owner = ProtectedStateProcessOwner({
            acquires++
            AutoCloseable { error("synthetic remote release uncertainty") }
        }) { 100L }
        try {
            val first = checkNotNull(owner.mutationPolicy().reserveMutation())
            assertThrows(IllegalStateException::class.java) { first.close() }
            // A timed-out/dead Binder may still hold a remote lease.  It cannot be retried or
            // reinterpreted as clean by a subsequent security mutation.
            assertNull(owner.mutationPolicy().reserveMutation())
            assertEquals(1, acquires)
        } finally {
            try { owner.close() } catch (_: Throwable) { }
        }
    }

    @Test fun reconstructedProcessOwnerRequiresQuiescenceProofBeforeItCanReserveDirtyMutation() {
        val oldProcess = ProtectedStateProcessOwner { 100L }
        val registration = checkNotNull(oldProcess.registerRuntimeRevision("2a".repeat(16), 1, 2))
        val lease = checkNotNull(registration.acquireFinalLease(200))
        lease.registerActive { }

        var oldAttemptClean = false
        var releases = 0
        val reconstructedProcess = ProtectedStateProcessOwner({
            if (!oldAttemptClean) null else AutoCloseable { releases++ }
        }) { 100L }
        try {
            // A fresh in-memory policy cannot make the missing VPN-process owner CLEAN.
            assertNull(reconstructedProcess.mutationPolicy().reserveMutation())
            oldAttemptClean = true
            reconstructedProcess.mutationPolicy().reserveMutation()!!.close()
            assertEquals(1, releases)
        } finally {
            reconstructedProcess.close()
            oldProcess.close()
        }
    }

    @Test fun processOwnerKeepsFinalLeaseUntilReleaseAndClosesEveryRegistration() {
        var now = 100L
        val owner = ProtectedStateProcessOwner { now }
        val first = checkNotNull(owner.registerRuntimeRevision("20".repeat(16), 1, 2))
        val lease = checkNotNull(first.acquireFinalLease(200))
        assertTrue(lease.isCurrent())
        var firstInvalidations = 0
        lease.registerActive { firstInvalidations++ }

        val second = checkNotNull(owner.registerRuntimeRevision("21".repeat(16), 1, 4))
        val secondLease = checkNotNull(second.acquireFinalLease(200))
        var secondInvalidations = 0
        secondLease.registerActive { secondInvalidations++ }

        lease.close()
        assertFalse(lease.isCurrent())
        assertTrue(secondLease.isCurrent())
        owner.close()

        assertEquals(1, firstInvalidations)
        assertEquals(1, secondInvalidations)
        assertFalse(secondLease.isCurrent())
        now = 201
        assertFalse(secondLease.isCurrent())
    }

    @Test fun processOwnerRetainsUnprovenCallbackFailureWhileClosingOtherRegistrations() {
        val owner = ProtectedStateProcessOwner { 100L }
        val bad = checkNotNull(owner.registerRuntimeRevision("22".repeat(16), 1, 2))
        checkNotNull(bad.acquireFinalLease(200)).registerActive { error("synthetic invalidation failure") }
        val good = checkNotNull(owner.registerRuntimeRevision("23".repeat(16), 1, 4))
        var goodInvalidations = 0
        checkNotNull(good.acquireFinalLease(200)).registerActive { goodInvalidations++ }

        assertThrows(IllegalStateException::class.java) { owner.close() }
        assertEquals(1, goodInvalidations)
        assertThrows(IllegalStateException::class.java) { owner.close() }
    }

    @Test fun liveFinalLeaseExcludesMutationUntilReleaseOrExpiry() {
        var now = 100L
        val policy = ActiveSessionMutationPolicy { now }
        var closes = 0
        val session = policy.register("18".repeat(16), 1, 2, AutoCloseable { closes++ })!!
        val lease = policy.acquireFinalLease(session, 2, 200)!!

        assertTrue(lease.validate(2))
        assertNull(policy.reserveMutation())
        assertNull(policy.beginMutation())
        assertEquals(0, closes)

        lease.close()
        policy.beginMutation()!!.use { assertEquals(1, closes) }

        val renewed = policy.register("19".repeat(16), 1, 4, AutoCloseable {})!!
        val expiring = policy.acquireFinalLease(renewed, 4, 120)!!
        now = 121
        assertFalse(expiring.validate(4))
        assertNotNull(policy.reserveMutation())
    }

    @Test fun reservationExcludesNewAndFinalAdmissionButDoesNotRetireOrCleanOwners() {
        val policy = ActiveSessionMutationPolicy { 100 }
        var closes = 0
        val session = policy.register("10".repeat(16), 1, 2, AutoCloseable { closes++ })!!
        val final = policy.acquireFinalLease(session, 2, 200)!!
        final.close()
        policy.reserveMutation()!!.use { reservation ->
            assertEquals(0, closes)
            assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
            assertFalse(final.validate(2))
            assertNull(policy.reserveMutation())
            assertNull(policy.acquireFinalLease(session, 2, 200))
            var rejectedCloses = 0
            assertNull(policy.register("11".repeat(16), 1, 2, AutoCloseable { rejectedCloses++ }))
            assertEquals(1, rejectedCloses)
            assertEquals(0, closes)
        }
        assertEquals(0, closes)
        session.close()
        session.close()
        assertEquals(1, closes)
    }

    @Test fun reservationOnlyBecomesUsableAfterInternallyProvenRetirementAndCannotRepeatIt() {
        val policy = ActiveSessionMutationPolicy { 100 }
        var closes = 0
        policy.register("12".repeat(16), 1, 2, AutoCloseable { closes++ })!!
        val reservation = policy.reserveMutation()!!
        assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
        reservation.retirePriorOwners()
        reservation.requireCurrent()
        assertEquals(1, closes)
        assertThrows(IllegalStateException::class.java) { reservation.retirePriorOwners() }
        assertEquals(1, closes)
        reservation.close()
        assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
        assertThrows(IllegalStateException::class.java) { reservation.retirePriorOwners() }
    }

    @Test fun unprovenRetirementKeepsReservationClosedToAdmissionAndRetriesOnlyOwnedGuard() {
        val policy = ActiveSessionMutationPolicy { 100 }
        var attempts = 0
        policy.register("13".repeat(16), 1, 2, AutoCloseable {
            attempts++
            if (attempts == 1) error("synthetic retry-safe guard has unfinished children")
        })!!
        policy.reserveMutation()!!.use { reservation ->
            assertThrows(IllegalStateException::class.java) { reservation.retirePriorOwners() }
            assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
            assertNull(policy.reserveMutation())
            assertNull(policy.register("14".repeat(16), 1, 2, AutoCloseable {}))
            reservation.retirePriorOwners()
            reservation.requireCurrent()
            assertEquals(2, attempts)
            assertEquals(listOf(ActiveSessionMutationPolicy.CleanupFailure.OWNER_CLEANUP_UNPROVEN), policy.failures())
        }
    }

    @Test fun reentrantRetirementCannotAuthorizeCleanupOrReleaseTheCurrentReservation() {
        val policy = ActiveSessionMutationPolicy { 100 }
        lateinit var reservation: ActiveSessionMutationPolicy.MutationReservation
        var closes = 0
        policy.register("15".repeat(16), 1, 2, AutoCloseable {
            closes++
            assertThrows(IllegalStateException::class.java) { reservation.retirePriorOwners() }
            assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
            assertNull(policy.reserveMutation())
        })!!
        reservation = policy.reserveMutation()!!
        reservation.retirePriorOwners()
        reservation.requireCurrent()
        assertEquals(1, closes)
        reservation.close()
    }

    @Test fun closingDuringRetirementCannotReleaseAdmissionUntilTheCallbackReturns() {
        val policy = ActiveSessionMutationPolicy { 100 }
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        policy.register("16".repeat(16), 1, 2, AutoCloseable {
            entered.countDown()
            check(release.await(2, java.util.concurrent.TimeUnit.SECONDS))
        })!!
        val reservation = policy.reserveMutation()!!
        val thread = Thread {
            try { reservation.retirePriorOwners() } catch (caught: Throwable) { failure.set(caught) }
        }.also { it.start() }
        assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
        try {
            reservation.close()
            reservation.close()
            assertNull(policy.reserveMutation())
            assertNull(policy.register("17".repeat(16), 1, 2, AutoCloseable {}))
            assertThrows(IllegalStateException::class.java) { reservation.requireCurrent() }
        } finally { release.countDown(); thread.join(2000) }
        assertFalse(thread.isAlive)
        assertTrue(failure.get() is IllegalStateException)
        val current = policy.reserveMutation()!!
        reservation.close()
        assertNull(policy.reserveMutation())
        assertThrows(IllegalStateException::class.java) { reservation.retirePriorOwners() }
        current.retirePriorOwners()
        current.requireCurrent()
        current.close()
    }

    @Test fun invalidEpochAndUncommittedRevisionNeverAcquireSessionAuthority() {
        val invalid = listOf(
            Triple("00".repeat(16), 1L, 2L),
            Triple("01".repeat(16), 1L, 0L),
            Triple("01".repeat(16), 0L, 2L),
            Triple("01".repeat(16), -1L, 2L),
            Triple("01".repeat(16), 1L, -2L),
            Triple("01".repeat(16), 1L, 3L),
            Triple("01".repeat(15), 1L, 2L),
            Triple("0G".repeat(16), 1L, 2L),
        )
        for ((epoch, generation, revision) in invalid) {
            var closes = 0
            val policy = ActiveSessionMutationPolicy { 100 }
            val session = policy.register(epoch, generation, revision, AutoCloseable { closes++ })
            assertNull("invalid session identity was admitted", session)
            assertEquals(1, closes)
            policy.beginMutation()!!.close()
            assertEquals(1, closes)
        }
    }

    @Test fun rejectedIdentityCleanupFailureRemainsOwnedUntilProvenClean() {
        var closes = 0
        val policy = ActiveSessionMutationPolicy { 100 }
        assertNull(policy.register("00".repeat(16), 1, 2, AutoCloseable {
            closes++
            if (closes < 3) error("synthetic incomplete cleanup")
        }))
        assertEquals(1, closes)
        assertNull(policy.register("02".repeat(16), 1, 2, AutoCloseable {}))
        assertNull(policy.beginMutation())
        assertEquals(2, closes)
        policy.beginMutation()!!.close()
        assertEquals(3, closes)
        assertEquals(2, policy.failures().size)
    }

    @Test fun positiveCommittedRevisionAndMaximumGenerationRetainTheirExactBinding() {
        val policy = ActiveSessionMutationPolicy { 100 }
        val revision = Long.MAX_VALUE - 1
        val session = policy.register("00".repeat(15) + "01", Long.MAX_VALUE, revision, AutoCloseable {})!!
        val lease = policy.acquireFinalLease(session, revision, 200)!!
        assertTrue(lease.validate(revision))
        assertFalse(lease.validate(revision - 2))
        assertFalse(lease.validate(revision))
        session.close()
    }

    @Test fun cleanupDoesNotHoldThePolicyMonitorAndConcurrentMutationCannotSlipThrough() {
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val policy = ActiveSessionMutationPolicy { 100 }
        val session = policy.register("09".repeat(16), 1, 2, AutoCloseable {
            entered.countDown()
            check(release.await(2, java.util.concurrent.TimeUnit.SECONDS))
        })!!
        val final = policy.acquireFinalLease(session, 2, 200)!!
        final.close()
        var writer: ActiveSessionMutationPolicy.MutationLease? = null
        val thread = Thread { writer = policy.beginMutation() }.also { it.start() }
        assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
        try {
            assertFalse(final.validate(2))
            assertNull(policy.beginMutation())
            assertNull(policy.register("0a".repeat(16), 1, 2, AutoCloseable {}))
        } finally { release.countDown(); thread.join(2000) }
        assertFalse(thread.isAlive)
        assertNotNull(writer)
        writer!!.close()
    }

    @Test fun foreignSessionAndOldWriterHandleCannotReleaseOrValidateCurrentAuthority() {
        val first = ActiveSessionMutationPolicy { 100 }
        val second = ActiveSessionMutationPolicy { 100 }
        val session = first.register("0b".repeat(16), 1, 2, AutoCloseable {})!!
        assertNull(second.acquireFinalLease(session, 2, 200))
        val old = first.beginMutation()!!
        old.close()
        val current = first.beginMutation()!!
        old.close()
        assertNull(first.beginMutation())
        current.close()
        assertNotNull(first.beginMutation())
    }

    @Test fun mutationRetiresTheActualOwnerBeforeItCanAcquireWriterAdmission() {
        var stops = 0
        val policy = ActiveSessionMutationPolicy { 100 }
        val session = policy.register("01".repeat(16), 1, 2, AutoCloseable { stops++ })!!
        val final = policy.acquireFinalLease(session, 2, 200)!!
        assertTrue(final.validate(2))
        assertNull(policy.beginMutation())
        final.close()
        policy.beginMutation()!!.use {
            assertEquals(1, stops)
            assertFalse(final.validate(2))
            assertNull(policy.acquireFinalLease(session, 2, 200))
        }
        final.close()
        session.close()
        assertEquals(1, stops)
    }

    @Test fun throwingCleanupRetainsFailureAndCannotPermitMutationOrActivation() {
        var attempts = 0
        val policy = ActiveSessionMutationPolicy { 100 }
        val session = policy.register("02".repeat(16), 1, 2, AutoCloseable {
            attempts++; if (attempts == 1) error("retryable owned cleanup")
        })!!
        val final = policy.acquireFinalLease(session, 2, 200)!!
        final.close()
        assertNull(policy.beginMutation())
        assertFalse(final.validate(2))
        assertTrue(policy.failures().isNotEmpty())
        // Retry invokes the same idempotent owner, not a newly fabricated resource.
        policy.beginMutation()!!.close()
        assertEquals(2, attempts)
        assertFalse(final.validate(2))
    }

    @Test fun expiredOrWrongRevisionLeaseCannotCommitAndTerminalLeaseCannotBeReused() {
        var now = 100L
        val policy = ActiveSessionMutationPolicy { now }
        val session = policy.register("03".repeat(16), 1, 2, AutoCloseable {})!!
        val lease = policy.acquireFinalLease(session, 2, 120)!!
        assertFalse(lease.validate(4))
        assertFalse(lease.validate(2))
        assertNull(policy.acquireFinalLease(session, 2, 120))
        now = 121
        assertFalse(lease.validate(2))
        lease.close()
    }

    @Test fun oneFinalLeasePerSessionAndNewAdmissionIsRejectedDuringMutation() {
        val policy = ActiveSessionMutationPolicy { 100 }
        val session = policy.register("04".repeat(16), 1, 2, AutoCloseable {})!!
        val final = policy.acquireFinalLease(session, 2, 120)!!
        assertNull(policy.acquireFinalLease(session, 2, 120))
        final.close()
        var rejectedOwnerClosed = false
        policy.beginMutation()!!.use {
            assertNull(policy.register("05".repeat(16), 1, 2, AutoCloseable { rejectedOwnerClosed = true }))
            assertNull(policy.beginMutation())
        }
        assertTrue(rejectedOwnerClosed)
    }

    @Test fun allOwnersAreRetiredEvenWhenOneCleanupFails() {
        var first = 0; var second = 0
        val policy = ActiveSessionMutationPolicy { 100 }
        policy.register("06".repeat(16), 1, 2, AutoCloseable { first++; error("uncertain") })
        policy.register("07".repeat(16), 1, 2, AutoCloseable { second++ })
        assertNull(policy.beginMutation())
        assertEquals(1, first); assertEquals(1, second)
        assertNull(policy.beginMutation())
        assertEquals(2, first); assertEquals(1, second)
    }

    @Test fun duplicateIdentityDoesNotReplaceAnExistingOwner() {
        var first = 0; var duplicate = 0
        val policy = ActiveSessionMutationPolicy { 100 }
        policy.register("08".repeat(16), 1, 2, AutoCloseable { first++ })
        assertNull(policy.register("08".repeat(16), 1, 2, AutoCloseable { duplicate++ }))
        assertEquals(0, first); assertEquals(1, duplicate)
        policy.beginMutation()!!.close()
        assertEquals(1, first)
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.*

class RuntimeActivationGuardTest {
    @Test fun optionalActiveNotificationCannotPublishBeforeCommitOrAfterCancellation() {
        val guard = RuntimeActivationGuard()
        var deliveries = 0
        assertFalse(guard.publishOptionalActiveStatus { deliveries++ })
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        assertTrue(guard.activate(readyLease(), ::checks, PartialSetupResource(), PartialSetupResource()) {
            assertFalse(guard.publishOptionalActiveStatus { deliveries++ })
        })
        assertEquals(0, deliveries)
        assertTrue(guard.publishOptionalActiveStatus { deliveries++ })
        assertEquals(1, deliveries)
        guard.markCancellation()
        assertFalse(guard.publishOptionalActiveStatus { deliveries++ })
        assertEquals(1, deliveries)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
    }

    @Test fun optionalActiveNotificationFailureCannotThrowIntoActivationOrReauthorizeState() {
        val guard = RuntimeActivationGuard()
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        assertTrue(guard.activate(readyLease(), ::checks, PartialSetupResource(), PartialSetupResource()) {})
        assertFalse(guard.publishOptionalActiveStatus { throw IOException("optional delivery") })
        assertTrue(guard.isActive())
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertFalse(guard.publishOptionalActiveStatus { fail("closed publication") })
    }

    @Test fun requiredResourcesPreparedDuringNativeAcquisitionHaveOneOwnerAndAreNotPreparedTwice() {
        val guard = RuntimeActivationGuard()
        val notification = PartialSetupResource()
        val health = PartialSetupResource()
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        guard.prepareActivationResource(RuntimeResourceKind.NOTIFICATION, notification)
        guard.prepareActivationResource(RuntimeResourceKind.HEALTH_MONITOR, health)
        assertFalse(guard.isActive())
        var publications = 0
        assertTrue(guard.activate(readyLease(), ::checks, notification, health) { publications++ })
        assertEquals(1, publications)
        assertEquals(1, notification.prepares); assertEquals(1, health.prepares)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(1, notification.closes); assertEquals(1, health.closes)
    }

    @Test fun earlyRequiredResourceFailureCannotBeRepreparedOrActivated() {
        val guard = RuntimeActivationGuard()
        val resource = PartialSetupResource(failDuringPrepare = true)
        assertThrows(IllegalStateException::class.java) {
            guard.prepareActivationResource(RuntimeResourceKind.HEALTH_MONITOR, resource)
        }
        assertFalse(guard.isActive())
        assertThrows(IllegalStateException::class.java) {
            guard.prepareActivationResource(RuntimeResourceKind.HEALTH_MONITOR, resource)
        }
        assertEquals(1, resource.prepares); assertEquals(1, resource.closes)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun notificationPartialConstructionIsOwnedBeforeItsPreparationCanThrow() {
        val guard = RuntimeActivationGuard()
        val notification = PartialSetupResource(failDuringPrepare = true)
        val health = PartialSetupResource()
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        var published = false
        assertFalse(guard.activate(readyLease(), ::checks, notification, health, { published = true }))
        assertFalse(published); assertFalse(guard.isActive())
        assertEquals(1, notification.closes)
        assertTrue(checkNotNull(notification.observedBacking).all { it == 0.toByte() })
        assertEquals(0, health.prepares)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun healthPartialConstructionIsOwnedBeforeItsPreparationCanThrow() {
        val guard = RuntimeActivationGuard()
        val notification = PartialSetupResource()
        val health = PartialSetupResource(failDuringPrepare = true)
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        var published = false
        assertFalse(guard.activate(readyLease(), ::checks, notification, health, { published = true }))
        assertFalse(published); assertFalse(guard.isActive())
        assertEquals(1, notification.closes); assertEquals(1, health.closes)
        assertTrue(checkNotNull(notification.observedBacking).all { it == 0.toByte() })
        assertTrue(checkNotNull(health.observedBacking).all { it == 0.toByte() })
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun oneResourceCannotBeRegisteredAsBothRequiredActivationRoles() {
        val guard = RuntimeActivationGuard()
        val shared = PartialSetupResource()
        var closed = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed++ })
        guard.own(RuntimeResourceKind.TUN, Closeable { closed++ })
        assertFalse(guard.activate(readyLease(), ::checks, shared, shared) { fail("invalid role publication") })
        assertEquals(0, shared.prepares)
        assertEquals(1, shared.closes)
        assertEquals(2, closed)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun anotherGuardCannotAcquireOrCloseAnAlreadyClaimedActivationResource() {
        val first = RuntimeActivationGuard(); val second = RuntimeActivationGuard()
        val shared = PartialSetupResource(); val firstHealth = PartialSetupResource(); val secondHealth = PartialSetupResource()
        for (guard in listOf(first, second)) {
            guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
            guard.own(RuntimeResourceKind.TUN, Closeable {})
        }
        assertTrue(first.activate(readyLease(), ::checks, shared, firstHealth) {})
        var secondPublished = false
        assertFalse(second.activate(readyLease(), ::checks, shared, secondHealth) { secondPublished = true })
        assertFalse(secondPublished)
        assertTrue(first.isActive()); assertFalse(second.isActive())
        assertEquals(1, shared.prepares); assertEquals(0, shared.closes)
        assertEquals(0, secondHealth.prepares); assertEquals(1, secondHealth.closes)
        assertEquals(RuntimeCleanupState.CLEAN, second.cleanupState())
        assertEquals(RuntimeCleanupState.CLEAN, first.cancel()); assertEquals(1, shared.closes)
        assertTrue(checkNotNull(shared.observedBacking).all { it == 0.toByte() })
    }

    @Test fun preparationBeforeClaimAndAfterTerminalCloseCannotAcquireAnything() {
        val resource = PartialSetupResource()
        assertThrows(IllegalStateException::class.java) { resource.prepareOwned(Any()) }
        assertEquals(0, resource.prepares); assertNull(resource.observedBacking)
        resource.close()
        assertThrows(IllegalStateException::class.java) { resource.prepareOwned(Any()) }
        val guard = RuntimeActivationGuard()
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        var published = false
        assertFalse(guard.activate(readyLease(), ::checks, resource, PartialSetupResource()) { published = true })
        assertFalse(published); assertEquals(0, resource.prepares); assertEquals(1, resource.closes)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun cancellationDefersPartialOwnerClosureUntilPreparationUnwinds() {
        val guard = RuntimeActivationGuard()
        val entered = CountDownLatch(1); val finish = CountDownLatch(1)
        val notification = PartialSetupResource()
        val health = PartialSetupResource(afterAllocation = {
            entered.countDown(); check(finish.await(5, TimeUnit.SECONDS))
        })
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        var published = false
        val worker = Thread { guard.activate(readyLease(), ::checks, notification, health) { published = true } }
            .apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        try {
            assertEquals(RuntimeCleanupState.CLEANUP_REQUIRED, guard.cancel())
            assertEquals(0, health.closes)
            assertTrue(checkNotNull(health.observedBacking).all { it == 9.toByte() })
            assertFalse(guard.isActive())
        } finally { finish.countDown(); worker.join(5000) }
        assertFalse(worker.isAlive); assertFalse(published)
        assertEquals(1, health.closes); assertEquals(1, notification.closes)
        assertTrue(checkNotNull(health.observedBacking).all { it == 0.toByte() })
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel()); assertEquals(1, health.closes)
    }

    @Test fun failureBeforePreparationAcquiresNoBackingAndClosesBothRegisteredObjects() {
        val guard = RuntimeActivationGuard()
        val notification = PartialSetupResource(beforeAllocation = { throw IOException("before allocation") })
        val health = PartialSetupResource()
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        assertFalse(guard.activate(readyLease(), ::checks, notification, health) { fail("failed preparation publication") })
        assertNull(notification.observedBacking); assertNull(health.observedBacking)
        assertEquals(1, notification.closes); assertEquals(1, health.closes)
        assertEquals(0, health.prepares)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun partialPreparationCleanupFailureStaysUnprovenAndDoesNotAbandonOtherOwners() {
        val guard = RuntimeActivationGuard()
        val notification = PartialSetupResource()
        val health = PartialSetupResource(failDuringPrepare = true, failDuringClose = true)
        var closed = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed++ })
        guard.own(RuntimeResourceKind.TUN, Closeable { closed++ })
        assertFalse(guard.activate(readyLease(), ::checks, notification, health) { fail("uncertain preparation publication") })
        assertEquals(2, closed)
        assertEquals(1, notification.closes); assertEquals(1, health.closes)
        assertTrue(checkNotNull(notification.observedBacking).all { it == 0.toByte() })
        assertTrue(checkNotNull(health.observedBacking).all { it == 0.toByte() })
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cleanupState())
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cancel()); assertEquals(1, health.closes)
        assertFalse(guard.isActive())
    }

    @Test fun cancellationDuringOwnershipTransferClosesIncomingResourceExactlyOnce() {
        val guard = RuntimeActivationGuard(); val backing = ByteArray(4) { 7 }; var closed = 0
        val incoming = Closeable { closed++; backing.fill(0) }
        guard.markCancellation()
        assertNull(guard.own(RuntimeResourceKind.SOCKET, incoming))
        assertEquals(1, closed); assertArrayEquals(ByteArray(4), backing)
        assertNull(guard.own(RuntimeResourceKind.SOCKET, incoming))
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel()); assertEquals(1, closed)
    }

    @Test fun cancellationMarkBlocksActiveButDoesNotCertifyUnclosedOwnersClean() {
        val guard = RuntimeActivationGuard()
        var closed = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed++ })
        guard.own(RuntimeResourceKind.TUN, Closeable { closed++ })
        guard.markCancellation()
        assertFalse(guard.isActive())
        assertEquals(0, closed)
        assertEquals(RuntimeCleanupState.CLEANUP_REQUIRED, guard.cleanupState())
        assertFalse(guard.activate(readyLease(), ::checks, setup(beforePrepare = { error("cancelled notification acquisition") }),
            setup(beforePrepare = { error("cancelled health acquisition") }), { error("cancelled ACTIVE publication") }))
        assertEquals(RuntimeCleanupState.CLEANUP_REQUIRED, guard.cleanupState())
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(2, closed)
    }

    @Test fun verifiedLeasesAndOwnedRequiredSetupPublishActiveThenStopClosesEverything() {
        val guard = RuntimeActivationGuard()
        var closes = 0
        var published = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closes++ })
        guard.own(RuntimeResourceKind.TUN, Closeable { closes++ })
        assertTrue(guard.activate(readyLease(), ::checks, setup(onClose = { closes++ }),
            setup(onClose = { closes++ }), { published++ }))
        assertEquals(1, published)
        assertTrue(guard.isActive())
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(4, closes)
        assertFalse(guard.isActive())
    }

    @Test fun partialAcquisitionClosesAllAdoptedOwnersOnceInReverseOrder() {
        val closed = mutableListOf<Int>()
        val guard = RuntimeActivationGuard()
        assertFalse(guard.acquire { scope ->
            scope.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed += 1 })
            scope.own(RuntimeResourceKind.SOCKET, Closeable { closed += 2 })
            throw IOException("acquisition failed")
        })
        assertEquals(listOf(2, 1), closed)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cancel())
        assertEquals(listOf(2, 1), closed)
    }

    @Test fun interruptedNativeCloseIsNotRetriedAndUnprovenIsSticky() {
        val guard = RuntimeActivationGuard()
        var calls = 0
        val owner = Closeable { calls++; throw IOException("EINTR") }
        guard.own(RuntimeResourceKind.NATIVE_SESSION, owner)
        guard.own(RuntimeResourceKind.NATIVE_SESSION, owner)
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cancel())
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cancel())
        assertEquals(1, calls)
        assertFalse(guard.isActive())
    }

    @Test fun cancelledInflightAcquisitionCannotReportCleanOrKeepLateResources() {
        val guard = RuntimeActivationGuard()
        val entered = CountDownLatch(1)
        val resume = CountDownLatch(1)
        var closed = 0
        val worker = Thread {
            guard.acquire { scope ->
                entered.countDown()
                check(resume.await(5, TimeUnit.SECONDS))
                scope.own(RuntimeResourceKind.TUN, Closeable { closed++ })
            }
        }.apply { start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertEquals(RuntimeCleanupState.CLEANUP_REQUIRED, guard.cancel())
        resume.countDown()
        worker.join(5000)
        assertFalse(worker.isAlive)
        assertEquals(1, closed)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    @Test fun notificationOrHealthFailurePreventsActiveAndCleansAcquisitionOwners() {
        val guard = RuntimeActivationGuard()
        var closed = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed++ })
        guard.own(RuntimeResourceKind.TUN, Closeable { closed++ })
        var published = false
        assertFalse(guard.activate(readyLease(), ::checks, setup(onClose = { closed++ }),
            setup(beforePrepare = { throw IOException("health setup") }), { published = true }))
        assertFalse(published)
        assertFalse(guard.isActive())
        assertEquals(3, closed)
    }

    @Test fun finalRevisionRecheckOccursAfterRequiredSetupAndBeforePublication() {
        val guard = RuntimeActivationGuard()
        var revision = 2L
        var published = false
        guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        guard.own(RuntimeResourceKind.TUN, Closeable {})
        assertFalse(guard.activate(readyLease(), { checks().copy(revision = revision) }, setup(),
            setup(beforePrepare = { revision = 4 }), { published = true }))
        assertFalse(published)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
    }

    private class PartialSetupResource(private val failDuringPrepare: Boolean = false,
        private val beforeAllocation: () -> Unit = {}, private val afterAllocation: () -> Unit = {},
        private val failDuringClose: Boolean = false) : RuntimeActivationResource() {
        private var backing: ByteArray? = null
        var observedBacking: ByteArray? = null
        var prepares = 0
        var closes = 0
        override fun acquire() {
            prepares++
            beforeAllocation()
            backing = ByteArray(4) { 9 }.also { observedBacking = it }
            afterAllocation()
            if (failDuringPrepare) throw IOException("synthetic partial construction")
        }
        override fun release() {
            closes++; backing?.fill(0); backing = null
            if (failDuringClose) throw IOException("synthetic close uncertainty")
        }
    }

    private fun setup(beforePrepare: () -> Unit = {}, onClose: () -> Unit = {}) = object : RuntimeActivationResource() {
        private var resource: Closeable? = null
        override fun acquire() { beforePrepare(); resource = Closeable(onClose) }
        override fun release() { resource?.also { resource = null }?.close() }
    }

    private fun checks() = RuntimeActivationChecks("1".repeat(32), "5".repeat(32), 1, 2, true, true, false, 100)
    private fun readyLease(): RuntimeRevisionLeaseClient {
        val request = RuntimeAuthorityRequest("1".repeat(32), "5".repeat(32), "2".repeat(32), 1, RuntimeAuthorityPurpose.FULL_AUTHORITY,
            RuntimeAuthorityTrigger.MANUAL, 2, 1000, "3".repeat(32), "6".repeat(32),
            RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480, RuntimeAuthorityFrameCodec.encodedLength(0).toLong(), 0), 2, 0)
        val client = RuntimeRevisionLeaseClient(request)
        listOf(RuntimeAuthorityPurpose.PRE_TUN, RuntimeAuthorityPurpose.PRE_ACTIVE).forEach { purpose ->
            val lease = request.forPurpose(purpose)
            val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 1 }, lease).seal(byteArrayOf())!!
            val verified = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, lease).verifyAndConsume(frame, lease.descriptor, 100)
            assertTrue(client.accept((verified as RuntimeFrameVerification.Verified).authority, checks()))
            if (purpose == RuntimeAuthorityPurpose.PRE_TUN) assertTrue(client.authorizeTun(checks()))
        }
        return client
    }
}

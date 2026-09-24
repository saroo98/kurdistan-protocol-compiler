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

class RuntimeStartCoordinatorTest {
    @Test fun terminalFailureDuringProviderDeathCannotBecomeARecoveryAtSettlement() {
        val coordinator = coordinator()
        val first = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.acceptProductionAuthority(first.token, 1))
        val failure = providerDeathFailureV1(RuntimeStartFailure.INTERNAL_FAILURE, true, false)
        assertEquals(RuntimeStartFailure.INTERNAL_FAILURE, failure)
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.INTERNAL_FAILURE),
            coordinator.failed(first.token, checkNotNull(failure)))
        val settled = providerDeathFailureV1(RuntimeStartFailure.AUTHORITY_REJECTED, false, true)
        assertEquals(RuntimeStartDecision.Stale, coordinator.failed(first.token, checkNotNull(settled)))
        assertNull(coordinator.currentToken())
    }

    @Test fun providerDeathRetryStillRequiresCleanRetirementAndTheExistingBudget() {
        for (budget in 0..1) for (clean in listOf(false, true)) {
            val coordinator = coordinator()
            val first = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
            assertTrue(coordinator.acceptProductionAuthority(first.token, budget))
            first.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable {
                check(clean) { "retirement unproven" }
            })
            assertNull(providerDeathFailureV1(RuntimeStartFailure.ENDPOINT_UNAVAILABLE, true, false))
            val outcome = coordinator.failed(first.token,
                checkNotNull(providerDeathFailureV1(RuntimeStartFailure.AUTHORITY_REJECTED, false, true)))
            if (!clean) assertTrue(outcome is RuntimeStartDecision.CleanupPending)
            else if (budget == 0) assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED), outcome)
            else {
                val retry = outcome as RuntimeStartDecision.RequestAuthority
                assertNotEquals(first.token.requestId, retry.token.requestId)
                coordinator.stop(RuntimeStopReason.REVOKE)
                assertFalse(coordinator.acceptProductionAuthority(retry.token, 1))
            }
        }
        assertEquals(RuntimeStartFailure.AUTHORITY_REJECTED,
            providerDeathFailureV1(RuntimeStartFailure.AUTHORITY_REJECTED, false, false))
    }
    @Test fun onlySixtySecondsOfCurrentActiveSessionResetRetryCount() {
        val coordinator = coordinator()
        val start = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.acceptProductionAuthority(start.token, 1))
        val retry = coordinator.failed(start.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
        assertFalse(coordinator.recordStableSession(retry.token, 60_000))
        assertTrue(coordinator.acceptProductionAuthority(retry.token, 1))
        retry.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        retry.guard.own(RuntimeResourceKind.TUN, Closeable {})
        assertTrue(retry.guard.activateNativeOwned(true, setup(), setup(), { true }, {}))
        assertTrue(coordinator.activationCompleted(retry.token) is RuntimeStartDecision.Active)
        assertFalse(coordinator.recordStableSession(start.token, 60_000))
        assertFalse(coordinator.recordStableSession(retry.token, 59_999))
        assertTrue(coordinator.recordStableSession(retry.token, 60_000))
        val fresh = coordinator.failed(retry.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
        assertEquals(1, fresh.token.retryAttempt)
        assertEquals(1000L, fresh.delayMillis)
    }
    @Test fun reconnectJitterStaysWithinTheSignedAttemptBudget() {
        for ((random, expected) in listOf(0.0 to 800L, 0.5 to 1000L, 0.999999 to 1199L)) {
            var id = 1
            val coordinator = RuntimeStartCoordinator("1".repeat(32), retryRandom = { random }) {
                (id++).toString(16).padStart(32, '0')
            }
            val start = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
            assertTrue(coordinator.acceptProductionAuthority(start.token, 1))
            val retry = coordinator.failed(start.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
            assertEquals(expected, retry.delayMillis)
            assertTrue(coordinator.acceptProductionAuthority(retry.token, 1))
            assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED),
                coordinator.failed(retry.token, RuntimeStartFailure.NETWORK_LOST))
        }
    }
    @Test fun anAdmittedOwnerMustRetainTheExactGuardNotJustCopyItsToken() {
        val coordinator = coordinator()
        val admitted = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.ownsAdmission(admitted))
        assertFalse(coordinator.ownsAdmission(admitted.copy(guard = RuntimeActivationGuard())))
        coordinator.stop(RuntimeStopReason.STOP)
        assertFalse(coordinator.ownsAdmission(admitted))
    }
    @Test fun productionAdmissionBindsRetryBudgetToTheCurrentAttemptOnly() {
        val coordinator = coordinator()
        val initial = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertFalse(coordinator.acceptProductionAuthority(initial.token.copy(generation = initial.token.generation + 1), 3))
        assertFalse(coordinator.acceptProductionAuthority(initial.token, 6))
        assertTrue(coordinator.acceptProductionAuthority(initial.token, 2))
        assertFalse(coordinator.acceptProductionAuthority(initial.token, 3))
        val retry = coordinator.failed(initial.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
        assertEquals(1, retry.token.retryAttempt)
        assertEquals(2, retry.retryBudgetCeiling)
        assertFalse(coordinator.acceptProductionAuthority(retry.token, 3))
        assertTrue(coordinator.acceptProductionAuthority(retry.token, 1))
        assertEquals(RuntimeStartDecision.Idle, coordinator.stop(RuntimeStopReason.STOP))
    }
    @Test fun staleTokenStopCannotCancelOrSuppressReplacement() {
        val coordinator = coordinator()
        val first = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertEquals(RuntimeStartDecision.Idle, coordinator.stopIfCurrent(first.token, RuntimeStopReason.STOP))
        val replacement = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertEquals(RuntimeStartDecision.Stale, coordinator.stopIfCurrent(first.token, RuntimeStopReason.REVOKE))
        assertEquals(replacement.token, coordinator.currentToken())
        assertTrue(replacement.guard.isAcquisitionCurrent())
        assertEquals(RuntimeStartDecision.Idle, coordinator.stopIfCurrent(replacement.token, RuntimeStopReason.STOP))
    }
    @Test fun idleOnlyAdmissionDoesNotCancelCoalesceQueueOrReplaceExistingAttempt() {
        val coordinator = coordinator()
        val existing = coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) as RuntimeStartDecision.RequestAuthority
        var closed = 0
        existing.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true))
        assertEquals(existing.token, coordinator.currentToken())
        assertTrue(existing.guard.isAcquisitionCurrent())
        assertEquals(0, closed)
        assertEquals(RuntimeStartDecision.Idle, coordinator.stop(RuntimeStopReason.STOP))
        assertEquals(1, closed)
        assertNull(coordinator.currentToken())
        val admitted = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertEquals(existing.token.generation + 1, admitted.token.generation)
    }

    @Test fun idleOnlyAdmissionRefusesQuiescenceAndUnprovenCleanup() {
        val coordinator = coordinator()
        val lease = checkNotNull(coordinator.acquireMutationQuiescenceLease())
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true))
        assertNull(coordinator.currentToken())
        lease.close()
        val admitted = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        admitted.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { throw IOException("cleanup unproven") })
        assertTrue(coordinator.stop(RuntimeStopReason.STOP) is RuntimeStartDecision.CleanupPending)
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true))
        assertEquals(admitted.token, coordinator.currentToken())
    }

    @Test fun idleOnlyAdmissionSerializesConcurrentStartsAndPreservesConsentChecks() {
        val coordinator = coordinator()
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CONSENT_REVOKED),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, false, true))
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CONSENT_REVOKED),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, false))
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CONSENT_REVOKED),
            coordinator.beginIfIdle(RuntimeAuthorityTrigger.NETWORK_RETRY, true, true))
        val gate = CountDownLatch(1)
        val results = arrayOfNulls<RuntimeStartDecision>(2)
        val workers = (0..1).map { index -> Thread {
            check(gate.await(5, TimeUnit.SECONDS))
            results[index] = coordinator.beginIfIdle(RuntimeAuthorityTrigger.MANUAL, true, true)
        }.apply { isDaemon = true; start() } }
        gate.countDown()
        workers.forEach { it.join(5000); assertFalse(it.isAlive) }
        assertEquals(1, results.count { it is RuntimeStartDecision.RequestAuthority })
        assertEquals(1, results.count { it == RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN) })
        assertEquals(RuntimeStartDecision.Idle, coordinator.stop(RuntimeStopReason.STOP))
    }

    @Test fun quiescenceAdmissionDeadlineRejectsStaleOrUnboundedReplies() {
        assertTrue(RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(100, 101))
        assertTrue(RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(100, 2_100))
        assertFalse(RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(100, 100))
        assertFalse(RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(100, 2_101))
        assertFalse(RuntimeMutationQuiescenceWire.acceptsAdmissionDeadline(-1, 1))
    }

    @Test fun quiescenceLeaseRequiresCleanRetirementAndExcludesNewStartsUntilReleased() {
        val coordinator = coordinator()
        val active = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertNull(coordinator.acquireMutationQuiescenceLease())

        assertEquals(RuntimeStartDecision.Idle, coordinator.stop(RuntimeStopReason.STOP))
        val lease = checkNotNull(coordinator.acquireMutationQuiescenceLease())
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN),
            coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true))

        lease.close()
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) is RuntimeStartDecision.RequestAuthority)
    }

    @Test fun migratedAppRetryRegressionsPreserveAllFiveSignedBackoffStepsAndFreshAuthority() {
        val coordinator = coordinator()
        var current = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val ids = mutableSetOf(current.token.requestId)
        repeat(6) { step ->
            assertTrue(coordinator.acceptAuthority(current.token, verified(current.token, 5), 100) is RuntimeStartDecision.Ready)
            val next = coordinator.failed(current.token, RuntimeStartFailure.NETWORK_LOST)
            assertEquals(RuntimeStartDecision.Stale, coordinator.failed(current.token, RuntimeStartFailure.NETWORK_LOST))
            if (step == 5) {
                assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED), next)
            } else {
                val retry = next as RuntimeStartDecision.RequestAuthority
                assertEquals(1000L shl step, retry.delayMillis)
                assertEquals(step + 1, retry.token.retryAttempt)
                assertTrue(ids.add(retry.token.requestId))
                assertTrue(retry.token.generation > current.token.generation)
                current = retry
            }
        }
        assertNull(coordinator.currentToken())
    }
    @Test fun migratedAppPermanentFailureAndMissingBudgetCasesCannotReopenAuthority() {
        for (failure in RuntimeStartFailure.entries.filter { !it.retryable }) {
            val coordinator = coordinator()
            val initial = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
            coordinator.acceptAuthority(initial.token, verified(initial.token, 5), 100)
            assertTrue(failure.name, coordinator.failed(initial.token, failure) is RuntimeStartDecision.Rejected)
            assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
        }
        val coordinator = coordinator()
        val initial = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        coordinator.acceptAuthority(initial.token, verified(initial.token, 0), 100)
        assertEquals(RuntimeStartDecision.Rejected(RuntimeStartFailure.RETRY_EXHAUSTED), coordinator.failed(initial.token, RuntimeStartFailure.NETWORK_LOST))
    }
    @Test fun migratedAppStopAtBackoffRejectsLateAuthorityAndFreshManualResetsBudget() {
        val coordinator = coordinator()
        val first = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        coordinator.acceptAuthority(first.token, verified(first.token), 100)
        val retry = coordinator.failed(first.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
        coordinator.stop(RuntimeStopReason.REVOKE)
        val stale = verified(retry.token)
        assertEquals(RuntimeStartDecision.Stale, coordinator.acceptAuthority(retry.token, stale, 100))
        assertNull(stale.takePayload())
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
        val manual = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertEquals(0, manual.token.retryAttempt)
        assertTrue(manual.token.generation > retry.token.generation)
        coordinator.acceptAuthority(manual.token, verified(manual.token, 1), 100)
        assertEquals(1000L, (coordinator.failed(manual.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority).delayMillis)
    }
    @Test fun processInstallationCannotBeReplacedByAnotherEpoch() {
        val installed = RuntimeStartCoordinator.processOwner()
        assertSame(installed, RuntimeStartCoordinator.processOwner())
        assertSame(installed, RuntimeStartCoordinator.installOnce(installed.epoch))
        val other = if (installed.epoch == "b".repeat(32)) "a".repeat(32) else "b".repeat(32)
        assertThrows(IllegalStateException::class.java) { RuntimeStartCoordinator.installOnce(other) }
    }

    @Test fun sharedProcessAdmissionExcludesBothConsumerOrdersUntilActualCleanup() {
        val legacy = RuntimeStartCoordinator.processOwner()
        val production = RuntimeStartCoordinator.processOwner()
        for ((first, second) in listOf(legacy to production, production to legacy)) {
            val request = first.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
            assertEquals(first.epoch, request.token.epoch)
            assertEquals(RuntimeStartDecision.Coalesced(request.token), second.begin(RuntimeAuthorityTrigger.MANUAL, true, true))
            var closed = 0
            request.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
            assertEquals(RuntimeStartDecision.Idle, first.stop(RuntimeStopReason.STOP))
            assertEquals(1, closed)
            assertNull(second.currentToken())
        }
    }

    @Test fun automaticDuplicatesCoalesceAndManualSupersedesWithFreshGeneration() {
        val coordinator = coordinator()
        val automatic = coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Coalesced)
        var closed = 0
        automatic.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, Closeable { closed++ })
        val manual = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        assertTrue(manual.token.generation > automatic.token.generation)
        assertEquals(1, closed)
        val stale = verified(automatic.token)
        assertTrue(coordinator.acceptAuthority(automatic.token, stale, 100) is RuntimeStartDecision.Stale)
        assertNull(stale.takePayload())
        assertEquals(manual.token, coordinator.currentToken())
    }

    @Test fun eachBoundedNetworkRetryRequestsAndConsumesFreshAuthority() {
        val coordinator = coordinator()
        var attempt = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val ids = mutableSetOf(attempt.token.requestId)
        repeat(3) { index ->
            assertTrue(coordinator.acceptAuthority(attempt.token, verified(attempt.token), 100) is RuntimeStartDecision.Ready)
            val next = coordinator.failed(attempt.token, RuntimeStartFailure.NETWORK_LOST)
            if (index < 2) {
                assertTrue(next is RuntimeStartDecision.RequestAuthority)
                val retry = next as RuntimeStartDecision.RequestAuthority
                assertTrue(ids.add(retry.token.requestId))
                assertTrue(retry.token.generation > attempt.token.generation)
                assertEquals(index + 1, retry.token.retryAttempt)
                assertEquals(RuntimeAuthorityTrigger.NETWORK_RETRY, retry.token.trigger)
                attempt = retry
            } else assertTrue(next is RuntimeStartDecision.Rejected)
        }
        assertNull(coordinator.currentToken())
    }

    @Test fun manualIntentSupersedesAnAutomaticRetryEvenForAManuallyStartedSession() {
        val coordinator = coordinator()
        val initial = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        coordinator.acceptAuthority(initial.token, verified(initial.token), 100)
        val retry = coordinator.failed(initial.token, RuntimeStartFailure.NETWORK_LOST) as RuntimeStartDecision.RequestAuthority
        val manual = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true)
        assertTrue(manual is RuntimeStartDecision.RequestAuthority)
        assertTrue((manual as RuntimeStartDecision.RequestAuthority).token.generation > retry.token.generation)
        assertEquals(RuntimeAuthorityTrigger.MANUAL, manual.token.trigger)
    }

    @Test fun finalPublicationAndStopUseOneSerialOwnerWithoutLockInversion() {
        val coordinator = coordinator()
        val pending = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val ready = coordinator.acceptAuthority(pending.token, verified(pending.token), 100) as RuntimeStartDecision.Ready
        val checks = RuntimeActivationChecks(pending.token.epoch, ready.authority.request.providerEpoch, pending.token.generation, 2, true, true, false, 100)
        listOf(RuntimeAuthorityPurpose.PRE_TUN, RuntimeAuthorityPurpose.PRE_ACTIVE).forEach { purpose ->
            val binding = ready.authority.request.forPurpose(purpose, ready.authority.request.descriptor.copy(length = RuntimeAuthorityFrameCodec.encodedLength(0).toLong()))
            val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 1 }, binding).seal(byteArrayOf())!!
            val reply = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, binding).verifyAndConsume(frame, binding.descriptor, 100)
            assertTrue(ready.leases.accept((reply as RuntimeFrameVerification.Verified).authority, checks))
            if (purpose == RuntimeAuthorityPurpose.PRE_TUN) assertTrue(ready.leases.authorizeTun(checks))
        }
        ready.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {})
        ready.guard.own(RuntimeResourceKind.TUN, Closeable {})
        val publishing = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val publisher = Thread {
            ready.guard.activate(ready.leases, { checks }, setup(), setup()) {
                publishing.countDown()
                check(resume.await(5, TimeUnit.SECONDS))
                coordinator.currentToken()
            }
        }.apply { isDaemon = true; start() }
        assertTrue(publishing.await(5, TimeUnit.SECONDS))
        val stopper = Thread { coordinator.stop(RuntimeStopReason.STOP) }.apply { isDaemon = true; start() }
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (stopper.state != Thread.State.BLOCKED && System.nanoTime() < until) Thread.yield()
        assertEquals(Thread.State.BLOCKED, stopper.state)
        resume.countDown()
        publisher.join(5000)
        stopper.join(5000)
        assertFalse("publication deadlocked", publisher.isAlive)
        assertFalse("stop deadlocked", stopper.isAlive)
        assertFalse(ready.guard.isActive())
    }

    @Test fun permanentFailureAndUnprovenCleanupCannotRetry() {
        val permanent = coordinator()
        val first = permanent.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        permanent.acceptAuthority(first.token, verified(first.token), 100)
        assertTrue(permanent.failed(first.token, RuntimeStartFailure.TLS_REJECTED) is RuntimeStartDecision.Rejected)
        assertTrue(permanent.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
        val uncertain = coordinator()
        val pending = uncertain.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        pending.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { throw IOException("EINTR") })
        uncertain.acceptAuthority(pending.token, verified(pending.token), 100)
        assertTrue(uncertain.failed(pending.token, RuntimeStartFailure.NETWORK_LOST) is RuntimeStartDecision.CleanupPending)
        assertTrue(uncertain.begin(RuntimeAuthorityTrigger.MANUAL, true, true) is RuntimeStartDecision.CleanupPending)
    }

    @Test fun terminalFailureSurvivesRequiredCleanupDrain() {
        val coordinator = coordinator()
        val pending = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val entered = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val acquisition = Thread {
            pending.guard.acquire { owner ->
                entered.countDown()
                check(finish.await(5, TimeUnit.SECONDS))
                owner.own(RuntimeResourceKind.SOCKET, Closeable {})
            }
        }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        try {
            assertTrue(
                coordinator.failed(pending.token, RuntimeStartFailure.AUTHORITY_REJECTED) is
                    RuntimeStartDecision.CleanupPending,
            )
        } finally {
            finish.countDown()
            acquisition.join(5_000)
        }
        assertFalse(acquisition.isAlive)
        assertEquals(
            RuntimeStartDecision.Rejected(RuntimeStartFailure.AUTHORITY_REJECTED),
            coordinator.cleanupCompleted(pending.token),
        )
    }

    @Test fun stopWinsWhileSupersededAcquisitionStillOwnsLocalResources() {
        val coordinator = coordinator()
        val old = coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) as RuntimeStartDecision.RequestAuthority
        val entered = CountDownLatch(1)
        val proceed = CountDownLatch(1)
        var closed = 0
        val thread = Thread {
            old.guard.acquire { scope ->
                entered.countDown()
                check(proceed.await(5, TimeUnit.SECONDS))
                scope.own(RuntimeResourceKind.TUN, Closeable { closed++ })
            }
        }.apply { start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) is RuntimeStartDecision.CleanupPending)
        coordinator.stop(RuntimeStopReason.REVOKE)
        proceed.countDown()
        thread.join(5000)
        assertFalse(thread.isAlive)
        assertEquals(RuntimeStartDecision.Idle, coordinator.cleanupCompleted(old.token))
        assertEquals(1, closed)
        assertNull(coordinator.currentToken())
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
    }

    @Test fun preparedAndUnlockedAreRequiredAndCallbacksCannotClaimActiveWithFlags() {
        val coordinator = coordinator()
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, false, true) is RuntimeStartDecision.Rejected)
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, false) is RuntimeStartDecision.Rejected)
        val pending = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        coordinator.acceptAuthority(pending.token, verified(pending.token), 100)
        assertTrue(coordinator.activationCompleted(pending.token) is RuntimeStartDecision.Rejected)
    }

    @Test fun resourceCleanupCanAwaitItsCallbackWithoutHoldingCoordinatorMonitor() {
        val coordinator = coordinator()
        val pending = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val callbackFinished = CountDownLatch(1)
        var callback: Thread? = null
        pending.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {
            callback = Thread {
                coordinator.currentToken()
                callbackFinished.countDown()
            }.apply { isDaemon = true; start() }
            check(callbackFinished.await(1, TimeUnit.SECONDS)) { "callback blocked by coordinator cleanup" }
        })
        val stopped = coordinator.stop(RuntimeStopReason.STOP)
        val joined = checkNotNull(callback)
        joined.join(2000)
        assertFalse(joined.isAlive)
        assertEquals(RuntimeStartDecision.Idle, stopped)
        assertEquals(RuntimeCleanupState.CLEAN, pending.guard.cleanupState())
        assertNull(coordinator.currentToken())
    }

    @Test fun manualStartDuringNetworkRetryCleanupReplacesQueuedAutomaticIntent() {
        for (stopWins in listOf(false, true)) {
            val coordinator = coordinator()
            val pending = coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) as RuntimeStartDecision.RequestAuthority
            coordinator.acceptAuthority(pending.token, verified(pending.token), 100)
            val entered = CountDownLatch(1); val finish = CountDownLatch(1)
            var closed = 0
            val acquisition = Thread {
                pending.guard.acquire { owner ->
                    entered.countDown(); check(finish.await(5, TimeUnit.SECONDS))
                    owner.own(RuntimeResourceKind.SOCKET, Closeable { closed++ })
                }
            }.apply { isDaemon = true; start() }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            try {
                assertTrue(coordinator.failed(pending.token, RuntimeStartFailure.NETWORK_LOST) is RuntimeStartDecision.CleanupPending)
                assertTrue(coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) is RuntimeStartDecision.CleanupPending)
                if (stopWins) coordinator.stop(RuntimeStopReason.REVOKE)
            } finally { finish.countDown(); acquisition.join(5000) }
            assertFalse(acquisition.isAlive)
            assertEquals(1, closed)
            val result = coordinator.cleanupCompleted(pending.token)
            if (stopWins) {
                assertEquals(RuntimeStartDecision.Idle, result)
                assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
            } else {
                assertTrue(result is RuntimeStartDecision.RequestAuthority)
                val next = result as RuntimeStartDecision.RequestAuthority
                assertEquals(RuntimeAuthorityTrigger.MANUAL, next.token.trigger)
                assertEquals(0, next.token.retryAttempt)
                assertTrue(next.token.generation > pending.token.generation)
                assertNotEquals(next.token.requestId, pending.token.requestId)
            }
        }
    }

    @Test fun reentrantStopAtPublicationCancelsImmediatelyAndDefersForeignCleanup() {
        val coordinator = coordinator()
        val pending = coordinator.begin(RuntimeAuthorityTrigger.MANUAL, true, true) as RuntimeStartDecision.RequestAuthority
        val ready = readyForPublication(coordinator, pending)
        val callbackDone = CountDownLatch(1)
        var callback: Thread? = null
        ready.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable {
            callback = Thread { coordinator.currentToken(); callbackDone.countDown() }.apply { isDaemon = true; start() }
            check(callbackDone.await(1, TimeUnit.SECONDS))
        })
        ready.guard.own(RuntimeResourceKind.TUN, Closeable {})
        var stopped: RuntimeStartDecision? = null
        assertFalse(ready.guard.activate(ready.leases, { activationChecks(pending.token) }, setup(), setup()) {
            stopped = coordinator.stop(RuntimeStopReason.REVOKE)
        })
        checkNotNull(callback).join(2000)
        assertEquals(0L, callbackDone.count)
        assertTrue(stopped is RuntimeStartDecision.CleanupPending)
        assertEquals(RuntimeCleanupState.CLEAN, ready.guard.cleanupState())
        assertFalse(ready.guard.isActive())
        assertEquals(RuntimeStartDecision.Idle, coordinator.cleanupCompleted(pending.token))
    }

    @Test fun revokeDuringRequiredActivationSetupClosesLateOwnersAndNeverPublishes() {
        val coordinator = coordinator()
        val pending = coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) as RuntimeStartDecision.RequestAuthority
        val ready = readyForPublication(coordinator, pending)
        var closed = 0; var published = false
        ready.guard.own(RuntimeResourceKind.NATIVE_SESSION, Closeable { closed++ })
        ready.guard.own(RuntimeResourceKind.TUN, Closeable { closed++ })
        val entered = CountDownLatch(1); val finish = CountDownLatch(1)
        val worker = Thread {
            ready.guard.activate(ready.leases, { activationChecks(pending.token) }, setup(onClose = { closed++ }),
                setup(beforePrepare = { entered.countDown(); check(finish.await(5, TimeUnit.SECONDS)) }, onClose = { closed++ }),
                { published = true })
        }.apply { isDaemon = true; start() }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        try { assertTrue(coordinator.stop(RuntimeStopReason.REVOKE) is RuntimeStartDecision.CleanupPending) }
        finally { finish.countDown(); worker.join(5000) }
        assertFalse(worker.isAlive); assertFalse(published); assertFalse(ready.guard.isActive())
        assertEquals(4, closed)
        assertEquals(RuntimeStartDecision.Idle, coordinator.cleanupCompleted(pending.token))
        assertTrue(coordinator.begin(RuntimeAuthorityTrigger.AUTOMATIC, true, true) is RuntimeStartDecision.Rejected)
    }

    private fun setup(beforePrepare: () -> Unit = {}, onClose: () -> Unit = {}) = object : RuntimeActivationResource() {
        private var resource: Closeable? = null
        override fun acquire() { beforePrepare(); resource = Closeable(onClose) }
        override fun release() { resource?.also { resource = null }?.close() }
    }

    private fun activationChecks(token: RuntimeStartToken) = RuntimeActivationChecks(token.epoch, "5".repeat(32),
        token.generation, 2, true, true, false, 100)

    private fun readyForPublication(coordinator: RuntimeStartCoordinator, pending: RuntimeStartDecision.RequestAuthority): RuntimeStartDecision.Ready {
        val ready = coordinator.acceptAuthority(pending.token, verified(pending.token), 100) as RuntimeStartDecision.Ready
        for (purpose in listOf(RuntimeAuthorityPurpose.PRE_TUN, RuntimeAuthorityPurpose.PRE_ACTIVE)) {
            val request = ready.authority.request.forPurpose(purpose,
                ready.authority.request.descriptor.copy(length = RuntimeAuthorityFrameCodec.encodedLength(0).toLong()))
            val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 3 }, request).seal(byteArrayOf())!!
            val response = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 3 }, request).verifyAndConsume(frame, request.descriptor, 100)
            assertTrue(ready.leases.accept((response as RuntimeFrameVerification.Verified).authority, activationChecks(pending.token)))
            if (purpose == RuntimeAuthorityPurpose.PRE_TUN) assertTrue(ready.leases.authorizeTun(activationChecks(pending.token)))
        }
        return ready
    }

    private fun coordinator(): RuntimeStartCoordinator {
        var next = 1
        return RuntimeStartCoordinator("1".repeat(32), retryRandom = { 0.5 }) { (next++).toString(16).padStart(32, '0') }
    }
    private fun verified(token: RuntimeStartToken, budget: Int = 2): RuntimeVerifiedAuthority {
        val capability = (token.generation * 2 + 10).toString(16).padStart(32, '0')
        val frame = (token.generation * 2 + 11).toString(16).padStart(32, '0')
        val request = RuntimeAuthorityRequest(token.epoch, "5".repeat(32), token.requestId, token.generation,
            RuntimeAuthorityPurpose.FULL_AUTHORITY, token.trigger, 2, 1000, capability, frame,
            RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480, RuntimeAuthorityFrameCodec.encodedLength(1).toLong(), 0),
            budget, token.retryAttempt)
        val bytes = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 5 }, request).seal(byteArrayOf(1))!!
        return (RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 5 }, request)
            .verifyAndConsume(bytes, request.descriptor, 100) as RuntimeFrameVerification.Verified).authority
    }
}

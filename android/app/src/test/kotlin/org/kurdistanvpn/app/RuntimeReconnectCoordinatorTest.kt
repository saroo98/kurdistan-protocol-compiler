// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class RuntimeReconnectCoordinatorTest {
    @Test
    fun everyRetryRequestsFreshAuthorityAndStartsANewSession() {
        val delays = mutableListOf<Long>()
        val prepared = ArrayDeque(
            listOf(
                byteArrayOf(1, 1, 1),
                byteArrayOf(2, 2, 2),
            ),
        )
        val started = mutableListOf<ByteArray>()
        var preparationCount = 0
        val coordinator = coordinator(
            wait = { delays += it },
            restart = { authority ->
                started += authority.copyOf()
                authority.fill(0)
            },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(prepared.removeFirst())
            },
        )

        coordinator.observe(retryable("request-1", maxAttempts = 5))
        coordinator.observe(retryable("request-2", maxAttempts = 5))

        assertEquals(listOf(1_000L, 2_000L), delays)
        assertEquals(2, preparationCount)
        assertEquals(
            listOf(listOf(1, 1, 1), listOf(2, 2, 2)),
            started.map { authority -> authority.map(Byte::toInt) },
        )
    }

    @Test
    fun exhaustedEndpointFallbackUsesTheSignedBudgetAndFreshAuthority() {
        var preparationCount = 0
        val started = mutableListOf<ByteArray>()
        val coordinator = coordinator(
            restart = { authority ->
                started += authority.copyOf()
                authority.fill(0)
            },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(9, 8, 7))
            },
        )

        coordinator.observe(
            VpnRuntimeSnapshot(
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_FALLBACK_EXHAUSTED",
                runtimeRequestId = "request-connect-failed",
                maxReconnectAttempts = 2,
            ),
        )

        assertEquals(1, preparationCount)
        assertEquals(1, coordinator.attempts)
        assertEquals(listOf(9, 8, 7), started.single().map(Byte::toInt))
    }

    @Test
    fun duplicateTerminalBroadcastCannotConsumeTwoAttempts() {
        var preparationCount = 0
        val coordinator = coordinator(
            restart = { it.fill(0) },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(preparationCount.toByte()))
            },
        )
        val terminal = retryable("request-1", maxAttempts = 5)

        coordinator.observe(terminal)
        coordinator.observe(terminal)

        assertEquals(1, preparationCount)
        assertEquals(1, coordinator.attempts)
    }

    @Test
    fun manualDisconnectCancelsAPendingRetryAndWipesItsAuthority() = runBlocking {
        val releaseDelay = CompletableDeferred<Unit>()
        var preparationCount = 0
        var restartCount = 0
        val coordinator = coordinator(
            wait = { releaseDelay.await() },
            restart = {
                restartCount++
                it.fill(0)
            },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(7))
            },
        )

        coordinator.observe(retryable("request-1", maxAttempts = 5))
        coordinator.cancel()
        releaseDelay.complete(Unit)

        assertEquals(0, preparationCount)
        assertEquals(0, restartCount)
    }

    @Test
    fun manualDisconnectDuringFreshAuthorityPreparationCannotRestart() = runBlocking {
        val releaseAuthority = CompletableDeferred<Unit>()
        var restartCount = 0
        val coordinator = coordinator(
            restart = {
                restartCount++
                it.fill(0)
            },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                releaseAuthority.await()
                FreshRuntimeAuthority.Ready(byteArrayOf(9))
            },
        )

        coordinator.observe(retryable("request-1", maxAttempts = 5))
        coordinator.cancel()
        releaseAuthority.complete(Unit)

        assertEquals(0, restartCount)
    }

    @Test
    fun revocationAndNonRetryableFailuresCancelWithoutReopeningAuthority() {
        var preparationCount = 0
        val published = mutableListOf<VpnRuntimeSnapshot>()
        val coordinator = coordinator(
            publish = published::add,
            restart = { it.fill(0) },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(1))
            },
        )

        coordinator.observe(
            VpnRuntimeSnapshot(
                state = VpnRuntimeState.REVOKED,
                failure = "PROFILE_REVOKED",
                runtimeRequestId = "request-1",
                maxReconnectAttempts = 5,
            ),
        )
        coordinator.observe(
            VpnRuntimeSnapshot(
                state = VpnRuntimeState.FAILED,
                failure = "LIVE_TLS_REJECTED",
                runtimeRequestId = "request-2",
                maxReconnectAttempts = 5,
            ),
        )

        assertEquals(0, preparationCount)
        assertTrue(published.isEmpty())
    }

    @Test
    fun revocationCancelsAnAlreadyScheduledReconnect() = runBlocking {
        val releaseDelay = CompletableDeferred<Unit>()
        var preparationCount = 0
        val coordinator = coordinator(
            wait = { releaseDelay.await() },
            restart = { it.fill(0) },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(1))
            },
        )
        coordinator.observe(retryable("request-1", maxAttempts = 5))

        coordinator.observe(
            VpnRuntimeSnapshot(
                state = VpnRuntimeState.REVOKED,
                failure = "PROFILE_REVOKED",
                runtimeRequestId = "request-1",
                maxReconnectAttempts = 5,
            ),
        )
        releaseDelay.complete(Unit)

        assertEquals(0, preparationCount)
    }

    @Test
    fun signedRetryBudgetFailsClosedWhenExhausted() {
        val published = mutableListOf<VpnRuntimeSnapshot>()
        var preparationCount = 0
        val coordinator = coordinator(
            publish = published::add,
            restart = { it.fill(0) },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                preparationCount++
                FreshRuntimeAuthority.Ready(byteArrayOf(preparationCount.toByte()))
            },
        )

        coordinator.observe(retryable("request-1", maxAttempts = 2))
        coordinator.observe(retryable("request-2", maxAttempts = 2))
        coordinator.observe(retryable("request-3", maxAttempts = 2))

        assertEquals(2, preparationCount)
        assertEquals(2, coordinator.attempts)
        assertEquals(VpnRuntimeState.FAILED, published.last().state)
        assertEquals("RECONNECT_EXHAUSTED", published.last().failure)
    }

    @Test
    fun invalidOrMissingSignedRetryBudgetFailsClosed() {
        val published = mutableListOf<VpnRuntimeSnapshot>()
        val coordinator = coordinator(
            publish = published::add,
            restart = { it.fill(0) },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                FreshRuntimeAuthority.Ready(byteArrayOf(1))
            },
        )

        coordinator.observe(retryable("request-1", maxAttempts = 0))

        assertEquals(VpnRuntimeState.FAILED, published.single().state)
        assertEquals("RECONNECT_POLICY_REJECTED", published.single().failure)
        assertEquals(0, coordinator.attempts)
    }

    @Test
    fun staleRetryCannotStartAfterANewUserConnectionBegins() = runBlocking {
        val releaseDelay = CompletableDeferred<Unit>()
        var restartCount = 0
        val coordinator = coordinator(
            wait = { releaseDelay.await() },
            restart = {
                restartCount++
                it.fill(0)
            },
        )
        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                FreshRuntimeAuthority.Ready(byteArrayOf(1))
            },
        )
        coordinator.observe(retryable("request-1", maxAttempts = 5))

        coordinator.begin(
            FreshRuntimeAuthorityProvider {
                FreshRuntimeAuthority.Ready(byteArrayOf(2))
            },
        )
        releaseDelay.complete(Unit)

        assertEquals(0, restartCount)
        assertEquals(0, coordinator.attempts)
    }

    private fun coordinator(
        wait: suspend (Long) -> Unit = {},
        publish: (VpnRuntimeSnapshot) -> Unit = {},
        restart: (ByteArray) -> Unit,
    ) = RuntimeReconnectCoordinator(
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined),
        policy = RuntimeReconnectPolicy(jitter = { it }),
        wait = wait,
        publish = publish,
        restart = restart,
    )

    private fun retryable(requestId: String, maxAttempts: Int) = VpnRuntimeSnapshot(
        state = VpnRuntimeState.BLOCKED,
        failure = "NETWORK_CHANGED",
        runtimeRequestId = requestId,
        maxReconnectAttempts = maxAttempts,
    )
}

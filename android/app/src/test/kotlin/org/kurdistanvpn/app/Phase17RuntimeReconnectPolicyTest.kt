// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class Phase17RuntimeReconnectPolicyTest {
    @Test
    fun networkTransitionsConsumeTheSignedBoundWithFrozenBackoff() {
        val policy = RuntimeReconnectPolicy(jitter = { it })

        assertEquals(1_000L, policy.nextDelayMillis(5, "NETWORK_CHANGED"))
        assertEquals(2_000L, policy.nextDelayMillis(5, "NETWORK_UNAVAILABLE"))
        assertEquals(4_000L, policy.nextDelayMillis(5, "LIVE_NETWORK_UNAVAILABLE"))
        assertEquals(8_000L, policy.nextDelayMillis(5, "NETWORK_CHANGED"))
        assertEquals(16_000L, policy.nextDelayMillis(5, "NETWORK_CHANGED"))
        assertNull(policy.nextDelayMillis(5, "NETWORK_CHANGED"))
        assertEquals(5, policy.attempts)
    }

    @Test
    fun authorityAndRevocationFailuresNeverReconnect() {
        val policy = RuntimeReconnectPolicy(jitter = { it })

        assertNull(policy.nextDelayMillis(5, "AUTHORITY_TRUST_REJECTED"))
        assertNull(policy.nextDelayMillis(5, "PROFILE_REVOKED"))
        assertNull(policy.nextDelayMillis(5, null))
        assertEquals(0, policy.attempts)
    }

    @Test
    fun aNewUserConnectionResetsThePreviousAttemptBudget() {
        val policy = RuntimeReconnectPolicy(jitter = { it })
        assertEquals(1_000L, policy.nextDelayMillis(2, "NETWORK_CHANGED"))
        assertEquals(2_000L, policy.nextDelayMillis(2, "NETWORK_CHANGED"))
        assertNull(policy.nextDelayMillis(2, "NETWORK_CHANGED"))

        policy.reset()

        assertEquals(1_000L, policy.nextDelayMillis(2, "NETWORK_CHANGED"))
        assertEquals(1, policy.attempts)
    }

    @Test
    fun retryClassificationIsNarrowAndFailClosed() {
        assertTrue(isRetryableRuntimeFailure("NETWORK_CHANGED"))
        assertTrue(isRetryableRuntimeFailure("NETWORK_UNAVAILABLE"))
        assertTrue(isRetryableRuntimeFailure("LIVE_NETWORK_UNAVAILABLE"))
        assertFalse(isRetryableRuntimeFailure("LIVE_TLS_REJECTED"))
        assertFalse(isRetryableRuntimeFailure("AUTHORITY_TRUST_REJECTED"))
        assertFalse(isRetryableRuntimeFailure("PROFILE_REVOKED"))
        assertFalse(isRetryableRuntimeFailure(""))
    }

    @Test
    fun fieldQualificationWaitsThroughRetryableInitialFailuresOnly() {
        assertFalse(
            isTerminalInitialRuntimeOutcome(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "LIVE_FALLBACK_EXHAUSTED",
                ),
            ),
        )
        assertFalse(
            isTerminalInitialRuntimeOutcome(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.BLOCKED,
                    failure = "NETWORK_UNAVAILABLE",
                ),
            ),
        )
        assertFalse(
            isTerminalInitialRuntimeOutcome(VpnRuntimeSnapshot(VpnRuntimeState.RECONNECTING)),
        )

        assertTrue(
            isTerminalInitialRuntimeOutcome(VpnRuntimeSnapshot(VpnRuntimeState.ACTIVE_KURD_LIVE)),
        )
        assertTrue(
            isTerminalInitialRuntimeOutcome(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "RECONNECT_EXHAUSTED",
                ),
            ),
        )
        assertTrue(
            isTerminalInitialRuntimeOutcome(
                VpnRuntimeSnapshot(
                    state = VpnRuntimeState.FAILED,
                    failure = "LIVE_TLS_REJECTED",
                ),
            ),
        )
        assertTrue(isTerminalInitialRuntimeOutcome(VpnRuntimeSnapshot(VpnRuntimeState.REVOKED)))
        assertTrue(isTerminalInitialRuntimeOutcome(VpnRuntimeSnapshot(VpnRuntimeState.IDLE)))
        assertTrue(isTerminalInitialRuntimeOutcome(VpnRuntimeSnapshot(VpnRuntimeState.STOPPING)))
    }

    @Test
    fun productionJitterIsBoundedAroundTheFrozenBackoff() {
        assertEquals(800L, jitterReconnectDelay(1_000L, sample = 0.0))
        assertEquals(1_000L, jitterReconnectDelay(1_000L, sample = 0.5))
        assertEquals(1_200L, jitterReconnectDelay(1_000L, sample = 1.0))
        assertEquals(19_200L, jitterReconnectDelay(16_000L, sample = 1.0))
    }
}

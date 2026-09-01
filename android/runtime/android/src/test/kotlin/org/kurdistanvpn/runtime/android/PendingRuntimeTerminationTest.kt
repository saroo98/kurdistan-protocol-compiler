// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class PendingRuntimeTerminationTest {
    @Test fun consumedManualStopCannotRearmFromALateNetworkCallback() {
        val pending = PendingRuntimeTermination()
        pending.request(VpnRuntimeState.IDLE, null)
        pending.take()
        pending.request(VpnRuntimeState.BLOCKED, "NETWORK_LOST")
        assertNull(pending.peek())
        assertNull(pending.take())
        assertEquals(RuntimeTermination(VpnRuntimeState.IDLE, null), pending.terminalOutcome())
        pending.request(VpnRuntimeState.REVOKED, "PROFILE_REVOKED")
        assertEquals(RuntimeTermination(VpnRuntimeState.REVOKED, "PROFILE_REVOKED"), pending.take())
        pending.request(VpnRuntimeState.IDLE, null)
        assertNull(pending.take())
    }

    @Test fun onlyTerminalStatesAndBoundedCategoricalFailuresCanBeRequested() {
        val pending = PendingRuntimeTermination()
        for (state in listOf(VpnRuntimeState.PREPARING, VpnRuntimeState.ACTIVE_KURD_LIVE, VpnRuntimeState.STOPPING)) {
            assertThrows(IllegalArgumentException::class.java) { pending.request(state, null) }
        }
        for (failure in listOf("private details", "X".repeat(65), "", "X\nY")) {
            assertThrows(IllegalArgumentException::class.java) { pending.request(VpnRuntimeState.FAILED, failure) }
        }
        assertNull(pending.peek())
    }
    @Test
    fun startupRacePreservesTheNetworkFailureWithTheTerminalState() {
        val pending = PendingRuntimeTermination()

        pending.request(VpnRuntimeState.BLOCKED, "NETWORK_CHANGED")

        assertEquals(
            RuntimeTermination(VpnRuntimeState.BLOCKED, "NETWORK_CHANGED"),
            pending.take(),
        )
        assertNull(pending.take())
    }

    @Test
    fun explicitManualStopOverridesAPendingNetworkFailure() {
        val pending = PendingRuntimeTermination()

        pending.request(VpnRuntimeState.BLOCKED, "NETWORK_UNAVAILABLE")
        pending.request(VpnRuntimeState.IDLE, null)

        assertEquals(
            RuntimeTermination(VpnRuntimeState.IDLE, null),
            pending.take(),
        )
    }

    @Test
    fun revocationOverridesNetworkFailureAndCannotBeDowngradedByStop() {
        val pending = PendingRuntimeTermination()

        pending.request(VpnRuntimeState.BLOCKED, "NETWORK_CHANGED")
        pending.request(VpnRuntimeState.REVOKED, "PROFILE_REVOKED")
        pending.request(VpnRuntimeState.IDLE, null)

        assertEquals(
            RuntimeTermination(VpnRuntimeState.REVOKED, "PROFILE_REVOKED"),
            pending.take(),
        )
    }
}

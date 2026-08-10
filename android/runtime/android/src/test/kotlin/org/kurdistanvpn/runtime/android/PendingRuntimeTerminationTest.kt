// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class PendingRuntimeTerminationTest {
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

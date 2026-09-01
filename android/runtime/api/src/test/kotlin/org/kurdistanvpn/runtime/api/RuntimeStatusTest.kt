// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import org.junit.Assert.*
import org.junit.Test

class RuntimeStatusTest {
    private fun active() = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE,
        startedAtElapsedRealtime = 1, profileGeneration = 2, planDigest = "1".repeat(64),
        profileFingerprint = "2".repeat(64), strategyFingerprint = "3".repeat(64),
        relayFingerprint = "4".repeat(64), runtimeRequestId = "5".repeat(32))

    @Test fun alwaysOnAndLockdownFlagsDoNotEstablishAnActiveTunnelClaim() {
        for (state in VpnRuntimeState.entries.filter { it != VpnRuntimeState.ACTIVE_KURD_LIVE }) {
            val value = VpnRuntimeSnapshot(state = state, alwaysOn = true, lockdown = true)
            assertEquals(state, value.validatedForDisplay().state)
        }
        val absent = VpnRuntimeSnapshot(state = VpnRuntimeState.ACTIVE_KURD_LIVE, alwaysOn = true, lockdown = true)
        assertEquals(VpnRuntimeState.BLOCKED, absent.validatedForDisplay().state)
    }
    @Test fun activeDisplayRequiresCurrentCompleteBoundedSessionMetadata() {
        assertEquals(active(), active().validatedForDisplay())
        for (value in listOf(active().copy(profileGeneration = 0), active().copy(planDigest = null),
            active().copy(runtimeRequestId = "invalid"), active().copy(startedAtElapsedRealtime = 0),
            active().copy(maxReconnectAttempts = 6), active().copy(failure = "REVOKED"))) {
            assertEquals(VpnRuntimeState.BLOCKED, value.validatedForDisplay().state)
        }
    }
    @Test fun malformedMetadataProducesCategoricalRedactedStatus() {
        val value = active().copy(failure = "unbounded / sensitive input", packetsRead = -1).validatedForDisplay()
        assertEquals(VpnRuntimeState.BLOCKED, value.state)
        assertEquals("INVALID_RUNTIME_STATUS", value.failure)
        assertNull(value.planDigest); assertNull(value.runtimeRequestId)
        assertEquals(0L, value.packetsRead)
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnNetworkTeardownBarrierTest {
    @Test
    fun waitsForEveryRegisteredVpnAfterDefaultNetworkAlreadyChanged() = runBlocking {
        var samples = 0
        val waits = mutableListOf<Long>()

        assertTrue(
            VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                timeoutMillis = 1_000,
                pollMillis = 25,
                vpnTransportSnapshot = {
                    samples++
                    if (samples < 3) listOf(false, true) else listOf(false, false)
                },
                wait = { delayMillis ->
                    waits.add(delayMillis)
                    Unit
                },
            ),
        )

        assertEquals(3, samples)
        assertEquals(listOf(25L, 25L), waits)
    }

    @Test
    fun snapshotFailureAndPersistentVpnFailClosed() = runBlocking {
        assertFalse(
            VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(
                timeoutMillis = 10,
                pollMillis = 1,
                vpnTransportSnapshot = { listOf(true) },
            ),
        )

        assertTrue(VpnNetworkTeardownBarrier.failedSnapshot().single())
    }
}

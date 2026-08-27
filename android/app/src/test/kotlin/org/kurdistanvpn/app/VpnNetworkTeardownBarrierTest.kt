// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnNetworkTeardownBarrierTest {
    @Test fun unknownCapabilitiesNeverProveVpnAbsence() {
        assertTrue(VpnNetworkTeardownBarrier.possiblyVpn(null))
        assertTrue(VpnNetworkTeardownBarrier.possiblyVpn(true))
        assertFalse(VpnNetworkTeardownBarrier.possiblyVpn(false))
    }

    @Test fun aVanishingCapabilityReadMustBeObservedAgainBeforeTeardownCompletes() = runBlocking {
        var count = 0
        assertTrue(VpnNetworkTeardownBarrier.awaitNoRegisteredVpn(1_000, 1,
            vpnTransportSnapshot = {
                count++
                listOf(VpnNetworkTeardownBarrier.possiblyVpn(if (count == 1) null else false))
            }, wait = { }))
        assertEquals(2, count)
    }

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

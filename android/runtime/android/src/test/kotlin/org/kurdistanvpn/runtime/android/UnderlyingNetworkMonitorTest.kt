// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class UnderlyingNetworkMonitorTest {
    @Test fun networkPolicyBlocksMeteredCaptiveAndSuspendedButNotCensoredValidation() {
        val state = UnderlyingNetworkState(1, false, false, true, false, false)
        val allow = org.kurdistanvpn.core.model.NetworkMeteredPolicy.ALLOW
        org.junit.Assert.assertTrue(state.permits(allow))
        for (policy in listOf(org.kurdistanvpn.core.model.NetworkMeteredPolicy.ASK,
                org.kurdistanvpn.core.model.NetworkMeteredPolicy.WAIT_FOR_UNMETERED)) {
            org.junit.Assert.assertFalse(state.permits(policy))
            org.junit.Assert.assertTrue(state.copy(metered = false).permits(policy))
        }
        for (blocked in listOf(state.copy(captive = true), state.copy(suspended = true),
                state.copy(vpn = true), state.copy(handle = 0))) org.junit.Assert.assertFalse(blocked.permits(allow))
    }
    @Test fun defaultNetworkStateIgnoresStaleCapabilitiesAndLoss() {
        val states = mutableListOf<UnderlyingNetworkState>()
        val tracker = DefaultNetworkStateTracker(states::add)
        tracker.available(1)
        tracker.capabilities(UnderlyingNetworkState(1, true, false, true, false, false))
        tracker.available(2)
        tracker.lost(1)
        tracker.capabilities(UnderlyingNetworkState(1, false, true, true, false, false))
        tracker.capabilities(UnderlyingNetworkState(2, true, false, false, false, false))
        tracker.lost(2)
        assertEquals(listOf(1L, 2L, 0L), states.map { it.handle })
        assertEquals(false, states[1].metered)
        assertEquals(false, states.last().validated)
    }
    @Test fun callbackRegistrationOwnsPartialAcquisitionAndCloseUncertainty() {
        var registered = 0; var closed = 0
        val owner = NetworkCallbackOwnership({ registered++; error("partial register") }, { closed++ })
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { owner.start() }
        owner.close(); owner.close()
        assertEquals(1, registered); assertEquals(1, closed)
        val uncertain = NetworkCallbackOwnership({}, { closed++; error("unregister failed") })
        uncertain.start()
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { uncertain.close() }
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { uncertain.close() }
        assertEquals(2, closed)
        org.junit.Assert.assertThrows(IllegalStateException::class.java) { uncertain.start() }
    }
    @Test
    fun retainsCurrentNetworkUntilLossThenPromotesAStandbyCandidate() {
        val transitions = mutableListOf<NetworkTransition<String>>()
        val tracker = CurrentNetworkTracker<String>(transitions::add)

        tracker.available("wifi")
        tracker.available("wifi")
        tracker.available("cell")
        tracker.lost("cell")
        tracker.available("cell")
        tracker.lost("wifi")
        tracker.lost("wifi")
        tracker.lost("cell")

        assertEquals(
            listOf(
                NetworkTransition(null, "wifi"),
                NetworkTransition("wifi", "cell"),
                NetworkTransition("cell", null),
            ),
            transitions,
        )
    }

    @Test
    fun waitsForAUsableUnderlyingNetwork() {
        val binding = UnderlyingNetworkAvailability<String>()
        val waiterStarted = CountDownLatch(1)
        var selected: String? = null
        val waiter = Thread {
            waiterStarted.countDown()
            selected = binding.awaitUsable(1_000)
        }

        waiter.start()
        waiterStarted.await(1, TimeUnit.SECONDS)
        binding.update("wifi", false)
        binding.update("wifi", true)
        waiter.join(1_000)

        assertEquals("wifi", selected)
    }

    @Test
    fun failsClosedWhenNoBoundUnderlyingNetworkArrives() {
        val binding = UnderlyingNetworkAvailability<String>()
        binding.update("wifi", false)

        assertNull(binding.awaitUsable(10))
    }
}

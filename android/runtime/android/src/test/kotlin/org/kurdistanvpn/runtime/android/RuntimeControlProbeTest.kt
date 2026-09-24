// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

class RuntimeControlProbeTest {
    @Test fun cancellationRejectsLateResultAndDoesNotFreeTheSlotBeforeNativeReturns() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val peer = Any()
        val probe = RuntimeControlProbe { id -> if (id != CatalogId("profile")) null else object : RuntimeSelectedProbeV1 {
            override fun runSelected(preferences: ProbePreferences): NativeProductResult<NativeProbeResult> {
                entered.countDown()
                check(release.await(3, TimeUnit.SECONDS))
                return NativeProductResult.Failure(ProductFailureCode.NETWORK_UNAVAILABLE)
            }
        } }
        val pool = Executors.newSingleThreadExecutor()
        try {
            val result = pool.submit<NativeProductResult<NativeProbeResult>> {
                probe.run("one", CatalogId("profile"), ProbePreferences(), peer)
            }
            assertTrue(entered.await(3, TimeUnit.SECONDS))
            assertFalse(probe.cancel("one", Any()))
            assertTrue(probe.cancel("one", peer))
            assertEquals(NativeProductResult.Failure(ProductFailureCode.OPERATION_ALREADY_ACTIVE),
                probe.run("two", CatalogId("profile"), ProbePreferences(), peer))
            release.countDown()
            assertEquals(NativeProductResult.Failure(ProductFailureCode.CANCELLED), result.get(3, TimeUnit.SECONDS))
            assertEquals(NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE),
                probe.run("three", CatalogId("foreign"), ProbePreferences(), peer))
        } finally { release.countDown(); pool.shutdownNow() }
    }
}

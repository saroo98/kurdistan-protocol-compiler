// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.android.RuntimeSelectedProbeV1

class RuntimeSessionCoordinatorProbeTest {
    @Test fun missingOwnedPortIsUnavailable() {
        assertEquals(NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE),
            RuntimeSessionCoordinator().probe(ProbePreferences()))
    }
    @Test fun forwardsExactPreferencesAndTypedResultOnce() {
        val expectedPreferences = ProbePreferences(method = ProbeMethod.TCP_CONNECT, signedTargetId = CatalogId("probe-7"))
        val expected = NativeProductResult.Success(NativeProbeResult(
            NativeProbePath.ACTIVE_RELAY_END_TO_END, NativeProbeMethod.TCP_CONNECT, 1, 1, 0, 0,
            123456, null, 0, NativeProbeStability.NOT_ENOUGH_SAMPLES, NativeProbeCompletion.COMPLETE))
        var calls = 0
        val port = object : RuntimeSelectedProbeV1 {
            override fun runSelected(preferences: ProbePreferences): NativeProductResult<NativeProbeResult> {
                assertSame(expectedPreferences, preferences)
                calls++
                return expected
            }
        }
        assertSame(expected, RuntimeSessionCoordinator(port).probe(expectedPreferences))
        assertEquals(1, calls)
    }
}

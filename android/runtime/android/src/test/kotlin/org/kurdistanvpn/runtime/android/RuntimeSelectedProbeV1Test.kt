// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

class RuntimeSelectedProbeV1Test {
    @Test fun exactRequestHasNoTranslationOrTimeoutClamping() {
        val result = selectedProbeRequestV1(ProbePreferences(ProbeMethod.TCP_CONNECT,
            signedTargetId = CatalogId("probe-7")))
        assertEquals(NativeProductResult.Success(NativeProbeRequest(7, NativeProbeMethod.TCP_CONNECT, 3000, 3000, 1)), result)
        val maximum = selectedProbeRequestV1(ProbePreferences(ProbeMethod.TCP_CONNECT,
            signedTargetId = CatalogId("probe-65535"), timeoutSeconds = 30))
        assertEquals(NativeProductResult.Success(NativeProbeRequest(65535, NativeProbeMethod.TCP_CONNECT, 30000, 30000, 1)), maximum)
    }
    @Test fun unsupportedMethodsAndAbsentOrNoncanonicalTargetsAreUnavailable() {
        for (method in ProbeMethod.entries.filter { it != ProbeMethod.TCP_CONNECT }) {
            assertEquals(unavailable, selectedProbeRequestV1(ProbePreferences(method, signedTargetId = CatalogId("probe-7"))))
        }
        assertEquals(unavailable, selectedProbeRequestV1(ProbePreferences(ProbeMethod.TCP_CONNECT)))
        for (target in listOf("probe-0", "probe-07", "probe-65536", "probe-999999999999999999", "probe", "other-7")) {
            assertEquals(target, unavailable, selectedProbeRequestV1(ProbePreferences(ProbeMethod.TCP_CONNECT, signedTargetId = CatalogId(target))))
        }
        for (target in listOf("probe-+7", "probe-٧", " probe-7", "probe-7 ")) {
            assertThrows(IllegalArgumentException::class.java) { CatalogId(target) }
        }
        for (timeout in listOf(0, 31, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { ProbePreferences(timeoutSeconds = timeout) }
        }
    }
    @Test fun actualCapturedBindingCannotReviveOntoIdenticalProfileNewStartOrAttempt() {
        // Availability boundary only. Authenticated KPA producer provenance is separately tested natively.
        val digest = ByteArray(32) { 1 }
        val facts = NativeProductionBootstrapFactsV1(9uL, digest, 1280, 1, 1)
        var opening = Any()
        val original = opening
        val binding = RuntimeCapturedProbeBindingV1(facts, { opening === original }, { it == 7 }, 9uL, digest)
        assertTrue(binding.permits(7))
        assertFalse(binding.permits(8))
        binding.observe(NativeControlEvent.TransportReady(1uL, 1uL))
        binding.observe(NativeControlEvent.ReconnectStarted(2uL, 2uL, NativeReconnectReason.USER_REQUEST, 1, 1))
        assertFalse(binding.isCurrent())
        val second = RuntimeCapturedProbeBindingV1(facts, { opening === original }, { it == 7 }, 9uL, digest)
        assertTrue(second.permits(7))
        opening = Any()
        assertFalse(second.isCurrent())
        opening = original
        assertFalse(second.isCurrent())
        assertFalse(RuntimeCapturedProbeBindingV1(facts, { true }, { true }, 8uL, digest).isCurrent())
        assertFalse(RuntimeCapturedProbeBindingV1(facts, { true }, { true }, 9uL, ByteArray(32)).isCurrent())
    }
    private val unavailable = NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
}

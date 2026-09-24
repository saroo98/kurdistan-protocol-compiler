// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativejni.ProductionSettingsEncodingV1
import org.kurdistanvpn.runtime.api.PerAppRoutingMode

class RuntimeCapturedRoutingTest {
    @Test fun readsPlatformPreferencesFromTheSameCapturedSettings() {
        val settings = ProductSettings(
            tunnelMode = TunnelMode.TUN_PLUS_PROXY,
            networkMeteredPolicy = NetworkMeteredPolicy.WAIT_FOR_UNMETERED,
            pausePolicy = PausePolicy.UNTIL_RESUMED,
            localProxy = LocalProxyPreferences(socksPort = 12080, httpConnectPort = 12081),
            notifications = NotificationPreferences(showSpeed = true))
        val encoded = encode(settings)
        val result = readCapturedPlatformSettingsV1(encoded)
        assertEquals(TunnelMode.TUN_PLUS_PROXY, result.tunnelMode)
        assertEquals(NetworkMeteredPolicy.WAIT_FOR_UNMETERED, result.meteredPolicy)
        assertEquals(PausePolicy.UNTIL_RESUMED, result.pausePolicy)
        assertEquals(12080, result.proxy.socksPort)
        assertEquals(12081, result.proxy.httpConnectPort)
        assertTrue(result.showSpeed)
        assertEquals(0, encoded.position())
    }

    @Test fun readsExactCapturedPackagesWithoutReconstructingFromTheNativeCount() {
        val settings = ProductSettings(routing = RoutingPreferences(mode = PerAppSelectionMode.INCLUDE_ONLY,
            packages = (1..256).map { "org.example.app$it" }.toSet()))
        val encoded = encode(settings)
        val result = readCapturedRoutingV1(encoded)
        assertEquals(PerAppRoutingMode.INCLUDE_ONLY, result.perAppMode)
        assertEquals(settings.routing.packages, result.packages)
        assertEquals(0, encoded.position())
    }

    @Test fun variableStrategyAndDnsFieldsCannotShiftThePackageBoundary() {
        val settings = ProductSettings(
            connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY,
                manualStrategyId = CatalogId("strategy-1")),
            tunnel = TunnelPreferences(dnsMode = ResolverPolicy.CUSTOM,
                customDns = "1.1.1.1", secondaryCustomDns = "2606:4700:4700::1111"),
            routing = RoutingPreferences(mode = PerAppSelectionMode.EXCLUDE_SELECTED,
                packages = setOf("org.example.browser")))
        val result = readCapturedRoutingV1(encode(settings))
        assertEquals(PerAppRoutingMode.EXCLUDE_SELECTED, result.perAppMode)
        assertEquals(setOf("org.example.browser"), result.packages)
    }

    @Test fun truncatedOrWrongVersionCaptureIsRejected() {
        val encoded = encode(ProductSettings())
        for (limit in 0 until encoded.limit()) {
            assertThrows(IllegalArgumentException::class.java) {
                readCapturedRoutingV1(encoded.duplicate().apply { limit(limit) })
            }
        }
        encoded.put(4, 2)
        assertThrows(IllegalArgumentException::class.java) { readCapturedRoutingV1(encoded) }
    }

    private fun encode(settings: ProductSettings): ByteBuffer {
        val output = ByteBuffer.allocate(196608)
        val result = ProductionSettingsEncodingV1.encode(settings, output)
        check(result is NativeProductResult.Success)
        return output.apply { limit(result.value) }
    }
}

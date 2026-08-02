// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ProductSettingsTest {
    @Test
    fun defaultsAreValidAndPrivacyPreserving() {
        val value = Phase9Settings().validated()
        assertEquals(DnsMode.INTERNAL_TUN, value.tunnel.dnsMode)
        assertEquals(PerAppSelectionMode.ALL_APPS, value.routing.mode)
        assertEquals(false, value.updates.automatic)
        assertEquals("", value.probes.testUrl)
        assertEquals(DiagnosticLogLevel.WARNING, value.diagnostics.level)
    }

    @Test
    fun customDnsRequiresAnIpLiteral() {
        assertThrows(IllegalArgumentException::class.java) {
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = "resolver.example").validated()
        }
        assertEquals(
            "1.1.1.1",
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = " 1.1.1.1 ")
                .validated().customDns,
        )
        assertEquals(
            "2001:db8::1",
            TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = "2001:0DB8:0:0:0:0:0:1")
                .validated().customDns,
        )
        listOf("1.2.3.01", "2001:::1", "gggg::1", "fe80::1%wlan0", "[2001:db8::1]").forEach { invalid ->
            val failure = assertThrows(SettingsValidationException::class.java) {
                TunnelPreferences(dnsMode = DnsMode.CUSTOM, customDns = invalid).validated()
            }
            assertEquals(SettingsField.CUSTOM_DNS, failure.field)
        }
    }

    @Test
    fun routingRejectsInvalidOrAmbiguousPolicies() {
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(packages = setOf("org.example.app")).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(mode = PerAppSelectionMode.INCLUDE_ONLY).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            RoutingPreferences(excludedCidrs = listOf("192.168.0.0/99")).validated()
        }
        assertEquals(
            listOf("192.168.0.0/24", "2001:db8::/32"),
            RoutingPreferences(
                excludedCidrs = listOf("192.168.0.42/24", "2001:0db8:1234::1/32"),
            ).validated().excludedCidrs,
        )
    }

    @Test
    fun unsafeResourceBoundsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            ExpertPreferences(memoryLimitMb = 20).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProbePreferences(timeoutSeconds = 0).validated()
        }
        assertThrows(IllegalArgumentException::class.java) {
            UpdatePreferences(intervalHours = 0).validated()
        }
    }

    @Test
    fun validationFailuresIdentifyTheExactSettingsField() {
        val failure = assertThrows(SettingsValidationException::class.java) {
            RoutingPreferences(
                mode = PerAppSelectionMode.INCLUDE_ONLY,
                packages = emptySet(),
            ).validated()
        }
        assertEquals(SettingsField.ROUTING_PACKAGES, failure.field)
        assertEquals("EMPTY_INCLUDE_SET", failure.category)
        assertTrue(failure.message.orEmpty().contains("ROUTING_PACKAGES"))
    }
}

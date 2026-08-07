// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.kurdistanvpn.core.model.SelectionMode

class VpnRoutingPolicyTest {
    @Test
    fun acceptsMutuallyExclusiveSupportedModes() {
        assertEquals(
            listOf("org.example.alpha", "org.example.zulu"),
            VpnRoutingPolicy(
                PerAppRoutingMode.INCLUDE_ONLY,
                setOf("org.example.zulu", "org.example.alpha"),
            ).validate().packages.toList(),
        )
        VpnRoutingPolicy(
            PerAppRoutingMode.EXCLUDE_SELECTED,
            setOf("org.example.browser"),
        ).validate()
    }

    @Test
    fun rejectsAmbiguousOrMalformedRules() {
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(packages = setOf("org.example.app")).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(
                PerAppRoutingMode.EXCLUDE_SELECTED,
                setOf("not a package"),
            ).validate()
        }
    }
}

class VpnRuntimeConfigTest {
    @Test
    fun loopbackRuntimeAcceptsOnlyExecutableDnsAndIpPolicies() {
        VpnRuntimeConfig(VpnRoutingPolicy()).validatedForLoopbackTransport()
        assertThrows(IllegalArgumentException::class.java) {
            VpnRuntimeConfig(
                VpnRoutingPolicy(),
                dnsMode = DnsMode.CLOUDFLARE,
            ).validatedForLoopbackTransport()
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnRuntimeConfig(
                VpnRoutingPolicy(),
                ipMode = IpMode.IPV6_ONLY,
            ).validatedForLoopbackTransport()
        }
    }

    @Test
    fun runtimeStartWireIsBoundedCanonicalAndConsumesAuthorityBytes() {
        val verify = byteArrayOf(1, 2, 3)
        val activation = byteArrayOf(4, 5, 6, 7)
        val recipientRequest = byteArrayOf(8, 9)
        val recipientPrivate = byteArrayOf(10, 11)
        val encoded = RuntimeStartWire.encode(
            verifyRequest = verify,
            activationRecord = activation,
            recipientRequest = recipientRequest,
            recipientPrivate = recipientPrivate,
            config = VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(
                    PerAppRoutingMode.INCLUDE_ONLY,
                    setOf("org.example.zulu", "org.example.alpha"),
                ),
                selectionMode = SelectionMode.AUTOMATIC,
                mtu = 1400,
            ),
        )
        assertEquals("KRV2", encoded.copyOfRange(0, 4).decodeToString())
        assertEquals(encoded.size, java.nio.ByteBuffer.wrap(encoded, 20, 4).int)
        assertEquals(listOf(1, 2, 3), verify.map(Byte::toInt))
        assertEquals(listOf(4, 5, 6, 7), activation.map(Byte::toInt))
    }

    @Test
    fun runtimeStartWireRejectsMissingAuthorityAndUnsupportedWidening() {
        assertThrows(IllegalArgumentException::class.java) {
            RuntimeStartWire.encode(
                byteArrayOf(),
                byteArrayOf(1),
                byteArrayOf(2),
                byteArrayOf(3),
                VpnRuntimeConfig(VpnRoutingPolicy()),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuntimeStartWire.encode(
                byteArrayOf(1),
                byteArrayOf(2),
                byteArrayOf(3),
                byteArrayOf(4),
                VpnRuntimeConfig(VpnRoutingPolicy(), allowLan = true),
            )
        }
    }

    @Test
    fun liveRuntimeAcceptsOnlyStrictNumericCustomDns() {
        listOf("1.1.1.1", "2606:4700:4700::1111").forEach { address ->
            VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(),
                dnsMode = DnsMode.CUSTOM,
                customDns = address,
            ).validatedForLiveTransport()
        }
        listOf("1", "001.1.1.1", "256.1.1.1", "resolver.example", "fe80::1%wlan0").forEach { address ->
            assertThrows(IllegalArgumentException::class.java) {
                VpnRuntimeConfig(
                    routingPolicy = VpnRoutingPolicy(),
                    dnsMode = DnsMode.CUSTOM,
                    customDns = address,
                ).validatedForLiveTransport()
            }
        }
    }
}

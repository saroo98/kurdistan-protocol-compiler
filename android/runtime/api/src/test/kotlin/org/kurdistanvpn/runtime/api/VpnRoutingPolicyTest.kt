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
        val encoded = RuntimeStartWire.encode(
            verifyRequest = verify,
            activationRecord = activation,
            config = VpnRuntimeConfig(
                routingPolicy = VpnRoutingPolicy(
                    PerAppRoutingMode.INCLUDE_ONLY,
                    setOf("org.example.zulu", "org.example.alpha"),
                ),
                selectionMode = SelectionMode.AUTOMATIC,
                mtu = 1400,
            ),
        )
        assertEquals("KRS1", encoded.copyOfRange(0, 4).decodeToString())
        assertEquals(verify.size + activation.size, encoded.size - 26 - 2 * 2 -
            "org.example.alpha".length - "org.example.zulu".length)
        assertEquals(listOf(1, 2, 3), verify.map(Byte::toInt))
        assertEquals(listOf(4, 5, 6, 7), activation.map(Byte::toInt))
    }

    @Test
    fun runtimeStartWireRejectsMissingAuthorityAndUnsupportedWidening() {
        assertThrows(IllegalArgumentException::class.java) {
            RuntimeStartWire.encode(
                byteArrayOf(),
                byteArrayOf(1),
                VpnRuntimeConfig(VpnRoutingPolicy()),
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            RuntimeStartWire.encode(
                byteArrayOf(1),
                byteArrayOf(2),
                VpnRuntimeConfig(VpnRoutingPolicy(), allowLan = true),
            )
        }
    }
}

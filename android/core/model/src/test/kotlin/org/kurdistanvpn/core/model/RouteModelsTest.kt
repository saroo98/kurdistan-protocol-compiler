// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class RouteModelsTest {
    @Test fun ipFamilyRequiresAddressesRoutesDnsAndNativeSupportTogether() {
        val both = setOf(IpFamily.IPV4, IpFamily.IPV6)
        assertEquals(IpMode.IPV4_ONLY, effectiveIpMode(IpMode.AUTO, both, both, setOf(IpFamily.IPV4), both))
        assertEquals(IpMode.DUAL_STACK, effectiveIpMode(IpMode.AUTO, both, both, both, both))
        assertThrows(IllegalArgumentException::class.java) { effectiveIpMode(IpMode.DUAL_STACK, both, both, setOf(IpFamily.IPV4), both) }
        assertThrows(IllegalArgumentException::class.java) { effectiveIpMode(IpMode.AUTO, emptySet(), both, both, both) }
    }
    @Test fun resolverAcceptsOnlyNumericCanonicalAddressesAndCopiesInput() {
        listOf("resolver.example", "fe80::1%wlan0", "1.2.3.01").forEach {
            assertThrows(IllegalArgumentException::class.java) { NumericAddress(it) }
        }
        val address = NumericAddress("2001:0DB8:0:0:0:0:0:1")
        assertEquals("2001:db8::1", address.value)
        assertFalse(address.toString().contains("2001"))
        val source = mutableListOf(address)
        val policy = ResolverConfiguration.Custom(source)
        source.clear()
        assertEquals(listOf(address), policy.addresses)
        assertThrows(UnsupportedOperationException::class.java) { (policy.addresses as MutableList).clear() }
        assertThrows(IllegalArgumentException::class.java) { ResolverConfiguration.Custom(emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { ResolverConfiguration.Custom(List(3) { address }) }
        assertEquals(policy, policy.copy())
    }

    @Test fun exclusionsMustBeCanonicalAndContainedInSignedRanges() {
        val signed = CanonicalRoute("10.0.0.0/8")
        assertTrue(signed.contains(CanonicalRoute("10.12.0.0/16")))
        assertFalse(signed.contains(CanonicalRoute("11.0.0.0/8")))
        assertFalse(signed.contains(CanonicalRoute("0.0.0.0/0")))
        assertFalse(signed.contains(CanonicalRoute("::/0")))
        assertTrue(CanonicalRoute("2001:db8::/32").contains(CanonicalRoute("2001:db8:1::/48")))
        assertEquals("10.12.0.0/16", CanonicalRoute("10.12.4.9/16").value)
        assertThrows(IllegalArgumentException::class.java) { ExcludedRoutes(listOf(CanonicalRoute("11.0.0.0/8"))).validatedAgainst(setOf(signed)) }
        assertEquals(1, ExcludedRoutes(listOf(CanonicalRoute("10.12.0.0/16"))).validatedAgainst(setOf(signed)).routes.size)
        assertThrows(IllegalArgumentException::class.java) { ExcludedRoutes(List(65) { signed }) }
    }

    @Test fun mtuCannotExpandSignedOrNativeBounds() {
        assertEquals(1350, RequestedMtu(1500).effective(1280..1400, 1280..1350))
        assertThrows(IllegalArgumentException::class.java) { RequestedMtu(1279) }
        assertThrows(IllegalArgumentException::class.java) { RequestedMtu(1501) }
        assertThrows(IllegalArgumentException::class.java) { RequestedMtu(1500).effective(1400..1450, 1280..1350) }
    }

    @Test fun subtractionCanonicalizesBothFamiliesAndRejectsRouteExplosion() {
        fun subtract(routes: List<String>, holes: List<String>, limit: Int = 256) = CanonicalRoute.subtract(
            routes.map(::CanonicalRoute).toSet(), holes.map(::CanonicalRoute), limit).map { it.value }.toSet()
        assertEquals(setOf("0.0.0.0/0"), subtract(listOf("0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/8"), emptyList()))
        assertEquals(setOf("2001:db8::/128", "2001:db8::2/127"),
            subtract(listOf("2001:0db8::/126"), listOf("2001:db8::1/128")))
        assertEquals(setOf("::/0"), subtract(listOf("0.0.0.0/0", "::/0"), listOf("0.0.0.0/0")))
        assertEquals(emptySet<String>(), subtract(listOf("10.0.0.1/32"), listOf("10.0.0.0/8")))
        assertEquals(32, subtract(listOf("0.0.0.0/0"), listOf("0.0.0.0/32"), 32).size)
        assertThrows(IllegalArgumentException::class.java) {
            subtract(listOf("0.0.0.0/0"), listOf("0.0.0.0/32"), 31)
        }
        assertThrows(IllegalArgumentException::class.java) {
            subtract(listOf("::/0"), listOf("::/128", "8000::/128", "4000::/128"))
        }
    }
}

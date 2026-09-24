// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.*

class TunPlanApplierTest {
    @Test fun preservesNativeIpv4Ipv6AndDualStackRoutesAndDns() {
        for (ip in listOf(IpMode.IPV4_ONLY, IpMode.IPV6_ONLY, IpMode.DUAL_STACK)) {
            val plan = productionTunConfigurationV1(snapshot(ip), VpnRoutingPolicy(), "org.kurdistanvpn.app")
            val expected = when (ip) {
                IpMode.IPV4_ONLY -> listOf(LiveIpPrefix("10.0.0.2", 32))
                IpMode.IPV6_ONLY -> listOf(LiveIpPrefix("fd00::2", 128))
                else -> listOf(LiveIpPrefix("10.0.0.2", 32), LiveIpPrefix("fd00::2", 128))
            }
            assertEquals(expected, plan.addresses)
            assertEquals(expected.map { LiveIpPrefix(if (it.prefixLength == 32) "0.0.0.0" else "::", 0) }, plan.routes)
            assertEquals(expected.map { if (it.prefixLength == 32) "10.0.0.1" else "fd00::1" }, plan.dnsServers)
            assertEquals(1280, plan.mtu)
        }
    }

    @Test fun packageModeCountAndSelfSelectionMustMatchBeforeBuilder() {
        val opening = snapshot(IpMode.IPV4_ONLY, PerAppSelectionMode.INCLUDE_ONLY, 1)
        val policy = VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY, setOf("org.example.browser"))
        assertEquals(policy, productionTunConfigurationV1(opening, policy, "org.kurdistanvpn.app").routingPolicy)
        assertThrows(IllegalArgumentException::class.java) {
            productionTunConfigurationV1(opening, VpnRoutingPolicy(), "org.kurdistanvpn.app")
        }
        assertThrows(IllegalArgumentException::class.java) {
            productionTunConfigurationV1(opening, policy.copy(packages = policy.packages + "org.example.other"), "org.kurdistanvpn.app")
        }
        assertThrows(IllegalArgumentException::class.java) {
            productionTunConfigurationV1(opening, policy, "org.example.browser")
        }
    }

    private fun snapshot(ip: IpMode, mode: PerAppSelectionMode = PerAppSelectionMode.ALL_APPS, count: Int = 0): NativeOpeningSnapshot {
        val v4 = ip != IpMode.IPV6_ONLY
        val v6 = ip != IpMode.IPV4_ONLY
        return NativeOpeningSnapshot(1u, ByteArray(32) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 },
            null, null, null, ExitRegion.UNKNOWN, TunnelMode.TUN_ONLY, ip, ResolverPolicy.INTERNAL, 1280, false, mode, count,
            if (v4) NumericAddress("10.0.0.2") else null, if (v6) NumericAddress("fd00::2") else null,
            buildList { if (v4) add(NumericAddress("10.0.0.1")); if (v6) add(NumericAddress("fd00::1")) },
            buildList { if (v4) add(CanonicalRoute("0.0.0.0/0")); if (v6) add(CanonicalRoute("::/0")) },
            NativeCapabilities(setOf(NativeCapability.RAW_IP), setOf(NativeCapability.RAW_IP), setOf(NativeCapability.RAW_IP)),
            NativePacketLimits(1280, 1, 1, setOf(NativePayloadProtocol.TCP)),
            NativeReconnectLimits(1, 10, 1, 1, 0, 1000, 300000), null, null, null,
            NativeResourceLimits(NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES, 4096, 2048, 256, 128, 300000,
                NativeSignedRawFlowCapStatus.NOT_SEPARATELY_SPECIFIED, 134217728, 83886080, 1048576))
    }
}

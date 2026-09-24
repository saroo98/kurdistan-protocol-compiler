// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeCapability
import org.kurdistanvpn.core.nativeapi.NativePayloadProtocol

class ProductionWireV1Test {
    @Test fun namespacesDoNotShareOrdinals() {
        assertEquals(ProductFailureCode.RESOURCE_LIMIT, productionFailureV1(5))
        assertEquals(ProductFailureCode.SIZE_LIMIT, maintenanceFailureV1(5))
        assertEquals(ProductFailureCode.PROFILE_UNTRUSTED, productionFailureV1(14))
        assertEquals(ProductFailureCode.UPDATE_FETCH_REJECTED, maintenanceFailureV1(14))
    }

    @Test fun everyStatusAndUnknownValueHasExplicitFailureMeaning() {
        val p1 = listOf(
            ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.PROFILE_INCOMPATIBLE, ProductFailureCode.INVALID_INPUT,
            ProductFailureCode.OPERATION_INTERRUPTED, ProductFailureCode.SIZE_LIMIT, ProductFailureCode.RESOURCE_LIMIT,
            ProductFailureCode.RATE_LIMITED, ProductFailureCode.CANCELLED, ProductFailureCode.OPERATION_TIMED_OUT,
            ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.NODE_UNREACHABLE,
            ProductFailureCode.PROFILE_EXPIRED, ProductFailureCode.PROFILE_REVOKED, ProductFailureCode.PROFILE_UNTRUSTED,
            ProductFailureCode.SESSION_AUTHENTICATION_FAILED, ProductFailureCode.SOCKET_PROTECTION_FAILED,
            ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.INTERNAL_FAILURE,
            ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.PROFILE_UNTRUSTED, ProductFailureCode.PROFILE_UNTRUSTED,
            ProductFailureCode.PROFILE_WRONG_DEVICE, ProductFailureCode.PROFILE_ROLLBACK, ProductFailureCode.PROFILE_INCOMPATIBLE,
            ProductFailureCode.DNS_POLICY_REJECTED,
        )
        (0..26).forEach { assertEquals(p1[it], productionFailureV1(it)) }
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, productionFailureV1(-1))
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, productionFailureV1(Int.MAX_VALUE))
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, maintenanceFailureV1(0))
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, maintenanceFailureV1(1))
        assertEquals(ProductFailureCode.INTERNAL_FAILURE, maintenanceFailureV1(65535))
    }

    @Test fun everySnapshotEnumAndMaskHasAnExplicitWireMapping() {
        val exits = listOf(
            ExitRegion.UNKNOWN,
            ExitRegion.EUROPE,
            ExitRegion.ASIA,
            ExitRegion.AFRICA,
            ExitRegion.NORTH_AMERICA,
            ExitRegion.SOUTH_AMERICA,
            ExitRegion.OCEANIA,
        )
        exits.forEachIndexed { wire, expected -> assertEquals(expected, decodeExitRegionV1(wire)) }
        assertNull(decodeExitRegionV1(-1))
        assertNull(decodeExitRegionV1(7))

        listOf(TunnelMode.TUN_ONLY, TunnelMode.TUN_PLUS_PROXY, TunnelMode.PROXY_ONLY)
            .forEachIndexed { index, expected -> assertEquals(expected, decodeTunnelModeV1(index + 1)) }
        listOf(IpMode.IPV4_ONLY, IpMode.IPV6_ONLY, IpMode.DUAL_STACK)
            .forEachIndexed { index, expected -> assertEquals(expected, decodeIpModeV1(index + 2)) }
        listOf(ResolverPolicy.INTERNAL, ResolverPolicy.PROFILE_DEFINED, ResolverPolicy.PRESET, ResolverPolicy.CUSTOM)
            .forEachIndexed { index, expected -> assertEquals(expected, decodeResolverPolicyV1(index + 1)) }
        listOf(PerAppSelectionMode.ALL_APPS, PerAppSelectionMode.INCLUDE_ONLY, PerAppSelectionMode.EXCLUDE_SELECTED)
            .forEachIndexed { index, expected -> assertEquals(expected, decodePerAppModeV1(index + 1)) }
        assertNull(decodeTunnelModeV1(0)); assertNull(decodeTunnelModeV1(4))
        assertNull(decodeIpModeV1(1)); assertNull(decodeIpModeV1(5))
        assertNull(decodeResolverPolicyV1(0)); assertNull(decodeResolverPolicyV1(5))
        assertNull(decodePerAppModeV1(0)); assertNull(decodePerAppModeV1(4))

        val capabilityBits = listOf(
            1 to NativeCapability.RAW_IP,
            2 to NativeCapability.PROXY_STREAM,
            4 to NativeCapability.PROBE_ACTIVE_RELAY,
            8 to NativeCapability.PROBE_DISCONNECTED,
            16 to NativeCapability.SAME_DEPLOYMENT_UPDATE,
        )
        capabilityBits.forEach { (wire, expected) -> assertEquals(setOf(expected), decodeCapabilitiesV1(wire)) }
        assertEquals(setOf(
            NativeCapability.RAW_IP,
            NativeCapability.PROXY_STREAM,
            NativeCapability.PROBE_ACTIVE_RELAY,
            NativeCapability.PROBE_DISCONNECTED,
            NativeCapability.SAME_DEPLOYMENT_UPDATE,
        ), decodeCapabilitiesV1(31))
        assertNull(decodeCapabilitiesV1(32))

        val payloadBits = listOf(
            1 to NativePayloadProtocol.ICMP,
            2 to NativePayloadProtocol.ICMPV6,
            4 to NativePayloadProtocol.TCP,
            8 to NativePayloadProtocol.UDP,
        )
        payloadBits.forEach { (wire, expected) -> assertEquals(setOf(expected), decodePayloadProtocolsV1(wire)) }
        assertEquals(setOf(
            NativePayloadProtocol.ICMP,
            NativePayloadProtocol.ICMPV6,
            NativePayloadProtocol.TCP,
            NativePayloadProtocol.UDP,
        ), decodePayloadProtocolsV1(15))
        assertNull(decodePayloadProtocolsV1(16))
    }

    @Test fun boundedOwnedWriterWipesRetiredAndFinalScratchBuffers() {
        val writer = ProductionWriterV1(maximum = 16, initialCapacity = 4)
        val field = ProductionWriterV1::class.java.getDeclaredField("buffer").apply { isAccessible = true }
        val retired = field.get(writer) as ByteArray
        writer.bytes(byteArrayOf(1, 2, 3, 4, 5))
        assertTrue(retired.all { it == 0.toByte() })

        val finalScratch = field.get(writer) as ByteArray
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), writer.result())
        assertTrue(finalScratch.all { it == 0.toByte() })

        lateinit var exceptionalScratch: ByteArray
        assertThrows(IllegalArgumentException::class.java) {
            ProductionWriterV1(maximum = 8, initialCapacity = 4).use { exceptional ->
                exceptionalScratch = field.get(exceptional) as ByteArray
                exceptional.bytes(byteArrayOf(1, 2, 3, 4))
                exceptional.bytes(byteArrayOf(5, 6, 7, 8, 9))
            }
        }
        assertTrue(exceptionalScratch.all { it == 0.toByte() })
    }
}

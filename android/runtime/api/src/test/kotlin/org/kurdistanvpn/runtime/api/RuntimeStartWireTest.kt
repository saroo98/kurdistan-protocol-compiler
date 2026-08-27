// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import org.junit.Assert.*
import org.junit.Test

class RuntimeStartWireTest {
    @Test fun oversizedBlankConfigurationFieldsAreRejectedBeforeEncoding() {
        for (config in listOf(VpnRuntimeConfig(VpnRoutingPolicy(), manualStrategyId = " ".repeat(257)),
            VpnRuntimeConfig(VpnRoutingPolicy(), customDns = " ".repeat(46)))) {
            assertThrows(IllegalArgumentException::class.java) {
                RuntimeStartWire.encode(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4), config)
            }
        }
    }
    @Test fun exactCanonicalRuntimeV2GoldenPreservesSourceBytes() {
        val source = arrayOf(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4))
        val encoded = RuntimeStartWire.encode(source[0], source[1], source[2], source[3], VpnRuntimeConfig(VpnRoutingPolicy()))
        val golden = "4b5256320200001c000000010000000100010001000000384b52533101010101010005dc0000000000000000000100000001010101020304"
        assertArrayEquals(golden.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), encoded)
        source.indices.forEach { assertArrayEquals(byteArrayOf((it + 1).toByte()), source[it]) }
        encoded.fill(0)
    }

    @Test fun sourceMutationDuringNestedConfigurationReadCannotChangeCapturedAuthorityBytes() {
        val source = arrayOf(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4))
        val packages = object : AbstractSet<String>() {
            override val size = 1
            override fun iterator(): Iterator<String> {
                source.forEach { it.fill(9) }
                return listOf("org.example.app").iterator()
            }
        }
        val encoded = RuntimeStartWire.encode(source[0], source[1], source[2], source[3],
            VpnRuntimeConfig(VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY, packages)))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), encoded.takeLast(4).toByteArray())
        encoded.fill(0)
    }

    @Test fun nestedConfigurationIsReadOnceBeforeSemanticValidation() {
        var iterations = 0
        val packages = object : AbstractSet<String>() {
            override val size = 1
            override fun iterator(): Iterator<String> {
                iterations++
                return listOf(if (iterations == 1) "org.example.app" else "invalid package").iterator()
            }
        }
        val encoded = RuntimeStartWire.encode(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), byteArrayOf(4),
            VpnRuntimeConfig(VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY, packages)))
        assertEquals(1, iterations)
        assertTrue(encoded.toString(Charsets.ISO_8859_1).contains("org.example.app"))
        assertFalse(encoded.toString(Charsets.ISO_8859_1).contains("invalid package"))
        encoded.fill(0)
    }

    @Test fun emptyOversizedAndInvalidPolicyInputsFailWithoutWipingCallerMaterial() {
        for (sizes in listOf(intArrayOf(0, 1, 1, 1), intArrayOf(1_500_001, 1, 1, 1),
            intArrayOf(1, 1_200_001, 1, 1), intArrayOf(1, 1, 513, 1), intArrayOf(1, 1, 1, 129))) {
            val source = sizes.map { ByteArray(it) { 7 } }
            assertThrows(IllegalArgumentException::class.java) { RuntimeStartWire.encode(source[0], source[1], source[2], source[3], VpnRuntimeConfig(VpnRoutingPolicy())) }
            source.forEach { assertTrue(it.all { byte -> byte == 7.toByte() }) }
        }
        val privateBytes = byteArrayOf(4)
        assertThrows(IllegalArgumentException::class.java) { RuntimeStartWire.encode(byteArrayOf(1), byteArrayOf(2), byteArrayOf(3), privateBytes,
            VpnRuntimeConfig(VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY, emptySet()))) }
        assertArrayEquals(byteArrayOf(4), privateBytes)
    }
}

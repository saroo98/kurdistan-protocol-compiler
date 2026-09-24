// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeProductResult

class ProductionOpeningCodecV1Test {
    @Test fun canonicalCapturedSettingsPackIdenticallyForBothPurposesWithoutDecodingSettings() {
        val settings = ByteBuffer.allocate(83).apply { position(1); limit(82) }
        assertEquals(NativeProductResult.Success(81), ProductionOpeningCodecV1.encodeSettings(ProductSettings(), settings))
        val part = ByteBuffer.wrap(byteArrayOf(9, 1, 2, 8)).apply { position(1); limit(3) }
        for (purpose in ProductionOpeningPurposeV1.entries) {
            val expected = ByteBuffer.allocate(121)
            assertEquals(NativeProductResult.Success(121), ProductionOpeningCodecV1.encodeOpening(
                ProductionOpeningInputV1(purpose, ProductSettings(), part, part, part, part), expected))
            val actual = ByteBuffer.allocate(125).apply { position(2); limit(123); array().fill(0x5a) }
            assertEquals(NativeProductResult.Success(121), ProductionOpeningCodecV1.encodeOpening(
                purpose, settings, part, part, part, part, actual))
            assertArrayEquals(expected.array(), actual.array().copyOfRange(2, 123))
            assertEquals(1, settings.position()); assertEquals(82, settings.limit())
            assertEquals(1, part.position()); assertEquals(3, part.limit())
            assertEquals(2, actual.position()); assertEquals(123, actual.limit())
            assertEquals(0x5a.toByte(), actual.array()[0]); assertEquals(0x5a.toByte(), actual.array()[124])
            val short = ByteBuffer.allocate(120).apply { array().fill(0x5a) }
            assertEquals(NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT), ProductionOpeningCodecV1.encodeOpening(
                purpose, settings, part, part, part, part, short))
            assertTrue(short.array().all { it == 0x5a.toByte() })
        }
    }

    @Test fun defaultSettingsHaveIndependentExactGolden() {
        val out = ByteBuffer.allocate(100).apply { position(7); limit(95); order(java.nio.ByteOrder.LITTLE_ENDIAN) }
        val result = ProductionOpeningCodecV1.encodeSettings(ProductSettings(), out)
        assertEquals(NativeProductResult.Success(81), result)
        // The default proxy budget is 64 MiB; explicit 32 MiB settings remain valid.
        val expected = hex("4b50533101000000000000510100000100000000000301010005dc0000000001000000000002000100010100030303012c0100008000500000000102012a382a390410012c0040001e0001000100000000")
        assertArrayEquals(expected, out.duplicate().apply { position(7); limit(88) }.slice().let { ByteArray(it.remaining()).also(it::get) })
        assertEquals(7, out.position()); assertEquals(95, out.limit()); assertEquals(java.nio.ByteOrder.LITTLE_ENDIAN, out.order())
    }

    @Test fun openingPurposeAndFailureAtomicityAreExact() {
        val input = ProductionOpeningInputV1(ProductionOpeningPurposeV1.MAINTENANCE, ProductSettings(),
            ByteBuffer.wrap(byteArrayOf(1)), ByteBuffer.wrap(byteArrayOf(2)), ByteBuffer.wrap(byteArrayOf(3)), ByteBuffer.wrap(byteArrayOf(4)))
        val out = ByteBuffer.allocate(117)
        assertEquals(NativeProductResult.Success(117), ProductionOpeningCodecV1.encodeOpening(input, out))
        assertArrayEquals(byteArrayOf('K'.code.toByte(),'P'.code.toByte(),'O'.code.toByte(),'1'.code.toByte(),1,2,0,0,0,0,0,117,0,0,0,81,0,0,0,1,0,0,0,1,0,1,0,1,0,0,0,0), out.array().copyOf(32))
        assertEquals("ProductionOpeningInputV1(redacted)", input.toString())

        val sentinel = ByteBuffer.allocate(116).apply { array().fill(0x5a) }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT), ProductionOpeningCodecV1.encodeOpening(input, sentinel))
        assertTrue(sentinel.array().all { it == 0x5a.toByte() })
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOpeningCodecV1.encodeSettings(ProductSettings().copy(), ByteBuffer.allocate(81).asReadOnlyBuffer()))
    }

    @Test fun fullNondefaultSettingsHaveIndependentExactGoldenAcrossAllRows() {
        val settings = ProductSettings(
            theme = ThemePreference.DARK, highContrast = true, reducedMotion = true,
            connection = ConnectionPreferences(SelectionMode.MANUAL_STRATEGY, true, false, true, true, CatalogId("strat-a"), 10),
            tunnel = TunnelPreferences(IpMode.DUAL_STACK, ResolverPolicy.CUSTOM, "1.1.1.1", 1280, true, false, null, "2606:4700:4700::1111"),
            routing = RoutingPreferences(PerAppSelectionMode.EXCLUDE_SELECTED, setOf("org.example.z", "com.example.a"), listOf("2001:db8::/32", "10.0.0.0/8")),
            updates = UpdatePreferences(true, 168, true, false, true),
            probes = ProbePreferences(ProbeMethod.ICMP, ProbeDisplay.HEALTH_DOTS, CatalogId("target-1"), 30),
            diagnostics = DiagnosticPreferences(DiagnosticLogLevel.DEBUG, DiagnosticRetention.SEVEN_DAYS),
            expert = ExpertPreferences(3600, 4096, 2048, 512),
            profiles = ProfilePreferences("active-1", setOf("favorite-2", "favorite-1")),
            tunnelMode = TunnelMode.PROXY_ONLY, networkMeteredPolicy = NetworkMeteredPolicy.WAIT_FOR_UNMETERED,
            pausePolicy = PausePolicy.UNTIL_RESUMED,
            localProxy = LocalProxyPreferences(65534, 65535, ProxyLimits(16, 64, 3600, 128)),
            privacy = PrivacyPreferences(true, 1, true, setOf(AllowedAuthenticator.STRONG_BIOMETRIC, AllowedAuthenticator.DEVICE_CREDENTIAL)),
            notifications = NotificationPreferences(true, false), automation = AutomationPreferences(true),
            networkTrust = NetworkTrustPreferences(true, setOf(CatalogId("rule-b"), CatalogId("rule-a"))),
        )
        val output = ByteBuffer.allocate(214)
        assertEquals(NativeProductResult.Success(214), ProductionOpeningCodecV1.encodeSettings(settings, output))
        assertArrayEquals(hex("4b50533101000000000000d603010103010001010773747261742d610a0404040101010105000100000626064700470000000000000000001111030002000d636f6d2e6578616d706c652e61000d6f72672e6578616d706c652e7a02040a000000080620010db8000000000000000000000000200100a80100010502087461726765742d311e05040e10100008000200086163746976652d3100020a6661766f726974652d310a6661766f726974652d32030302fffeffff10400e100080010101030100010100020672756c652d610672756c652d62"), output.array())
    }

    @Test fun bothPurposesAndBorrowedBufferSpansAreExactAndUnchanged() {
        val component = ByteBuffer.allocate(5).apply { put(byteArrayOf(9, 1, 2, 8, 7)); position(1); limit(3); order(java.nio.ByteOrder.LITTLE_ENDIAN) }
        val expectedPositions = listOf(component.position(), component.limit())
        for ((purpose, wire) in listOf(ProductionOpeningPurposeV1.SESSION to 1, ProductionOpeningPurposeV1.MAINTENANCE to 2)) {
            val input = ProductionOpeningInputV1(purpose, ProductSettings(), component, component, component, component)
            val output = ByteBuffer.allocate(125).apply { position(2); limit(123); order(java.nio.ByteOrder.LITTLE_ENDIAN) }
            assertEquals(NativeProductResult.Success(121), ProductionOpeningCodecV1.encodeOpening(input, output))
            val bytes = output.array().copyOfRange(2, 123)
            assertEquals(wire, bytes[5].toInt()); assertEquals(121, ByteBuffer.wrap(bytes, 8, 4).int)
            assertArrayEquals(byteArrayOf(1, 2, 1, 2, 1, 2, 1, 2), bytes.copyOfRange(113, 121))
            assertEquals(expectedPositions[0], component.position()); assertEquals(expectedPositions[1], component.limit())
            assertEquals(java.nio.ByteOrder.LITTLE_ENDIAN, component.order())
            assertEquals(2, output.position()); assertEquals(123, output.limit()); assertEquals(java.nio.ByteOrder.LITTLE_ENDIAN, output.order())
        }
    }

    @Test fun malformedSettingsAndComponentBoundsLeaveOutputUntouched() {
        val sentinel = ByteBuffer.allocate(100).apply { array().fill(0x33) }
        val manualWithoutId = ProductSettings(connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOpeningCodecV1.encodeSettings(manualWithoutId, sentinel))
        assertTrue(sentinel.array().all { it == 0x33.toByte() })
        val invalidLocal = ProductSettings(profiles = ProfilePreferences("INVALID"))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOpeningCodecV1.encodeSettings(invalidLocal, sentinel))
        val duplicateRoute = ProductSettings(routing = RoutingPreferences(excludedCidrs = listOf("10.0.0.0/8", "10.0.0.0/8")))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT), ProductionOpeningCodecV1.encodeSettings(duplicateRoute, sentinel))

        val oversized = ProductionOpeningInputV1(ProductionOpeningPurposeV1.SESSION, ProductSettings(),
            ByteBuffer.allocate(1405997), ByteBuffer.wrap(byteArrayOf(1)), ByteBuffer.wrap(byteArrayOf(1)), ByteBuffer.wrap(byteArrayOf(1)))
        val largeSentinel = ByteBuffer.allocate(128).apply { array().fill(0x44) }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT), ProductionOpeningCodecV1.encodeOpening(oversized, largeSentinel))
        assertTrue(largeSentinel.array().all { it == 0x44.toByte() })
    }

    @Test fun uppercaseAsciiPackageIsPreservedInAnIndependentGolden() {
        val settings = ProductSettings(routing = RoutingPreferences(
            PerAppSelectionMode.INCLUDE_ONLY,
            setOf("com.Example.app"),
        ))
        val output = ByteBuffer.allocateDirect(98).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        assertEquals(NativeProductResult.Success(98), ProductionOpeningCodecV1.encodeSettings(settings, output))
        val actual = ByteArray(98).also { output.duplicate().get(it) }
        assertArrayEquals(hex("4b50533101000000000000620100000100000000000301010005dc00000000020001000f636f6d2e4578616d706c652e61707000000002000100010100030303012c0100008000500000000102012a382a390410012c0040001e0001000100000000"), actual)
        assertEquals(0, output.position()); assertEquals(98, output.limit()); assertEquals(java.nio.ByteOrder.LITTLE_ENDIAN, output.order())
    }

    @Test fun everyBorrowedComponentAcceptsItsExactMaximumAndRejectsBothOutsideBounds() {
        val verify = ByteBuffer.allocateDirect(1405996)
        val activation = ByteBuffer.allocateDirect(1118299)
        val recipient = ByteBuffer.allocateDirect(512)
        val privateKey = ByteBuffer.allocateDirect(128)
        val exactTotal = 32 + 81 + 1405996 + 1118299 + 512 + 128
        val output = ByteBuffer.allocateDirect(exactTotal).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val input = ProductionOpeningInputV1(
            ProductionOpeningPurposeV1.SESSION,
            ProductSettings(),
            verify,
            activation,
            recipient,
            privateKey,
        )
        assertEquals(NativeProductResult.Success(exactTotal), ProductionOpeningCodecV1.encodeOpening(input, output))
        listOf(verify, activation, recipient, privateKey, output).forEach {
            assertEquals(0, it.position()); assertEquals(it.capacity(), it.limit())
        }
        assertEquals(java.nio.ByteOrder.LITTLE_ENDIAN, output.order())

        fun rejected(sizes: List<Int>, expected: ProductFailureCode) {
            val sentinel = ByteBuffer.allocate(64).apply { array().fill(0x55) }
            val result = ProductionOpeningCodecV1.encodeOpening(
                ProductionOpeningInputV1(
                    ProductionOpeningPurposeV1.SESSION,
                    ProductSettings(),
                    ByteBuffer.allocate(sizes[0]),
                    ByteBuffer.allocate(sizes[1]),
                    ByteBuffer.allocate(sizes[2]),
                    ByteBuffer.allocate(sizes[3]),
                ),
                sentinel,
            )
            assertEquals(NativeProductResult.Failure(expected), result)
            assertTrue(sentinel.array().all { it == 0x55.toByte() })
        }
        val maxima = listOf(1405996, 1118299, 512, 128)
        maxima.indices.forEach { index ->
            rejected(maxima.mapIndexed { current, maximum -> if (current == index) 0 else 1 }, ProductFailureCode.INVALID_INPUT)
            rejected(maxima.mapIndexed { current, maximum -> if (current == index) maximum + 1 else 1 }, ProductFailureCode.SIZE_LIMIT)
        }
    }

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class ProductionResultCodecV1Test {
    @Test fun decodesCompleteTunSnapshotWithoutMutatingInput() {
        val bytes = tunSnapshot()
        val input = ByteBuffer.allocate(bytes.size + 4).apply { position(2); put(bytes); limit(2 + bytes.size); position(2); order(ByteOrder.LITTLE_ENDIAN) }
        val value = ProductionResultCodecV1.decodeOpening(input)
        assertTrue(value is NativeProductResult.Success)
        val snapshot = (value as NativeProductResult.Success).value
        assertEquals(1uL, snapshot.profileGeneration); assertEquals(1280, snapshot.packetLimits.packetMax)
        assertEquals(2, input.position()); assertEquals(2 + bytes.size, input.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN, input.order())
    }

    @Test fun malformedAndOversizedSnapshotsFailCategorically() {
        val malformed = tunSnapshot().copyOf().also { it[5] = 1 }
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(malformed)))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionResultCodecV1.decodeOpening(ByteBuffer.allocate(32769)))
    }

    @Test fun allFixedControlBodiesAndUnsignedOrderingDecode() {
        val event = control(1, ULong.MAX_VALUE, ULong.MAX_VALUE, ByteBuffer.allocate(14).putLong(Long.MIN_VALUE).putInt(7).put(1).put(1).array())
        val value = ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(event), ULong.MAX_VALUE - 1uL, ULong.MAX_VALUE)
        assertTrue(value is NativeProductResult.Success && value.value is NativeControlEvent.SocketProtectionRequired)
        val bad = control(2, 1uL, 1uL, byteArrayOf(1))
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(bad), 0uL, 0uL))
    }

    @Test fun allTwelveControlKindsDecodeWithoutInventingAThirteenth() {
        val bodies = listOf(
            ByteBuffer.allocate(14).putLong(Long.MIN_VALUE).putInt(7).put(1).put(1).array(),
            byteArrayOf(), byteArrayOf(), tunSnapshot(),
            ByteBuffer.allocate(42).apply { repeat(5) { putLong(ULong.MAX_VALUE.toLong()) }; put(64); put(4) }.array(),
            tunSnapshot(), byteArrayOf(1, 1), byteArrayOf(1, 1, 1), byteArrayOf(1), byteArrayOf(),
            byteArrayOf(0, 5), byteArrayOf(),
        )
        val expected = listOf(
            NativeControlEvent.SocketProtectionRequired::class, NativeControlEvent.TransportConnecting::class,
            NativeControlEvent.TransportReady::class, NativeControlEvent.RoutePlanReady::class,
            NativeControlEvent.MetricsUpdated::class, NativeControlEvent.PathChanged::class,
            NativeControlEvent.FallbackStarted::class, NativeControlEvent.ReconnectStarted::class,
            NativeControlEvent.Degraded::class, NativeControlEvent.Revoked::class,
            NativeControlEvent.Failed::class, NativeControlEvent.Stopped::class,
        )
        bodies.forEachIndexed { index, body ->
            val decoded = ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(index + 1, 1uL, (index + 1).toULong(), body)), 0uL, 0uL)
            assertTrue("kind ${index + 1}", decoded is NativeProductResult.Success && decoded.value::class == expected[index])
        }
        assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(13, 1uL, 13uL, byteArrayOf())), 0uL, 0uL))
    }

    @Test fun controlReservedLengthsAndContextOnlyStatusesFailClosed() {
        for (status in listOf(0, 19, 20, 27, 65535)) {
            val body = byteArrayOf((status ushr 8).toByte(), status.toByte())
            assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(11, 1uL, 1uL, body)), 0uL, 0uL))
        }
        val negativeFd = ByteBuffer.allocate(14).putLong(1).putInt(-1).put(1).put(0).array()
        assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(1, 1uL, 1uL, negativeFd)), 0uL, 0uL))
        assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(2, 1uL, 1uL, byteArrayOf())), 1uL, 0uL))
        assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(control(2, 1uL, 2uL, byteArrayOf())), 1uL, 2uL))
        val reserved = control(2, 1uL, 1uL, byteArrayOf()).also { it[6] = 1 }
        assertInternal(ProductionResultCodecV1.decodeControl(ByteBuffer.wrap(reserved), 0uL, 0uL))
    }

    @Test fun snapshotLabelsUseStrictUtf8AndStructuralFieldsFailClosed() {
        val verified = withFirstLabel(byteArrayOf('n'.code.toByte()))
        val decoded = ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(verified)) as NativeProductResult.Success
        assertEquals("n", decoded.value.nodeLabel?.value)
        assertNull(decoded.value.pathLabel)
        assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(withFirstLabel(byteArrayOf(0xff.toByte())))))
        assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(withFirstLabel(byteArrayOf()))))
        assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(withFirstLabel(ByteArray(385) { 'a'.code.toByte() }))))

        val fixedMutations = listOf(6 to 1, 109 to 7, 110 to 0, 111 to 1, 112 to 0, 115 to 2,
            116 to 2, 119 to 5, 125 to 3, 139 to 0x20, 144 to 0, 150 to 0)
        fixedMutations.forEach { (offset, value) ->
            val bad = tunSnapshot().also { it[offset] = value.toByte() }
            assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(bad)))
        }
        assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(tunSnapshot() + byteArrayOf(0))))
        assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(tunSnapshot().copyOf(234))))
    }

    @Test fun populatedDualStackAndProxyOnlyBoundarySnapshotsDecodeExactly() {
        val dual = boundarySnapshot(proxyOnly = false)
        val direct = ByteBuffer.allocateDirect(dual.bytes.size + 2).apply {
            position(1); put(dual.bytes); limit(1 + dual.bytes.size); position(1); order(ByteOrder.LITTLE_ENDIAN)
        }
        val decoded = ProductionResultCodecV1.decodeOpening(direct) as NativeProductResult.Success
        val snapshot = decoded.value
        assertEquals(1uL shl 63, snapshot.profileGeneration)
        assertEquals("Node_1", snapshot.nodeLabel?.value)
        assertNull(snapshot.pathLabel)
        assertEquals("Strategy 9", snapshot.strategyLabel?.value)
        assertEquals(256, snapshot.effectivePackageCount)
        assertEquals(listOf("10.0.0.1", "2001:db8::1"), snapshot.dnsAddresses.map { it.value })
        assertEquals(listOf("0.0.0.0/0", "::/0"), snapshot.routes.map { it.value })
        assertEquals(setOf(
            NativeCapability.RAW_IP,
            NativeCapability.PROXY_STREAM,
            NativeCapability.PROBE_ACTIVE_RELAY,
            NativeCapability.PROBE_DISCONNECTED,
            NativeCapability.SAME_DEPLOYMENT_UPDATE,
        ), snapshot.capabilities.effective)
        assertEquals(setOf(
            NativePayloadProtocol.ICMP,
            NativePayloadProtocol.ICMPV6,
            NativePayloadProtocol.TCP,
            NativePayloadProtocol.UDP,
        ), snapshot.packetLimits.payloadProtocols)
        assertEquals(64, snapshot.proxyLimits?.effectiveStreamMax)
        assertEquals(4, snapshot.probeLimits?.maxConcurrent)
        assertEquals(1052763, snapshot.updateLimits?.maxArtifactBytes)
        assertEquals(134217728L, snapshot.resourceLimits.effectiveAggregateBufferMax)
        assertEquals(1, direct.position()); assertEquals(1 + dual.bytes.size, direct.limit()); assertEquals(ByteOrder.LITTLE_ENDIAN, direct.order())

        val proxy = ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(boundarySnapshot(proxyOnly = true).bytes)) as NativeProductResult.Success
        assertEquals(NativeRawFlowStatus.NOT_APPLICABLE, proxy.value.resourceLimits.rawFlowStatus)
        assertNull(proxy.value.clientV4); assertNull(proxy.value.clientV6)
        assertTrue(proxy.value.dnsAddresses.isEmpty()); assertTrue(proxy.value.routes.isEmpty())
        assertFalse(NativeCapability.RAW_IP in proxy.value.capabilities.effective)
        assertTrue(NativeCapability.PROXY_STREAM in proxy.value.capabilities.effective)
    }

    @Test fun snapshotCountsMasksAddressesServicesAndResourceRelationsFailClosed() {
        val fixture = boundarySnapshot(proxyOnly = false)
        fun mutant(name: String, mutate: (ByteArray, Int) -> Unit) {
            val bytes = fixture.bytes.copyOf()
            mutate(bytes, fixture.offsets.getValue(name))
            assertInternal(ProductionResultCodecV1.decodeOpening(ByteBuffer.wrap(bytes)))
        }

        mutant("packageCount") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 2).putShort(0) }
        listOf("exit", "mode", "ip", "dns", "perApp").forEach { field ->
            mutant(field) { bytes, offset -> bytes[offset] = 0xff.toByte() }
        }
        mutant("metered") { bytes, offset -> bytes[offset] = 2 }
        mutant("dnsCount") { bytes, offset -> bytes[offset] = 3 }
        mutant("routeCount") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 2).putShort(257) }
        mutant("clientV6") { bytes, offset ->
            repeat(10) { bytes[offset + 1 + it] = 0 }
            bytes[offset + 11] = 0xff.toByte(); bytes[offset + 12] = 0xff.toByte()
        }
        mutant("routeV4Address") { bytes, offset -> bytes[offset + 3] = 1 }
        mutant("signedMask") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 2).putShort(32) }
        mutant("payloadMask") { bytes, offset -> bytes[offset] = 16 }
        mutant("proxyStart") { bytes, offset -> bytes[offset] = 0 }
        mutant("probeStart") { bytes, offset -> bytes[offset] = 0 }
        mutant("updateStart") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 4).putInt(0) }
        mutant("flowIdle") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 4).putInt(3600001) }
        mutant("effectiveAggregate") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 4).putInt(40 shl 20) }
        mutant("reservedBytes") { bytes, offset -> ByteBuffer.wrap(bytes, offset, 4).putInt(1048577) }
    }

    private fun withFirstLabel(raw: ByteArray): ByteArray {
        val base = tunSnapshot()
        val replacement = byteArrayOf(1, (raw.size ushr 8).toByte(), raw.size.toByte()) + raw
        return (base.copyOfRange(0, 100) + replacement + base.copyOfRange(103, base.size)).also {
            ByteBuffer.wrap(it, 8, 4).putInt(it.size)
        }
    }

    private fun assertInternal(value: NativeProductResult<*>) =
        assertEquals(NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE), value)

    private fun control(kind: Int, generation: ULong, sequence: ULong, body: ByteArray): ByteArray = ByteBuffer.allocate(32 + body.size).apply {
        put("KPC1".toByteArray()); put(1); put(kind.toByte()); putShort(0); putInt(capacity()); putLong(generation.toLong()); putLong(sequence.toLong()); putInt(body.size); put(body)
    }.array()

    companion object {
        private data class SnapshotFixture(val bytes: ByteArray, val offsets: Map<String, Int>)

        private fun boundarySnapshot(proxyOnly: Boolean): SnapshotFixture {
            val offsets = linkedMapOf<String, Int>()
            val output = ByteBuffer.allocate(512)
            fun mark(name: String) { offsets[name] = output.position() }
            fun label(value: String?) {
                if (value == null) {
                    output.put(0); output.putShort(0)
                } else {
                    val bytes = value.toByteArray(Charsets.UTF_8)
                    output.put(1); output.putShort(bytes.size.toShort()); output.put(bytes)
                }
            }
            fun ipv6(last: Int) = byteArrayOf(
                0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, last.toByte(),
            )

            output.put("KPN1".toByteArray())
            output.put(1); output.put(0); output.putShort(0); output.putInt(0)
            output.putLong(Long.MIN_VALUE)
            output.put(ByteArray(32) { 1 }); output.put(ByteArray(16) { 2 }); output.put(ByteArray(16) { 3 }); output.put(ByteArray(16) { 4 })
            label("Node_1"); label(null); label("Strategy 9")
            mark("exit"); output.put(6)
            mark("mode"); output.put(if (proxyOnly) 3 else 2)
            mark("ip"); output.put(4)
            mark("dns"); output.put(4)
            output.putShort(1500)
            mark("metered"); output.put(1)
            mark("perApp"); output.put(2)
            mark("packageCount"); output.putShort(256)
            if (proxyOnly) {
                output.put(0); output.put(0)
                mark("dnsCount"); output.put(0)
                mark("routeCount"); output.putShort(0)
            } else {
                output.put(4); output.put(byteArrayOf(10, 0, 0, 2))
                mark("clientV6"); output.put(6); output.put(ipv6(2))
                mark("dnsCount"); output.put(2)
                output.put(4); output.put(byteArrayOf(10, 0, 0, 1))
                output.put(6); output.put(ipv6(1))
                mark("routeCount"); output.putShort(2)
                output.put(4); mark("routeV4Address"); output.put(ByteArray(4)); output.put(0)
                output.put(6); output.put(ByteArray(16)); output.put(0)
            }
            mark("signedMask"); output.putShort(31)
            output.putShort(31)
            output.putShort(if (proxyOnly) 30 else 31)
            output.putInt(1500); output.putShort(256); output.putShort(64)
            mark("payloadMask"); output.put(15)
            output.put(5); output.put(10); output.put(5); output.put(5); output.put(5); output.putInt(10000); output.putInt(3600000)
            mark("proxyStart")
            output.put(64); output.put(64); output.put(64); output.put(16); output.put(16)
            output.putInt(134217728); output.putInt(134217728); output.putShort(3600); output.putShort(30000); output.putInt(65536); output.putShort(16384)
            mark("probeStart")
            output.put(4); output.put(10); output.putInt(3600000); output.put(60); output.putShort(30000)
            mark("updateStart")
            output.putInt(1052763); output.putShort(30000); output.putInt(604800)
            output.put(if (proxyOnly) 2 else 1)
            output.putShort(if (proxyOnly) 0 else 4096); output.putShort(if (proxyOnly) 0 else 2048)
            output.putShort(if (proxyOnly) 0 else 4096); output.putShort(if (proxyOnly) 0 else 2048)
            mark("flowIdle"); output.putInt(if (proxyOnly) 0 else 3600000)
            output.put(0); output.putInt(134217728)
            mark("effectiveAggregate"); output.putInt(134217728)
            mark("reservedBytes"); output.putInt(if (proxyOnly) 0 else 1048576)
            val bytes = output.array().copyOf(output.position())
            ByteBuffer.wrap(bytes, 8, 4).putInt(bytes.size)
            return SnapshotFixture(bytes, offsets)
        }

        fun tunSnapshot(): ByteArray = ByteBuffer.allocate(235).apply {
            put("KPN1".toByteArray()); put(1); put(0); putShort(0); putInt(235); putLong(1)
            put(ByteArray(32) { 1 }); put(ByteArray(16) { 2 }); put(ByteArray(16) { 3 }); put(ByteArray(16) { 4 })
            repeat(3) { put(0); putShort(0) }
            put(0); put(1); put(2); put(1); putShort(1280); put(0); put(1); putShort(0)
            put(4); put(byteArrayOf(10,0,0,2)); put(0); put(1); put(4); put(byteArrayOf(10,0,0,1)); putShort(1); put(4); put(ByteArray(4)); put(0)
            putShort(1); putShort(1); putShort(1); putInt(1280); putShort(1); putShort(1); put(4)
            put(1); put(10); put(1); put(1); put(0); putInt(1000); putInt(300000)
            repeat(5) { put(0) }; putInt(0); putInt(0); putShort(0); putShort(0); putInt(0); putShort(0)
            put(0); put(0); putInt(0); put(0); putShort(0); putInt(0); putShort(0); putInt(0)
            put(1); putShort(4096); putShort(2048); putShort(256); putShort(128); putInt(300000); put(0); putInt(134217728); putInt(83886080); putInt(1048576)
        }.array()
    }
}

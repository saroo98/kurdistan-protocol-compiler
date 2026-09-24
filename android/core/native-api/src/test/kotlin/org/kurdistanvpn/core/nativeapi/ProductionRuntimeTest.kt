// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class ProductionRuntimeTest {
    @Test fun publicPortsCompileWithoutRuntimeImplementation() {
        val snapshot = snapshot()
        val session = object : ProductionNativeSession {
            override val openingSnapshot = snapshot
            override fun nextControl(output: ByteBuffer) = NativeProductResult.Failure(ProductFailureCode.CANCELLED)
            override fun confirmSocketProtection(token: Long, protected: Boolean, networkHandle: Long?) = NativeProductResult.Success(Unit)
            override fun submitOutboundPacket(packet: ByteBuffer, length: Int) = NativeProductResult.Success(Unit)
            override fun receiveInboundPacket(output: ByteBuffer) = NativeProductResult.Success(NativePacketDelivery(1, Long.MIN_VALUE))
            override fun confirmInboundDelivery(token: Long, deliveredLength: Int) = NativeProductResult.Success(Unit)
            override fun rejectInboundDelivery(token: Long) = NativeProductResult.Success(Unit)
            override fun openProxyStream(request: NativeProxyRequest) = NativeProductResult.Failure(ProductFailureCode.CANCELLED)
            override fun runProbe(request: NativeProbeRequest) = NativeProductResult.Failure(ProductFailureCode.CANCELLED)
            override fun requestReconnect(reason: NativeReconnectReason) = NativeProductResult.Success(Unit)
            override fun requestHandover(networkHandle: Long?) = NativeProductResult.Success(Unit)
            override fun cancel() = NativeProductResult.Success(Unit)
            override fun close() = Unit
        }
        assertSame(snapshot, session.openingSnapshot)
        assertEquals(NativeProductResult.Success(Unit), session.requestHandover(null))
    }

    @Test fun snapshotsAndRequestsDefensivelyCopyAndRedact() {
        val digest = ByteArray(32) { it.toByte() }
        val snapshot = snapshot(digest)
        digest.fill(99)
        assertEquals(0, snapshot.planDigest[0].toInt())
        val returned = snapshot.planDigest
        returned[0] = 77
        assertEquals(0, snapshot.planDigest[0].toInt())
        assertThrows(UnsupportedOperationException::class.java) {
            (snapshot.dnsAddresses as MutableList).add(NumericAddress("1.1.1.1"))
        }
        assertEquals("NativeOpeningSnapshot(redacted)", snapshot.toString())

        val address = byteArrayOf(1, 1, 1, 1)
        val request = NativeProxyRequest(NativeProxyAddressKind.IPV4, address, 443)
        address[0] = 9
        assertArrayEquals(byteArrayOf(1, 1, 1, 1), request.address)
        request.address[0] = 9
        assertArrayEquals(byteArrayOf(1, 1, 1, 1), request.address)
        assertEquals("NativeProxyRequest(redacted)", request.toString())

        val protocols = mutableSetOf(NativePayloadProtocol.TCP)
        val limits = NativePacketLimits(1500, 4, 2, protocols)
        protocols += NativePayloadProtocol.UDP
        assertEquals(setOf(NativePayloadProtocol.TCP), limits.payloadProtocols)
        assertThrows(UnsupportedOperationException::class.java) {
            (limits.payloadProtocols as MutableSet).add(NativePayloadProtocol.UDP)
        }
    }

    @Test fun opaqueAndUnsignedBoundariesStayDistinct() {
        assertEquals(Long.MIN_VALUE, NativePacketDelivery(65535, Long.MIN_VALUE).token)
        assertThrows(IllegalArgumentException::class.java) { NativePacketDelivery(1, 0) }
        assertEquals(ULong.MAX_VALUE, snapshot(profileGeneration = ULong.MAX_VALUE).profileGeneration)
        assertEquals(NativeStreamRead.EndOfStream, NativeStreamRead.EndOfStream)
        assertEquals(Long.MIN_VALUE, NativeStreamRead.Data(16384, Long.MIN_VALUE).token)
    }

    @Test fun proxyDestinationsUseTheConservativePublicGrammar() {
        listOf("192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1").forEach { address ->
            assertThrows(IllegalArgumentException::class.java) {
                NativeProxyRequest(NativeProxyAddressKind.IPV4, address.split('.').map { it.toInt().toByte() }.toByteArray(), 443)
            }
        }
        listOf("192.0.1.1", "192.2.1.1").forEach { address ->
            assertEquals(443, NativeProxyRequest(NativeProxyAddressKind.IPV4,
                address.split('.').map { it.toInt().toByte() }.toByteArray(), 443).port)
        }
        listOf("2001:db8::1", "2002::1").forEach { address ->
            assertThrows(IllegalArgumentException::class.java) {
                NativeProxyRequest(NativeProxyAddressKind.IPV6, ipv6(address), 443)
            }
        }
        assertEquals(443, NativeProxyRequest(NativeProxyAddressKind.IPV6, ipv6("2606:4700:4700::1111"), 443).port)
        listOf("Example.com", "-example.com", "example.com.", "example..com").forEach { domain ->
            assertThrows(IllegalArgumentException::class.java) {
                NativeProxyRequest(NativeProxyAddressKind.DOMAIN, domain.toByteArray(), 443)
            }
        }
    }

    @Test fun probeAggregateConstructorEnforcesAllCrossFields() {
        val stable = NativeProbeResult(NativeProbePath.DISCONNECTED_TCP_CONNECT, NativeProbeMethod.TCP_CONNECT,
            3, 3, 0, 0, 1000, 250, 0, NativeProbeStability.STABLE, NativeProbeCompletion.COMPLETE)
        assertEquals(NativeProbeStability.STABLE, stable.stability)
        assertThrows(IllegalArgumentException::class.java) {
            stable.copy(stability = NativeProbeStability.VARIABLE)
        }
        assertThrows(IllegalArgumentException::class.java) {
            stable.copy(unstarted = 8, completion = NativeProbeCompletion.TIMED_OUT)
        }
        assertThrows(IllegalArgumentException::class.java) {
            stable.copy(unstarted = 1)
        }
    }

    @Test fun transientAndCollectionBearingValuesHaveFixedRedactedStrings() {
        val opening = snapshot(profileGeneration = ULong.MAX_VALUE)
        val controls = listOf(
            NativeControlEvent.SocketProtectionRequired(ULong.MAX_VALUE, ULong.MAX_VALUE, Long.MIN_VALUE, 7, NativeSocketKind.TUNNEL_TLS_TCP, true),
            NativeControlEvent.TransportConnecting(ULong.MAX_VALUE, ULong.MAX_VALUE),
            NativeControlEvent.TransportReady(ULong.MAX_VALUE, ULong.MAX_VALUE),
            NativeControlEvent.RoutePlanReady(ULong.MAX_VALUE, ULong.MAX_VALUE, opening),
            NativeControlEvent.MetricsUpdated(ULong.MAX_VALUE, ULong.MAX_VALUE, NativeMetrics(1uL, 2uL, 3uL, 4uL, 5uL, 6, 3)),
            NativeControlEvent.PathChanged(ULong.MAX_VALUE, ULong.MAX_VALUE, opening),
            NativeControlEvent.FallbackStarted(ULong.MAX_VALUE, ULong.MAX_VALUE, 1, 2),
            NativeControlEvent.ReconnectStarted(ULong.MAX_VALUE, ULong.MAX_VALUE, NativeReconnectReason.NETWORK_FAILURE, 1, 2),
            NativeControlEvent.Degraded(ULong.MAX_VALUE, ULong.MAX_VALUE, DegradationReason.RESOURCE_LIMIT),
            NativeControlEvent.Revoked(ULong.MAX_VALUE, ULong.MAX_VALUE),
            NativeControlEvent.Failed(ULong.MAX_VALUE, ULong.MAX_VALUE, ProductFailureCode.RESOURCE_LIMIT),
            NativeControlEvent.Stopped(ULong.MAX_VALUE, ULong.MAX_VALUE),
        )
        val expected = listOf("SocketProtectionRequired", "TransportConnecting", "TransportReady", "RoutePlanReady",
            "MetricsUpdated", "PathChanged", "FallbackStarted", "ReconnectStarted", "Degraded", "Revoked", "Failed", "Stopped")
        controls.zip(expected).forEach { (value, name) ->
            assertEquals("NativeControlEvent.$name(redacted)", value.toString())
            assertFalse(NativeProductResult.Success(value).toString().contains(ULong.MAX_VALUE.toString()))
        }
        val packet = NativePacketDelivery(65535, Long.MIN_VALUE)
        val stream = NativeStreamRead.Data(16384, -1)
        val probe = NativeProbeRequest(65535, NativeProbeMethod.TCP_CONNECT, 1000, 30000, 10)
        assertEquals("NativePacketDelivery(redacted)", packet.toString())
        assertEquals("NativeStreamRead.Data(redacted)", stream.toString())
        assertEquals("NativeProbeRequest(redacted)", probe.toString())
        assertFalse(NativeProductResult.Success(packet).toString().contains(Long.MIN_VALUE.toString()))
        assertFalse(NativeProductResult.Success(stream).toString().contains("-1"))
        assertFalse(NativeProductResult.Success(probe).toString().contains("65535"))
        assertEquals("NativeCapabilities(redacted)", opening.capabilities.toString())
        assertEquals("NativePacketLimits(redacted)", opening.packetLimits.toString())
    }

    @Test fun openingSnapshotConstructorEnforcesCrossObjectStructure() {
        assertThrows(IllegalArgumentException::class.java) { snapshot(perAppMode = PerAppSelectionMode.ALL_APPS, packageCount = 1) }
        assertThrows(IllegalArgumentException::class.java) { snapshot(perAppMode = PerAppSelectionMode.INCLUDE_ONLY, packageCount = 0) }
        assertThrows(IllegalArgumentException::class.java) { snapshot(reconnectIdleMillis = 1000, flowIdleMillis = 1001) }

        assertThrows(IllegalArgumentException::class.java) {
            NativeOpeningSnapshot(
                1uL, ByteArray(32) { 1 }, ByteArray(16), ByteArray(16), ByteArray(16), null, null, null,
                ExitRegion.UNKNOWN, TunnelMode.TUN_PLUS_PROXY, IpMode.IPV4_ONLY, ResolverPolicy.INTERNAL, 1280, false,
                PerAppSelectionMode.ALL_APPS, 0, NumericAddress("10.0.0.2"), null,
                listOf(NumericAddress("10.0.0.1")), listOf(CanonicalRoute("0.0.0.0/0")),
                NativeCapabilities(setOf(NativeCapability.RAW_IP, NativeCapability.PROXY_STREAM),
                    setOf(NativeCapability.RAW_IP, NativeCapability.PROXY_STREAM),
                    setOf(NativeCapability.RAW_IP, NativeCapability.PROXY_STREAM)),
                NativePacketLimits(1280, 1, 1, setOf(NativePayloadProtocol.TCP)),
                NativeReconnectLimits(1, 10, 1, 1, 0, 1000, 300000),
                NativeProxyLimits(1, 1, 1, 1, 1, 64L shl 20, 64L shl 20, 300, 1000, 1024, 1024),
                null, null,
                NativeResourceLimits(NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES, 4096, 2048, 256, 128,
                    300000, NativeSignedRawFlowCapStatus.NOT_SEPARATELY_SPECIFIED, 134217728, 40L shl 20, 1048576),
            )
        }
    }

    private fun ipv6(value: String): ByteArray {
        val halves = value.lowercase().split("::", limit = 2)
        fun words(part: String) = if (part.isEmpty()) emptyList() else part.split(':').map { it.toInt(16) }
        val left = words(halves[0]); val right = if (halves.size == 2) words(halves[1]) else emptyList()
        return (left + List(8 - left.size - right.size) { 0 } + right).flatMap { listOf((it ushr 8).toByte(), it.toByte()) }.toByteArray()
    }

    private fun snapshot(
        digest: ByteArray = ByteArray(32) { 1 },
        profileGeneration: ULong = 1uL,
        perAppMode: PerAppSelectionMode = PerAppSelectionMode.ALL_APPS,
        packageCount: Int = 0,
        reconnectIdleMillis: Long = 300000,
        flowIdleMillis: Long = 300000,
    ) = NativeOpeningSnapshot(
        profileGeneration, digest, ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(16) { 4 },
        null, null, null, ExitRegion.UNKNOWN, TunnelMode.TUN_ONLY, IpMode.IPV4_ONLY,
        ResolverPolicy.INTERNAL, 1280, false, perAppMode, packageCount,
        NumericAddress("10.0.0.2"), null, listOf(NumericAddress("10.0.0.1")),
        listOf(CanonicalRoute("0.0.0.0/0")),
        NativeCapabilities(setOf(NativeCapability.RAW_IP), setOf(NativeCapability.RAW_IP), setOf(NativeCapability.RAW_IP)),
        NativePacketLimits(1280, 1, 1, setOf(NativePayloadProtocol.TCP)),
        NativeReconnectLimits(1, 10, 1, 1, 0, 1000, reconnectIdleMillis),
        null, null, null,
        NativeResourceLimits(NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES, 4096, 2048, 256, 128, flowIdleMillis,
            NativeSignedRawFlowCapStatus.NOT_SEPARATELY_SPECIFIED, 134217728, 83886080, 1048576),
    )
}

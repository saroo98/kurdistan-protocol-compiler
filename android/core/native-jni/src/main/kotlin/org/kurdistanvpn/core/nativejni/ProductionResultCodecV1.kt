// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

internal object ProductionResultCodecV1 {
    fun decodeOpening(input: ByteBuffer): NativeProductResult<NativeOpeningSnapshot> {
        if (input.remaining() > 32768) return fail()
        if (input.remaining() < 220) return fail()
        return try {
            decodeSnapshot(input)
        } catch (_: IllegalArgumentException) {
            fail()
        }
    }

    private fun decodeSnapshot(input: ByteBuffer): NativeProductResult<NativeOpeningSnapshot> {
        val total = input.remaining()
        val reader = ProductionReaderV1(input, 32768)
        if (!reader.bytes(4).contentEquals("KPN1".toByteArray()) ||
            reader.u8() != 1 || reader.u8() != 0 || reader.u16() != 0 || reader.u32() != total.toLong()
        ) return fail()

        val generation = reader.u64()
        val digest = reader.bytes(32)
        val profileFingerprint = reader.bytes(16)
        val strategyFingerprint = reader.bytes(16)
        val relayFingerprint = reader.bytes(16)
        val labels = List(3) { readLabel(reader) ?: return fail() }
        val exitRegion = decodeExitRegionV1(reader.u8()) ?: return fail()
        val tunnelMode = decodeTunnelModeV1(reader.u8()) ?: return fail()
        val ipMode = decodeIpModeV1(reader.u8()) ?: return fail()
        val resolverPolicy = decodeResolverPolicyV1(reader.u8()) ?: return fail()
        val mtu = reader.u16()
        val metered = reader.bool()
        val perAppWire = reader.u8()
        val perAppMode = decodePerAppModeV1(perAppWire) ?: return fail()
        val packageCount = reader.u16()
        if (generation == 0uL || digest.all { it == 0.toByte() } || mtu !in 1280..1500 ||
            packageCount > 256 || !validPerApp(perAppWire, packageCount)
        ) return fail()

        val clientV4 = readAddress(reader, optional = true) ?: return fail()
        val clientV6 = readAddress(reader, optional = true) ?: return fail()
        val dnsCount = reader.u8()
        if (dnsCount > 2) return fail()
        val dnsAddresses = ArrayList<Pair<Int, ByteArray>>()
        repeat(dnsCount) { dnsAddresses += readAddress(reader, optional = false) ?: return fail() }

        val routeCount = reader.u16()
        if (routeCount > 256) return fail()
        val routes = ArrayList<Triple<Int, ByteArray, Int>>()
        repeat(routeCount) {
            val address = readAddress(reader, optional = false) ?: return fail()
            val prefixBits = reader.u8()
            if (prefixBits > address.second.size * 8 || !hostBitsZero(address.second, prefixBits)) return fail()
            routes += Triple(address.first, address.second, prefixBits)
        }
        if (!strictlySorted(dnsAddresses.map { byteArrayOf(it.first.toByte()) + it.second }) ||
            !strictlySorted(routes.map { byteArrayOf(it.first.toByte()) + it.second + byteArrayOf(it.third.toByte()) })
        ) return fail()
        if (!validNetwork(tunnelMode, ipMode, clientV4, clientV6, dnsAddresses, routes)) return fail()

        val signedMask = reader.u16()
        val nativeMask = reader.u16()
        val effectiveMask = reader.u16()
        val signedCapabilities = decodeCapabilitiesV1(signedMask) ?: return fail()
        val nativeCapabilities = decodeCapabilitiesV1(nativeMask) ?: return fail()
        val effectiveCapabilities = decodeCapabilitiesV1(effectiveMask) ?: return fail()
        if (effectiveMask and signedMask != effectiveMask || effectiveMask and nativeMask != effectiveMask ||
            !validModeCapabilities(tunnelMode, effectiveMask)
        ) return fail()

        val packetMax = reader.u32()
        val queuePackets = reader.u16()
        val incompleteOps = reader.u16()
        val payloadProtocols = decodePayloadProtocolsV1(reader.u8()) ?: return fail()
        if (packetMax != mtu.toLong() || queuePackets !in 1..256 || incompleteOps !in 1..64 || payloadProtocols.isEmpty()) return fail()

        val signedReconnect = reader.u8()
        val nativeReconnect = reader.u8()
        val effectiveReconnect = reader.u8()
        val fallbackMax = reader.u8()
        val fallbackUsed = reader.u8()
        val dialTimeout = reader.u32()
        val idleTimeout = reader.u32()
        if (signedReconnect !in 1..5 || nativeReconnect != 10 ||
            effectiveReconnect > minOf(10, signedReconnect, nativeReconnect) ||
            fallbackMax !in 1..minOf(5, signedReconnect, nativeReconnect) || fallbackUsed > fallbackMax ||
            dialTimeout !in 1..10000 || idleTimeout == 0L
        ) return fail()

        val proxyValues = longArrayOf(
            reader.u8().toLong(), reader.u8().toLong(), reader.u8().toLong(), reader.u8().toLong(), reader.u8().toLong(),
            reader.u32(), reader.u32(), reader.u16().toLong(), reader.u16().toLong(), reader.u32(), reader.u16().toLong(),
        )
        val probeValues = longArrayOf(
            reader.u8().toLong(), reader.u8().toLong(), reader.u32(), reader.u8().toLong(), reader.u16().toLong(),
        )
        val updateValues = longArrayOf(reader.u32(), reader.u16().toLong(), reader.u32())

        val rawStatus = reader.u8()
        val nativeTcp = reader.u16()
        val nativeUdp = reader.u16()
        val effectiveTcp = reader.u16()
        val effectiveUdp = reader.u16()
        val flowIdle = reader.u32()
        val signedFlow = reader.u8()
        val nativeAggregate = reader.u32()
        val effectiveAggregate = reader.u32()
        val reservedBytes = reader.u32()
        if (!reader.end() || signedFlow != 0 || nativeAggregate != 134217728L ||
            effectiveAggregate !in (40L shl 20)..nativeAggregate
        ) return fail()
        if (rawStatus == 1) {
            if (tunnelMode == TunnelMode.PROXY_ONLY || nativeTcp != 4096 || nativeUdp != 2048 ||
                effectiveTcp !in 16..nativeTcp || effectiveUdp !in 0..nativeUdp ||
                flowIdle !in 1..minOf(3600000L, idleTimeout) ||
                reservedBytes !in 1..minOf(1048576L, effectiveAggregate)
            ) return fail()
        } else if (rawStatus == 2) {
            if (tunnelMode != TunnelMode.PROXY_ONLY || listOf(nativeTcp, nativeUdp, effectiveTcp, effectiveUdp).any { it != 0 } ||
                flowIdle != 0L || reservedBytes != 0L
            ) return fail()
        } else {
            return fail()
        }

        val proxy = decodeProxy(proxyValues, effectiveMask, effectiveAggregate)
            ?: if (proxyValues.any { it != 0L }) return fail() else null
        val probe = decodeProbeLimits(probeValues, signedMask)
            ?: if (probeValues.any { it != 0L }) return fail() else null
        val update = decodeUpdateLimits(updateValues, signedMask)
            ?: if (updateValues.any { it != 0L }) return fail() else null
        val capabilities = NativeCapabilities(signedCapabilities, nativeCapabilities, effectiveCapabilities)
        val snapshot = NativeOpeningSnapshot(
            generation,
            digest,
            profileFingerprint,
            strategyFingerprint,
            relayFingerprint,
            labels[0].value,
            labels[1].value,
            labels[2].value,
            exitRegion,
            tunnelMode,
            ipMode,
            resolverPolicy,
            mtu,
            metered,
            perAppMode,
            packageCount,
            clientV4.takeIf { it.first == 4 }?.let { NumericAddress(renderAddress(it)) },
            clientV6.takeIf { it.first == 6 }?.let { NumericAddress(renderAddress(it)) },
            dnsAddresses.map { NumericAddress(renderAddress(it)) },
            routes.map { CanonicalRoute("${renderAddress(it.first to it.second)}/${it.third}") },
            capabilities,
            NativePacketLimits(packetMax.toInt(), queuePackets, incompleteOps, payloadProtocols),
            NativeReconnectLimits(signedReconnect, nativeReconnect, effectiveReconnect, fallbackMax, fallbackUsed, dialTimeout, idleTimeout),
            proxy,
            probe,
            update,
            NativeResourceLimits(
                if (rawStatus == 1) NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES else NativeRawFlowStatus.NOT_APPLICABLE,
                nativeTcp,
                nativeUdp,
                effectiveTcp,
                effectiveUdp,
                flowIdle,
                NativeSignedRawFlowCapStatus.NOT_SEPARATELY_SPECIFIED,
                nativeAggregate,
                effectiveAggregate,
                reservedBytes,
            ),
        )
        return NativeProductResult.Success(snapshot)
    }

    fun decodeControl(input: ByteBuffer, previousSequence: ULong, previousConnectionGeneration: ULong): NativeProductResult<NativeControlEvent> {
        val total = input.remaining()
        if (total !in 32..32800) return fail()
        return try {
            val reader = ProductionReaderV1(input, 32800)
            if (!reader.bytes(4).contentEquals("KPC1".toByteArray()) || reader.u8() != 1) return fail()
            val kind = reader.u8()
            if (reader.u16() != 0 || reader.u32() != total.toLong()) return fail()
            val generation = reader.u64()
            val sequence = reader.u64()
            val bodyLength = reader.u32()
            if (generation == 0uL || sequence == 0uL || generation < previousConnectionGeneration ||
                sequence <= previousSequence || bodyLength != reader.remaining.toLong()
            ) return fail()

            val event: NativeControlEvent = when (kind) {
                1 -> {
                    if (bodyLength != 14L) return fail()
                    val token = reader.opaque64()
                    val fileDescriptor = reader.i32()
                    val socketKind = reader.u8()
                    val networkBindingRequired = reader.bool()
                    if (token == 0L || fileDescriptor < 0 || socketKind != 1) return fail()
                    NativeControlEvent.SocketProtectionRequired(
                        generation,
                        sequence,
                        token,
                        fileDescriptor,
                        NativeSocketKind.TUNNEL_TLS_TCP,
                        networkBindingRequired,
                    )
                }
                2 -> {
                    if (bodyLength != 0L) return fail()
                    NativeControlEvent.TransportConnecting(generation, sequence)
                }
                3 -> {
                    if (bodyLength != 0L) return fail()
                    NativeControlEvent.TransportReady(generation, sequence)
                }
                4, 6 -> {
                    if (bodyLength !in 220..32768) return fail()
                    val nested = reader.bytes(bodyLength.toInt())
                    val decoded = decodeOpening(ByteBuffer.wrap(nested))
                    if (decoded !is NativeProductResult.Success) return fail()
                    if (kind == 4) NativeControlEvent.RoutePlanReady(generation, sequence, decoded.value)
                    else NativeControlEvent.PathChanged(generation, sequence, decoded.value)
                }
                5 -> {
                    if (bodyLength != 42L) return fail()
                    val metrics = NativeMetrics(
                        reader.u64(), reader.u64(), reader.u64(), reader.u64(), reader.u64(), reader.u8(), reader.u8(),
                    )
                    NativeControlEvent.MetricsUpdated(generation, sequence, metrics)
                }
                7 -> {
                    if (bodyLength != 2L) return fail()
                    NativeControlEvent.FallbackStarted(generation, sequence, reader.u8(), reader.u8())
                }
                8 -> {
                    if (bodyLength != 3L) return fail()
                    val reason = when (reader.u8()) {
                        1 -> NativeReconnectReason.USER_REQUEST
                        2 -> NativeReconnectReason.NETWORK_FAILURE
                        3 -> NativeReconnectReason.SETTINGS_CHANGE
                        4 -> NativeReconnectReason.HANDOVER
                        else -> return fail()
                    }
                    NativeControlEvent.ReconnectStarted(generation, sequence, reason, reader.u8(), reader.u8())
                }
                9 -> {
                    if (bodyLength != 1L) return fail()
                    val reason = when (reader.u8()) {
                        1 -> DegradationReason.HEALTH
                        2 -> DegradationReason.NETWORK
                        3 -> DegradationReason.RESOURCE_LIMIT
                        else -> return fail()
                    }
                    NativeControlEvent.Degraded(generation, sequence, reason)
                }
                10 -> {
                    if (bodyLength != 0L) return fail()
                    NativeControlEvent.Revoked(generation, sequence)
                }
                11 -> {
                    if (bodyLength != 2L) return fail()
                    val status = reader.u16()
                    if (status in listOf(0, 19, 20) || ProductionStatusV1.fromWire(status) == null) return fail()
                    NativeControlEvent.Failed(generation, sequence, productionFailureV1(status))
                }
                12 -> {
                    if (bodyLength != 0L) return fail()
                    NativeControlEvent.Stopped(generation, sequence)
                }
                else -> return fail()
            }
            if (!reader.end()) fail() else NativeProductResult.Success(event)
        } catch (_: IllegalArgumentException) {
            fail()
        }
    }

    private data class DecodedLabel(val value: SafeAlias?)

    private fun readLabel(reader: ProductionReaderV1): DecodedLabel? {
        val available = reader.u8()
        val length = reader.u16()
        if (length > 384) return null
        val text = reader.utf8(length) ?: return null
        return when (available) {
            0 -> if (length == 0) DecodedLabel(null) else null
            1 -> try { DecodedLabel(SafeAlias(text)) } catch (_: IllegalArgumentException) { null }
            else -> null
        }
    }

    private fun readAddress(reader: ProductionReaderV1, optional: Boolean): Pair<Int, ByteArray>? {
        val family = reader.u8()
        if (optional && family == 0) return 0 to byteArrayOf()
        val size = when (family) {
            4 -> 4
            6 -> 16
            else -> return null
        }
        val bytes = reader.bytes(size)
        if (bytes.size != size || family == 6 && bytes.sliceArray(0..9).all { it == 0.toByte() } &&
            bytes[10] == (-1).toByte() && bytes[11] == (-1).toByte()
        ) return null
        return family to bytes
    }

    private fun validPerApp(mode: Int, count: Int) = when (mode) {
        1 -> count == 0
        2 -> count > 0
        3 -> true
        else -> false
    }

    private fun hostBitsZero(address: ByteArray, prefix: Int) =
        (prefix until address.size * 8).all { (address[it / 8].toInt() and (1 shl (7 - it % 8))) == 0 }

    private fun strictlySorted(values: List<ByteArray>) =
        values.zipWithNext().all { compareUnsignedV1(it.first, it.second) < 0 }

    private fun validNetwork(
        mode: TunnelMode,
        ipMode: IpMode,
        clientV4: Pair<Int, ByteArray>,
        clientV6: Pair<Int, ByteArray>,
        dns: List<Pair<Int, ByteArray>>,
        routes: List<Triple<Int, ByteArray, Int>>,
    ): Boolean {
        if (mode == TunnelMode.PROXY_ONLY) {
            return clientV4.first == 0 && clientV6.first == 0 && dns.isEmpty() && routes.isEmpty()
        }
        fun isDefaultRoute(route: Triple<Int, ByteArray, Int>, family: Int) =
            route.first == family && route.third == 0 && route.second.all { it == 0.toByte() }
        return when (ipMode) {
            IpMode.IPV4_ONLY -> clientV4.first == 4 && clientV6.first == 0 && dns.size == 1 && dns[0].first == 4 &&
                routes.size == 1 && isDefaultRoute(routes[0], 4)
            IpMode.IPV6_ONLY -> clientV4.first == 0 && clientV6.first == 6 && dns.size == 1 && dns[0].first == 6 &&
                routes.size == 1 && isDefaultRoute(routes[0], 6)
            IpMode.DUAL_STACK -> clientV4.first == 4 && clientV6.first == 6 && dns.map { it.first } == listOf(4, 6) &&
                routes.size == 2 && isDefaultRoute(routes[0], 4) && isDefaultRoute(routes[1], 6)
            IpMode.AUTO -> false
        }
    }

    private fun validModeCapabilities(mode: TunnelMode, mask: Int) = when (mode) {
        TunnelMode.TUN_ONLY -> mask and 1 != 0 && mask and 2 == 0
        TunnelMode.TUN_PLUS_PROXY -> mask and 3 == 3
        TunnelMode.PROXY_ONLY -> mask and 1 == 0 && mask and 2 != 0
    }

    private fun decodeProxy(values: LongArray, mask: Int, aggregate: Long): NativeProxyLimits? {
        if (mask and 2 == 0) return null
        return try {
            val limits = NativeProxyLimits(
                values[0].toInt(), values[1].toInt(), values[2].toInt(), values[3].toInt(), values[4].toInt(),
                values[5], values[6], values[7].toInt(), values[8].toInt(), values[9], values[10].toInt(),
            )
            if (values[5] !in (16L shl 20)..(128L shl 20) || values[6] > aggregate ||
                values[9] !in 1024..65536 || values[10] > values[9]
            ) null else limits
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun decodeProbeLimits(values: LongArray, mask: Int): NativeProbeLimits? {
        if (mask and 12 == 0) return null
        return try {
            if (values[2] !in 1000..3600000 || values[3] !in 1..60) return null
            NativeProbeLimits(values[0].toInt(), values[1].toInt(), values[2], values[3].toInt(), values[4].toInt())
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun decodeUpdateLimits(values: LongArray, mask: Int): NativeUpdateLimits? {
        if (mask and 16 == 0) return null
        return try {
            if (values[2] !in 60..604800) return null
            NativeUpdateLimits(values[0].toInt(), values[1].toInt(), values[2])
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun renderAddress(address: Pair<Int, ByteArray>): String = if (address.first == 4) {
        address.second.joinToString(".") { (it.toInt() and 255).toString() }
    } else {
        (0 until 8).joinToString(":") {
            (((address.second[it * 2].toInt() and 255) shl 8) or (address.second[it * 2 + 1].toInt() and 255)).toString(16)
        }
    }

    private fun <T> fail(): NativeProductResult<T> = NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
}

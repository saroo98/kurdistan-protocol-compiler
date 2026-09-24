// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import java.nio.ByteBuffer
import java.util.Collections
import org.kurdistanvpn.core.model.*

interface ProductionNativeSession : AutoCloseable {
    val openingSnapshot: NativeOpeningSnapshot
    fun nextControl(output: ByteBuffer): NativeProductResult<NativeControlEvent>
    fun confirmSocketProtection(token: Long, protected: Boolean, networkHandle: Long?): NativeProductResult<Unit>
    fun submitOutboundPacket(packet: ByteBuffer, length: Int): NativeProductResult<Unit>
    fun receiveInboundPacket(output: ByteBuffer): NativeProductResult<NativePacketDelivery>
    fun confirmInboundDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit>
    fun rejectInboundDelivery(token: Long): NativeProductResult<Unit>
    fun openProxyStream(request: NativeProxyRequest): NativeProductResult<NativeProxyStream>
    fun runProbe(request: NativeProbeRequest): NativeProductResult<NativeProbeResult>
    fun requestReconnect(reason: NativeReconnectReason): NativeProductResult<Unit>
    fun requestHandover(networkHandle: Long?): NativeProductResult<Unit>
    fun cancel(): NativeProductResult<Unit>
}

interface NativeProxyStream : AutoCloseable {
    fun send(input: ByteBuffer, length: Int): NativeProductResult<Unit>
    fun receive(output: ByteBuffer): NativeProductResult<NativeStreamRead>
    fun confirmDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit>
    fun rejectDelivery(token: Long): NativeProductResult<Unit>
    fun halfClose(): NativeProductResult<Unit>
    fun cancel(): NativeProductResult<Unit>
}

sealed interface NativeProductResult<out T> {
    data class Success<T>(val value: T) : NativeProductResult<T>
    data class Failure(val code: ProductFailureCode) : NativeProductResult<Nothing>
}

enum class NativeCapability { RAW_IP, PROXY_STREAM, PROBE_ACTIVE_RELAY, PROBE_DISCONNECTED, SAME_DEPLOYMENT_UPDATE }

class NativeCapabilities(signed: Set<NativeCapability>, native: Set<NativeCapability>, effective: Set<NativeCapability>) {
    val signed = Collections.unmodifiableSet(signed.toSet())
    val native = Collections.unmodifiableSet(native.toSet())
    val effective = Collections.unmodifiableSet(effective.toSet())
    init { require(signed.containsAll(effective) && native.containsAll(effective)) }
    override fun toString() = "NativeCapabilities(redacted)"
}

class NativePacketLimits(val packetMax: Int, val queuePackets: Int, val incompleteOps: Int,
    payloadProtocols: Set<NativePayloadProtocol>) {
    val payloadProtocols: Set<NativePayloadProtocol> = Collections.unmodifiableSet(payloadProtocols.toSet())
    init { require(packetMax in 40..65535 && queuePackets in 1..256 && incompleteOps in 1..64 && this.payloadProtocols.isNotEmpty()) }

    override fun equals(other: Any?) = other is NativePacketLimits && packetMax == other.packetMax &&
        queuePackets == other.queuePackets && incompleteOps == other.incompleteOps && payloadProtocols == other.payloadProtocols
    override fun hashCode() = arrayOf(packetMax, queuePackets, incompleteOps, payloadProtocols).contentHashCode()
    override fun toString() = "NativePacketLimits(redacted)"
}

data class NativeReconnectLimits(val signedReconnectMax: Int, val nativeReconnectMax: Int,
    val effectiveAutomaticReconnectMax: Int, val fallbackAttemptMax: Int, val fallbackAttemptsUsed: Int,
    val dialTimeoutMillis: Long, val idleTimeoutMillis: Long) {
    init {
        require(signedReconnectMax in 1..5 && nativeReconnectMax == 10)
        require(effectiveAutomaticReconnectMax in 0..10 && effectiveAutomaticReconnectMax <= signedReconnectMax && effectiveAutomaticReconnectMax <= nativeReconnectMax)
        require(fallbackAttemptMax in 1..minOf(5, signedReconnectMax, nativeReconnectMax) && fallbackAttemptsUsed in 0..fallbackAttemptMax)
        require(dialTimeoutMillis in 1..10000 && idleTimeoutMillis in 1..UInt.MAX_VALUE.toLong())
    }
}

data class NativeProxyLimits(val signedStreamMax: Int, val nativeStreamMax: Int, val effectiveStreamMax: Int,
    val nativeClientMax: Int, val effectiveClientMax: Int, val signedBufferBytes: Long,
    val effectiveTotalBufferBytes: Long, val effectiveIdleSeconds: Int, val signedConnectMillis: Int,
    val perDirectionQueueBytes: Long, val streamChunkMax: Int) {
    init {
        require(signedStreamMax in 1..64 && nativeStreamMax in 1..64 && effectiveStreamMax in 1..minOf(signedStreamMax, nativeStreamMax))
        require(nativeClientMax in 1..16 && effectiveClientMax in 1..nativeClientMax)
        require(signedBufferBytes in (16L shl 20)..(128L shl 20) && effectiveTotalBufferBytes in (16L shl 20)..signedBufferBytes)
        require(effectiveIdleSeconds in 30..3600 && signedConnectMillis in 1000..30000)
        require(perDirectionQueueBytes in 1024..65536 && streamChunkMax in 1..minOf(16384, perDirectionQueueBytes.toInt()))
    }
}

data class NativeProbeLimits(val maxConcurrent: Int, val maxSamples: Int, val minimumAttemptIntervalMillis: Long,
    val attemptsPerMinute: Int, val maxTotalMillis: Int) {
    init { require(maxConcurrent in 1..4 && maxSamples in 1..10 && minimumAttemptIntervalMillis in 1000..3600000 && attemptsPerMinute in 1..60 && maxTotalMillis in 1000..30000) }
}

data class NativeUpdateLimits(val maxArtifactBytes: Int, val maxTimeoutMillis: Int, val minimumCheckIntervalSeconds: Long) {
    init { require(maxArtifactBytes in 1..1052763 && maxTimeoutMillis in 1000..30000 && minimumCheckIntervalSeconds in 60..604800) }
}

enum class NativeRawFlowStatus { ENFORCED_FORWARDING_LEASES, NOT_APPLICABLE }
enum class NativeSignedRawFlowCapStatus { NOT_SEPARATELY_SPECIFIED }

data class NativeResourceLimits(val rawFlowStatus: NativeRawFlowStatus, val nativeTcpFlowMax: Int,
    val nativeUdpFlowMax: Int, val effectiveTcpFlowMax: Int, val effectiveUdpFlowMax: Int,
    val effectiveFlowIdleMillis: Long, val signedRawFlowCapStatus: NativeSignedRawFlowCapStatus,
    val nativeAggregateBufferMax: Long, val effectiveAggregateBufferMax: Long, val flowTableReservedBytes: Long) {
    init {
        require(nativeTcpFlowMax in 0..65535 && nativeUdpFlowMax in 0..65535)
        require(effectiveTcpFlowMax in 0..nativeTcpFlowMax && effectiveUdpFlowMax in 0..nativeUdpFlowMax)
        require(effectiveFlowIdleMillis in 0..UInt.MAX_VALUE.toLong())
        require(nativeAggregateBufferMax == 134217728L && effectiveAggregateBufferMax in (40L shl 20)..nativeAggregateBufferMax)
        require(flowTableReservedBytes in 0..1048576 && flowTableReservedBytes <= effectiveAggregateBufferMax)
        require(when (rawFlowStatus) {
            NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES -> nativeTcpFlowMax == 4096 && nativeUdpFlowMax == 2048 &&
                effectiveTcpFlowMax in 16..nativeTcpFlowMax && effectiveUdpFlowMax in 0..nativeUdpFlowMax &&
                effectiveFlowIdleMillis in 1..3600000 && flowTableReservedBytes in 1..1048576
            NativeRawFlowStatus.NOT_APPLICABLE -> listOf(nativeTcpFlowMax, nativeUdpFlowMax, effectiveTcpFlowMax, effectiveUdpFlowMax).all { it == 0 } &&
                effectiveFlowIdleMillis == 0L && flowTableReservedBytes == 0L
        })
    }
}

class NativeOpeningSnapshot(
    val profileGeneration: ULong, planDigest: ByteArray, profileFingerprint: ByteArray,
    strategyFingerprint: ByteArray, relayFingerprint: ByteArray, val nodeLabel: SafeAlias?, val pathLabel: SafeAlias?,
    val strategyLabel: SafeAlias?, val exitRegion: ExitRegion, val effectiveMode: TunnelMode, val effectiveIp: IpMode,
    val effectiveDnsMode: ResolverPolicy, val effectiveMtu: Int, val metered: Boolean,
    val perAppMode: PerAppSelectionMode, val effectivePackageCount: Int, val clientV4: NumericAddress?,
    val clientV6: NumericAddress?, dnsAddresses: List<NumericAddress>, routes: List<CanonicalRoute>,
    val capabilities: NativeCapabilities, val packetLimits: NativePacketLimits, val reconnectLimits: NativeReconnectLimits,
    val proxyLimits: NativeProxyLimits?, val probeLimits: NativeProbeLimits?, val updateLimits: NativeUpdateLimits?,
    val resourceLimits: NativeResourceLimits,
) {
    private val ownedPlanDigest = planDigest.copyOf()
    private val ownedProfileFingerprint = profileFingerprint.copyOf()
    private val ownedStrategyFingerprint = strategyFingerprint.copyOf()
    private val ownedRelayFingerprint = relayFingerprint.copyOf()
    val planDigest get() = ownedPlanDigest.copyOf()
    val profileFingerprint get() = ownedProfileFingerprint.copyOf()
    val strategyFingerprint get() = ownedStrategyFingerprint.copyOf()
    val relayFingerprint get() = ownedRelayFingerprint.copyOf()
    val dnsAddresses: List<NumericAddress> = Collections.unmodifiableList(dnsAddresses.toList())
    val routes: List<CanonicalRoute> = Collections.unmodifiableList(routes.toList())
    init {
        require(profileGeneration > 0uL && ownedPlanDigest.size == 32 && ownedPlanDigest.any { it.toInt() != 0 })
        require(ownedProfileFingerprint.size == 16 && ownedStrategyFingerprint.size == 16 && ownedRelayFingerprint.size == 16)
        require(effectiveIp != IpMode.AUTO && effectiveMtu in 1280..1500 && effectivePackageCount in 0..256)
        require(dnsAddresses.size <= 2 && dnsAddresses.distinct().size == dnsAddresses.size && routes.size <= 256 && routes.distinct().size == routes.size)
        require(when (perAppMode) {
            PerAppSelectionMode.ALL_APPS -> effectivePackageCount == 0
            PerAppSelectionMode.INCLUDE_ONLY -> effectivePackageCount > 0
            PerAppSelectionMode.EXCLUDE_SELECTED -> true
        })
        require(packetLimits.packetMax == effectiveMtu)
        require(proxyLimits == null || proxyLimits.effectiveTotalBufferBytes <= resourceLimits.effectiveAggregateBufferMax)
        require(resourceLimits.effectiveFlowIdleMillis <= reconnectLimits.idleTimeoutMillis)
        val raw = NativeCapability.RAW_IP in capabilities.effective
        val proxy = NativeCapability.PROXY_STREAM in capabilities.effective
        require(when (effectiveMode) {
            TunnelMode.TUN_ONLY -> raw && !proxy
            TunnelMode.TUN_PLUS_PROXY -> raw && proxy
            TunnelMode.PROXY_ONLY -> !raw && proxy
        })
        require((proxyLimits != null) == proxy)
        require((probeLimits != null) == capabilities.signed.any { it == NativeCapability.PROBE_ACTIVE_RELAY || it == NativeCapability.PROBE_DISCONNECTED })
        require((updateLimits != null) == (NativeCapability.SAME_DEPLOYMENT_UPDATE in capabilities.signed))
        val v4 = clientV4?.value?.let { ':' !in it } == true
        val v6 = clientV6?.value?.let { ':' in it } == true
        require(clientV4 == null || v4); require(clientV6 == null || v6)
        val dnsFamilies = dnsAddresses.map { if (':' in it.value) 6 else 4 }
        val routeFamilies = routes.map { if (':' in it.value.substringBefore('/')) 6 else 4 }
        require(when (effectiveMode) {
            TunnelMode.PROXY_ONLY -> clientV4 == null && clientV6 == null && dnsAddresses.isEmpty() && routes.isEmpty() &&
                resourceLimits.rawFlowStatus == NativeRawFlowStatus.NOT_APPLICABLE
            else -> when (effectiveIp) {
                IpMode.IPV4_ONLY -> v4 && clientV6 == null && dnsFamilies == listOf(4) && routeFamilies == listOf(4) && routes.single().value == "0.0.0.0/0"
                IpMode.IPV6_ONLY -> clientV4 == null && v6 && dnsFamilies == listOf(6) && routeFamilies == listOf(6) && routes.single().value == "::/0"
                IpMode.DUAL_STACK -> v4 && v6 && dnsFamilies == listOf(4, 6) && routeFamilies == listOf(4, 6) && routes.map { it.value } == listOf("0.0.0.0/0", "::/0")
                IpMode.AUTO -> false
            } && resourceLimits.rawFlowStatus == NativeRawFlowStatus.ENFORCED_FORWARDING_LEASES
        })
    }
    override fun toString() = "NativeOpeningSnapshot(redacted)"
}

enum class NativeSocketKind { TUNNEL_TLS_TCP }
enum class NativeReconnectReason { USER_REQUEST, NETWORK_FAILURE, SETTINGS_CHANGE, HANDOVER }

sealed interface NativeControlEvent {
    val connectionGeneration: ULong
    val eventSequence: ULong
    class SocketProtectionRequired(override val connectionGeneration: ULong, override val eventSequence: ULong,
        val token: Long, val fileDescriptor: Int, val socketKind: NativeSocketKind, val bindingRequired: Boolean) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence); require(token != 0L && fileDescriptor >= 0) }
        override fun toString() = "NativeControlEvent.SocketProtectionRequired(redacted)"
    }
    data class TransportConnecting(override val connectionGeneration: ULong, override val eventSequence: ULong) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.TransportConnecting(redacted)"
    }
    data class TransportReady(override val connectionGeneration: ULong, override val eventSequence: ULong) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.TransportReady(redacted)"
    }
    class RoutePlanReady(override val connectionGeneration: ULong, override val eventSequence: ULong, val snapshot: NativeOpeningSnapshot) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.RoutePlanReady(redacted)"
    }
    data class MetricsUpdated(override val connectionGeneration: ULong, override val eventSequence: ULong, val metrics: NativeMetrics) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.MetricsUpdated(redacted)"
    }
    class PathChanged(override val connectionGeneration: ULong, override val eventSequence: ULong, val snapshot: NativeOpeningSnapshot) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.PathChanged(redacted)"
    }
    data class FallbackStarted(override val connectionGeneration: ULong, override val eventSequence: ULong, val attempt: Int, val maximum: Int) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence); require(maximum in 1..255 && attempt in 1..maximum) }
        override fun toString() = "NativeControlEvent.FallbackStarted(redacted)"
    }
    data class ReconnectStarted(override val connectionGeneration: ULong, override val eventSequence: ULong, val reason: NativeReconnectReason, val attempt: Int, val maximum: Int) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence); require(maximum in 1..255 && attempt in 1..maximum) }
        override fun toString() = "NativeControlEvent.ReconnectStarted(redacted)"
    }
    data class Degraded(override val connectionGeneration: ULong, override val eventSequence: ULong, val reason: DegradationReason) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.Degraded(redacted)"
    }
    data class Revoked(override val connectionGeneration: ULong, override val eventSequence: ULong) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.Revoked(redacted)"
    }
    data class Failed(override val connectionGeneration: ULong, override val eventSequence: ULong, val code: ProductFailureCode) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence); require(code in P1_FAILURE_CODES) }
        override fun toString() = "NativeControlEvent.Failed(redacted)"
    }
    data class Stopped(override val connectionGeneration: ULong, override val eventSequence: ULong) : NativeControlEvent {
        init { controlIds(connectionGeneration, eventSequence) }
        override fun toString() = "NativeControlEvent.Stopped(redacted)"
    }
}

private fun controlIds(generation: ULong, sequence: ULong) { require(generation > 0uL && sequence > 0uL) }
private val P1_FAILURE_CODES = setOf(ProductFailureCode.PROFILE_INCOMPATIBLE, ProductFailureCode.INVALID_INPUT,
    ProductFailureCode.OPERATION_INTERRUPTED, ProductFailureCode.SIZE_LIMIT, ProductFailureCode.RESOURCE_LIMIT,
    ProductFailureCode.RATE_LIMITED, ProductFailureCode.CANCELLED, ProductFailureCode.OPERATION_TIMED_OUT,
    ProductFailureCode.NETWORK_UNAVAILABLE, ProductFailureCode.ROUTE_POLICY_REJECTED, ProductFailureCode.NODE_UNREACHABLE,
    ProductFailureCode.PROFILE_EXPIRED, ProductFailureCode.PROFILE_REVOKED, ProductFailureCode.PROFILE_UNTRUSTED,
    ProductFailureCode.SESSION_AUTHENTICATION_FAILED, ProductFailureCode.SOCKET_PROTECTION_FAILED,
    ProductFailureCode.INTERNAL_FAILURE, ProductFailureCode.PROFILE_WRONG_DEVICE, ProductFailureCode.PROFILE_ROLLBACK,
    ProductFailureCode.DNS_POLICY_REJECTED)

data class NativeMetrics(val cumulativeBytesSent: ULong, val cumulativeBytesReceived: ULong,
    val connectedDurationMillis: ULong, val outboundPackets: ULong, val inboundPackets: ULong,
    val activeStreams: Int, val activeProbes: Int) {
    init { require(activeStreams in 0..64 && activeProbes in 0..4) }
}

data class NativePacketDelivery(val length: Int, val token: Long) {
    init { require(length in 1..65535 && token != 0L) }
    override fun toString() = "NativePacketDelivery(redacted)"
}

sealed interface NativeStreamRead {
    data class Data(val length: Int, val token: Long) : NativeStreamRead {
        init { require(length in 1..16384 && token != 0L) }
        override fun toString() = "NativeStreamRead.Data(redacted)"
    }
    data object EndOfStream : NativeStreamRead
}

enum class NativeProxyAddressKind { IPV4, DOMAIN, IPV6 }

class NativeProxyRequest(val kind: NativeProxyAddressKind, address: ByteArray, val port: Int) {
    private val ownedAddress = address.copyOf()
    val address get() = ownedAddress.copyOf()
    init { require(port in 1..65535); require(validProxyAddress(kind, ownedAddress)) }
    override fun toString() = "NativeProxyRequest(redacted)"
}

private fun validProxyAddress(kind: NativeProxyAddressKind, address: ByteArray): Boolean = when (kind) {
    NativeProxyAddressKind.IPV4 -> address.size == 4 && isPublicV4(address)
    NativeProxyAddressKind.IPV6 -> address.size == 16 && isPublicV6(address)
    NativeProxyAddressKind.DOMAIN -> address.size in 1..253 && address.all { (it.toInt() and 255) in 0x21..0x7e } &&
        String(address, Charsets.US_ASCII).let { name -> name == name.lowercase() && !name.endsWith('.') && name.split('.').all { label -> label.length in 1..63 && label.first() != '-' && label.last() != '-' && label.all { it in 'a'..'z' || it in '0'..'9' || it == '-' } } }
}

private fun isPublicV4(a: ByteArray): Boolean {
    val x = a[0].toInt() and 255; val y = a[1].toInt() and 255; val z = a[2].toInt() and 255
    return x in 1..223 && x != 10 && x != 127 && !(x == 100 && y in 64..127) && !(x == 169 && y == 254) &&
        !(x == 172 && y in 16..31) && !(x == 192 && ((y == 0 && (z == 0 || z == 2)) || y == 168)) &&
        !(x == 198 && (y in 18..19 || y == 51 && z == 100)) && !(x == 203 && y == 0 && z == 113)
}

private fun isPublicV6(a: ByteArray): Boolean {
    val first = a[0].toInt() and 255; val second = a[1].toInt() and 255
    val third = a[2].toInt() and 255
    val fourth = a[3].toInt() and 255
    return first in 0x20..0x3f && !(first == 0x20 && second == 0x01 && third in 0x00..0x01) &&
        !(first == 0x20 && second == 0x01 && third == 0x0d && fourth == 0xb8) &&
        !(first == 0x20 && second == 0x02)
}

enum class NativeProbeMethod { TCP_CONNECT }
data class NativeProbeRequest(val targetId: Int, val method: NativeProbeMethod, val attemptTimeoutMillis: Int,
    val totalTimeoutMillis: Int, val samples: Int) {
    init { require(targetId in 1..65535 && attemptTimeoutMillis in 1000..30000 && totalTimeoutMillis in 1000..30000 && samples in 1..10) }
    override fun toString() = "NativeProbeRequest(redacted)"
}
enum class NativeProbePath { DISCONNECTED_TCP_CONNECT, ACTIVE_RELAY_END_TO_END }
enum class NativeProbeStability { NOT_ENOUGH_SAMPLES, STABLE, VARIABLE }
enum class NativeProbeCompletion { COMPLETE, TIMED_OUT, RATE_LIMITED }
data class NativeProbeResult(val path: NativeProbePath, val method: NativeProbeMethod, val attempted: Int,
    val succeeded: Int, val failed: Int, val unstarted: Int, val meanLatencyMicros: Int?, val jitterMicros: Int?,
    val lossPermille: Int, val stability: NativeProbeStability, val completion: NativeProbeCompletion) {
    init {
        require(attempted in 1..10 && succeeded >= 0 && failed >= 0 && succeeded + failed == attempted && unstarted in 0..(10 - attempted))
        require(meanLatencyMicros?.let { it in 0..30000000 } ?: (succeeded == 0))
        require((meanLatencyMicros != null) == (succeeded >= 1) && (jitterMicros != null) == (succeeded >= 2))
        require(jitterMicros == null || jitterMicros in 0..30000000)
        require(lossPermille == failed * 1000 / attempted)
        val expectedStability = when {
            attempted < 3 -> NativeProbeStability.NOT_ENOUGH_SAMPLES
            failed == 0 && jitterMicros!! <= meanLatencyMicros!! / 4 -> NativeProbeStability.STABLE
            else -> NativeProbeStability.VARIABLE
        }
        require(stability == expectedStability)
        require(completion != NativeProbeCompletion.COMPLETE || unstarted == 0)
    }
}

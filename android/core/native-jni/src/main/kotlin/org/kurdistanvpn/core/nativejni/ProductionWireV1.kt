// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.CodingErrorAction
import org.kurdistanvpn.core.model.ExitRegion
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.PerAppSelectionMode
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.model.ResolverPolicy
import org.kurdistanvpn.core.model.TunnelMode
import org.kurdistanvpn.core.nativeapi.NativeCapability
import org.kurdistanvpn.core.nativeapi.NativePayloadProtocol
import org.kurdistanvpn.core.nativeapi.NativeProductResult

internal enum class ProductionStatusV1(val wireValue: Int) {
    SUCCESS(0), NOT_ADMITTED(1), INVALID_REQUEST(2), INVALID_STATE(3), SIZE_LIMIT(4), RESOURCE_LIMIT(5),
    RATE_LIMITED(6), CANCELLED(7), TIMEOUT(8), NETWORK_UNAVAILABLE(9), DESTINATION_DENIED(10),
    UNREACHABLE(11), AUTHORITY_EXPIRED(12), AUTHORITY_REVOKED(13), TLS_REJECTED(14),
    SESSION_AUTHENTICATION_FAILED(15), SOCKET_PROTECTION_FAILED(16), POLICY_REJECTED(17),
    INTERNAL_FAILURE(18), END_OF_STREAM(19), NO_EVENT(20), TRUST_UNAVAILABLE(21),
    VERIFICATION_REJECTED(22), WRONG_RECIPIENT(23), ROLLBACK(24), INCOMPATIBLE(25), DNS_POLICY_REJECTED(26);
    companion object { fun fromWire(value: Int) = entries.firstOrNull { it.wireValue == value } }
}

internal enum class MaintenanceStatusV1(val wireValue: Int) {
    SUCCESS(0), NO_CHANGE(1), NOT_ADMITTED(2), INVALID_REQUEST(3), INVALID_STATE(4), SIZE_LIMIT(5),
    RESOURCE_LIMIT(6), RATE_LIMITED(7), CANCELLED(8), TIMEOUT(9), NETWORK_UNAVAILABLE(10),
    DESTINATION_DENIED(11), TLS_TRUST_UNAVAILABLE(12), TLS_REJECTED(13), FETCH_REJECTED(14),
    SIGNATURE_INVALID(15), WRONG_RECIPIENT(16), PROFILE_MISMATCH(17), ROLLBACK(18), EXPIRED(19),
    REVOKED(20), INCOMPATIBLE(21), ROOT_ROTATION_REJECTED(22), INTERNAL_FAILURE(23);
    companion object { fun fromWire(value: Int) = entries.firstOrNull { it.wireValue == value } }
}

internal fun productionFailureV1(status: Int): ProductFailureCode = when (ProductionStatusV1.fromWire(status)) {
    ProductionStatusV1.NOT_ADMITTED, ProductionStatusV1.INCOMPATIBLE -> ProductFailureCode.PROFILE_INCOMPATIBLE
    ProductionStatusV1.INVALID_REQUEST -> ProductFailureCode.INVALID_INPUT
    ProductionStatusV1.INVALID_STATE -> ProductFailureCode.OPERATION_INTERRUPTED
    ProductionStatusV1.SIZE_LIMIT -> ProductFailureCode.SIZE_LIMIT
    ProductionStatusV1.RESOURCE_LIMIT -> ProductFailureCode.RESOURCE_LIMIT
    ProductionStatusV1.RATE_LIMITED -> ProductFailureCode.RATE_LIMITED
    ProductionStatusV1.CANCELLED -> ProductFailureCode.CANCELLED
    ProductionStatusV1.TIMEOUT -> ProductFailureCode.OPERATION_TIMED_OUT
    ProductionStatusV1.NETWORK_UNAVAILABLE -> ProductFailureCode.NETWORK_UNAVAILABLE
    ProductionStatusV1.DESTINATION_DENIED, ProductionStatusV1.POLICY_REJECTED -> ProductFailureCode.ROUTE_POLICY_REJECTED
    ProductionStatusV1.UNREACHABLE -> ProductFailureCode.NODE_UNREACHABLE
    ProductionStatusV1.AUTHORITY_EXPIRED -> ProductFailureCode.PROFILE_EXPIRED
    ProductionStatusV1.AUTHORITY_REVOKED -> ProductFailureCode.PROFILE_REVOKED
    ProductionStatusV1.TLS_REJECTED, ProductionStatusV1.TRUST_UNAVAILABLE,
    ProductionStatusV1.VERIFICATION_REJECTED -> ProductFailureCode.PROFILE_UNTRUSTED
    ProductionStatusV1.SESSION_AUTHENTICATION_FAILED -> ProductFailureCode.SESSION_AUTHENTICATION_FAILED
    ProductionStatusV1.SOCKET_PROTECTION_FAILED -> ProductFailureCode.SOCKET_PROTECTION_FAILED
    ProductionStatusV1.WRONG_RECIPIENT -> ProductFailureCode.PROFILE_WRONG_DEVICE
    ProductionStatusV1.ROLLBACK -> ProductFailureCode.PROFILE_ROLLBACK
    ProductionStatusV1.DNS_POLICY_REJECTED -> ProductFailureCode.DNS_POLICY_REJECTED
    else -> ProductFailureCode.INTERNAL_FAILURE
}

internal fun maintenanceFailureV1(status: Int): ProductFailureCode = when (MaintenanceStatusV1.fromWire(status)) {
    MaintenanceStatusV1.NOT_ADMITTED -> ProductFailureCode.PROFILE_INCOMPATIBLE
    MaintenanceStatusV1.INVALID_REQUEST -> ProductFailureCode.INVALID_INPUT
    MaintenanceStatusV1.INVALID_STATE -> ProductFailureCode.OPERATION_INTERRUPTED
    MaintenanceStatusV1.SIZE_LIMIT -> ProductFailureCode.SIZE_LIMIT
    MaintenanceStatusV1.RESOURCE_LIMIT -> ProductFailureCode.RESOURCE_LIMIT
    MaintenanceStatusV1.RATE_LIMITED -> ProductFailureCode.RATE_LIMITED
    MaintenanceStatusV1.CANCELLED -> ProductFailureCode.CANCELLED
    MaintenanceStatusV1.TIMEOUT -> ProductFailureCode.OPERATION_TIMED_OUT
    MaintenanceStatusV1.NETWORK_UNAVAILABLE -> ProductFailureCode.NETWORK_UNAVAILABLE
    MaintenanceStatusV1.DESTINATION_DENIED -> ProductFailureCode.ROUTE_POLICY_REJECTED
    MaintenanceStatusV1.TLS_TRUST_UNAVAILABLE, MaintenanceStatusV1.TLS_REJECTED,
    MaintenanceStatusV1.PROFILE_MISMATCH, MaintenanceStatusV1.ROOT_ROTATION_REJECTED -> ProductFailureCode.PROFILE_UNTRUSTED
    MaintenanceStatusV1.FETCH_REJECTED -> ProductFailureCode.UPDATE_FETCH_REJECTED
    MaintenanceStatusV1.SIGNATURE_INVALID -> ProductFailureCode.UPDATE_SIGNATURE_INVALID
    MaintenanceStatusV1.WRONG_RECIPIENT -> ProductFailureCode.PROFILE_WRONG_DEVICE
    MaintenanceStatusV1.ROLLBACK -> ProductFailureCode.UPDATE_ROLLBACK
    MaintenanceStatusV1.EXPIRED -> ProductFailureCode.PROFILE_EXPIRED
    MaintenanceStatusV1.REVOKED -> ProductFailureCode.PROFILE_REVOKED
    MaintenanceStatusV1.INCOMPATIBLE -> ProductFailureCode.UPDATE_INCOMPATIBLE
    else -> ProductFailureCode.INTERNAL_FAILURE
}

internal class ProductionWriterV1(
    private val maximum: Int,
    initialCapacity: Int = minOf(64, maximum),
) : Closeable {
    private var buffer: ByteArray
    private var count = 0
    private var closed = false

    init {
        require(maximum > 0)
        require(initialCapacity in 1..maximum)
        buffer = ByteArray(initialCapacity)
    }

    val size get() = count

    fun u8(value: Int) {
        require(value in 0..255)
        ensureCapacity(1)
        buffer[count++] = value.toByte()
    }

    fun bool(value: Boolean) = u8(if (value) 1 else 0)
    fun u16(value: Int) { require(value in 0..65535); u8(value ushr 8); u8(value and 0xff) }
    fun u32(value: Long) { require(value in 0..0xffff_ffffL); repeat(4) { shift -> u8(((value ushr (24 - shift * 8)) and 0xffL).toInt()) } }
    fun u64(value: ULong) { repeat(8) { shift -> u8(((value shr (56 - shift * 8)) and 0xffuL).toInt()) } }
    fun opaque64(value: Long) = u64(value.toULong())
    fun i32(value: Int) { u32(value.toUInt().toLong()) }
    fun bytes(value: ByteArray) {
        ensureCapacity(value.size)
        value.copyInto(buffer, count)
        count += value.size
    }

    fun result(): ByteArray {
        check(!closed)
        return try {
            buffer.copyOf(count)
        } finally {
            close()
        }
    }

    override fun close() {
        if (!closed) {
            buffer.fill(0)
            count = 0
            closed = true
        }
    }

    private fun ensureCapacity(additional: Int) {
        check(!closed)
        require(additional >= 0 && additional <= maximum - count)
        val required = count + additional
        if (required <= buffer.size) return
        var nextSize = buffer.size
        while (nextSize < required) nextSize = minOf(maximum, nextSize * 2)
        val replacement = ByteArray(nextSize)
        buffer.copyInto(replacement, endIndex = count)
        buffer.fill(0)
        buffer = replacement
    }
}

internal fun decodeExitRegionV1(value: Int): ExitRegion? = when (value) {
    0 -> ExitRegion.UNKNOWN
    1 -> ExitRegion.EUROPE
    2 -> ExitRegion.ASIA
    3 -> ExitRegion.AFRICA
    4 -> ExitRegion.NORTH_AMERICA
    5 -> ExitRegion.SOUTH_AMERICA
    6 -> ExitRegion.OCEANIA
    else -> null
}

internal fun decodeTunnelModeV1(value: Int): TunnelMode? = when (value) {
    1 -> TunnelMode.TUN_ONLY
    2 -> TunnelMode.TUN_PLUS_PROXY
    3 -> TunnelMode.PROXY_ONLY
    else -> null
}

internal fun decodeIpModeV1(value: Int): IpMode? = when (value) {
    2 -> IpMode.IPV4_ONLY
    3 -> IpMode.IPV6_ONLY
    4 -> IpMode.DUAL_STACK
    else -> null
}

internal fun decodeResolverPolicyV1(value: Int): ResolverPolicy? = when (value) {
    1 -> ResolverPolicy.INTERNAL
    2 -> ResolverPolicy.PROFILE_DEFINED
    3 -> ResolverPolicy.PRESET
    4 -> ResolverPolicy.CUSTOM
    else -> null
}

internal fun decodePerAppModeV1(value: Int): PerAppSelectionMode? = when (value) {
    1 -> PerAppSelectionMode.ALL_APPS
    2 -> PerAppSelectionMode.INCLUDE_ONLY
    3 -> PerAppSelectionMode.EXCLUDE_SELECTED
    else -> null
}

internal fun decodeCapabilitiesV1(mask: Int): Set<NativeCapability>? {
    if (mask and 0xffe0 != 0) return null
    return buildSet {
        if (mask and 0x01 != 0) add(NativeCapability.RAW_IP)
        if (mask and 0x02 != 0) add(NativeCapability.PROXY_STREAM)
        if (mask and 0x04 != 0) add(NativeCapability.PROBE_ACTIVE_RELAY)
        if (mask and 0x08 != 0) add(NativeCapability.PROBE_DISCONNECTED)
        if (mask and 0x10 != 0) add(NativeCapability.SAME_DEPLOYMENT_UPDATE)
    }
}

internal fun decodePayloadProtocolsV1(mask: Int): Set<NativePayloadProtocol>? {
    if (mask and 0xfff0 != 0) return null
    return buildSet {
        if (mask and 0x01 != 0) add(NativePayloadProtocol.ICMP)
        if (mask and 0x02 != 0) add(NativePayloadProtocol.ICMPV6)
        if (mask and 0x04 != 0) add(NativePayloadProtocol.TCP)
        if (mask and 0x08 != 0) add(NativePayloadProtocol.UDP)
    }
}

internal class ProductionReaderV1(input: ByteBuffer, private val maximum: Int) {
    private val source = input.duplicate().order(ByteOrder.BIG_ENDIAN)
    private val start = source.position()
    var failed = source.remaining() > maximum
        private set
    val consumed get() = source.position() - start
    val remaining get() = source.remaining()
    private fun need(count: Int): Boolean {
        val valid = !failed && count >= 0 && count <= source.remaining()
        if (!valid) failed = true
        return valid
    }
    fun u8(): Int = if (need(1)) source.get().toInt() and 255 else 0
    fun bool(): Boolean { val value = u8(); if (value !in 0..1) failed = true; return value == 1 }
    fun u16(): Int = if (need(2)) source.short.toInt() and 65535 else 0
    fun u32(): Long = if (need(4)) source.int.toLong() and 0xffff_ffffL else 0
    fun u64(): ULong = if (need(8)) source.long.toULong() else 0uL
    fun opaque64(): Long = u64().toLong()
    fun i32(): Int = if (need(4)) source.int else 0
    fun bytes(count: Int): ByteArray = if (need(count)) ByteArray(count).also(source::get) else byteArrayOf()
    fun utf8(count: Int): String? {
        val raw = bytes(count); if (failed) return null
        return try { Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString() }
        catch (_: java.nio.charset.CharacterCodingException) { failed = true; null }
    }
    fun end(): Boolean = !failed && !source.hasRemaining()
}

internal fun atomicWriteV1(bytes: ByteArray, output: ByteBuffer, maximum: Int): NativeProductResult<Int> {
    if (output.isReadOnly) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
    if (bytes.size > maximum || output.remaining() < bytes.size) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
    output.duplicate().put(bytes)
    return NativeProductResult.Success(bytes.size)
}

internal fun ByteBuffer.spanBytesV1(maximum: Int): ByteArray? {
    if (remaining() !in 1..maximum) return null
    return ByteArray(remaining()).also { duplicate().get(it) }
}

internal fun addressBytesV1(value: String): ByteArray? {
    if (value != value.trim() || '%' in value || '[' in value || ']' in value) return null
    val v4 = value.split('.')
    if (v4.size == 4) {
        val bytes = ByteArray(4)
        for (i in 0..3) { val part=v4[i]; if (part.isEmpty() || (part.length>1&&part[0]=='0') || part.any{!it.isDigit()}) return null; val n=part.toIntOrNull()?:return null; if(n !in 0..255)return null; bytes[i]=n.toByte() }
        return bytes
    }
    if ('.' in value || value.isEmpty() || value.indexOf("::") != value.lastIndexOf("::")) return null
    fun groups(part:String):List<Int>? = if(part.isEmpty()) emptyList() else part.split(':').map { if(it.isEmpty()||it.length>4||it.any{c->c.lowercaseChar() !in '0'..'9' && c.lowercaseChar() !in 'a'..'f'}) return null; it.toInt(16) }
    val compressed="::" in value; val halves=if(compressed)value.lowercase().split("::",limit=2) else listOf(value.lowercase())
    val left=groups(halves[0])?:return null; val right=if(compressed)groups(halves[1])?:return null else emptyList()
    if((!compressed&&left.size!=8)||(compressed&&left.size+right.size>=8)) return null
    val words=left+List(8-left.size-right.size){0}+right
    val out=ByteArray(16); words.forEachIndexed{i,w->out[i*2]=(w ushr 8).toByte();out[i*2+1]=w.toByte()}
    if (out.sliceArray(0..9).all { it==0.toByte() } && out[10]==(-1).toByte() && out[11]==(-1).toByte()) return null
    return out
}

internal fun encodedAddressV1(value: String): ByteArray? = addressBytesV1(value)?.let { byteArrayOf(if(it.size==4)4 else 6)+it }
internal fun encodedPrefixV1(value: String): ByteArray? {
    val slash=value.indexOf('/'); if(slash<=0||slash!=value.lastIndexOf('/'))return null
    val address=addressBytesV1(value.substring(0,slash))?:return null; val prefix=value.substring(slash+1).toIntOrNull()?:return null
    if(prefix !in 0..address.size*8)return null
    for(bit in prefix until address.size*8) if((address[bit/8].toInt() and (1 shl (7-bit%8)))!=0)return null
    return byteArrayOf(if(address.size==4)4 else 6)+address+byteArrayOf(prefix.toByte())
}

internal fun compareUnsignedV1(a: ByteArray,b:ByteArray):Int { for(i in 0 until minOf(a.size,b.size)){val d=(a[i].toInt() and 255)-(b[i].toInt() and 255);if(d!=0)return d};return a.size-b.size }

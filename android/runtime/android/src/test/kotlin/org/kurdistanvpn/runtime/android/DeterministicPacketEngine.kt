// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

internal object DeterministicPacketEngine {
    private val serviceAddress = byteArrayOf(198.toByte(), 18, 0, 53)

    data class Result(val response: ByteArray?, val disposition: String)

    fun reply(
        packet: ByteArray,
        length: Int,
        kurdRoundTrip: (ByteArray) -> ByteArray? = { it.copyOf() },
    ): Result {
        if (length < IPV4_MINIMUM + UDP_HEADER || length > packet.size) {
            return Result(null, "INVALID_LENGTH")
        }
        val packetOffset = if (
            length >= TUN_PI_HEADER + IPV4_MINIMUM + UDP_HEADER &&
            packet[0] == 0.toByte() &&
            packet[1] == 0.toByte() &&
            packet[2] == 0x08.toByte() &&
            packet[3] == 0.toByte()
        ) {
            TUN_PI_HEADER
        } else {
            0
        }
        val versionAndHeader = packet[packetOffset].toInt() and 0xff
        if (versionAndHeader ushr 4 != 4) {
            val offsetFourVersion = if (length > 4) {
                (packet[4].toInt() and 0xff) ushr 4
            } else {
                -1
            }
            return Result(
                null,
                "NOT_IPV4_${versionAndHeader ushr 4}_$offsetFourVersion",
            )
        }
        val headerLength = (versionAndHeader and 0x0f) * 4
        if (
            headerLength < IPV4_MINIMUM ||
            packetOffset + headerLength + UDP_HEADER > length
        ) {
            return Result(null, "INVALID_HEADER")
        }
        val totalLength = unsignedShort(packet, packetOffset + 2)
        if (
            totalLength !in (headerLength + UDP_HEADER)..(length - packetOffset)
        ) {
            return Result(null, "INVALID_TOTAL")
        }
        if (packet[packetOffset + 9].toInt() and 0xff != UDP_PROTOCOL) {
            return Result(null, "NOT_UDP")
        }
        if (unsignedShort(packet, packetOffset + 6) and FRAGMENT_MASK != 0) {
            return Result(null, "FRAGMENTED")
        }
        if (!packet.copyOfRange(packetOffset + 16, packetOffset + 20).contentEquals(serviceAddress)) {
            return Result(null, "WRONG_ADDRESS")
        }
        val udpOffset = packetOffset + headerLength
        val destinationPort = unsignedShort(packet, udpOffset + 2)
        val udpLength = unsignedShort(packet, udpOffset + 4)
        if (udpLength !in UDP_HEADER..(totalLength - headerLength)) {
            return Result(null, "INVALID_UDP_LENGTH")
        }
        val requestPayload = packet.copyOfRange(
            udpOffset + UDP_HEADER,
            udpOffset + udpLength,
        )
        val payloadResult = responsePayload(destinationPort, requestPayload, kurdRoundTrip)
        requestPayload.fill(0)
        val responsePayload = payloadResult.response
            ?: return Result(null, payloadResult.disposition)
        val responseTotalLength = headerLength + UDP_HEADER + responsePayload.size
        val response = packet.copyOf(packetOffset + responseTotalLength).also { response ->
            responsePayload.copyInto(response, udpOffset + UDP_HEADER)
            responsePayload.fill(0)
            swap(response, packetOffset + 12, packetOffset + 16, 4)
            swap(response, udpOffset, udpOffset + 2, 2)
            response[packetOffset + 2] = (responseTotalLength ushr 8).toByte()
            response[packetOffset + 3] = responseTotalLength.toByte()
            response[packetOffset + 8] = 64
            response[packetOffset + 10] = 0
            response[packetOffset + 11] = 0
            val checksum = checksum(response, packetOffset, headerLength)
            response[packetOffset + 10] = (checksum ushr 8).toByte()
            response[packetOffset + 11] = checksum.toByte()
            val responseUdpLength = UDP_HEADER + responseTotalLength - headerLength - UDP_HEADER
            response[udpOffset + 4] = (responseUdpLength ushr 8).toByte()
            response[udpOffset + 5] = responseUdpLength.toByte()
            response[udpOffset + 6] = 0
            response[udpOffset + 7] = 0
            val udpChecksum = udpChecksum(
                response,
                packetOffset,
                udpOffset,
                responseUdpLength,
            )
            response[udpOffset + 6] = (udpChecksum ushr 8).toByte()
            response[udpOffset + 7] = udpChecksum.toByte()
        }
        return Result(response, payloadResult.disposition)
    }

    private fun unsignedShort(value: ByteArray, offset: Int): Int =
        ((value[offset].toInt() and 0xff) shl 8) or
            (value[offset + 1].toInt() and 0xff)

    private fun responsePayload(
        destinationPort: Int,
        request: ByteArray,
        kurdRoundTrip: (ByteArray) -> ByteArray?,
    ): PayloadResult =
        when (destinationPort) {
            ECHO_PORT -> {
                val protected = kurdRoundTrip(request)
                    ?: return PayloadResult(null, "KURD_TRANSPORT_REJECTED")
                PayloadResult(protected, "KURD_RELAY_REPLIED")
            }
            DNS_PORT -> {
                val protected = kurdRoundTrip(request)
                    ?: return PayloadResult(null, "KURD_TRANSPORT_REJECTED")
                val result = try {
                    DeterministicDnsResponder.reply(protected)
                } finally {
                    protected.fill(0)
                }
                PayloadResult(result.payload, "KURD_${result.disposition}")
            }
            else -> PayloadResult(null, "WRONG_PORT")
        }

    private data class PayloadResult(
        val response: ByteArray?,
        val disposition: String,
    )

    private fun swap(value: ByteArray, first: Int, second: Int, count: Int) {
        repeat(count) { index ->
            val temporary = value[first + index]
            value[first + index] = value[second + index]
            value[second + index] = temporary
        }
    }

    private fun checksum(value: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += unsignedShort(value, index).toLong()
            index += 2
        }
        if (index < end) sum += (value[index].toInt() and 0xff).toLong() shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun udpChecksum(
        value: ByteArray,
        ipOffset: Int,
        udpOffset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        fun addWord(high: Int, low: Int) {
            sum += ((high and 0xff) shl 8 or (low and 0xff)).toLong()
        }
        for (index in (ipOffset + 12) until (ipOffset + 20) step 2) {
            addWord(value[index].toInt(), value[index + 1].toInt())
        }
        addWord(0, UDP_PROTOCOL)
        addWord(length ushr 8, length)
        var index = udpOffset
        val end = udpOffset + length
        while (index + 1 < end) {
            addWord(value[index].toInt(), value[index + 1].toInt())
            index += 2
        }
        if (index < end) addWord(value[index].toInt(), 0)
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        val result = sum.inv().toInt() and 0xffff
        return if (result == 0) 0xffff else result
    }

    private const val IPV4_MINIMUM = 20
    private const val UDP_HEADER = 8
    private const val UDP_PROTOCOL = 17
    private const val ECHO_PORT = 5353
    private const val DNS_PORT = 53
    private const val FRAGMENT_MASK = 0x3fff
    private const val TUN_PI_HEADER = 4
}

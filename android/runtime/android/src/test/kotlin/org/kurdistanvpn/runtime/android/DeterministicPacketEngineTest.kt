// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeterministicPacketEngineTest {
    @Test
    fun repliesOnlyToBoundedIpv4UdpEchoService() {
        val request = packet(destinationPort = 5353)
        val response = requireNotNull(DeterministicPacketEngine.reply(request, request.size).response)

        assertArrayEquals(byteArrayOf(198.toByte(), 18, 0, 53), response.copyOfRange(12, 16))
        assertArrayEquals(byteArrayOf(198.toByte(), 18, 0, 2), response.copyOfRange(16, 20))
        assertEquals(5353, unsignedShort(response, 20))
        assertEquals(41234, unsignedShort(response, 22))
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), response.copyOfRange(28, 32))
    }

    @Test
    fun rejectsWrongPortAndFragmentedPackets() {
        assertNull(DeterministicPacketEngine.reply(packet(destinationPort = 53), 32).response)
        val fragmented = packet(destinationPort = 5353).apply { this[6] = 0x20 }
        assertNull(DeterministicPacketEngine.reply(fragmented, fragmented.size).response)
    }

    @Test
    fun answersTheBoundedSyntheticDnsService() {
        val request = packet(destinationPort = 53, payload = dnsQuery())
        val result = DeterministicPacketEngine.reply(request, request.size)
        val response = requireNotNull(result.response)

        assertEquals("KURD_DNS_REPLIED", result.disposition)
        assertEquals(1, unsignedShort(response, 34))
        assertArrayEquals(
            byteArrayOf(198.toByte(), 18, 0, 42),
            response.copyOfRange(response.size - 4, response.size),
        )
    }

    @Test
    fun failsClosedWhenKurdTransportRejectsTheFlow() {
        val request = packet(destinationPort = 5353)
        val result = DeterministicPacketEngine.reply(request, request.size) { null }

        assertNull(result.response)
        assertEquals("KURD_TRANSPORT_REJECTED", result.disposition)
    }

    private fun packet(
        destinationPort: Int,
        payload: ByteArray = byteArrayOf(1, 2, 3, 4),
    ): ByteArray = ByteArray(28 + payload.size).apply {
        this[0] = 0x45
        this[2] = 0
        this[3] = size.toByte()
        this[8] = 64
        this[9] = 17
        byteArrayOf(198.toByte(), 18, 0, 2).copyInto(this, 12)
        byteArrayOf(198.toByte(), 18, 0, 53).copyInto(this, 16)
        this[20] = (41234 ushr 8).toByte()
        this[21] = 41234.toByte()
        this[22] = (destinationPort ushr 8).toByte()
        this[23] = destinationPort.toByte()
        this[24] = 0
        this[25] = (8 + payload.size).toByte()
        payload.copyInto(this, 28)
    }

    private fun dnsQuery(): ByteArray = byteArrayOf(
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x07, 'p'.code.toByte(), 'h'.code.toByte(), 'a'.code.toByte(),
        's'.code.toByte(), 'e'.code.toByte(), '1'.code.toByte(), '0'.code.toByte(),
        0x04, 't'.code.toByte(), 'e'.code.toByte(), 's'.code.toByte(), 't'.code.toByte(),
        0x00, 0x00, 0x01, 0x00, 0x01,
    )

    private fun unsignedShort(value: ByteArray, offset: Int): Int =
        ((value[offset].toInt() and 0xff) shl 8) or
            (value[offset + 1].toInt() and 0xff)
}

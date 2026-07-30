// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeterministicDnsResponderTest {
    @Test
    fun answersOnlyTheOwnedSyntheticName() {
        val result = DeterministicDnsResponder.reply(query("phase10", "test"))
        val response = requireNotNull(result.payload)

        assertEquals("DNS_REPLIED", result.disposition)
        assertEquals(1, unsignedShort(response, 6))
        assertArrayEquals(
            byteArrayOf(198.toByte(), 18, 0, 42),
            response.copyOfRange(response.size - 4, response.size),
        )
    }

    @Test
    fun rejectsUnownedCompressedOrTrailingQueries() {
        assertNull(DeterministicDnsResponder.reply(query("example", "test")).payload)
        assertNull(
            DeterministicDnsResponder.reply(
                query("phase10", "test").copyOf(query("phase10", "test").size + 1),
            ).payload,
        )
        val compressed = query("phase10", "test").apply {
            this[12] = 0xc0.toByte()
        }
        assertNull(DeterministicDnsResponder.reply(compressed).payload)
    }

    private fun query(vararg labels: String): ByteArray {
        val size = 12 + labels.sumOf { it.length + 1 } + 1 + 4
        return ByteArray(size).apply {
            this[0] = 0x12
            this[1] = 0x34
            this[2] = 0x01
            this[5] = 0x01
            var offset = 12
            labels.forEach { label ->
                this[offset++] = label.length.toByte()
                label.toByteArray(Charsets.US_ASCII).copyInto(this, offset)
                offset += label.length
            }
            this[offset++] = 0
            this[offset++] = 0
            this[offset++] = 1
            this[offset++] = 0
            this[offset] = 1
        }
    }

    private fun unsignedShort(value: ByteArray, offset: Int): Int =
        ((value[offset].toInt() and 0xff) shl 8) or
            (value[offset + 1].toInt() and 0xff)
}

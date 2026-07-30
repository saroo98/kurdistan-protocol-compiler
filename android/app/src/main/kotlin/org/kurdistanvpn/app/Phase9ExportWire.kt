// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import java.nio.ByteBuffer
import java.nio.ByteOrder

internal object Phase9ExportWire {
    fun diagnosticRequest(profileCount: Int): ByteArray {
        return ByteBuffer.allocate(22).order(ByteOrder.BIG_ENDIAN).apply {
            put("KDR1".encodeToByteArray())
            putLong(1)
            put(3.toByte())
            put(1.toByte()) // contract versions
            put(1.toByte()) // supported
            put(0.toByte()) // counts are forbidden for this category
            put(2.toByte()) // profile lifecycle
            put((if (profileCount == 0) 4 else 5).toByte()) // absent or admitted
            put(0.toByte()) // counts are forbidden for this category
            put(5.toByte()) // runtime disposition
            put(14.toByte()) // unavailable
            put(0.toByte()) // counts are forbidden for this category
        }.array()
    }

    fun diagnosticPreview(encoded: ByteArray): Triple<Int, String, String> {
        require(encoded.size == 15)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(reader::get).toString(Charsets.US_ASCII) == "KDP1")
        reader.long
        val categoryCount = Integer.bitCount(reader.get().toInt() and 0xff)
        val count = when (reader.get().toInt() and 0xff) {
            1 -> "zero"
            2 -> "one"
            3 -> "few"
            4 -> "many"
            else -> error("invalid diagnostic count")
        }
        val size = when (reader.get().toInt() and 0xff) {
            1 -> "small"
            2 -> "maximum"
            else -> error("invalid diagnostic size")
        }
        return Triple(categoryCount, count, size)
    }

    fun backupPreview(encoded: ByteArray): Pair<Int, Int> {
        require(encoded.size == 16)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(reader::get).toString(Charsets.US_ASCII) == "KBV1")
        val total = reader.short.toInt() and 0xffff
        val nativeProfiles = reader.short.toInt() and 0xffff
        repeat(4) { reader.short }
        require(!reader.hasRemaining())
        return total to nativeProfiles
    }
}

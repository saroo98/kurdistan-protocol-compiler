// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.runtime.api.VpnRuntimeState

internal object Phase9ExportWire {
    fun diagnosticRequest(profileCount: Int, events: List<DiagnosticEvent> = emptyList()): ByteArray {
        val failures = events.asSequence()
            .filter { it.level == DiagnosticLogLevel.ERROR || it.level == DiagnosticLogLevel.WARNING }
            .mapNotNull(::failureValue)
            .groupingBy { it }
            .eachCount()
            .toSortedMap()
        val entryCount = 3 + failures.size
        return ByteBuffer.allocate(13 + entryCount * 3).order(ByteOrder.BIG_ENDIAN).apply {
            put("KDR1".encodeToByteArray())
            putLong(1)
            put(entryCount.toByte())
            put(1.toByte()) // contract versions
            put(1.toByte()) // supported
            put(0.toByte()) // counts are forbidden for this category
            put(2.toByte()) // profile lifecycle
            put((if (profileCount == 0) 4 else 5).toByte()) // absent or admitted
            put(0.toByte()) // counts are forbidden for this category
            put(5.toByte()) // runtime disposition
            put(14.toByte()) // unavailable
            put(0.toByte()) // counts are forbidden for this category
            failures.forEach { (value, count) ->
                put(6.toByte()) // failure summary
                put(value.toByte())
                put(countBucket(count).toByte())
            }
        }.array()
    }

    private fun failureValue(event: DiagnosticEvent): Int? {
        val category = event.category.uppercase()
        return when {
            "PERMISSION" in category -> 15
            event.component == DiagnosticComponent.STORAGE || "KEY_" in category || "STORAGE" in category -> 16
            "ROUT" in category -> 17
            "DNS" in category -> 18
            "KILL" in category -> 19
            event.component == DiagnosticComponent.PROFILE || "PROFILE" in category || "IMPORT" in category -> 20
            "FALLBACK" in category -> 21
            "RELAY" in category -> 22
            "INCOMPATIBLE" in category || "ABI" in category || "AUTHORITY" in category -> 23
            "MALFORMED" in category || "INVALID_INPUT" in category -> 24
            else -> null
        }
    }

    private fun countBucket(count: Int): Int = when {
        count <= 0 -> 1
        count == 1 -> 2
        count <= 8 -> 3
        else -> 4
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
        val reader = ByteBuffer.wrap(encoded.copyOf()).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(4).also(reader::get).toString(Charsets.US_ASCII)
        require(magic == "KBV1" || magic == "KBV2")
        val total = reader.short.toInt() and 0xffff
        val kindCounts = IntArray(5) { reader.short.toInt() and 0xffff }
        require(total <= 128 && kindCounts.sum() == total)
        require(!reader.hasRemaining())
        return total to kindCounts[0]
    }
}

internal data class RuntimeStatusDecision(
    val accept: Boolean,
    val bindRequestId: String? = null,
    val consumeQuery: Boolean = false,
)

internal fun selectRuntimeStatus(
    expectedRequestId: String?,
    pendingQueryId: String?,
    incomingRequestId: String?,
    incomingQueryId: String?,
): RuntimeStatusDecision {
    if (expectedRequestId != null) {
        return RuntimeStatusDecision(accept = expectedRequestId == incomingRequestId)
    }
    if (pendingQueryId == null || incomingQueryId != pendingQueryId) {
        return RuntimeStatusDecision(accept = false)
    }
    return RuntimeStatusDecision(
        accept = true,
        bindRequestId = incomingRequestId,
        consumeQuery = true,
    )
}

internal fun activeRequestIdAfterRuntimeStatus(
    activeRequestId: String?,
    incomingRequestId: String?,
    state: VpnRuntimeState,
): String? =
    if (
        state == VpnRuntimeState.IDLE &&
        activeRequestId != null &&
        activeRequestId == incomingRequestId
    ) {
        null
    } else {
        activeRequestId
    }

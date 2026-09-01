// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel

private const val DIAGNOSTIC_MAGIC = 0x4B444531
private const val DIAGNOSTIC_RECORD_ID = "diagnostic-events-current"
private const val MAX_DIAGNOSTIC_EVENTS = 200
private const val MAX_CATEGORY_BYTES = 64
private const val MAX_ALIAS_BYTES = 32

class EncryptedDiagnosticEventStore private constructor(
    private val blobs: SecureBlobReadAccess,
    private val writer: SecureBlobAccess?,
) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)

    companion object {
        /** No cast or later composition can upgrade this instance to a writer. */
        fun readOnly(blobs: SecureBlobReadAccess): EncryptedDiagnosticEventStore = EncryptedDiagnosticEventStore(blobs, null)
    }

    private fun writes(): SecureBlobAccess = checkNotNull(writer) { "READ_ONLY_DIAGNOSTIC_VIEW" }

    fun load(): List<DiagnosticEvent> {
        if (!blobs.exists(DIAGNOSTIC_RECORD_ID, SecureDataClass.DIAGNOSTIC_EVENTS)) return emptyList()
        val encoded = blobs.reopen(DIAGNOSTIC_RECORD_ID, SecureDataClass.DIAGNOSTIC_EVENTS)
        return try {
            decode(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    fun save(events: List<DiagnosticEvent>) {
        val writable = writes()
        require(events.size <= MAX_DIAGNOSTIC_EVENTS) { "TOO_MANY_DIAGNOSTIC_EVENTS" }
        val normalized = events.sortedBy { it.sequence }
        require(normalized.zipWithNext().all { (first, second) -> second.sequence > first.sequence }) {
            "NON_MONOTONIC_DIAGNOSTIC_SEQUENCE"
        }
        val size = 4 + 2 + normalized.fold(0) { total, event ->
            val category = event.category.encodeToByteArray()
            val alias = event.sessionAlias?.encodeToByteArray() ?: ByteArray(0)
            total + 8 + 8 + 1 + 1 + 1 + category.size + 1 + alias.size + 1 + if (event.metricValue == null) 0 else 8
        }
        val encoded = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(DIAGNOSTIC_MAGIC)
            putShort(normalized.size.toShort())
            normalized.forEach { event ->
                val category = event.category.encodeToByteArray()
                val alias = event.sessionAlias?.encodeToByteArray() ?: ByteArray(0)
                require(category.size in 1..MAX_CATEGORY_BYTES)
                require(alias.size <= MAX_ALIAS_BYTES)
                putLong(event.sequence)
                putLong(event.coarseEpochMinutes)
                put(event.level.ordinal.toByte())
                put(event.component.ordinal.toByte())
                put(category.size.toByte())
                put(category)
                put(alias.size.toByte())
                put(alias)
                put(if (event.metricValue == null) 0 else 1)
                event.metricValue?.let { putLong(it) }
                category.fill(0)
                alias.fill(0)
            }
        }.array()
        try {
            writable.stage(DIAGNOSTIC_RECORD_ID, SecureDataClass.DIAGNOSTIC_EVENTS, encoded)
        } finally {
            encoded.fill(0)
        }
    }

    fun clear() {
        writes().delete(DIAGNOSTIC_RECORD_ID, SecureDataClass.DIAGNOSTIC_EVENTS)
    }

    private fun decode(encoded: ByteArray): List<DiagnosticEvent> {
        require(encoded.size >= 6) { "TRUNCATED_DIAGNOSTIC_STORE" }
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(input.int == DIAGNOSTIC_MAGIC) { "INVALID_DIAGNOSTIC_MAGIC" }
        val count = input.short.toInt() and 0xffff
        require(count <= MAX_DIAGNOSTIC_EVENTS) { "TOO_MANY_DIAGNOSTIC_EVENTS" }
        val result = ArrayList<DiagnosticEvent>(count)
        repeat(count) {
            require(input.remaining() >= 21) { "TRUNCATED_DIAGNOSTIC_EVENT" }
            val sequence = input.long
            val timestamp = input.long
            val level = DiagnosticLogLevel.entries.getOrNull(input.get().toInt() and 0xff)
                ?: throw IllegalArgumentException("INVALID_DIAGNOSTIC_LEVEL")
            val component = DiagnosticComponent.entries.getOrNull(input.get().toInt() and 0xff)
                ?: throw IllegalArgumentException("INVALID_DIAGNOSTIC_COMPONENT")
            val category = readBoundedString(input, MAX_CATEGORY_BYTES, false)
            val alias = readBoundedString(input, MAX_ALIAS_BYTES, true).ifEmpty { null }
            require(input.hasRemaining()) { "TRUNCATED_DIAGNOSTIC_METRIC" }
            val hasMetric = input.get().toInt() and 0xff
            require(hasMetric in 0..1)
            val metric = if (hasMetric == 1) {
                require(input.remaining() >= 8)
                input.long
            } else null
            result += DiagnosticEvent(sequence, level, component, category, timestamp, alias, metric)
        }
        require(!input.hasRemaining()) { "TRAILING_DIAGNOSTIC_DATA" }
        require(result.zipWithNext().all { (first, second) -> second.sequence > first.sequence }) {
            "NON_MONOTONIC_DIAGNOSTIC_SEQUENCE"
        }
        return result
    }

    private fun readBoundedString(input: ByteBuffer, maximum: Int, emptyAllowed: Boolean): String {
        require(input.hasRemaining())
        val length = input.get().toInt() and 0xff
        require(length <= maximum && (emptyAllowed || length > 0) && input.remaining() >= length)
        val bytes = ByteArray(length)
        input.get(bytes)
        return try {
            bytes.decodeToString(throwOnInvalidSequence = true)
        } finally {
            bytes.fill(0)
        }
    }
}

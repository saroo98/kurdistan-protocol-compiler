// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Call-scoped views. Syntax is not authenticity, currentness or runtime authority. */
class RuntimeCapturePartsV1(val verifyRequest: ByteBuffer, val activationRecord: ByteBuffer,
    val recipientRequest: ByteBuffer, val recipientPrivate: ByteBuffer, val settings: ByteBuffer) {
    internal fun spans() = arrayOf(verifyRequest, activationRecord, recipientRequest, recipientPrivate, settings)
    override fun toString() = "RuntimeCapturePartsV1(redacted)"
}

/** One owned encoding; no raw array or borrowed view escapes. */
class RuntimeCaptureSnapshotV1 internal constructor(private var owned: ByteArray?, private val offsets: IntArray) : Closeable {
    val length: Int get() = synchronized(this) { requireNotNull(owned) { "capture closed" }.size }
    /** Exact metadata only, without allocating or exposing a borrowed capture view. */
    @Synchronized fun copySizesInto(output: IntArray) {
        requireNotNull(owned) { "capture closed" }
        require(output.size == 5) { "capture size output rejected" }
        for (index in 0..4) output[index] = offsets[index + 1] - offsets[index]
    }
    @Synchronized private fun copy(index: Int, output: ByteBuffer): Int {
        val bytes = requireNotNull(owned) { "capture closed" }
        val count = offsets[index + 1] - offsets[index]
        require(!output.isReadOnly && output.remaining() >= count) { "capture output rejected" }
        output.duplicate().put(bytes, offsets[index], count)
        return count
    }
    fun copyVerifyRequestTo(output: ByteBuffer) = copy(0, output)
    fun copyActivationRecordTo(output: ByteBuffer) = copy(1, output)
    fun copyRecipientRequestTo(output: ByteBuffer) = copy(2, output)
    fun copyRecipientPrivateTo(output: ByteBuffer) = copy(3, output)
    fun copySettingsTo(output: ByteBuffer) = copy(4, output)
    @Synchronized override fun close() { owned?.fill(0); owned = null; offsets.fill(0) }
    override fun toString() = "RuntimeCaptureSnapshotV1(redacted)"
}

object RuntimeCaptureCodecV1 {
    const val MAX_BYTES = 2_721_575
    private val maxima = intArrayOf(1_405_996, 1_118_299, 512, 128, 196_608)

    fun encode(parts: RuntimeCapturePartsV1, output: ByteBuffer): Int {
        val spans = parts.spans().map { it.duplicate() }
        val lengths = IntArray(5) { spans[it].remaining() }
        val offsets = offsets(lengths)
        val total = offsets[5]
        require(!output.isReadOnly && output.remaining() >= total) { "capture output rejected" }
        // Preflight is complete before any write. Input views must remain unchanged
        // for this synchronous call and must not alias the output span.
        val writer = output.duplicate().order(ByteOrder.BIG_ENDIAN)
        writer.putInt(0x4b435431).put(1).put(0).putShort(0).putInt(total)
        writer.putInt(lengths[0]).putInt(lengths[1]).putShort(lengths[2].toShort()).putShort(lengths[3].toShort())
        writer.putInt(lengths[4]).putInt(0)
        spans.forEach { writer.put(it) }
        return total
    }

    fun decode(input: ByteBuffer): RuntimeCaptureSnapshotV1 {
        require(input.remaining() in 37..MAX_BYTES) { "capture size rejected" }
        val reader = input.duplicate().order(ByteOrder.BIG_ENDIAN)
        require(reader.int == 0x4b435431 && reader.get() == 1.toByte() && reader.get() == 0.toByte() && reader.short == 0.toShort()) { "capture header rejected" }
        val total = reader.int
        require(total == input.remaining()) { "capture length rejected" }
        val lengths = intArrayOf(reader.int, reader.int, reader.short.toInt() and 65535, reader.short.toInt() and 65535, reader.int)
        require(reader.int == 0) { "capture reserved rejected" }
        val offsets = offsets(lengths)
        require(offsets[5] == total) { "capture lengths rejected" }
        var owned: ByteArray? = ByteArray(total)
        return try {
            input.duplicate().get(requireNotNull(owned))
            RuntimeCaptureSnapshotV1(owned, offsets).also { owned = null }
        } finally { owned?.fill(0) }
    }

    private fun offsets(lengths: IntArray): IntArray {
        val offsets = IntArray(6)
        offsets[0] = 32
        for (i in 0..4) {
            require(lengths[i] in 1..maxima[i]) { "capture row rejected" }
            require(lengths[i] <= MAX_BYTES - offsets[i]) { "capture sum rejected" }
            offsets[i + 1] = offsets[i] + lengths[i]
        }
        return offsets
    }
}

/** Fixed successor kind, preserving the complete existing descriptor binding. */
data class RuntimeProductionAuthorityRequestV1(val request: RuntimeAuthorityRequest) {
    val captureFormat: Int get() = 1
    fun sameArm(other: RuntimeProductionAuthorityRequestV1) = request.sameArm(other.request)
    override fun toString() = "RuntimeProductionAuthorityRequestV1(redacted)"
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.ProfileTrust
import org.kurdistanvpn.core.model.RedactedProfilePreview

private const val PREVIEW_MAGIC = 0x4B505231

internal object ProfilePreviewCodec {
    fun encode(preview: RedactedProfilePreview, alias: String): ByteArray {
        val fields = listOf(
            preview.artifactClass,
            preview.audienceClass,
            preview.contentFingerprint,
            preview.lineageFingerprint,
            alias,
        ).map {
            it.encodeToByteArray().also { bytes -> require(bytes.isNotEmpty() && bytes.size <= 255) }
        }
        val size = 4 + fields.sumOf { 1 + it.size } + 1 + 8 + 8
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(PREVIEW_MAGIC)
            fields.forEach { bytes ->
                put(bytes.size.toByte())
                put(bytes)
            }
            put(if (preview.sealed) 1 else 0)
            putLong(preview.generation.toLong())
            putLong(preview.validUntilEpochSeconds)
        }.array()
    }

    fun decode(encoded: ByteArray): Pair<RedactedProfilePreview, String> {
        require(encoded.size in 4..2048)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(reader.remaining() >= 4)
        require(reader.int == PREVIEW_MAGIC)
        fun field(): String {
            require(reader.hasRemaining())
            val length = reader.get().toInt() and 0xff
            require(length in 1..reader.remaining())
            return ByteArray(length).also(reader::get).toString(Charsets.UTF_8)
        }
        val artifactClass = field()
        val audienceClass = field()
        val fingerprint = field()
        val lineageFingerprint = field()
        val alias = field()
        require(reader.remaining() == 17)
        val sealedWire = reader.get().toInt()
        require(sealedWire == 0 || sealedWire == 1)
        val generation = reader.long.toULong()
        require(generation > 0u)
        val validUntil = reader.long
        require(validUntil > 0)
        val preview = RedactedProfilePreview(
            artifactClass = artifactClass,
            audienceClass = audienceClass,
            contentFingerprint = fingerprint,
            lineageFingerprint = lineageFingerprint,
            sealed = sealedWire == 1,
            generation = generation,
            validUntilEpochSeconds = validUntil,
        )
        require(!reader.hasRemaining())
        return preview to alias
    }

    fun summary(
        localRecordId: String,
        preview: RedactedProfilePreview,
        alias: String,
        productionTrust: Boolean,
    ): ProfileSummary =
        ProfileSummary(
            localRecordId = localRecordId,
            displayAlias = alias,
            trust = if (productionTrust) {
                ProfileTrust.VERIFIED_PRODUCTION
            } else {
                ProfileTrust.VERIFIED_NONPRODUCTION
            },
            generation = preview.generation,
            expiresAtEpochSeconds = preview.validUntilEpochSeconds,
        )
}

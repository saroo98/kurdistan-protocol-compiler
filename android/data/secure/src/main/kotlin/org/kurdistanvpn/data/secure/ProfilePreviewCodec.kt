// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.ProfileTrust
import org.kurdistanvpn.core.model.RedactedProfilePreview

private const val PREVIEW_MAGIC_V1 = 0x4B505231
private const val PREVIEW_MAGIC_V2 = 0x4B505232

internal object ProfilePreviewCodec {
    fun encode(preview: RedactedProfilePreview, alias: String): ByteArray {
        val fields = listOf(
            preview.artifactClass,
            preview.audienceClass,
            preview.contentFingerprint,
            preview.lineageFingerprint,
            preview.deploymentFingerprint,
            preview.relayEndpointSummary,
            preview.authorityScope,
            preview.updateLocation,
            alias,
        ).map {
            it.encodeToByteArray().also { bytes -> require(bytes.size <= 255) }
        }
        require(fields.take(4).all { it.isNotEmpty() } && fields.last().isNotEmpty())
        val size = 4 + fields.sumOf { 1 + it.size } + 1 + 8 + 8
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(PREVIEW_MAGIC_V2)
            fields.forEach { bytes ->
                put(bytes.size.toByte())
                put(bytes)
            }
            var flags = 0
            if (preview.sealed) flags = flags or 1
            if (preview.ownerControlled) flags = flags or 2
            if (preview.updatesEnabled) flags = flags or 4
            put(flags.toByte())
            putLong(preview.generation.toLong())
            putLong(preview.validUntilEpochSeconds)
        }.array()
    }

    fun decode(encoded: ByteArray): Pair<RedactedProfilePreview, String> {
        require(encoded.size in 4..2048)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(reader.remaining() >= 4)
        val magic = reader.int
        require(magic == PREVIEW_MAGIC_V1 || magic == PREVIEW_MAGIC_V2)
        fun field(): String {
            require(reader.hasRemaining())
            val length = reader.get().toInt() and 0xff
            require(length <= reader.remaining())
            return ByteArray(length).also(reader::get).toString(Charsets.UTF_8)
        }
        val artifactClass = field()
        val audienceClass = field()
        val fingerprint = field()
        val lineageFingerprint = field()
        require(artifactClass.isNotEmpty() && audienceClass.isNotEmpty() && fingerprint.isNotEmpty() && lineageFingerprint.isNotEmpty())
        val deploymentFingerprint: String
        val relayEndpointSummary: String
        val authorityScope: String
        val updateLocation: String
        if (magic == PREVIEW_MAGIC_V2) {
            deploymentFingerprint = field()
            relayEndpointSummary = field()
            authorityScope = field()
            updateLocation = field()
        } else {
            deploymentFingerprint = ""
            relayEndpointSummary = ""
            authorityScope = ""
            updateLocation = ""
        }
        val alias = field()
        require(alias.isNotEmpty())
        require(reader.remaining() == 17)
        val flags = reader.get().toInt() and 0xff
        require(flags and 0xf8 == 0)
        val generation = reader.long.toULong()
        require(generation > 0u)
        val validUntil = reader.long
        require(validUntil > 0)
        val preview = RedactedProfilePreview(
            artifactClass = artifactClass,
            audienceClass = audienceClass,
            contentFingerprint = fingerprint,
            lineageFingerprint = lineageFingerprint,
            sealed = flags and 1 != 0,
            generation = generation,
            validUntilEpochSeconds = validUntil,
            deploymentFingerprint = deploymentFingerprint,
            relayEndpointSummary = relayEndpointSummary,
            authorityScope = authorityScope,
            updateLocation = updateLocation,
            ownerControlled = flags and 2 != 0,
            updatesEnabled = flags and 4 != 0,
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

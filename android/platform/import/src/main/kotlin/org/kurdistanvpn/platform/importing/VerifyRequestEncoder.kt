// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import java.nio.ByteBuffer
import java.nio.ByteOrder

const val MAX_ARTIFACT_BYTES = 1_052_762
const val MAX_QR_CHUNKS = 64
const val MAX_QR_CHUNK_CHARS = 4096
const val MAX_CLIPBOARD_CHARS = 262_144

enum class IngressKind(val wire: Int) {
    FILE(1),
    URI(2),
    CLIPBOARD(3),
    QR_CHUNKS(4),
}

enum class ArtifactClass(val wire: Int) {
    SIGNED_PUBLIC(1),
    PROVIDER_GROUP(2),
    DEVICE_RECIPIENT(3),
    ENCRYPTED_BACKUP(4),
}

data class ImportCandidate(
    val ingress: IngressKind,
    val artifactClass: ArtifactClass,
    val parts: List<ByteArray>,
)

object VerifyRequestEncoder {
    private const val MAGIC = 0x4B564931
    private const val HEADER_BYTES = 8

    fun encode(candidate: ImportCandidate): ByteArray {
        require(candidate.parts.isNotEmpty() && candidate.parts.size <= MAX_QR_CHUNKS)
        if (candidate.ingress != IngressKind.QR_CHUNKS) {
            require(candidate.parts.size == 1)
        }
        var size = HEADER_BYTES
        candidate.parts.forEach { part ->
            require(part.isNotEmpty() && part.size <= MAX_ARTIFACT_BYTES * 4 / 3 + 1)
            size = Math.addExact(size, 4 + part.size)
        }
        require(size <= 1_500_000)
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(MAGIC)
            put(candidate.ingress.wire.toByte())
            put(candidate.artifactClass.wire.toByte())
            putShort(candidate.parts.size.toShort())
            candidate.parts.forEach { part ->
                putInt(part.size)
                put(part)
            }
        }.array()
    }
}

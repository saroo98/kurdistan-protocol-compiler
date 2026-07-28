// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import android.os.SystemClock

class MultipartQrAccumulator(
    private val nowMillis: () -> Long = SystemClock::elapsedRealtime,
) {
    private var startedAt = 0L
    private var declaredTotal = 0
    private val parts = linkedMapOf<Int, String>()

    fun add(chunk: String, artifactClass: ArtifactClass): ImportCandidate? {
        expireIfNeeded()
        require(chunk.length in 1..MAX_QR_CHUNK_CHARS && chunk.startsWith("KURD1/"))
        val fields = chunk.removePrefix("KURD1/").split("/")
        require(fields.size == 3)
        val index = canonicalDecimal(fields[0])
        val total = canonicalDecimal(fields[1])
        require(total in 1..MAX_QR_CHUNKS && index in 1..total && fields[2].isNotEmpty())
        if (parts.isEmpty()) {
            startedAt = nowMillis()
            declaredTotal = total
        }
        require(total == declaredTotal)
        val existing = parts[index]
        require(existing == null || existing == chunk)
        parts[index] = chunk
        if (parts.size != declaredTotal) return null
        val ordered = (1..declaredTotal).map { checkNotNull(parts[it]).encodeToByteArray() }
        clear()
        return ImportCandidate(IngressKind.QR_CHUNKS, artifactClass, ordered)
    }

    fun onBackgrounded() = clear()
    fun cancel() = clear()

    private fun expireIfNeeded() {
        if (parts.isNotEmpty() && nowMillis() - startedAt >= EXPIRY_MILLIS) {
            clear()
        }
    }

    private fun clear() {
        parts.clear()
        startedAt = 0
        declaredTotal = 0
    }

    private fun canonicalDecimal(value: String): Int {
        require(value.isNotEmpty() && value.length <= 3)
        require(value.length == 1 || value.first() != '0')
        require(value.all(Char::isDigit))
        return value.toInt().also { require(it.toString() == value) }
    }

    private companion object {
        const val EXPIRY_MILLIS = 5 * 60 * 1000L
    }
}

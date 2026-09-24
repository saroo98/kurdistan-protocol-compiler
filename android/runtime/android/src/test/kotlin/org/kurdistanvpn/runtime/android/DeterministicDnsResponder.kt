// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

internal object DeterministicDnsResponder {
    private val expectedLabels = listOf("phase10", "test")
    private val answerAddress = byteArrayOf(198.toByte(), 18, 0, 42)

    data class Result(val payload: ByteArray?, val disposition: String)

    fun reply(request: ByteArray): Result {
        if (request.size !in DNS_HEADER..MAX_DNS_MESSAGE) {
            return Result(null, "DNS_INVALID_LENGTH")
        }
        if (
            unsignedShort(request, 4) != 1 ||
            unsignedShort(request, 6) != 0 ||
            unsignedShort(request, 8) != 0 ||
            unsignedShort(request, 10) != 0
        ) {
            return Result(null, "DNS_UNSUPPORTED_COUNTS")
        }
        if (request[2].toInt() and QR_MASK != 0) {
            return Result(null, "DNS_NOT_QUERY")
        }

        var offset = DNS_HEADER
        val labels = mutableListOf<String>()
        while (true) {
            if (offset >= request.size) return Result(null, "DNS_TRUNCATED_NAME")
            val labelLength = request[offset].toInt() and 0xff
            offset += 1
            if (labelLength == 0) break
            if (labelLength > MAX_LABEL || offset + labelLength > request.size) {
                return Result(null, "DNS_INVALID_NAME")
            }
            val label = request.copyOfRange(offset, offset + labelLength)
            if (label.any { byte -> byte.toInt() !in ASCII_MIN..ASCII_MAX }) {
                label.fill(0)
                return Result(null, "DNS_NON_ASCII_NAME")
            }
            labels += label.toString(Charsets.US_ASCII).lowercase()
            label.fill(0)
            offset += labelLength
        }
        if (labels != expectedLabels) return Result(null, "DNS_NAME_NOT_AUTHORIZED")
        if (offset + QUESTION_TAIL != request.size) {
            return Result(null, "DNS_TRAILING_DATA")
        }
        if (unsignedShort(request, offset) != TYPE_A) {
            return Result(null, "DNS_UNSUPPORTED_TYPE")
        }
        if (unsignedShort(request, offset + 2) != CLASS_IN) {
            return Result(null, "DNS_UNSUPPORTED_CLASS")
        }

        val response = request.copyOf(request.size + ANSWER_LENGTH)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[6] = 0
        response[7] = 1
        var answer = request.size
        response[answer++] = 0xc0.toByte()
        response[answer++] = 0x0c
        response[answer++] = 0
        response[answer++] = TYPE_A.toByte()
        response[answer++] = 0
        response[answer++] = CLASS_IN.toByte()
        response[answer++] = 0
        response[answer++] = 0
        response[answer++] = 0
        response[answer++] = TTL_SECONDS.toByte()
        response[answer++] = 0
        response[answer++] = answerAddress.size.toByte()
        answerAddress.copyInto(response, answer)
        return Result(response, "DNS_REPLIED")
    }

    private fun unsignedShort(value: ByteArray, offset: Int): Int =
        ((value[offset].toInt() and 0xff) shl 8) or
            (value[offset + 1].toInt() and 0xff)

    private const val DNS_HEADER = 12
    private const val MAX_DNS_MESSAGE = 512
    private const val MAX_LABEL = 63
    private const val QUESTION_TAIL = 4
    private const val ANSWER_LENGTH = 16
    private const val QR_MASK = 0x80
    private const val TYPE_A = 1
    private const val CLASS_IN = 1
    private const val TTL_SECONDS = 60
    private const val ASCII_MIN = 0x21
    private const val ASCII_MAX = 0x7e
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import java.nio.ByteBuffer

/** One-use pipe payload, never a status parcel. Both callers must clear owned byte arrays. */
object ProxyCredentialLeaseWire {
    const val SIZE = 72
    fun encode(secret: ByteArray, elapsedMillis: Long): ByteArray {
        require(elapsedMillis >= 0 && elapsedMillis <= Long.MAX_VALUE - 10000)
        validate(secret)
        return ByteBuffer.allocate(SIZE).putInt(0x4b504331).putLong(elapsedMillis).put(secret).array()
    }
    fun decode(encoded: ByteArray, elapsedMillis: Long): ByteArray {
        require(encoded.size == SIZE)
        val input = ByteBuffer.wrap(encoded)
        require(input.int == 0x4b504331)
        val created = input.long
        require(created >= 0 && elapsedMillis >= created && elapsedMillis - created < 10000)
        val secret = ByteArray(60)
        try { input.get(secret); validate(secret); return secret }
        catch (failure: Throwable) { secret.fill(0); throw failure }
    }
    private fun validate(secret: ByteArray) {
        require(secret.size == 60 && secret[16] == ':'.code.toByte())
        require(secret.indices.all { i -> i == 16 || secret[i].toInt().toChar().let {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
        } })
    }
}

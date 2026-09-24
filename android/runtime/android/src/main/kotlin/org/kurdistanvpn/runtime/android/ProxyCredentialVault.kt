// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.io.Closeable

/** Session memory only. The caller of copyForReveal owns and must clear its short-lived copy. */
internal class ProxyCredentialVault : Closeable {
    private val random = SecureRandom()
    private var username = secret(12)
    private var password = secret(32)
    private var closed = false

    private fun secret(size: Int): ByteArray {
        val raw = ByteArray(size)
        return try { random.nextBytes(raw); Base64.getUrlEncoder().withoutPadding().encode(raw) }
        finally { raw.fill(0) }
    }
    @Synchronized fun authenticate(user: ByteArray, pass: ByteArray): Boolean {
        val userMatches = MessageDigest.isEqual(username, user)
        val passMatches = MessageDigest.isEqual(password, pass)
        return userMatches and passMatches and !closed
    }
    @Synchronized fun copyForReveal(): ByteArray {
        check(!closed)
        return ByteArray(60).also {
            username.copyInto(it); it[16] = ':'.code.toByte(); password.copyInto(it, 17)
        }
    }
    @Synchronized fun rotate() {
        check(!closed)
        val nextUser = secret(12)
        val nextPassword = try { secret(32) } catch (failure: Throwable) { nextUser.fill(0); throw failure }
        username.fill(0); password.fill(0)
        username = nextUser; password = nextPassword
    }
    @Synchronized override fun close() { closed = true; username.fill(0); password.fill(0) }
    override fun toString() = "ProxyCredentialVault(redacted)"
}

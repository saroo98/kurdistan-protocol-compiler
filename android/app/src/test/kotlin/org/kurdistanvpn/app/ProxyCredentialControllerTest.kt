// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test

class ProxyCredentialControllerTest {
    @Test fun credentialPromptClearsSecretsButAllowsItsOneForegroundResult() {
        var result: ((Boolean) -> Unit)? = null
        var copied: CharArray? = null
        val controller = ProxyCredentialController({ 10L }, { result = it }, { it(credential()) },
            { it(true) }, { copied = it.copyOf() }, { })
        controller.reveal(); result!!(true)
        val displayed = checkNotNull(controller.visible.value)
        controller.copy()
        controller.background(preserveAuthorization = true)
        assertTrue(displayed.all { it == '\u0000' })
        assertNull(controller.visible.value)
        controller.foreground(); result!!(true)
        assertEquals(60, checkNotNull(copied).size)
        controller.reveal()
        controller.background()
        controller.foreground(); result!!(true)
        assertNull(controller.visible.value)
    }
    @Test fun eachAuthorizationResultIsConsumedOnlyOnce() {
        var result: ((Boolean) -> Unit)? = null
        var reads = 0
        var copies = 0
        var rotations = 0
        val controller = ProxyCredentialController({ 10L }, { result = it },
            { reads++; it(credential()) }, { rotations++; it(true) }, { copies++ }, { })
        controller.reveal()
        result!!(true); result!!(true)
        assertEquals(1, reads)
        controller.copy()
        result!!(true); result!!(true)
        assertEquals(1, copies)
        controller.rotate()
        result!!(true); result!!(true)
        assertEquals(1, rotations)
        controller.reveal()
        result!!(false); result!!(true)
        assertEquals(2, reads) // Copy obtains its own fresh one-use credential lease.
    }

    @Test fun authorizationAndForegroundGenerationGateEverySecretAndLateResponseIsWiped() {
        var authorized: ((Boolean) -> Unit)? = null
        var response: ((ByteArray?) -> Unit)? = null
        var reads = 0
        var clears = 0
        val controller = ProxyCredentialController({ 10L }, { authorized = it },
            { reads++; response = it }, { it(true) }, { }, { clears++ })
        controller.reveal()
        assertEquals(0, reads)
        authorized!!(false)
        assertNull(controller.visible.value)
        controller.reveal(); authorized!!(true)
        assertEquals(1, reads)
        controller.background()
        val bytes = credential()
        response!!(bytes)
        assertTrue(bytes.all { it == 0.toByte() })
        assertNull(controller.visible.value)
        controller.reveal(); authorized!!(true)
        assertEquals(1, reads)
        assertTrue(clears > 0)
    }

    @Test fun expiryRotationAndExplicitClearWipeOwnedCharactersAndClipboard() {
        var now = 100L
        var copied: CharArray? = null
        var clears = 0
        var rotations = 0
        val controller = ProxyCredentialController({ now }, { it(true) }, { it(credential()) },
            { rotations++; it(true) }, { copied = it.copyOf() }, { clears++ })
        controller.reveal()
        val first = checkNotNull(controller.visible.value)
        assertEquals(60, first.size)
        controller.copy()
        assertArrayEquals(first, copied)
        now += 60_000
        controller.expire()
        assertNull(controller.visible.value)
        assertTrue(first.all { it == '\u0000' })
        controller.reveal()
        val second = checkNotNull(controller.visible.value)
        controller.rotate()
        assertEquals(1, rotations)
        assertTrue(second.all { it == '\u0000' })
        assertNull(controller.visible.value)
        assertTrue(clears >= 2)
        controller.close()
        controller.reveal()
        assertNull(controller.visible.value)
    }

    private fun credential() = ByteArray(60) { if (it == 16) ':'.code.toByte() else 'A'.code.toByte() }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.net.Socket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ActiveVpnOwnerSocketProtectorRegistryTest {
    @Test
    fun protectionRegistrationIsLimitedToTheExactInternalApp() {
        assertTrue(
            internalQualificationSocketProtectionEnabled(
                packageName = "org.kurdistanvpn.app.internal",
                debuggable = true,
            ),
        )
        assertFalse(
            internalQualificationSocketProtectionEnabled(
                packageName = "org.kurdistanvpn.app.internal",
                debuggable = false,
            ),
        )
        assertFalse(
            internalQualificationSocketProtectionEnabled(
                packageName = "org.kurdistanvpn.app.debug",
                debuggable = true,
            ),
        )
        assertFalse(
            internalQualificationSocketProtectionEnabled(
                packageName = "example.org.kurdistanvpn.app.internal",
                debuggable = true,
            ),
        )
    }

    @Test
    fun absentProtectorFailsClosed() {
        val registry = ActiveVpnOwnerSocketProtectorRegistry()

        Socket().use { socket ->
            assertFalse(registry.protect(socket))
        }
    }

    @Test
    fun debuggableOwnerProtectsTheExactSocket() {
        val registry = ActiveVpnOwnerSocketProtectorRegistry()
        val owner = Any()
        val protected = mutableListOf<Socket>()
        registry.register(owner, debuggable = true) { socket ->
            protected += socket
            true
        }

        Socket().use { socket ->
            assertTrue(registry.protect(socket))
            assertEquals(listOf(socket), protected)
        }
    }

    @Test
    fun nonDebuggableOwnerCannotExposeProtection() {
        val registry = ActiveVpnOwnerSocketProtectorRegistry()
        registry.register(Any(), debuggable = false) { true }

        Socket().use { socket ->
            assertFalse(registry.protect(socket))
        }
    }

    @Test
    fun protectorFailureAndExceptionFailClosed() {
        val registry = ActiveVpnOwnerSocketProtectorRegistry()
        val owner = Any()
        registry.register(owner, debuggable = true) { false }
        Socket().use { socket -> assertFalse(registry.protect(socket)) }

        registry.register(owner, debuggable = true) { error("synthetic protect failure") }
        Socket().use { socket -> assertFalse(registry.protect(socket)) }
    }

    @Test
    fun staleOwnerCannotClearANewerServiceRegistration() {
        val registry = ActiveVpnOwnerSocketProtectorRegistry()
        val staleOwner = Any()
        val activeOwner = Any()
        registry.register(staleOwner, debuggable = true) { false }
        registry.register(activeOwner, debuggable = true) { true }

        registry.unregister(staleOwner)
        Socket().use { socket -> assertTrue(registry.protect(socket)) }

        registry.unregister(activeOwner)
        Socket().use { socket -> assertFalse(registry.protect(socket)) }
    }
}

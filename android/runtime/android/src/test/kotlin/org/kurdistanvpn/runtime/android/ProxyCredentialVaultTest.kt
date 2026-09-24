// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test

class ProxyCredentialVaultTest {
    @Test fun credentialsAreSessionLocalRotateAndBecomeUnusableAfterClose() {
        val vault = ProxyCredentialVault()
        val first = vault.copyForReveal()
        val second = ProxyCredentialVault().use { it.copyForReveal() }
        try {
            assertEquals(60, first.size) // 16 base64url bytes, colon, 43 base64url bytes.
            assertFalse(first.contentEquals(second))
            val username = first.copyOfRange(0, 16)
            val password = first.copyOfRange(17, 60)
            try {
                assertTrue(vault.authenticate(username, password))
                assertFalse(vault.authenticate(username, password.copyOf().apply { this[0] = 0 }))
                vault.rotate()
                assertFalse(vault.authenticate(username, password))
                vault.close(); vault.close()
                assertFalse(vault.authenticate(username, password))
                assertThrows(IllegalStateException::class.java) { vault.copyForReveal() }
                assertThrows(IllegalStateException::class.java) { vault.rotate() }
            } finally { username.fill(0); password.fill(0) }
        } finally { first.fill(0); second.fill(0); vault.close() }
    }
}

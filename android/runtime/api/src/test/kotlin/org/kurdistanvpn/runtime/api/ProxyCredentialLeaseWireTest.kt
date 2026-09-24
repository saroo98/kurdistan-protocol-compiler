// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

import org.junit.Assert.*
import org.junit.Test

class ProxyCredentialLeaseWireTest {
    @Test fun credentialsRequireExactShortLivedEnvelopeAndAreNotDisplayData() {
        val secret = ByteArray(60) { 'x'.code.toByte() }.also { it[16] = ':'.code.toByte() }
        val encoded = ProxyCredentialLeaseWire.encode(secret, 1000)
        try {
            assertArrayEquals(secret, ProxyCredentialLeaseWire.decode(encoded, 1001))
            assertThrows(IllegalArgumentException::class.java) { ProxyCredentialLeaseWire.decode(encoded, 11000) }
            assertThrows(IllegalArgumentException::class.java) { ProxyCredentialLeaseWire.decode(encoded, 999) }
            for (size in 0 until encoded.size) assertThrows(IllegalArgumentException::class.java) {
                ProxyCredentialLeaseWire.decode(encoded.copyOf(size), 1001)
            }
            assertThrows(IllegalArgumentException::class.java) { ProxyCredentialLeaseWire.decode(encoded + 0, 1001) }
            secret[0] = 0
            assertThrows(IllegalArgumentException::class.java) { ProxyCredentialLeaseWire.encode(secret, 1000) }
        } finally { secret.fill(0); encoded.fill(0) }
    }
}

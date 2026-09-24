// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.*
import java.util.Base64
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.NativeProxyAddressKind

class LocalProxyHandshakeTest {
    @Test fun socksRequiresPasswordAndPassesDomainWithoutResolvingIt(): Unit = ProxyCredentialVault().use { vault ->
        val credentials = vault.copyForReveal()
        try {
            val auth = byteArrayOf(5, 1, 2, 1, 16) + credentials.copyOfRange(0, 16) + byteArrayOf(43) + credentials.copyOfRange(17, 60)
            val target = "example.com".toByteArray()
            val request = auth + byteArrayOf(5, 1, 0, 3, 11) + target + byteArrayOf(1, -69)
            val output = ByteArrayOutputStream()
            val parsed = LocalProxyHandshake.socks(ByteArrayInputStream(request), output, vault)
            assertEquals(NativeProxyAddressKind.DOMAIN, parsed.kind)
            assertArrayEquals(target, parsed.address)
            assertEquals(443, parsed.port)
            assertArrayEquals(byteArrayOf(5, 2, 1, 0), output.toByteArray())
            for (size in 0 until request.size) assertThrows(IOException::class.java) {
                LocalProxyHandshake.socks(ByteArrayInputStream(request.copyOf(size)), ByteArrayOutputStream(), vault)
            }
            assertThrows(IOException::class.java) {
                LocalProxyHandshake.socks(ByteArrayInputStream(byteArrayOf(5, 1, 0)), ByteArrayOutputStream(), vault)
            }
            for (tail in listOf(
                byteArrayOf(5, 2, 0, 1, 127, 0, 0, 1, 1, -69), // BIND, not CONNECT
                byteArrayOf(5, 3, 0, 1, 127, 0, 0, 1, 1, -69), // UDP association
                byteArrayOf(5, 1, 1, 1, 127, 0, 0, 1, 1, -69), // reserved byte
                byteArrayOf(5, 1, 0, 3, 0, 1, -69),
                byteArrayOf(5, 1, 0, 3, 2, -64, -81, 1, -69), // invalid UTF-8
                byteArrayOf(5, 1, 0, 3, 3, 97, 0, 98, 1, -69),
                byteArrayOf(5, 1, 0, 3, -1) + ByteArray(255) { 97 } + byteArrayOf(1, -69),
                byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, 0, 0))) {
                assertThrows(IOException::class.java) {
                    LocalProxyHandshake.socks(ByteArrayInputStream(auth + tail), ByteArrayOutputStream(), vault)
                }
            }
        } finally { credentials.fill(0) }
    }

    @Test fun httpRequiresOneBasicCredentialAndRejectsForwardingAndHeaderAmbiguity(): Unit = ProxyCredentialVault().use { vault ->
        val credentials = vault.copyForReveal()
        val basic = Base64.getEncoder().encode(credentials)
        try {
            val prefix = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic ".toByteArray()
            val request = prefix + basic + "\r\n\r\n".toByteArray()
            val parsed = LocalProxyHandshake.http(ByteArrayInputStream(request), vault)
            assertEquals(443, parsed.port)
            assertArrayEquals("example.com".toByteArray(), parsed.address)
            for (bad in listOf(
                "GET http://example.com/ HTTP/1.1\r\n\r\n".toByteArray(),
                prefix + basic + "\r\nProxy-Authorization: Basic ".toByteArray() + basic + "\r\n\r\n".toByteArray(),
                prefix + basic + "\r\nTransfer-Encoding: chunked\r\n\r\n".toByteArray(),
                prefix + basic + "\r\nX: ".toByteArray() + ByteArray(8192) { 65 } + "\r\n\r\n".toByteArray(),
                prefix + basic + byteArrayOf(0, 13, 10, 13, 10))) {
                assertThrows(IOException::class.java) { LocalProxyHandshake.http(ByteArrayInputStream(bad), vault) }
            }
            for (size in 0 until request.size) assertThrows(IOException::class.java) {
                LocalProxyHandshake.http(ByteArrayInputStream(request.copyOf(size)), vault)
            }
        } finally { credentials.fill(0); basic.fill(0) }
    }
}

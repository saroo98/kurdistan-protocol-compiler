// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.util.Base64
import org.kurdistanvpn.core.nativeapi.NativeProxyAddressKind
import org.kurdistanvpn.core.nativeapi.NativeProxyRequest

/** Bounded parsing only. Success is sent by the owner after native stream admission. */
internal object LocalProxyHandshake {
    fun socks(input: InputStream, output: OutputStream, vault: ProxyCredentialVault): NativeProxyRequest {
        requireWire(input.octet() == 5)
        val methods = input.exact(input.octet())
        requireWire(methods.any { it == 2.toByte() })
        output.write(byteArrayOf(5, 2)); output.flush()
        requireWire(input.octet() == 1)
        val user = input.exact(input.octet())
        try {
            val pass = input.exact(input.octet())
            try { requireWire(vault.authenticate(user, pass)) } finally { pass.fill(0) }
        } finally { user.fill(0) }
        output.write(byteArrayOf(1, 0)); output.flush()
        requireWire(input.octet() == 5 && input.octet() == 1 && input.octet() == 0)
        val kind = when (input.octet()) {
            1 -> NativeProxyAddressKind.IPV4
            3 -> NativeProxyAddressKind.DOMAIN
            4 -> NativeProxyAddressKind.IPV6
            else -> throw IOException("Proxy request rejected")
        }
        val address = input.exact(when (kind) {
            NativeProxyAddressKind.IPV4 -> 4
            NativeProxyAddressKind.IPV6 -> 16
            NativeProxyAddressKind.DOMAIN -> input.octet()
        })
        return request(kind, address, input.octet() * 256 + input.octet())
    }

    fun http(input: InputStream, vault: ProxyCredentialVault): NativeProxyRequest {
        val header = ByteArray(8192)
        try {
            var length = 0
            while (true) {
                requireWire(length < header.size)
                val next = input.octet()
                requireWire(next == 13 || next == 10 || next in 32..126)
                header[length++] = next.toByte()
                if (length >= 4 && header[length - 4] == 13.toByte() && header[length - 3] == 10.toByte() &&
                    header[length - 2] == 13.toByte() && header[length - 1] == 10.toByte()) break
            }
            var start = 0
            var lines = 0
            var authority: String? = null
            var host: String? = null
            var authenticated = false
            var authorizationSeen = false
            for (end in 1 until length) {
                if (header[end] != 10.toByte()) continue
                requireWire(header[end - 1] == 13.toByte() && end - start <= 2049 && ++lines <= 34)
                val stop = end - 1
                requireWire((start until stop).none { header[it] == 13.toByte() || header[it] == 10.toByte() })
                if (lines == 1) {
                    val parts = String(header, start, stop - start, Charsets.US_ASCII).split(' ')
                    requireWire(parts.size == 3 && parts[0] == "CONNECT" && parts[2] == "HTTP/1.1")
                    authority = parts[1]
                } else if (stop > start) {
                    val colon = (start until stop).firstOrNull { header[it] == ':'.code.toByte() }
                        ?: throw IOException("Proxy request rejected")
                    requireWire(colon > start && (start until colon).all {
                        header[it].toInt().toChar().let { c -> c in 'a'..'z' || c in 'A'..'Z' || c == '-' }
                    })
                    val name = String(header, start, colon - start, Charsets.US_ASCII).lowercase(java.util.Locale.ROOT)
                    var value = colon + 1
                    while (value < stop && header[value] == 32.toByte()) value++
                    when (name) {
                        "proxy-authorization" -> {
                            requireWire(!authorizationSeen); authorizationSeen = true
                            requireWire(stop - value > 6 && String(header, value, 6, Charsets.US_ASCII).equals("Basic ", true))
                            val encoded = header.copyOfRange(value + 6, stop)
                            val decoded = try { Base64.getDecoder().decode(encoded) }
                            catch (_: IllegalArgumentException) { throw IOException("Proxy request rejected") }
                            finally { encoded.fill(0) }
                            try {
                                val separator = decoded.indexOf(':'.code.toByte())
                                requireWire(separator in 1 until decoded.lastIndex)
                                val user = decoded.copyOfRange(0, separator)
                                val pass = decoded.copyOfRange(separator + 1, decoded.size)
                                try { authenticated = vault.authenticate(user, pass) }
                                finally { user.fill(0); pass.fill(0) }
                            } finally { decoded.fill(0) }
                        }
                        "host" -> { requireWire(host == null); host = String(header, value, stop - value, Charsets.US_ASCII) }
                        "transfer-encoding" -> throw IOException("Proxy request rejected")
                        "content-length" -> requireWire(stop - value == 1 && header[value] == '0'.code.toByte())
                    }
                }
                start = end + 1
            }
            requireWire(authenticated && authority != null && host == authority)
            return authorityRequest(authority!!)
        } finally { header.fill(0) }
    }

    private fun authorityRequest(authority: String): NativeProxyRequest {
        val separator = authority.lastIndexOf(':')
        requireWire(separator > 0)
        val host = authority.substring(0, separator)
        val portText = authority.substring(separator + 1)
        requireWire(portText.isNotEmpty() && portText.length <= 5 && portText.all { it in '0'..'9' })
        val port = portText.toInt()
        if (host.startsWith('[') && host.endsWith(']')) {
            val numeric = host.substring(1, host.lastIndex)
            // A colon and a hex-only grammar make this a numeric parse, never a DNS lookup.
            requireWire(':' in numeric && numeric.all { it in "0123456789abcdefABCDEF:" })
            val address = try { InetAddress.getByName(numeric).address } catch (_: IOException) { throw IOException("Proxy request rejected") }
            return request(NativeProxyAddressKind.IPV6, address, port)
        }
        if (host.all { it in '0'..'9' || it == '.' }) {
            val octets = host.split('.')
            requireWire(octets.size == 4 && octets.all { it.isNotEmpty() && it.length <= 3 && (it.length == 1 || it[0] != '0') && it.toInt() <= 255 })
            return request(NativeProxyAddressKind.IPV4, octets.map { it.toInt().toByte() }.toByteArray(), port)
        }
        return request(NativeProxyAddressKind.DOMAIN, host.lowercase(java.util.Locale.ROOT).toByteArray(Charsets.US_ASCII), port)
    }

    private fun request(kind: NativeProxyAddressKind, address: ByteArray, port: Int): NativeProxyRequest =
        try { NativeProxyRequest(kind, address, port) } catch (_: IllegalArgumentException) { throw IOException("Proxy request rejected") }
    private fun requireWire(value: Boolean) { if (!value) throw IOException("Proxy request rejected") }
    private fun InputStream.octet(): Int = read().also { if (it < 0) throw IOException("Incomplete proxy request") }
    private fun InputStream.exact(length: Int): ByteArray = ByteArray(length).also { bytes ->
        try { for (i in bytes.indices) bytes[i] = octet().toByte() }
        catch (failure: Throwable) { bytes.fill(0); throw failure }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import java.security.KeyStore
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal data class AndroidSystemTrustSelectionV1(val provider: String,
    val managers: Array<TrustManager>, val managerClass: String)
internal fun interface AndroidSystemTrustRootsSourceV1 {
    fun select(): AndroidSystemTrustSelectionV1
}

/** Final private composition. Release never accepts roots from a caller or ambient fallback. */
internal class AndroidSystemTrustRootsV1 internal constructor(
    private val source: AndroidSystemTrustRootsSourceV1 = AndroidSystemTrustRootsSourceV1 {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as KeyStore?)
        val managers = factory.trustManagers
        AndroidSystemTrustSelectionV1(factory.provider.name, managers,
            if (managers.size == 1) managers[0].javaClass.name else "")
    },
) {
    fun copyInto(destination: ByteBuffer, written: IntArray, cancelled: () -> Boolean): Int {
        var result = 12
        fun wipe() {
            if (!destination.isReadOnly) {
                val limit = destination.limit()
                try {
                    destination.limit(destination.capacity())
                    for (i in 0 until destination.capacity()) destination.put(i, 0)
                } finally { destination.limit(limit) }
            }
        }
        if (written.size != 1) { wipe(); return 1 }
        written[0] = 0
        try {
            if (!destination.isDirect || destination.isReadOnly || destination.position() != 0 ||
                destination.limit() != destination.capacity() || destination.capacity() !in 1..1048576) return 1
            wipe()
            if (cancelled()) { result = 8; return result }
            val selected = source.select()
            // The app's merged release/internal manifest selects the repository's
            // system-only base config. Public JCA provenance is checked here;
            // API/OEM provider qualification remains an installed evidence gate.
            if (selected.provider != "AndroidNSSP" || selected.managers.size != 1 ||
                selected.managerClass != "android.security.net.config.RootTrustManager") return result
            val manager = selected.managers[0] as? X509TrustManager ?: return result
            val issuers = manager.acceptedIssuers
            if (issuers.isEmpty()) return result
            if (issuers.size > 512) { result = 6; return result }
            // Old Android stores can contain negative-serial anchors, rejected by
            // standard Go X.509. Omit only those anchors, never relax peer parsing
            // or substitute another trust source. An empty supported set fails.
            val count = issuers.count { it.serialNumber.signum() >= 0 }
            if (count == 0) return result
            if (destination.capacity() < 3) { result = 6; return result }
            destination.put(0, 1)
            destination.put(1, (count ushr 8).toByte()); destination.put(2, count.toByte())
            var at = 3
            for (issuer in issuers) {
                if (cancelled()) { result = 8; return result }
                if (issuer.serialNumber.signum() < 0) continue
                val der = issuer.encoded
                try {
                    if (der.isEmpty()) return result
                    if (der.size > 16384 || der.size > destination.capacity() - at - 4) { result = 6; return result }
                    for (shift in 3 downTo 0) destination.put(at++, (der.size ushr (shift * 8)).toByte())
                    for (byte in der) destination.put(at++, byte)
                } finally { der.fill(0) }
            }
            if (cancelled()) { result = 8; return result }
            written[0] = at
            result = 0
            return result
        } catch (_: Throwable) {
            result = 12
            return result
        } finally {
            if (result != 0) { wipe(); written[0] = 0 }
        }
    }
}

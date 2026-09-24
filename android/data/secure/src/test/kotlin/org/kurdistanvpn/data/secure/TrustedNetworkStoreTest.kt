// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class TrustedNetworkStoreTest {
    @Test fun malformedTrustIdsHmacLengthsAndOrderingFailClosed() {
        TrustedNetworkRule(CatalogId("a"), ByteArray(32) { 1 }, SafeAlias("A")).use { a ->
            TrustedNetworkRule(CatalogId("b"), ByteArray(32) { 2 }, SafeAlias("B")).use { b ->
                StoredTrustedNetworks(1, listOf(a), setOf(CatalogId("a"))).use { value ->
                    val bytes = value.encode()
                    checkMalformed(bytes, listOf({ putLong(it, 6, 0) }, { putShort(it, 14, 257) }, { putShort(it, 16, 65) },
                        { it[18] = 'A'.code.toByte() }, { it.fill(0, 19, 51) }, { putShort(it, 51, 385) },
                        { it[53] = 0xc0.toByte() }, { putShort(it, 54, 257) }, { it[58] = 'b'.code.toByte() })) {
                        StoredTrustedNetworks.decode(it).use { }
                    }
                    val decoded = StoredTrustedNetworks.decode(bytes); bytes.fill(0)
                    decoded.use { assertArrayEquals(value.encode(), it.encode()) }
                }
                StoredTrustedNetworks(1, listOf(a, b), setOf(CatalogId("a"), CatalogId("b"))).use { value ->
                    val bytes = value.encode()
                    val badRules = bytes.copyOfRange(0, 16) + bytes.copyOfRange(54, 92) + bytes.copyOfRange(16, 54) + bytes.copyOfRange(92, bytes.size)
                    val badSelected = bytes.clone().also { it[96] = 'b'.code.toByte(); it[99] = 'a'.code.toByte() }
                    val duplicateHmac = bytes.clone().also { it.fill(1, 57, 89) }
                    for (bad in listOf(badRules, badSelected, duplicateHmac))
                        assertThrows(IllegalArgumentException::class.java) { StoredTrustedNetworks.decode(bad).use { } }
                }
            }
        }
    }
    @Test fun trustedRulesOwnHmacAndCanonicalSets() {
        val hmac = ByteArray(32) { 1 }
        TrustedNetworkRule(CatalogId("rule-a"), hmac, SafeAlias("Home")).use { rule ->
            hmac.fill(0)
            val rules = mutableListOf(rule); val selected = mutableSetOf(CatalogId("rule-a"))
            StoredTrustedNetworks(1, rules, selected).use { value ->
                rules.clear(); selected.clear(); rule.close()
                checkRecord(value.encode(), 23, 262144) { StoredTrustedNetworks.decode(it).use { r -> r.encode() } }
                val raw = value.rules.single().hmac(); raw.fill(0)
                assertArrayEquals(ByteArray(32) { 1 }, value.rules.single().hmac())
                assertEquals(setOf(CatalogId("rule-a")), value.selectedRuleIds)
                assertEquals("StoredTrustedNetworks(redacted)", value.toString())
                value.close()
                assertThrows(IllegalStateException::class.java) { value.encode() }
                assertThrows(IllegalStateException::class.java) { value.rules.single().hmac() }
            }
        }
        assertThrows(IllegalArgumentException::class.java) { TrustedNetworkRule(CatalogId("r"), ByteArray(32), SafeAlias("Home")) }
        TrustedNetworkRule(CatalogId("a"), ByteArray(32) { 1 }, SafeAlias("A")).use { a ->
            TrustedNetworkRule(CatalogId("b"), ByteArray(32) { 1 }, SafeAlias("B")).use { b ->
                for (rules in listOf(listOf(a, a), listOf(a, b)))
                    assertThrows(IllegalArgumentException::class.java) { StoredTrustedNetworks(1, rules, emptySet()) }
                assertThrows(IllegalArgumentException::class.java) { StoredTrustedNetworks(1, listOf(a), setOf(CatalogId("missing"))) }
            }
        }
    }
    @Test fun trustWrapperContract() {
        StoredTrustedNetworks(1, emptyList(), emptySet()).use { value ->
            checkStore("trusted-networks-current", SecureDataClass.TRUSTED_NETWORK_RULES, value.encode(),
                { TrustedNetworkStore(it).save(value) }, { TrustedNetworkStore(it).load()?.use { r -> r.encode() } },
                { TrustedNetworkStore(it).delete() }, { TrustedNetworkStore.readOnly(it).save(value) },
                { TrustedNetworkStore.readOnly(it).delete() })
        }
    }
}

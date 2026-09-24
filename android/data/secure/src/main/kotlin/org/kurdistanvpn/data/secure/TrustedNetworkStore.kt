// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.*

class TrustedNetworkRule(val id: CatalogId, hmac: ByteArray, val alias: SafeAlias) : AutoCloseable {
    private val identity: ByteArray
    private var closed = false
    init {
        require(hmac.size == 32 && hmac.any { it != 0.toByte() })
        identity = hmac.clone()
    }
    fun hmac(): ByteArray { check(!closed); return identity.clone() }
    internal fun sameHmac(other: TrustedNetworkRule): Boolean { check(!closed && !other.closed); return identity.contentEquals(other.identity) }
    internal fun ownedCopy(): TrustedNetworkRule {
        val raw = hmac()
        return try { TrustedNetworkRule(id, raw, alias) } finally { raw.fill(0) }
    }
    override fun close() { if (!closed) { closed = true; identity.fill(0) } }
    override fun toString(): String = "TrustedNetworkRule(redacted)"
}
class StoredTrustedNetworks(val settingsRevision: Long, rules: List<TrustedNetworkRule>, selectedRuleIds: Set<CatalogId>) : AutoCloseable {
    val rules: List<TrustedNetworkRule>
    val selectedRuleIds: Set<CatalogId>
    private var closed = false
    init {
        require(settingsRevision > 0 && rules.size <= 256 && selectedRuleIds.size <= 256)
        require(rules.map { it.id }.distinct().size == rules.size)
        require(selectedRuleIds.all { id -> rules.any { it.id == id } })
        for (i in rules.indices) for (j in 0 until i) require(!rules[i].sameHmac(rules[j]))
        val owned = mutableListOf<TrustedNetworkRule>()
        try {
            rules.sortedBy { it.id.value }.forEach { owned += it.ownedCopy() }
            this.rules = java.util.Collections.unmodifiableList(owned)
            this.selectedRuleIds = java.util.Collections.unmodifiableSet(selectedRuleIds.sortedBy { it.value }.toSet())
        } catch (failure: Throwable) { owned.forEach { it.close() }; throw failure }
    }
    fun encode(): ByteArray {
        check(!closed)
        return encodeRecord(0x50363233, SecureDataClass.TRUSTED_NETWORK_RULES, MAX_BYTES) { w ->
            w.writeLong(settingsRevision); w.writeShort(rules.size)
            rules.forEach {
                w.recordId(it.id.value)
                val raw = it.hmac()
                try { w.write(raw) } finally { raw.fill(0) }
                w.recordAlias(it.alias)
            }
            w.writeShort(selectedRuleIds.size); selectedRuleIds.forEach { w.recordId(it.value) }
        }
    }
    override fun close() { if (!closed) { closed = true; rules.forEach { it.close() } } }
    override fun toString(): String = "StoredTrustedNetworks(redacted)"
    companion object {
        const val RECORD_ID = "trusted-networks-current"
        const val MAX_BYTES = 256 * 1024
        fun decode(input: ByteArray): StoredTrustedNetworks = decodeRecord(input, MAX_BYTES, 0x50363233, SecureDataClass.TRUSTED_NETWORK_RULES, { r ->
            val revision = r.readLong()
            val rules = mutableListOf<TrustedNetworkRule>()
            try {
                repeat(r.recordCount(256)) {
                    val id = CatalogId(r.recordId())
                    require(r.available() >= 32)
                    val hmac = ByteArray(32)
                    try { r.readFully(hmac); rules += TrustedNetworkRule(id, hmac, r.recordAlias()) } finally { hmac.fill(0) }
                }
                val selected = List(r.recordCount(256)) { CatalogId(r.recordId()) }
                require(selected == selected.distinct().sortedBy { it.value })
                StoredTrustedNetworks(revision, rules, selected.toSet())
            } finally { rules.forEach { it.close() } }
        }, { it.encode() })
    }
}

class TrustedNetworkStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredTrustedNetworks? {

        val raw = blobs.reopenIfPresent(StoredTrustedNetworks.RECORD_ID, SecureDataClass.TRUSTED_NETWORK_RULES) ?: return null
        return try { StoredTrustedNetworks.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredTrustedNetworks) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        val raw = value.encode()
        try { writable.stage(StoredTrustedNetworks.RECORD_ID, SecureDataClass.TRUSTED_NETWORK_RULES, raw) } finally { raw.fill(0) }
    }
    fun delete() {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        writable.delete(StoredTrustedNetworks.RECORD_ID, SecureDataClass.TRUSTED_NETWORK_RULES)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = TrustedNetworkStore(blobs, null) }
}

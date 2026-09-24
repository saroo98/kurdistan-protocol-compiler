// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.*

class StoredProbeHistory(val currentEpochMinutes: Long, samples: List<ProbeSample>) {
    val samples: List<ProbeSample>
    init {
        ProbeHistory(samples, currentEpochMinutes)
        this.samples = java.util.Collections.unmodifiableList(samples.sortedBy { it.coarseEpochMinutes })
    }
    fun encode(): ByteArray = encodeRecord(0x50363232, SecureDataClass.PROBE_HISTORY, MAX_BYTES) { w ->
        w.writeLong(currentEpochMinutes); w.writeShort(samples.size)
        samples.forEach {
            w.writeLong(it.coarseEpochMinutes); w.writeInt(it.latencyMillis); w.writeInt(it.jitterMillis); w.writeInt(it.lossBasisPoints)
            w.recordEnum(it.stability); w.recordBoolean(it.failure != null); it.failure?.let(w::recordEnum); w.recordEnum(it.method)
        }
    }
    override fun toString(): String = "StoredProbeHistory(redacted)"
    companion object {
        const val MAX_BYTES = 32 * 1024
        fun decode(input: ByteArray): StoredProbeHistory = decodeRecord(input, MAX_BYTES, 0x50363232, SecureDataClass.PROBE_HISTORY, { r ->
            val current = r.readLong()
            StoredProbeHistory(current, List(r.recordCount(200)) {
                ProbeSample(r.readLong(), r.readInt(), r.readInt(), r.readInt(), r.recordEnum<ProbeStability>(),
                    if (r.recordBoolean()) r.recordEnum<ProductFailureCode>() else null, r.recordEnum<ProbeMethod>())
            })
        }, { it.encode() })
    }
}

class ProbeHistoryStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(profileId: String): StoredProbeHistory? {
        org.kurdistanvpn.core.model.CatalogId(profileId)
        if (!blobs.exists(profileId, SecureDataClass.PROBE_HISTORY)) return null
        val raw = blobs.reopen(profileId, SecureDataClass.PROBE_HISTORY)
        return try { StoredProbeHistory.decode(raw) } finally { raw.fill(0) }
    }
    fun save(profileId: String, value: StoredProbeHistory) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        val raw = value.encode()
        try { writable.stage(profileId, SecureDataClass.PROBE_HISTORY, raw) } finally { raw.fill(0) }
    }
    fun delete(profileId: String) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        writable.delete(profileId, SecureDataClass.PROBE_HISTORY)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = ProbeHistoryStore(blobs, null) }
}

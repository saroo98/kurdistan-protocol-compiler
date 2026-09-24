// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.UpdateCategory

class StoredUpdateState(val publicationGeneration: ULong?, val profileGeneration: ULong?, val category: UpdateCategory,
    val lastAttemptEpochHour: Long, val nextEligibleEpochHour: Long, val failureCount: Int) {
    init { require(lastAttemptEpochHour >= 0 && nextEligibleEpochHour >= lastAttemptEpochHour && failureCount in 0..10) }
    fun encode(): ByteArray = encodeRecord(0x50363231, SecureDataClass.UPDATE_STATE, MAX_BYTES) { w ->
        w.optionalGeneration(publicationGeneration); w.optionalGeneration(profileGeneration); w.recordEnum(category)
        w.writeLong(lastAttemptEpochHour); w.writeLong(nextEligibleEpochHour); w.writeByte(failureCount)
    }
    override fun toString(): String = "StoredUpdateState(redacted)"
    companion object {
        const val MAX_BYTES = 1024
        fun decode(input: ByteArray): StoredUpdateState = decodeRecord(input, MAX_BYTES, 0x50363231, SecureDataClass.UPDATE_STATE,
            { r -> StoredUpdateState(r.optionalGeneration(), r.optionalGeneration(), r.recordEnum<UpdateCategory>(), r.readLong(), r.readLong(), r.readUnsignedByte()) },
            { it.encode() })
    }
}

class UpdateStateStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(profileId: String): StoredUpdateState? {
        org.kurdistanvpn.core.model.CatalogId(profileId)
        if (!blobs.exists(profileId, SecureDataClass.UPDATE_STATE)) return null
        val raw = blobs.reopen(profileId, SecureDataClass.UPDATE_STATE)
        return try { StoredUpdateState.decode(raw) } finally { raw.fill(0) }
    }
    fun save(profileId: String, value: StoredUpdateState) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        val raw = value.encode()
        try { writable.stage(profileId, SecureDataClass.UPDATE_STATE, raw) } finally { raw.fill(0) }
    }
    fun delete(profileId: String) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        org.kurdistanvpn.core.model.CatalogId(profileId)
        writable.delete(profileId, SecureDataClass.UPDATE_STATE)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = UpdateStateStore(blobs, null) }
}

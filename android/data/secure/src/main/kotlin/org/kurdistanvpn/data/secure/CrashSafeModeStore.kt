// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.kurdistanvpn.core.model.*

class StoredCrashSafeMode(val startedEpochHour: Long, val cleanStop: Boolean, val consecutiveUncleanStarts: Int, val safeMode: Boolean) {
    init { require(startedEpochHour >= 0 && consecutiveUncleanStarts in 0..10 && safeMode == (consecutiveUncleanStarts >= 3)) }
    fun started(epochHour: Long): StoredCrashSafeMode {
        val count = if (cleanStop) 0 else minOf(10, consecutiveUncleanStarts + 1)
        return StoredCrashSafeMode(epochHour, false, count, count >= 3)
    }
    fun cleanStopped(): StoredCrashSafeMode = StoredCrashSafeMode(startedEpochHour, true, 0, false)
    fun encode(): ByteArray = encodeRecord(0x50363239, SecureDataClass.CRASH_SAFE_MODE_STATE, MAX_BYTES) { w ->
        w.writeLong(startedEpochHour); w.recordBoolean(cleanStop); w.writeByte(consecutiveUncleanStarts); w.recordBoolean(safeMode)
    }
    override fun toString(): String = "StoredCrashSafeMode(redacted)"
    companion object {
        const val RECORD_ID = "crash-safe-mode-current"
        const val MAX_BYTES = 64
        fun decode(input: ByteArray): StoredCrashSafeMode = decodeRecord(input, MAX_BYTES, 0x50363239, SecureDataClass.CRASH_SAFE_MODE_STATE,
            { r -> StoredCrashSafeMode(r.readLong(), r.recordBoolean(), r.readUnsignedByte(), r.recordBoolean()) }, { it.encode() })
    }
}

class CrashSafeModeStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredCrashSafeMode? {

        if (!blobs.exists(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE)) return null
        val raw = blobs.reopen(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE)
        return try { StoredCrashSafeMode.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredCrashSafeMode) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        val raw = value.encode()
        try { writable.stage(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE, raw) } finally { raw.fill(0) }
    }
    fun delete() {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }

        writable.delete(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE)
    }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = CrashSafeModeStore(blobs, null) }
}

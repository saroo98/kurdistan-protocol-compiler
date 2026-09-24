// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

/** A timer suppresses automatic connection; it never supplies runtime authority or schedules a wakeup. */
class StoredPauseState(val startedWallMillis: Long, val startedElapsedMillis: Long,
    val bootCount: Int, val durationMillis: Long) {
    init { require(startedWallMillis >= 0 && startedElapsedMillis >= 0 && bootCount >= 0 && durationMillis in 0..86_400_000) }
    fun expired(wallMillis: Long, elapsedMillis: Long, currentBoot: Int): Boolean {
        if (durationMillis == 0L || currentBoot < bootCount || elapsedMillis < 0) return false
        return if (currentBoot == bootCount)
            elapsedMillis >= startedElapsedMillis && elapsedMillis - startedElapsedMillis >= durationMillis
        else wallMillis >= startedWallMillis && wallMillis - startedWallMillis >= durationMillis
    }
    fun encode(): ByteArray = encodeRecord(0x50363330, SecureDataClass.PAUSE_STATE, MAX_BYTES) {
        it.writeLong(startedWallMillis); it.writeLong(startedElapsedMillis); it.writeInt(bootCount); it.writeLong(durationMillis)
    }
    override fun toString() = "StoredPauseState(redacted)"
    companion object {
        const val RECORD_ID = "pause-current"
        const val MAX_BYTES = 64
        fun decode(bytes: ByteArray): StoredPauseState = decodeRecord(bytes, MAX_BYTES, 0x50363330, SecureDataClass.PAUSE_STATE,
            { StoredPauseState(it.readLong(), it.readLong(), it.readInt(), it.readLong()) }, { it.encode() })
    }
}

class PauseStateStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): StoredPauseState? {
        val raw = blobs.reopenIfPresent(StoredPauseState.RECORD_ID, SecureDataClass.PAUSE_STATE) ?: return null
        return try { StoredPauseState.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: StoredPauseState) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        val raw = value.encode()
        try { writable.stage(StoredPauseState.RECORD_ID, SecureDataClass.PAUSE_STATE, raw) } finally { raw.fill(0) }
    }
    fun delete() { checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }.delete(StoredPauseState.RECORD_ID, SecureDataClass.PAUSE_STATE) }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = PauseStateStore(blobs, null) }
}

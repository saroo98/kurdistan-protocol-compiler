// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.nio.ByteBuffer
import java.security.MessageDigest
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.data.secure.StoredProbeHistory
import org.kurdistanvpn.data.secure.StoredUpdateState

/** Encrypted journal presentation record, never runtime authority. Caller owns the directory lease. */
internal class ProtectedProbeHistoryStore(private val storage: JournalStorage) {
    fun read(id: CatalogId, trustRevision: Long): StoredProbeHistory? {
        return read(name(id), trustRevision, StoredProbeHistory::decode)
    }

    fun readUpdate(id: CatalogId, trustRevision: Long): StoredUpdateState? =
        read(updateName(id), trustRevision, StoredUpdateState::decode)

    fun writeUpdate(id: CatalogId, trustRevision: Long, value: StoredUpdateState) {
        readUpdate(id, trustRevision)?.let { old ->
            old.publicationGeneration?.let { prior -> require(value.publicationGeneration?.let { it >= prior } == true) }
            old.profileGeneration?.let { prior -> require(value.profileGeneration?.let { it >= prior } == true) }
        }
        write(updateName(id), trustRevision, value.encode())
    }

    private fun <T> read(name: String, trustRevision: Long, decode: (ByteArray) -> T): T? {
        val bytes = storage.read(name, MAX_BYTES) ?: return null
        return try {
            val reader = ByteBuffer.wrap(bytes)
            require(bytes.size >= HEADER && reader.int == MAGIC)
            val store = ByteArray(16).also(reader::get)
            require(MessageDigest.isEqual(store, storeId()))
            val revision = reader.long
            require(revision >= 0)
            val payload = ByteArray(reader.remaining()).also(reader::get)
            try { decode(payload).takeIf { revision == trustRevision } }
            finally { payload.fill(0) }
        } finally { bytes.fill(0) }
    }

    fun write(id: CatalogId, trustRevision: Long, value: StoredProbeHistory) {
        write(name(id), trustRevision, value.encode())
    }

    private fun write(name: String, trustRevision: Long, payload: ByteArray) {
        require(trustRevision >= 0)
        val bytes = try { ByteBuffer.allocate(HEADER + payload.size).putInt(MAGIC)
            .put(storeId()).putLong(trustRevision).put(payload).array() } finally { payload.fill(0) }
        val old = storage.read(name, MAX_BYTES)
        try {
            val entries = storage.inventory(JournalLimits.OBJECTS)
            require(entries.size + (if (old == null) 1 else 0) <= JournalLimits.OBJECTS)
            require(entries.sumOf { it.length } + bytes.size + 2048 <= JournalLimits.RETAINED_OBJECT_BYTES)
            require(entries.filter { it.name.startsWith("journal-") }.sumOf { it.length } + bytes.size + 2048 <=
                JournalLimits.CONTROL_BYTES - JournalLimits.RESERVED_BYTES)
            storage.compareAndReplace(name, old, bytes)
            val reopened = checkNotNull(storage.read(name, MAX_BYTES))
            try { check(MessageDigest.isEqual(bytes, reopened)) } finally { reopened.fill(0) }
        } finally { old?.fill(0); bytes.fill(0) }
    }

    private fun storeId(): ByteArray {
        val raw = checkNotNull(storage.read("journal-control", JournalLimits.RECORD_BYTES))
        return try { JournalControl.decode(raw).also { check(!it.dirty) }.storeId() }
        finally { raw.fill(0) }
    }

    companion object {
        private const val MAGIC = 0x4b504831
        private const val HEADER = 28
        const val MAX_BYTES = HEADER + StoredProbeHistory.MAX_BYTES
        fun isName(name: String) = name.matches(Regex("journal-probe-history-[a-z0-9][a-z0-9-]{0,63}"))
        fun isUpdateName(name: String) = name.matches(Regex("journal-update-observation-[a-z0-9][a-z0-9-]{0,63}"))
        private fun name(id: CatalogId) = "journal-probe-history-${id.value}"
        private fun updateName(id: CatalogId) = "journal-update-observation-${id.value}"
    }
}

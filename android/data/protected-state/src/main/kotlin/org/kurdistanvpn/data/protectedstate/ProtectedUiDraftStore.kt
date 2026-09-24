// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.protectedstate

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.data.secure.ProductSettingsMetadata
import org.kurdistanvpn.data.settings.*
import org.kurdistanvpn.domain.SettingsEffectiveValues

/** Non-authoritative edit staging under the existing encrypted directory lease. */
internal class ProtectedUiDraftStore(private val storage: JournalStorage) : SettingsDraftPort {
    override suspend fun create(value: StoredSettingsDraft) = access {
        val name = name(value.id)
        val entries = storage.inventory(JournalLimits.OBJECTS)
        val drafts = entries.filter { isName(it.name) }
        if (drafts.size >= MAX_RECORDS) return@access SettingsPortResult.Rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        if (entries.any { it.name == name }) return@access interrupted()
        write(value, null)
        SettingsPortResult.Success(Unit)
    }

    override suspend fun read(id: CatalogId): SettingsPortResult<StoredSettingsDraft> = access {
        val raw = storage.read(name(id), MAX_BYTES) ?: return@access interrupted()
        try {
            SettingsPortResult.Success(ProtectedUiDraftCodec.decode(raw, id, storeId()))
        } catch (_: IllegalArgumentException) {
            interrupted()
        } finally { raw.fill(0) }
    }

    override suspend fun replace(value: StoredSettingsDraft) = access {
        val old = storage.read(name(value.id), MAX_BYTES) ?: return@access interrupted()
        try {
            val saved = ProtectedUiDraftCodec.decode(old, value.id, storeId())
            if (saved.base != value.base) return@access interrupted()
            write(value, old)
            SettingsPortResult.Success(Unit)
        } finally { old.fill(0) }
    }

    override suspend fun delete(id: CatalogId) = access {
        val name = name(id)
        val old = storage.read(name, MAX_BYTES) ?: return@access interrupted()
        try {
            storage.delete(name, old)
            check(storage.read(name, MAX_BYTES) == null) { "DRAFT_DELETE_UNPROVEN" }
            SettingsPortResult.Success(Unit)
        } finally { old.fill(0) }
    }

    private fun write(value: StoredSettingsDraft, old: ByteArray?) {
        val bytes = ProtectedUiDraftCodec.encode(value, storeId())
        try {
            val entries = storage.inventory(JournalLimits.OBJECTS)
            val projected = entries.filter { isName(it.name) && it.name != name(value.id) }
                .sumOf { it.length } + bytes.size + ENVELOPE_ALLOWANCE
            require(projected <= MAX_TOTAL_BYTES)
            require(entries.size + (if (old == null) 1 else 0) <= JournalLimits.OBJECTS)
            require(entries.sumOf { it.length } + bytes.size + ENVELOPE_ALLOWANCE <= JournalLimits.RETAINED_OBJECT_BYTES)
            storage.compareAndReplace(name(value.id), old, bytes)
            val reopened = checkNotNull(storage.read(name(value.id), MAX_BYTES))
            try { check(MessageDigest.isEqual(bytes, reopened)) { "DRAFT_REOPEN_MISMATCH" } }
            finally { reopened.fill(0) }
        } finally { bytes.fill(0) }
    }

    private fun storeId(): ByteArray {
        val raw = checkNotNull(storage.read("journal-control", JournalLimits.RECORD_BYTES))
        return try { JournalControl.decode(raw).also { check(!it.dirty) }.storeId() }
        finally { raw.fill(0) }
    }

    private suspend fun <T> access(block: () -> SettingsPortResult<T>): SettingsPortResult<T> = withContext(Dispatchers.IO) {
        try { storage.exclusive(block) }
        catch (cancelled: java.util.concurrent.CancellationException) { throw cancelled }
        catch (_: IllegalArgumentException) { SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED) }
        catch (_: Exception) { SettingsPortResult.Rejected(ProductFailureCode.STORAGE_DEGRADED) }
    }

    private fun interrupted() = SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)

    companion object {
        const val MAX_RECORDS = 16
        const val MAX_BYTES = 512 * 1024
        const val ENVELOPE_ALLOWANCE = 2048
        const val MAX_TOTAL_BYTES = MAX_RECORDS * (MAX_BYTES + ENVELOPE_ALLOWANCE)
        private val names = Regex("journal-ui-draft-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        fun isName(name: String) = names.matches(name)
        fun name(id: CatalogId): String = "journal-ui-draft-${id.value}".also { require(isName(it)) }
    }
}

/** Composes existing settings codecs, with bounded identifiers omitted by their nonsecret image. */
internal object ProtectedUiDraftCodec {
    fun encode(value: StoredSettingsDraft, storeId: ByteArray): ByteArray {
        require(storeId.size == 16)
        ProtectedUiDraftStore.name(value.id)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { w ->
            w.writeInt(0x4b554431); w.writeByte(1); w.write(storeId); w.writeUTF(value.id.value)
            w.writeLong(value.base.journalRevision); w.writeLong(value.base.appliedRevision)
            w.writeInt(value.base.effective?.mtu ?: -1); w.writeInt(value.base.effective?.reconnectMaximum ?: -1)
            w.writeBoolean(value.base.effective != null)
            writeSettings(w, value.base.requested)
            writeSettings(w, value.requested)
        }
        return output.toByteArray().also { require(it.size <= ProtectedUiDraftStore.MAX_BYTES) }
    }

    fun decode(bytes: ByteArray, id: CatalogId, storeId: ByteArray): StoredSettingsDraft {
        require(bytes.size in 1..ProtectedUiDraftStore.MAX_BYTES && storeId.size == 16)
        val r = DataInputStream(ByteArrayInputStream(bytes))
        try {
            require(r.readInt() == 0x4b554431 && r.readUnsignedByte() == 1)
            require(ByteArray(16).also(r::readFully).contentEquals(storeId))
            require(r.readUTF() == id.value)
            val journal = r.readLong(); val applied = r.readLong()
            val mtu = r.readInt(); val reconnect = r.readInt(); val effectivePresent = r.readBoolean()
            require(mtu >= -1 && reconnect >= -1)
            val effective = if (effectivePresent) SettingsEffectiveValues(mtu.takeIf { it >= 0 }, reconnect.takeIf { it >= 0 })
                else null.also { require(mtu == -1 && reconnect == -1) }
            val base = readSettings(r); val requested = readSettings(r)
            require(r.available() == 0)
            val value = StoredSettingsDraft(id, SettingsStoreState(journal, applied, base, effective), requested)
            val canonical = encode(value, storeId)
            try { require(MessageDigest.isEqual(bytes, canonical)) } finally { canonical.fill(0) }
            return value
        } catch (_: java.io.IOException) { throw IllegalArgumentException("DRAFT_MALFORMED") }
    }

    private fun writeSettings(w: DataOutputStream, s: ProductSettings) {
        val image = ProductSettingsImage.create(s.copy(profiles = ProfilePreferences(),
            routing = s.routing.copy(packages = emptySet()),
            networkTrust = s.networkTrust.copy(protectedRuleIds = emptySet())), 1).encode()
        val metadata = ProductSettingsMetadata(1, s.profiles.favoriteLocalRecordIds, SettingsIdentifiers.from(s)).encode()
        try {
            w.writeInt(image.size); w.write(image); w.writeInt(metadata.size); w.write(metadata)
            val selected = s.profiles.activeLocalRecordId.orEmpty()
            require(selected.isEmpty() || selected.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")))
            w.writeUTF(selected)
            val packages = s.routing.packages.sorted()
            require(packages.size <= 64)
            w.writeShort(packages.size)
            packages.forEach { require(it.length <= 255); w.writeUTF(it) }
            w.writeShort(s.networkTrust.protectedRuleIds.size)
            s.networkTrust.protectedRuleIds.map { it.value }.sorted().forEach(w::writeUTF)
        } finally { image.fill(0); metadata.fill(0) }
    }

    private fun readSettings(r: DataInputStream): ProductSettings {
        fun part(max: Int): ByteArray {
            val size = r.readInt(); require(size in 1..max && size <= r.available())
            return ByteArray(size).also(r::readFully)
        }
        val image = part(ProductSettingsImage.MAX_BYTES)
        val metadata = part(128 * 1024)
        return try {
            val decoded = ProductSettingsImage.decode(image)
            val references = ProductSettingsMetadata.decode(metadata)
            require(decoded.revision == 1L && references.settingsRevision == 1L)
            val selected = r.readUTF().takeIf { it.isNotEmpty() }
            val packageCount = r.readUnsignedShort(); require(packageCount <= 64)
            val packages = List(packageCount) { r.readUTF().also { require(it.length <= 255) } }.toSet()
            require(packages.size == packageCount)
            val ruleCount = r.readUnsignedShort(); require(ruleCount <= 256)
            val rules = List(ruleCount) { CatalogId(r.readUTF()) }.toSet(); require(rules.size == ruleCount)
            val base = decoded.resolve(references.identifiers)
            base.copy(profiles = ProfilePreferences(selected, references.favoriteIds),
                routing = base.routing.copy(packages = packages).validated(),
                networkTrust = base.networkTrust.copy(protectedRuleIds = rules))
        } finally { image.fill(0); metadata.fill(0) }
    }
}

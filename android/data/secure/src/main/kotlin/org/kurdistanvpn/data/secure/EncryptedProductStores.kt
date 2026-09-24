// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import java.io.*
import java.util.Collections
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.SettingsIdentifiers
import org.kurdistanvpn.core.model.SafeAlias
import org.kurdistanvpn.core.model.UpdateCategory

/** Role20 v1 user metadata: favorites and user-selected profile-derived settings references.
 * Active profile ownership remains in the encrypted protected checkpoint, never this record. */
class ProductSettingsMetadata(val settingsRevision: Long, favoriteIds: Set<String>, val identifiers: SettingsIdentifiers) {
    val favoriteIds: Set<String>
    init {
        require(settingsRevision > 0 && favoriteIds.size <= 1024) { "INVALID_SETTINGS_METADATA" }
        val owned = favoriteIds.toTypedArray().toSortedSet()
        require(owned.size <= 1024 && owned.all { it.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")) }) { "INVALID_SETTINGS_METADATA" }
        this.favoriteIds = Collections.unmodifiableSet(owned)
    }
    fun encode(): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { w ->
            w.writeInt(MAGIC); w.writeByte(1); w.writeByte(SecureDataClass.DEPLOYMENT_METADATA.wireValue)
            w.writeLong(settingsRevision); w.writeShort(favoriteIds.size)
            favoriteIds.forEach(w::writeUTF)
            w.writeUTF(identifiers.manualStrategy?.value.orEmpty()); w.writeUTF(identifiers.resolver?.value.orEmpty())
            w.writeUTF(identifiers.probeTarget?.value.orEmpty())
        }
        return output.toByteArray().also { require(it.size <= MAX_BYTES) }
    }
    override fun toString(): String = "ProductSettingsMetadata(redacted)"
    companion object {
        const val RECORD_ID = "product-settings-metadata"
        const val MAX_BYTES = 68000
        private const val MAGIC = 0x4b504d31
        fun decode(input: ByteArray): ProductSettingsMetadata {
            require(input.size in 22..MAX_BYTES) { "MALFORMED_SETTINGS_METADATA" }
            val owned = input.clone()
            try {
                val r = DataInputStream(ByteArrayInputStream(owned))
                require(r.readInt() == MAGIC && r.readUnsignedByte() == 1 && r.readUnsignedByte() == SecureDataClass.DEPLOYMENT_METADATA.wireValue)
                val revision = r.readLong(); val count = r.readUnsignedShort().also { require(it <= 1024) }
                val favorites = List(count) { r.readUTF().also { require(it.length in 1..64) } }
                require(favorites == favorites.distinct().sorted())
                fun id() = r.readUTF().also { require(it.length <= 64) }.takeIf { it.isNotEmpty() }?.let(::CatalogId)
                val result = ProductSettingsMetadata(revision, favorites.toSet(), SettingsIdentifiers(id(), id(), id()))
                require(r.available() == 0)
                val canonical = result.encode()
                try { require(owned.contentEquals(canonical)) } finally { canonical.fill(0) }
                return result
            } catch (_: IOException) { throw IllegalArgumentException("MALFORMED_SETTINGS_METADATA") }
            catch (_: RuntimeException) { throw IllegalArgumentException("MALFORMED_SETTINGS_METADATA") }
            finally { owned.fill(0) }
        }
    }
}

data class DeploymentDisplayEntry(val profileId: CatalogId, val alias: SafeAlias, val priority: Int,
    val expanded: Boolean, val updateCategory: UpdateCategory) {
    init { require(priority in 0..1023) }
    override fun toString(): String = "DeploymentDisplayEntry(redacted)"
}

class DeploymentDisplayMetadata(entries: List<DeploymentDisplayEntry>) {
    val entries: List<DeploymentDisplayEntry>
    init {
        require(entries.size <= 1024)
        val owned = entries.sortedBy { it.profileId.value }
        require(owned.map { it.profileId }.distinct().size == owned.size)
        this.entries = Collections.unmodifiableList(owned)
    }
    fun encode(): ByteArray = encodeRecord(0x50363230, SecureDataClass.DEPLOYMENT_METADATA, MAX_BYTES) { w ->
        w.writeShort(entries.size)
        entries.forEach { w.recordId(it.profileId.value); w.recordAlias(it.alias); w.writeInt(it.priority); w.recordBoolean(it.expanded); w.recordEnum(it.updateCategory) }
    }
    override fun toString(): String = "DeploymentDisplayMetadata(redacted)"
    companion object {
        const val RECORD_ID = "deployment-display-current"
        const val MAX_BYTES = 1024 * 1024
        fun decode(input: ByteArray): DeploymentDisplayMetadata = decodeRecord(input, MAX_BYTES, 0x50363230,
            SecureDataClass.DEPLOYMENT_METADATA, { r ->
                DeploymentDisplayMetadata(List(r.recordCount(1024)) {
                    DeploymentDisplayEntry(CatalogId(r.recordId()), r.recordAlias(), r.readInt(), r.recordBoolean(), r.recordEnum<UpdateCategory>())
                })
            }, { it.encode() })
    }
}

class DeploymentDisplayMetadataStore private constructor(private val blobs: SecureBlobReadAccess, private val writer: SecureBlobAccess?) {
    constructor(blobs: SecureBlobAccess) : this(blobs, blobs)
    fun load(): DeploymentDisplayMetadata? {
        if (!blobs.exists(DeploymentDisplayMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA)) return null
        val raw = blobs.reopen(DeploymentDisplayMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA)
        return try { DeploymentDisplayMetadata.decode(raw) } finally { raw.fill(0) }
    }
    fun save(value: DeploymentDisplayMetadata) {
        val writable = checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }
        val raw = value.encode()
        try { writable.stage(DeploymentDisplayMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA, raw) } finally { raw.fill(0) }
    }
    fun delete() { checkNotNull(writer) { "READ_ONLY_PRODUCT_VIEW" }.delete(DeploymentDisplayMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA) }
    companion object { fun readOnly(blobs: SecureBlobReadAccess) = DeploymentDisplayMetadataStore(blobs, null) }
}

// Primitive framing shared only by the explicit P6 record codecs below. Legacy v1 codecs do not use it.
private class ClearedRecordOutput(private val maximum: Int) : ByteArrayOutputStream(maximum) {
    override fun write(value: Int) { require(count < maximum); super.write(value) }
    override fun write(bytes: ByteArray, offset: Int, length: Int) {
        require(length >= 0 && length <= maximum - count)
        super.write(bytes, offset, length)
    }
    override fun close() { buf.fill(0); reset() }
}
internal fun encodeRecord(magic: Int, role: SecureDataClass, maximum: Int, payload: (DataOutputStream) -> Unit): ByteArray {
    require(maximum >= 6)
    val out = ClearedRecordOutput(maximum)
    try {
        val w = DataOutputStream(out)
        w.writeInt(magic); w.writeByte(1); w.writeByte(role.wireValue); payload(w)
        require(out.size() <= maximum)
        return out.toByteArray()
    } finally { out.close() }
}
internal fun <T> decodeRecord(input: ByteArray, maximum: Int, magic: Int, role: SecureDataClass,
    payload: (DataInputStream) -> T, encode: (T) -> ByteArray): T {
    require(input.size in 6..maximum) { "MALFORMED_PRODUCT_RECORD" }
    val owned = input.clone()
    var result: T? = null
    var accepted = false
    try {
        val r = DataInputStream(ByteArrayInputStream(owned))
        require(r.readInt() == magic && r.readUnsignedByte() == 1 && r.readUnsignedByte() == role.wireValue)
        val decoded = payload(r)
        result = decoded
        require(r.available() == 0)
        val canonical = encode(decoded)
        try { require(owned.contentEquals(canonical)) } finally { canonical.fill(0) }
        accepted = true
        return decoded
    } catch (_: IOException) { throw IllegalArgumentException("MALFORMED_PRODUCT_RECORD") }
    catch (_: RuntimeException) { throw IllegalArgumentException("MALFORMED_PRODUCT_RECORD") }
    finally {
        owned.fill(0)
        if (!accepted) (result as? AutoCloseable)?.close()
    }
}
internal fun DataOutputStream.recordBoolean(value: Boolean) = writeByte(if (value) 1 else 0)
internal fun DataInputStream.recordBoolean(): Boolean = readUnsignedByte().also { require(it in 0..1) } == 1
internal fun DataInputStream.recordCount(maximum: Int): Int = readUnsignedShort().also { require(it <= maximum && it <= available()) }
internal fun DataOutputStream.recordString(value: String, maximum: Int) {
    val raw = value.encodeToByteArray()
    try { require(raw.size in 1..maximum); writeShort(raw.size); write(raw) } finally { raw.fill(0) }
}
internal fun DataInputStream.recordString(maximum: Int): String {
    val size = readUnsignedShort()
    require(size in 1..maximum && size <= available())
    val raw = ByteArray(size)
    try { readFully(raw); return raw.decodeToString(throwOnInvalidSequence = true) } finally { raw.fill(0) }
}
internal fun DataOutputStream.recordId(value: String) { CatalogId(value); recordString(value, 64) }
internal fun DataInputStream.recordId(): String = recordString(64).also { CatalogId(it) }
internal fun DataOutputStream.recordAlias(value: SafeAlias) = recordString(value.value, 384)
internal fun DataInputStream.recordAlias(): SafeAlias = SafeAlias(recordString(384))
internal fun DataOutputStream.recordEnum(value: Enum<*>) = recordString(value.name, 64)
internal inline fun <reified E : Enum<E>> DataInputStream.recordEnum(): E = enumValueOf<E>(recordString(64))
internal fun DataOutputStream.optionalGeneration(value: ULong?) { recordBoolean(value != null); value?.let { writeLong(it.toLong()) } }
internal fun DataInputStream.optionalGeneration(): ULong? = if (recordBoolean()) readLong().toULong() else null
internal fun DataOutputStream.optionalId(value: String?) { recordBoolean(value != null); value?.let { recordId(it) } }
internal fun DataInputStream.optionalId(): String? = if (recordBoolean()) recordId() else null

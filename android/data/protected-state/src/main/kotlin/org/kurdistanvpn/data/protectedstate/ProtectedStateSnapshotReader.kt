// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Collections
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.SecureBlobReadAccess
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.secure.SecureOperationBinding

/** Immutable references and a read function only. This type has no mutable storage supertype. */
internal class ReadOnlyProtectedBlobView(
    references: List<ProtectedObjectReference>,
    private val readEncrypted: (String) -> ByteArray?,
    private val codec: SecureEnvelopeCodec, private val key: KeyEncryptionKey,
) : SecureBlobReadAccess {
    private val entries = references.toTypedArray().let { owned ->
        require(owned.size <= JournalLimits.OBJECTS)
        owned.associateBy { it.dataClass to it.logicalId }.also { require(it.size == owned.size) }
    }
    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        require(localRecordId.validRecordId() && dataClass.wireValue in 1..13)
        val reference = checkNotNull(entries[dataClass.wireValue to localRecordId]) { "OBJECT_NOT_COMMITTED" }
        require(reference.keyGeneration == key.generation)
        val encrypted = checkNotNull(readEncrypted(reference.physicalId)) { "OBJECT_MISSING" }
        return try {
            check(reference.matches(encrypted)) { "OBJECT_BINDING_MISMATCH" }
            val opened = codec.openForOperation(encrypted, localRecordId, dataClass, key, reference.binding)
            try {
                check(opened.dataClass == dataClass && opened.keyGeneration == reference.keyGeneration)
                opened.plaintext.clone()
            } finally { opened.plaintext.fill(0) }
        } finally { encrypted.fill(0) }
    }
    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean {
        require(localRecordId.validRecordId() && dataClass.wireValue in 1..13)
        if (!entries.containsKey(dataClass.wireValue to localRecordId)) return false
        // Missing/corrupt referenced material is an integrity failure, not an absent optional record.
        reopen(localRecordId, dataClass).fill(0)
        return true
    }
}

/** Immutable reference to exact encrypted bytes, never a persisted runtime capability. */
internal class ProtectedObjectReference private constructor(
    val dataClass: Int, val logicalId: String, val physicalId: String,
    val keyGeneration: Int, val length: Int, private val digest: ByteArray, val binding: SecureOperationBinding,
) {
    fun matches(encrypted: ByteArray): Boolean {
        val owned = encrypted.clone()
        return try { owned.size == length && JournalDigest.objectContent(owned).matches(digest) }
        finally { owned.fill(0) }
    }
    internal fun write(output: DataOutputStream) {
        output.writeByte(dataClass); output.writeAscii(logicalId); output.writeAscii(physicalId)
        output.writeInt(keyGeneration); output.writeInt(length); output.write(digest)
        output.writeByte(2); output.write(binding.operationId()); output.writeLong(binding.revision)
    }
    companion object {
        fun fromEncryptedObject(dataClass: Int, logicalId: String, physicalId: String,
            generation: Int, encrypted: ByteArray, binding: SecureOperationBinding): ProtectedObjectReference {
            val owned = encrypted.clone()
            return try {
                validate(dataClass, logicalId, physicalId, generation, owned.size)
                ProtectedObjectReference(dataClass, logicalId, physicalId, generation, owned.size,
                    JournalDigest.objectContent(owned).bytes(), binding)
            } finally { owned.fill(0) }
        }
        internal fun read(input: ByteBuffer): ProtectedObjectReference {
            val role = input.get().toInt() and 255
            val logical = input.readAscii()
            val physical = input.readAscii()
            val generation = input.int
            val length = input.int
            validate(role, logical, physical, generation, length)
            val digest = ByteArray(32).also(input::get)
            require(input.get().toInt() == 2) { "LEGACY_REFERENCE_REQUIRES_EXPLICIT_MIGRATION" }
            val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(input::get)
            val binding = try { SecureOperationBinding(operation, input.long) } finally { operation.fill(0) }
            return ProtectedObjectReference(role, logical, physical, generation, length, digest, binding)
        }
        private fun validate(role: Int, logical: String, physical: String, generation: Int, length: Int) {
            require(role in 1..13 && logical.validRecordId() && physical.validRecordId())
            require(generation > 0 && length in 1..JournalLimits.OBJECT_BYTES)
        }
    }
}

/** Contains only references plus bounded catalog/settings projections inside the encrypted checkpoint. */
internal class ProtectedStateSnapshot private constructor(
    private val store: ByteArray, val revision: Long, val selectedProfile: String?,
    private val refs: List<ProtectedObjectReference>, private val settings: ByteArray, private val catalog: ByteArray,
    private val operation: ByteArray,
    val disposition: ProtectedStateDisposition,
) {
    fun storeId(): ByteArray = store.clone()
    fun operationId(): ByteArray = operation.clone()
    fun objects(): List<ProtectedObjectReference> = Collections.unmodifiableList(ArrayList(refs))
    fun settingsBytes(): ByteArray = settings.clone()
    fun catalogBytes(): ByteArray = catalog.clone()
    fun objectFor(id: String, dataClass: Int): ProtectedObjectReference? = refs.singleOrNull {
        it.logicalId == id && it.dataClass == dataClass
    }
    fun encode(): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.writeInt(0x4b505331); output.writeByte(2); output.writeByte(disposition.wire)
            output.write(store); output.writeLong(revision); output.write(operation)
            output.writeAscii(selectedProfile.orEmpty(), allowEmpty = true)
            output.writeInt(settings.size); output.write(settings)
            output.writeInt(catalog.size); output.write(catalog)
            output.writeInt(refs.size); refs.forEach { it.write(output) }
        }
        return bytes.toByteArray().also { require(it.size <= JournalLimits.CHECKPOINT_BYTES) }
    }
    companion object {
        fun create(storeId: ByteArray, revision: Long, selected: String?, references: List<ProtectedObjectReference>,
            settings: ByteArray, catalog: ByteArray, operationId: ByteArray,
            disposition: ProtectedStateDisposition = ProtectedStateDisposition.VERIFIED): ProtectedStateSnapshot {
            val store = storeId.clone()
            val operation = operationId.clone()
            val ownedSettings = settings.clone()
            val ownedCatalog = catalog.clone()
            val ownedRefs = references.toTypedArray().toList()
            try {
                require(store.size == 16 && store.any { it != 0.toByte() } && revision > 0 && revision and 1L == 0L)
                require(operation.size == JournalLimits.OPERATION_BYTES && operation.any { it != 0.toByte() })
                require(selected == null || selected.validRecordId())
                require(ownedSettings.size in 1..64 * 1024 && ownedCatalog.size in 1..512 * 1024)
                require(ownedRefs.size <= JournalLimits.OBJECTS)
                require(ownedRefs.map { it.dataClass to it.logicalId }.toSet().size == ownedRefs.size)
                require(ownedRefs.map { it.physicalId }.toSet().size == ownedRefs.size)
                require(ownedRefs.sumOf { it.length.toLong() } <= JournalLimits.LIVE_OBJECT_BYTES)
                require(ownedRefs.all { it.binding.revision <= revision }) { "FUTURE_OBJECT_REVISION" }
                val ordered = ownedRefs.sortedWith(compareBy<ProtectedObjectReference> { it.dataClass }.thenBy { it.logicalId })
                return ProtectedStateSnapshot(store, revision, selected, ordered, ownedSettings, ownedCatalog, operation, disposition)
            } catch (failure: Throwable) { store.fill(0); operation.fill(0); ownedSettings.fill(0); ownedCatalog.fill(0); throw failure }
        }
        fun decode(input: ByteArray): ProtectedStateSnapshot {
            val owned = input.clone()
            try {
                require(owned.size in 77..JournalLimits.CHECKPOINT_BYTES)
                val bytes = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
                require(bytes.int == 0x4b505331 && bytes.get().toInt() == 2)
                val dispositionCode = bytes.get().toInt()
                val disposition = requireNotNull(ProtectedStateDisposition.entries.singleOrNull { it.wire == dispositionCode })
                val store = ByteArray(16).also(bytes::get)
                val revision = bytes.long
                val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(bytes::get)
                val selected = bytes.readAscii(allowEmpty = true).ifEmpty { null }
                val settings = bytes.readBounded(64 * 1024)
                val catalog = bytes.readBounded(512 * 1024)
                try {
                    val count = bytes.int
                    require(count in 0..JournalLimits.OBJECTS && count <= bytes.remaining() / 86)
                    val refs = List(count) { ProtectedObjectReference.read(bytes) }
                    require(!bytes.hasRemaining())
                    val decoded = create(store, revision, selected, refs, settings, catalog, operation, disposition)
                    val canonical = decoded.encode()
                    try { require(MessageDigest.isEqual(owned, canonical)) { "noncanonical checkpoint" } }
                    finally { canonical.fill(0) }
                    return decoded
                } finally { store.fill(0); operation.fill(0); settings.fill(0); catalog.fill(0) }
            } catch (_: java.nio.BufferUnderflowException) { throw IllegalArgumentException("truncated checkpoint") }
            finally { owned.fill(0) }
        }
    }
}

/** No writer, Room, DataStore, directory creation or Keystore generation capability is accepted. */
internal class ProtectedStateSnapshotReader(
    private val journal: ProtectedStateOperationJournal,
    private val readEncryptedObject: (ProtectedObjectReference) -> ByteArray,
) {
    fun readCheckpointSnapshot(): ProtectedStateSnapshot {
        val raw = journal.readCheckpoint()
        return try { ProtectedStateSnapshot.decode(raw) } finally { raw.fill(0) }
    }

    fun requirePhysicalProjection(snapshot: ProtectedStateSnapshot, observations: List<ProjectionFileObservation>) {
        journal.readProjectionWitness(snapshot).requireMatches(snapshot, observations)
    }

    fun readVerified(): ProtectedStateSnapshot {
        val start = System.nanoTime()
        val snapshot = readCheckpointSnapshot()
        for (reference in snapshot.objects()) {
            check(System.nanoTime() - start <= JournalLimits.RESTORE_NANOS) { "protected read deadline" }
            val encrypted = readEncryptedObject(reference)
            try { check(reference.matches(encrypted)) { "protected object mismatch" } }
            finally { encrypted.fill(0) }
        }
        val final = journal.readControl()
        check(!final.dirty && final.revision == snapshot.revision && final.storeId().contentEquals(snapshot.storeId()))
        return snapshot
    }
}

internal fun String.validRecordId(): Boolean = length in 1..64 && all { it in 'a'..'z' || it in '0'..'9' || it == '-' }
private fun DataOutputStream.writeAscii(value: String, allowEmpty: Boolean = false) {
    require((allowEmpty && value.isEmpty()) || value.validRecordId())
    writeByte(value.length); write(value.toByteArray(Charsets.US_ASCII))
}
private fun ByteBuffer.readAscii(allowEmpty: Boolean = false): String {
    val length = get().toInt() and 255
    require(length in (if (allowEmpty) 0 else 1)..64 && length <= remaining())
    val raw = ByteArray(length).also(::get)
    val value = raw.toString(Charsets.US_ASCII)
    require((allowEmpty && value.isEmpty()) || value.validRecordId())
    require(raw.contentEquals(value.toByteArray(Charsets.US_ASCII)))
    return value
}
private fun ByteBuffer.readBounded(maximum: Int): ByteArray {
    val length = int
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get)
}

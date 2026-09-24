// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableDirectory
import org.kurdistanvpn.core.nativeapi.DurableFileIdentity
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.core.nativeapi.DurableSnapshot
import org.kurdistanvpn.core.nativeapi.DurableWriter
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import org.kurdistanvpn.core.nativeapi.DurableBounds
import org.kurdistanvpn.core.nativeapi.DurableReadResult
import org.kurdistanvpn.core.nativeapi.DurableMutationResult
import org.kurdistanvpn.data.metadata.CatalogProjection
import org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.ProtectedProjectionEntity
import org.kurdistanvpn.data.metadata.RecipientBindingEntity
import org.kurdistanvpn.data.settings.ProductSettingsStore
import org.kurdistanvpn.data.settings.SettingsProjection
import org.kurdistanvpn.data.settings.SettingsProjectionCodec
import org.kurdistanvpn.data.settings.SettingsProjectionIdentity
import android.content.Context
import android.database.DatabaseErrorHandler
import android.database.sqlite.SQLiteDatabase
import android.os.ParcelFileDescriptor
import android.os.UserManager
import android.system.Os
import android.system.OsConstants
import android.system.ErrnoException
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.DurableOwnedDirectory
import org.kurdistanvpn.data.secure.AndroidKeystoreKek
import org.kurdistanvpn.data.secure.KeyInvalidatedException
import org.kurdistanvpn.data.secure.MissingKeyException
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.secure.ClientKeySummary
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withContext
import org.kurdistanvpn.data.settings.SettingsApplyCoordinator
import org.kurdistanvpn.data.settings.SettingsMutationPort
import org.kurdistanvpn.data.settings.SettingsPortResult
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.domain.SettingsRepository
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.data.secure.*

/** Explicit provisioning only. The known cross-process lock covers the last absence check and
 * first-use key creation. An empty existing directory is not evidence that any prior reset
 * completed; this boundary admits only a new user-requested initialization with no old state. */
internal fun <T> initializeUnderEmptyRootLease(primitives: DurableFilePrimitives,
    directory: DurableDirectory, lock: DurableFileIdentity,
    requireAbsentSource: () -> Unit, create: () -> T): T {
    val acquired = primitives.openWriter(directory, "protected-state.lock", lock)
    check(acquired.code == DurableCode.OK) { "INITIALIZATION_LOCK_UNAVAILABLE" }
    val writer = checkNotNull(acquired.writer)
    var failure: Throwable? = null
    try {
        val inventory = writer.list(DurableBounds.MAX_ENTRIES)
        check(inventory.code == DurableCode.OK) { "INITIALIZATION_INVENTORY_UNPROVEN" }
        val entries = checkNotNull(inventory.entries)
        check(entries.size == 1 && entries.single().leaf == "protected-state.lock" &&
            entries.single().identity == lock && entries.single().length == 0L) {
            "EXISTING_STATE_CANNOT_BE_BOOTSTRAPPED"
        }
        val observed = writer.read("protected-state.lock", 1)
        val lockSnapshot = observed.snapshot
        check(observed.code == DurableCode.OK && lockSnapshot?.identity == lock &&
            lockSnapshot.size == 0) { "INITIALIZATION_LOCK_IDENTITY_UNPROVEN" }
        requireAbsentSource()
        return create()
    } catch (error: Throwable) { failure = error; throw error }
    finally {
        if (writer.closeResult() != DurableCode.OK) {
            val uncertainty = IllegalStateException("INITIALIZATION_UNPROVEN")
            if (failure == null) throw uncertainty else failure.addSuppressed(uncertainty)
        }
    }
}

/** Authenticated in the existing KEK envelope. Inodes are installation-local identities,
 * not portable backup identifiers or a hardware anti-rollback anchor. */
internal class ProtectedStoreIdentity private constructor(
    private val epoch: ByteArray, private val uid: Long,
    private val directory: DurableFileIdentity, private val lock: DurableFileIdentity,
    private val keyGeneration: Int,
) {
    fun encode(): ByteArray = java.nio.ByteBuffer.allocate(65).putInt(0x4b534931).put(1)
        .put(epoch).putLong(uid).putLong(directory.device).putLong(directory.inode)
        .putLong(lock.device).putLong(lock.inode).putInt(keyGeneration).array()
    fun requireMatches(current: DurableDirectory, currentLock: DurableFileIdentity, storeId: ByteArray, generation: Int) {
        val owned = storeId.clone()
        try { check(uid == current.expectedUid && directory == current.identity && lock == currentLock &&
            keyGeneration == generation && MessageDigest.isEqual(epoch, owned)) { "STORE_IDENTITY_MISMATCH" } }
        finally { owned.fill(0) }
    }
    companion object {
        fun create(directory: DurableDirectory, lock: DurableFileIdentity, storeId: ByteArray, generation: Int): ProtectedStoreIdentity {
            val owned = storeId.clone()
            try {
                require(owned.size == 16 && owned.any { it != 0.toByte() } && generation > 0)
                require(lock.device == directory.identity.device && lock.inode != directory.identity.inode)
                return ProtectedStoreIdentity(owned, directory.expectedUid, directory.identity, lock, generation)
            } catch (failure: Throwable) { owned.fill(0); throw failure }
        }
        fun decode(input: ByteArray): ProtectedStoreIdentity {
            val owned = input.clone()
            try {
                require(owned.size == 65)
                val reader = java.nio.ByteBuffer.wrap(owned)
                require(reader.int == 0x4b534931 && reader.get().toInt() == 1)
                val epoch = ByteArray(16).also(reader::get)
                try {
                    val uid = reader.long
                    require(org.kurdistanvpn.core.nativeapi.DurableBounds.validUid(uid))
                    val directory = DurableFileIdentity(reader.long, reader.long)
                    val lock = DurableFileIdentity(reader.long, reader.long)
                    return create(DurableDirectory(0, uid, directory), lock, epoch, reader.int)
                } finally { epoch.fill(0) }
            } finally { owned.fill(0) }
        }
    }
}

/** The sole writer adapter. Restoration receives only [readOnly] and cannot bootstrap a lock. */
internal class EncryptedJournalStorage private constructor(
    private val directory: DurableDirectory,
    private val primitives: DurableFilePrimitives,
    private val codec: SecureEnvelopeCodec,
    private val key: KeyEncryptionKey,
    private val lockIdentity: DurableFileIdentity?,
    private val random: SecureRandom,
) : JournalStorage {
    private val monitor = Any()
    private var writer: DurableWriter? = null
    private var writerThread: Thread? = null
    private var poisoned = false

    /** A read-only, explicitly owned view for one capture; never retained by the facade. */
    fun captureReadScope() = CaptureReadScope()

    inner class CaptureReadScope internal constructor() : JournalStorage by this@EncryptedJournalStorage, AutoCloseable {
        private var closed = false
        private val entries = LinkedHashMap<String, AuthenticatedJournalRead>()
        private var retainedBytes = 0
        @Synchronized override fun read(name: String, maximum: Int): ByteArray? {
            check(!closed) { "CAPTURE_READ_SCOPE_CLOSED" }
            return this@EncryptedJournalStorage.read(name, maximum, this)
        }
        override fun <T> exclusive(block: () -> T): T = error("READ_ONLY_CAPTURE")
        override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray): Unit = error("READ_ONLY_CAPTURE")
        override fun delete(name: String, expected: ByteArray): Unit = error("READ_ONLY_CAPTURE")
        @Synchronized override fun inventory(maximum: Int): List<JournalStoredEntry> {
            check(!closed) { "CAPTURE_READ_SCOPE_CLOSED" }
            return this@EncryptedJournalStorage.inventory(maximum)
        }
        internal fun previous(name: String, encoded: ByteArray, maximum: Int): ByteArray? {
            val entry = entries[name] ?: return null
            if (entry.generation != key.generation || !MessageDigest.isEqual(entry.encoded, encoded)) return null
            require(entry.plaintext.size <= maximum)
            return entry.plaintext.clone()
        }
        internal fun remember(name: String, encoded: ByteArray, plaintext: ByteArray) {
            // Controls/store identities always unwrap afresh, as do all selected authority objects.
            if (!(name.startsWith("journal-checkpoint-") || name.startsWith("journal-projection-") ||
                    name.startsWith("journal-record-") || name.startsWith("journal-intent-") ||
                    name.startsWith("journal-resolution-"))) return
            entries.remove(name)?.let { retainedBytes -= it.encoded.size + it.plaintext.size; it.close() }
            val size = encoded.size.toLong() + plaintext.size
            // The measured capture has 16 distinct eligible records. Larger histories fall back
            // to ordinary authentication instead of retaining unbounded decrypted journal data.
            if (entries.size >= 16 || size > 256 * 1024 - retainedBytes) return
            entries[name] = AuthenticatedJournalRead(encoded.clone(), plaintext.clone(), key.generation)
            retainedBytes += size.toInt()
        }
        @Synchronized override fun close() {
            closed = true
            entries.values.forEach { it.close() }
            entries.clear(); retainedBytes = 0
        }
    }

    private class AuthenticatedJournalRead(val encoded: ByteArray, val plaintext: ByteArray, val generation: Int) {
        fun close() { encoded.fill(0); plaintext.fill(0) }
    }

    /** Only a newly provisioned installation may call this. Existing data is never adopted. */
    fun provisionStoreIdentity(storeId: ByteArray) = exclusive {
        check(inventory(JournalLimits.OBJECTS).all { it.name == LOCK }) { "EXISTING_STATE_CANNOT_BE_BOOTSTRAPPED" }
        val binding = ProtectedStoreIdentity.create(directory, checkNotNull(lockIdentity), storeId, key.generation).encode()
        try {
            compareAndReplace("journal-store", null, binding)
            requireStoreIdentity(storeId)
        } finally { binding.fill(0) }
    }

    private fun requireStoreIdentity(storeId: ByteArray) {
        val lockRead = primitives.read(directory, LOCK, 1)
        check(lockRead.code == DurableCode.OK && lockRead.snapshot?.size == 0) { "LOCK_IDENTITY_UNPROVEN" }
        val raw = checkNotNull(read("journal-store", 65)) { "STORE_IDENTITY_MISSING" }
        try { ProtectedStoreIdentity.decode(raw).requireMatches(directory, checkNotNull(lockRead.snapshot).identity,
            storeId, key.generation) } finally { raw.fill(0) }
    }

    override fun <T> exclusive(block: () -> T): T = synchronized(monitor) {
        check(!poisoned && writer == null && lockIdentity != null) { "WRITE_CAPABILITY_UNAVAILABLE" }
        val lease = primitives.openWriter(directory, LOCK, lockIdentity)
        if (lease.code != DurableCode.OK) throw IOException("WRITER_UNAVAILABLE_${lease.code.name}")
        val acquired = checkNotNull(lease.writer)
        writer = acquired
        writerThread = Thread.currentThread()
        var failure: Throwable? = null
        try { block() }
        catch (error: Throwable) { failure = error; throw error }
        finally {
            writer = null
            writerThread = null
            val close = acquired.closeResult()
            if (close != DurableCode.OK) {
                poisoned = true
                val uncertainty = IOException("MUTATION_UNPROVEN")
                if (failure != null) failure.addSuppressed(uncertainty) else throw uncertainty
            }
        }
    }

    /** The closed projection writer can only borrow the exact thread-bound journal lease. */
    fun <T> withCurrentWriter(block: (DurableWriter) -> T): T? = synchronized(monitor) {
        if (writerThread !== Thread.currentThread() || writer == null || poisoned) null else block(checkNotNull(writer))
    }

    /** Ciphertext only. Reading an absent or corrupt reference never repairs storage. */
    fun readObject(name: String): ByteArray? = readObject(name, JournalLimits.OBJECT_BYTES)

    fun readObject(name: String, maximum: Int): ByteArray? {
        require(name.startsWith("object-") && name.validRecordId() && maximum in 1..JournalLimits.OBJECT_BYTES)
        val observed = primitives.read(directory, name, maximum)
        if (observed.code == DurableCode.ABSENT) return null
        if (observed.code != DurableCode.OK) throw IOException("OBJECT_READ_UNPROVEN")
        return checkNotNull(observed.snapshot).bytes
    }

    fun objectWriter(operationId: ByteArray): ImmutableProtectedObjectWriter {
        val operation = operationId.clone()
        require(operation.size == JournalLimits.OPERATION_BYTES && operation.any { it != 0.toByte() })
        return object : ImmutableProtectedObjectWriter {
            override fun requireDirtyOperation(operation: ByteArray) {
                check(MessageDigest.isEqual(operation, operationIdOwned)) { "WRONG_OPERATION" }
                currentWriter()
                val raw = checkNotNull(read("journal-control", JournalLimits.RECORD_BYTES))
                try {
                    val control = JournalControl.decode(raw)
                    check(control.dirty && MessageDigest.isEqual(control.operationId(), operationIdOwned)) {
                        "DIRTY_OPERATION_REQUIRED"
                    }
                } finally { raw.fill(0) }
            }
            private val operationIdOwned = operation
            override fun read(name: String): ByteArray? = readObject(name)
            override fun create(name: String, bytes: ByteArray) {
                val owned = bytes.clone()
                try {
                    requireDirtyOperation(operationIdOwned)
                    require(name.startsWith("object-") && name.validRecordId() && owned.size in 1..JournalLimits.OBJECT_BYTES)
                    val active = currentWriter()
                    check(active.read(name, JournalLimits.OBJECT_BYTES).code == DurableCode.ABSENT) { "IMMUTABLE_OBJECT_EXISTS" }
                    val outcome = active.replace(name, temporaryLeaf(), null, owned, JournalLimits.OBJECT_BYTES).code
                    if (outcome != DurableCode.OK) {
                        if (outcome == DurableCode.MUTATION_UNPROVEN) poisoned = true
                        throw IOException("OBJECT_CREATE_${outcome.name}")
                    }
                    val observed = checkNotNull(readObject(name))
                    try { check(MessageDigest.isEqual(owned, observed)) { "OBJECT_REOPEN_MISMATCH" } }
                    finally { observed.fill(0) }
                    requireDirtyOperation(operationIdOwned)
                } finally { owned.fill(0) }
            }
        }
    }

    /** GC receives ciphertext CAS operations only, never decryption or product-state authority. */
    fun garbageObjects(): JournalObjectAccess = object : JournalObjectAccess {
        override fun inventory(): List<JournalStoredEntry> = this@EncryptedJournalStorage.inventory(JournalLimits.OBJECTS)
        override fun read(name: String): ByteArray? = readObject(name)
        override fun read(name: String, maximum: Int): ByteArray? = readObject(name, maximum)
        override fun delete(name: String, expected: ByteArray) {
            require(name.startsWith("object-") && name.validRecordId())
            val owned = expected.clone()
            try {
                val active = currentWriter()
                val current = active.read(name, owned.size)
                check(current.code == DurableCode.OK)
                val snapshot = checkNotNull(current.snapshot)
                val actual = snapshot.bytes
                try { check(MessageDigest.isEqual(owned, actual)) } finally { actual.fill(0) }
                if (active.delete(name, snapshot, owned.size).code != DurableCode.OK) {
                    poisoned = true; throw IOException("MUTATION_UNPROVEN")
                }
            } finally { owned.fill(0) }
        }
    }

    private fun currentWriter(): DurableWriter {
        check(!poisoned && writerThread === Thread.currentThread()) { "WRITER_CAPABILITY_UNAVAILABLE" }
        return checkNotNull(writer) { "WRITER_CAPABILITY_UNAVAILABLE" }
    }

    override fun read(name: String, maximum: Int): ByteArray? = read(name, maximum, null)

    private fun read(name: String, maximum: Int, scope: CaptureReadScope?): ByteArray? {
        require(name.validRecordId() && maximum in 1..JournalLimits.OBJECT_BYTES)
        // Bound native allocation and wiping to this record plus the envelope allowance.
        val result = primitives.read(directory, leaf(name), minOf(JournalLimits.OBJECT_BYTES, maximum + 2048))
        if (result.code == DurableCode.ABSENT) return null
        if (result.code != DurableCode.OK) throw IOException("PROTECTED_READ_${result.code.name}")
        val encoded = checkNotNull(result.snapshot).bytes
        return try {
            require(codec.keyGeneration(encoded) == key.generation)
            scope?.previous(name, encoded, maximum)?.let { return it }
            val opened = codec.open(encoded, name, key)
            try {
                require(opened.dataClass == category(name) && opened.plaintext.size <= maximum)
                if (name == "journal-control") requireStoreIdentity(JournalControl.decode(opened.plaintext).storeId())
                scope?.remember(name, encoded, opened.plaintext)
                opened.plaintext.clone()
            } finally { opened.plaintext.fill(0) }
        } finally { encoded.fill(0) }
    }

    override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
        val acquired = currentWriter()
        require(name.validRecordId() && replacement.isNotEmpty() && replacement.size <= JournalLimits.CHECKPOINT_BYTES)
        val expectedCopy = expected?.clone()
        val replacementCopy = replacement.clone()
        val current = acquired.read(leaf(name), JournalLimits.OBJECT_BYTES)
        try {
            val old: DurableSnapshot? = when (current.code) {
                DurableCode.ABSENT -> { check(expectedCopy == null); null }
                DurableCode.OK -> checkNotNull(current.snapshot).also { snapshot ->
                    check(expectedCopy != null)
                    val encoded = snapshot.bytes
                    try {
                        val opened = codec.open(encoded, name, key)
                        try { check(opened.dataClass == category(name) && MessageDigest.isEqual(expectedCopy, opened.plaintext)) }
                        finally { opened.plaintext.fill(0) }
                    } finally { encoded.fill(0) }
                }
                else -> throw IOException("EXPECTED_OLD_UNPROVEN")
            }
            val encoded = codec.seal(name, category(name), replacementCopy, key)
            try {
                val code = acquired.replace(leaf(name), temporaryLeaf(), old, encoded, JournalLimits.OBJECT_BYTES).code
                if (code != DurableCode.OK) {
                    if (code == DurableCode.MUTATION_UNPROVEN) poisoned = true
                    throw IOException("PROTECTED_REPLACE_${code.name}")
                }
            } finally { encoded.fill(0) }
        } finally { expectedCopy?.fill(0); replacementCopy.fill(0) }
    }

    override fun delete(name: String, expected: ByteArray) {
        val acquired = currentWriter()
        check(!poisoned && name.validRecordId())
        val maximum = minOf(JournalLimits.OBJECT_BYTES, expected.size + 2048)
        val current = acquired.read(leaf(name), maximum)
        check(current.code == DurableCode.OK)
        val snapshot = checkNotNull(current.snapshot)
        val encoded = snapshot.bytes
        val expectedCopy = expected.clone()
        try {
            val opened = codec.open(encoded, name, key)
            try { check(opened.dataClass == category(name) && MessageDigest.isEqual(expectedCopy, opened.plaintext)) }
            finally { opened.plaintext.fill(0) }
            val code = acquired.delete(leaf(name), snapshot, encoded.size).code
            if (code != DurableCode.OK) { poisoned = true; throw IOException("MUTATION_UNPROVEN") }
        } finally { encoded.fill(0); expectedCopy.fill(0) }
    }

    override fun inventory(maximum: Int): List<JournalStoredEntry> {
        val observed = primitives.list(directory, maximum)
        check(observed.code == DurableCode.OK) { "BOUNDED_INVENTORY_UNAVAILABLE" }
        return checkNotNull(observed.entries).map { entry ->
            val name = if (entry.leaf.startsWith("journal-") && entry.leaf.endsWith(".blob")) {
                entry.leaf.removeSuffix(".blob")
            } else entry.leaf
            JournalStoredEntry(name, entry.length)
        }
    }

    private fun temporaryLeaf(): String {
        val bytes = ByteArray(16).also(random::nextBytes)
        return try { "pending-" + bytes.joinToString("") { "%02x".format(it) } }
        finally { bytes.fill(0) }
    }
    private fun leaf(name: String): String = "$name.blob"
    private fun category(name: String): SecureDataClass = when {
        ProtectedUiDraftStore.isName(name) -> SecureDataClass.OPERATION_STATE
        ProtectedProbeHistoryStore.isName(name) -> SecureDataClass.PROBE_HISTORY
        ProtectedProbeHistoryStore.isUpdateName(name) -> SecureDataClass.UPDATE_STATE
        name == "journal-control" || name == "journal-store" -> SecureDataClass.PROTECTED_JOURNAL_CONTROL
        name == "journal-reset" || name == "journal-reset-ready" -> SecureDataClass.PROTECTED_RESET_MANIFEST
        name.startsWith("journal-checkpoint-") || name.startsWith("journal-projection-") -> SecureDataClass.PROTECTED_CHECKPOINT
        name == "journal-gc" || name == ProtectedPresentationOverlay.NAME || name.startsWith("journal-record-") || name.startsWith("journal-intent-") ||
            name.startsWith("journal-resolution-") -> SecureDataClass.PROTECTED_JOURNAL_RECORD
        else -> error("UNKNOWN_JOURNAL_RECORD")
    }

    companion object {
        const val LOCK = "protected-state.lock"
        /** The caller must have independently established the expected existing lock inode. */
        fun writer(directory: DurableDirectory, primitives: DurableFilePrimitives, codec: SecureEnvelopeCodec,
            key: KeyEncryptionKey, expectedLock: DurableFileIdentity): EncryptedJournalStorage =
            EncryptedJournalStorage(directory, primitives, codec, key, expectedLock, SecureRandom())
        fun readOnly(directory: DurableDirectory, primitives: DurableFilePrimitives, codec: SecureEnvelopeCodec,
            existingKey: KeyEncryptionKey): EncryptedJournalStorage =
            EncryptedJournalStorage(directory, primitives, codec, existingKey, null, SecureRandom())
    }
}

/** Fixed child names only. The owning root and native directory capability are supplied explicitly. */
internal class ProjectionLeafLayout(val room: String, val settings: String) {
    init {
        require(DurableBounds.leaf(room) != null && room.endsWith(".db"))
        require(DurableBounds.leaf(settings) != null && settings.endsWith(".preferences_pb"))
        require(listOf(room, settings).none { it.startsWith("journal-") || it.startsWith("object-") ||
            it == EncryptedJournalStorage.LOCK })
        require(room != settings)
        require(listOf("$room-wal", "$room-shm", "$room-journal", "$settings.tmp").all { DurableBounds.leaf(it) != null })
    }
    fun leaf(role: ProjectionFileRole): String = when (role) {
        ProjectionFileRole.ROOM_MAIN -> room
        ProjectionFileRole.ROOM_WAL -> "$room-wal"
        ProjectionFileRole.ROOM_SHM -> "$room-shm"
        ProjectionFileRole.ROOM_JOURNAL -> "$room-journal"
        ProjectionFileRole.DATASTORE -> settings
    }
    fun requireNoUnboundSidecars(names: List<String>) {
        val known = ProjectionFileRole.entries.map(::leaf).toSet()
        check(names.none { (it.startsWith("$room-") || it.startsWith("$settings.")) && it !in known }) {
            "UNBOUND_PROJECTION_SIDECAR"
        }
    }
}

/** Native bounded reads only. This class has no Room, DataStore, path-opening or repair capability. */
internal class ClosedProjectionFiles(private val directory: DurableDirectory,
    private val primitives: DurableFilePrimitives, private val layout: ProjectionLeafLayout) {
    fun observe(writer: DurableWriter? = null, synchronize: Boolean = false,
        allowAbsent: Boolean = false): List<ProjectionFileObservation> {
        check(!synchronize || writer != null) { "BROKER_WRITER_REQUIRED" }
        if (synchronize) {
            val acquired = checkNotNull(writer)
            for (role in ProjectionFileRole.entries) {
                val restricted = acquired.restrictAndObserveExisting(layout.leaf(role), limit(role))
                check(restricted.code == DurableCode.OK || restricted.code == DurableCode.ABSENT) {
                    "PROJECTION_MODE_RESTRICTION_UNPROVEN"
                }
            }
        }
        val inventory = if (writer == null) primitives.list(directory, JournalLimits.OBJECTS) else writer.list(JournalLimits.OBJECTS)
        check(inventory.code == DurableCode.OK) { "PROJECTION_INVENTORY_UNPROVEN" }
        layout.requireNoUnboundSidecars(checkNotNull(inventory.entries).map { it.leaf })
        val reads = ProjectionFileRole.entries.map { role -> role to read(role, writer) }
        for ((role, result) in reads) {
            check(result.code == DurableCode.OK || result.code == DurableCode.ABSENT) { "PROJECTION_READ_UNPROVEN" }
            if (role == ProjectionFileRole.ROOM_MAIN || role == ProjectionFileRole.DATASTORE) {
                check(allowAbsent || (result.code == DurableCode.OK && checkNotNull(result.snapshot).size > 0)) {
                    "PROJECTION_FILE_MISSING"
                }
            } else check(result.snapshot?.size.let { it == null || it == 0 }) { "UNCLOSED_SQLITE_SIDECAR" }
        }
        val observed = reads.map { (role, result) ->
            if (synchronize && result.code == DurableCode.OK) {
                val before = checkNotNull(result.snapshot)
                val synced = checkNotNull(writer).syncAndObserveExisting(layout.leaf(role), before, limit(role))
                check(synced.code == DurableCode.OK) { "PROJECTION_DURABILITY_UNPROVEN" }
                val after = checkNotNull(synced.snapshot)
                val a = before.bytes; val b = after.bytes
                try { check(before.identity == after.identity && MessageDigest.isEqual(a, b)) { "PROJECTION_SYNC_SUBSTITUTION" } }
                finally { a.fill(0); b.fill(0) }
                ProjectionFileObservation.fromRead(role, DurableReadResult(DurableCode.OK, after))
            } else ProjectionFileObservation.fromRead(role, result)
        }
        // Recheck all entries, including previously absent sidecars, after the final synchronization.
        val fresh = ProjectionFileRole.entries.map { ProjectionFileObservation.fromRead(it, read(it, writer)) }
        requireSameProjectionFiles(observed, fresh)
        val finalInventory = if (writer == null) primitives.list(directory, JournalLimits.OBJECTS) else writer.list(JournalLimits.OBJECTS)
        check(finalInventory.code == DurableCode.OK) { "PROJECTION_INVENTORY_UNPROVEN" }
        layout.requireNoUnboundSidecars(checkNotNull(finalInventory.entries).map { it.leaf })
        return java.util.Collections.unmodifiableList(ArrayList(observed))
    }

    fun settingsBytes(expected: List<ProjectionFileObservation>, writer: DurableWriter? = null): ByteArray {
        val result = read(ProjectionFileRole.DATASTORE, writer)
        val actual = ProjectionFileObservation.fromRead(ProjectionFileRole.DATASTORE, result)
        requireSameProjectionFiles(listOf(expected.single { it.role == ProjectionFileRole.DATASTORE }), listOf(actual))
        return checkNotNull(result.snapshot).bytes
    }

    fun roomVersion(expected: List<ProjectionFileObservation>, writer: DurableWriter): Int {
        val result = read(ProjectionFileRole.ROOM_MAIN, writer)
        requireSameProjectionFiles(listOf(expected.single { it.role == ProjectionFileRole.ROOM_MAIN }),
            listOf(ProjectionFileObservation.fromRead(ProjectionFileRole.ROOM_MAIN, result)))
        val bytes = checkNotNull(result.snapshot).bytes
        return try { ProductProjectionSchemaMigration.headerVersion(bytes) } finally { bytes.fill(0) }
    }

    private fun read(role: ProjectionFileRole, writer: DurableWriter?): DurableReadResult =
        if (writer == null) primitives.read(directory, layout.leaf(role), limit(role)) else writer.read(layout.leaf(role), limit(role))
    private fun limit(role: ProjectionFileRole) = when (role) {
        ProjectionFileRole.ROOM_MAIN -> JournalLimits.OBJECT_BYTES
        ProjectionFileRole.DATASTORE -> 65536
        // Closed SQLite sidecars must be absent or empty; one byte detects any violation.
        else -> 1
    }
}

private fun requireSameProjectionFiles(expected: List<ProjectionFileObservation>, observed: List<ProjectionFileObservation>) {
    check(expected.size == observed.size && expected.map { it.role } == observed.map { it.role }) { "PROJECTION_COVERAGE_MISMATCH" }
    for ((before, after) in expected.zip(observed)) {
        val a = before.bytes(); val b = after.bytes()
        try { check(MessageDigest.isEqual(a, b)) { "PHYSICAL_PROJECTION_CHANGED" } }
        finally { a.fill(0); b.fill(0) }
    }
}

/** The authenticated journal supplies both inputs. Physical equality is checked on every read. */
internal class ReadOnlyCheckpointProjectionAccess(private val files: ClosedProjectionFiles,
    private val checkpoint: () -> ProtectedStateSnapshot,
    private val physicalWitness: (ProtectedStateSnapshot) -> PhysicalProjectionWitness) : ProtectedProjectionReadAccess {
    fun withReaders(checkpoint: () -> ProtectedStateSnapshot,
        physicalWitness: (ProtectedStateSnapshot) -> PhysicalProjectionWitness) =
        ReadOnlyCheckpointProjectionAccess(files, checkpoint, physicalWitness)
    override fun read(): ProjectionImages = readForCheckpoint(checkpoint())
    override fun readForCheckpoint(snapshot: ProtectedStateSnapshot): ProjectionImages {
        val observed = files.observe()
        physicalWitness(snapshot).requireMatches(snapshot, observed)
        val catalog = snapshot.catalogBytes(); val settings = snapshot.settingsBytes()
        try {
            return ProjectionImages(catalog, settings, ProjectionImageWitness.reconstruct(snapshot.storeId(),
                snapshot.operationId(), snapshot.revision, catalog, settings), observed)
        } finally { catalog.fill(0); settings.fill(0) }
    }
}

/** Supplied only by the broker root. Null means there is no current thread-bound writer lease. */
internal interface ProjectionWriterLeaseAccess {
    fun <T> withCurrentWriter(block: (DurableWriter) -> T): T?
}

/** Own the typed wrapper BEFORE it starts any fallible acquisition. Failed closes are retained. */
internal class ProjectionOwnership : AutoCloseable {
    private val resources = ArrayList<AutoCloseable>()
    private var terminal = false
    fun <T : AutoCloseable> own(resource: T): T {
        try { resources += resource }
        catch (failure: Throwable) {
            try { resource.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
        if (terminal) { close(); error("PROJECTION_OWNER_ALREADY_TERMINAL") }
        return resource
    }
    fun isClean(): Boolean = terminal && resources.isEmpty()
    override fun close() {
        terminal = true
        var failure: Throwable? = null
        for (index in resources.lastIndex downTo 0) {
            try { resources[index].close(); resources.removeAt(index) }
            catch (error: Throwable) { if (failure == null) failure = error else failure.addSuppressed(error) }
        }
        if (failure != null) throw IllegalStateException("PROJECTION_CLEANUP_UNPROVEN", failure)
    }
}

internal interface ProjectionStoreSession {
    fun readCatalog(): CatalogProjection
    fun publishCatalog(expected: CatalogProjection, next: ProtectedProjectionEntity,
        rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
        operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?)
    fun readSettings(): SettingsProjection
    fun publishSettings(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity)
    fun recoverCatalog(expected: CatalogProjection, next: ProtectedProjectionEntity,
        rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
        operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) =
        publishCatalog(expected, next, rows, bindings, operation)
    fun recoverSettings(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) =
        publishSettings(expected, replacement, next)
}
internal interface ProjectionStoreOwnerFactory {
    fun requireRootIdentity()
    fun open(ownership: ProjectionOwnership, withSettings: Boolean): ProjectionStoreSession
    fun inspectClosed(writer: DurableWriter, files: ClosedProjectionFiles): ClosedSchemaProjection =
        error("CLOSED_SCHEMA_INSPECTION_UNSUPPORTED")
    fun openMigrating(ownership: ProjectionOwnership, withSettings: Boolean,
        permit: ProductProjectionSchemaMigration.Permit): ProjectionStoreSession = error("SCHEMA_MIGRATION_UNSUPPORTED")
}

internal data class ClosedSchemaProjection(val version: Int, val catalog: CatalogProjection,
    val settings: SettingsProjection, val physical: List<ProjectionFileObservation>)

/**
 * Interactive DIRTY-operation adapter only. No writer-supplied normalized success is accepted.
 * The binding resolver must use authenticated immutable objects and read-only recipient validation.
 */
internal class ClosedStoreProjectionAccess(private val owners: ProjectionStoreOwnerFactory,
    private val files: ClosedProjectionFiles, private val leases: ProjectionWriterLeaseAccess,
    private val readControl: () -> JournalControl, private val committed: ProtectedProjectionReadAccess,
    private val bindings: (ProtectedStateSnapshot) -> List<RecipientBindingEntity>) : ProtectedProjectionAccess {
    private val monitor = Any()
    private var pending: PendingProjection? = null
    private var poisoned = false
    private val unprovenOwners = ArrayList<ProjectionOwnership>()
    private class PendingProjection(val writer: DurableWriter, val snapshot: ProtectedStateSnapshot, val images: ProjectionImages)

    override fun requireClosedSchema(expected: ProtectedStateSnapshot, version: Int) {
        synchronized(monitor) {
            check(!poisoned)
            check(leases.withCurrentWriter { writer ->
                val control = readControl()
                check(!control.dirty && control.revision == expected.revision && control.storeId().contentEquals(expected.storeId()))
                val authenticated = committed.read().also { it.requireMatches(expected) }
                val inspected = owners.inspectClosed(writer, files)
                check(inspected.version == version)
                requireSameProjectionFiles(authenticated.physical(), inspected.physical)
                requireMatchingIdentities(inspected.catalog, inspected.settings)
                val bytes = expected.catalogBytes(); val settings = expected.settingsBytes()
                val actual = catalogInExpectedFormat(inspected.catalog, bytes); val actualSettings = inspected.settings.image()
                try { check(MessageDigest.isEqual(bytes, actual) && MessageDigest.isEqual(settings, actualSettings)) }
                finally { bytes.fill(0); settings.fill(0); actual.fill(0); actualSettings.fill(0) }
                check(inspected.catalog.bindings == bindings(expected).sortedBy { it.profileRecordId })
            } != null) { "BROKER_WRITER_REQUIRED" }
        }
    }

    override fun read(): ProjectionImages = synchronized(monitor) {
        check(!poisoned) { "PROJECTION_CLEANUP_UNPROVEN" }
        val current = pending
        if (current != null) {
            if (!readControl().dirty) {
                // A completed security write may be followed immediately by a new presentation
                // writer. Its old DIRTY cache is not committed evidence for either lease.
                pending = null
                return@synchronized committed.read()
            }
            val value = leases.withCurrentWriter { writer ->
                check(writer === current.writer) { "STALE_PROJECTION_LEASE" }
                requireDirty(current.snapshot)
                owners.requireRootIdentity()
                val observed = files.observe(writer)
                requireSameProjectionFiles(current.images.physical(), observed)
                ProjectionImages(current.images.catalog(), current.images.settings(), current.images.witness, observed)
            }
            if (value != null) return@synchronized value
            pending = null
        }
        committed.read()
    }

    override fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot) = write(expected.copyOwned(), replacement)
    override fun initialize(replacement: ProtectedStateSnapshot) = write(null, replacement)
    override fun recover(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot, replacement: ProtectedStateSnapshot) =
        write(null, replacement, prior to candidate)
    override fun migrateSchema(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot,
        replacement: ProtectedStateSnapshot, verifyEvidence: () -> Unit) = write(null, replacement, prior to candidate, verifyEvidence)

    private fun write(expected: ProjectionImages?, replacement: ProtectedStateSnapshot,
        recovery: Pair<ProtectedStateSnapshot, ProtectedStateSnapshot>? = null,
        schemaEvidence: (() -> Unit)? = null) = synchronized(monitor) {
        check(!poisoned) { "PROJECTION_CLEANUP_UNPROVEN" }
        pending = null
        val result = leases.withCurrentWriter { writer ->
            requireDirty(replacement)
            owners.requireRootIdentity()
            val initial = files.observe(writer, allowAbsent = expected == null && recovery == null)
            if (expected == null && recovery == null) check(initial.none { it.present }) { "EXISTING_PROJECTION_CANNOT_BE_INITIALIZED" }
            else if (expected != null) requireSameProjectionFiles(expected.physical(), initial)
            val permit = if (schemaEvidence == null) null else {
                schemaEvidence()
                check(readControl().kind == MutationKind.PROJECTION_SCHEMA)
                val inspected = owners.inspectClosed(writer, files)
                check(inspected.version == 2 || inspected.version == 3)
                requireSameProjectionFiles(initial, inspected.physical)
                val endpoints = checkNotNull(recovery)
                requireRecoveryComponents(inspected.catalog, inspected.settings, endpoints.first, endpoints.second, replacement)
                ProductProjectionSchemaMigration.Permit.acquire(writer, leases, readControl, replacement, schemaEvidence)
            }
            val catalogBytes = replacement.catalogBytes(); val settingsBytes = replacement.settingsBytes()
            try {
                val content = org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(catalogBytes)
                val rows = content.rows
                val relationships = bindings(replacement).toTypedArray().toList()
                val store = replacement.storeId().hexString(); val operation = replacement.operationId().hexString()
                val nextRoom = ProtectedProjectionEntity(storeEpoch = store, operationId = operation, revision = replacement.revision,
                    imageDigest = ProfileCatalogProjectionCodec.imageDigest(rows, relationships))
                val nextSettings = SettingsProjectionIdentity.capture(store, operation, replacement.revision, settingsBytes)
                if (permit != null) {
                    owners.requireRootIdentity()
                    requireSameProjectionFiles(initial, files.observe(writer))
                    permit.requireCurrentWriterAndDirtySchemaOperation()
                }
                withOwners(withSettings = true, permit = permit) { opened ->
                    val previousRoom = opened.readCatalog()
                    val previousSettings = opened.readSettings()
                    if (recovery != null) {
                        requireRecoveryComponents(previousRoom, previousSettings, recovery.first, recovery.second, replacement)
                    } else if (expected == null) {
                        check(previousRoom.rows.isEmpty() && previousRoom.bindings.isEmpty() && previousRoom.operation == null && previousRoom.witness == null &&
                            previousSettings.witness == null) { "PROJECTION_INITIALIZATION_NOT_EMPTY" }
                    } else {
                        val expectedCatalog = expected.catalog()
                        val observedRows = catalogInExpectedFormat(previousRoom, expectedCatalog)
                        expectedCatalog.fill(0)
                        val previousImage = previousSettings.image()
                        try {
                            check(MessageDigest.isEqual(observedRows, expected.catalog()) &&
                                MessageDigest.isEqual(previousImage, expected.settings())) { "STALE_PROJECTION_CONTENT" }
                            requireMatchingIdentities(previousRoom, previousSettings)
                        } finally { observedRows.fill(0); previousImage.fill(0) }
                    }
                    requireDirty(replacement)
                    if (recovery == null) {
                        opened.publishCatalog(previousRoom, nextRoom, rows, relationships, content.operation)
                        opened.publishSettings(previousSettings, settingsBytes, nextSettings)
                    } else {
                        opened.recoverCatalog(previousRoom, nextRoom, rows, relationships, content.operation)
                        opened.recoverSettings(previousSettings, settingsBytes, nextSettings)
                    }
                }
                // Both writable owners are closed here. Every present file is synchronized and reread.
                owners.requireRootIdentity()
                val beforeReader = files.observe(writer, synchronize = true)
                val observedRoom = withOwners(withSettings = false) { it.readCatalog() }
                owners.requireRootIdentity()
                val observedPhysical = files.observe(writer, synchronize = true)
                requireSameProjectionFiles(beforeReader, observedPhysical)
                val stored = files.settingsBytes(observedPhysical, writer)
                val observedSettings = try { runBlocking { SettingsProjectionCodec.fromStoredBytes(stored) } }
                    finally { stored.fill(0) }
                requireMatchingIdentities(observedRoom, observedSettings)
                check(observedRoom.witness == nextRoom && observedSettings.witness == nextSettings) { "PROJECTION_COMMIT_MISMATCH" }
                val freshRelationships = bindings(replacement).toTypedArray().toList()
                check(observedRoom.bindings == freshRelationships.sortedBy { it.profileRecordId }) { "RECIPIENT_PROJECTION_MISMATCH" }
                val actualRows = catalogInExpectedFormat(observedRoom, catalogBytes)
                val actualSettings = observedSettings.image()
                try {
                    val actual = ProjectionImages(actualRows, actualSettings, ProjectionImageWitness.reconstruct(replacement.storeId(),
                        replacement.operationId(), replacement.revision, actualRows, actualSettings), observedPhysical)
                    actual.requireMatches(replacement)
                    requireDirty(replacement)
                    pending = PendingProjection(writer, replacement, actual)
                } finally { actualRows.fill(0); actualSettings.fill(0) }
            } finally { catalogBytes.fill(0); settingsBytes.fill(0) }
        }
        check(result != null) { "BROKER_WRITER_REQUIRED" }
    }

    private fun requireDirty(snapshot: ProtectedStateSnapshot) {
        val current = readControl()
        val op = current.operationId(); val requested = snapshot.operationId()
        val store = current.storeId(); val expectedStore = snapshot.storeId()
        try { check(current.dirty && current.reservedCleanRevision == snapshot.revision &&
            MessageDigest.isEqual(op, requested) && MessageDigest.isEqual(store, expectedStore)) { "PROJECTION_DIRTY_LEASE_MISMATCH" } }
        finally { op.fill(0); requested.fill(0); store.fill(0); expectedStore.fill(0) }
    }

    /** Each independently atomic file may be at either authenticated endpoint, never a third value. */
    private fun requireRecoveryComponents(room: CatalogProjection, settings: SettingsProjection,
        prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot, replacement: ProtectedStateSnapshot) {
        requireDirty(candidate)
        check(prior.storeId().contentEquals(candidate.storeId()))
        var roomMatches = false; var settingsMatch = false
        val actualSettings = settings.image()
        try {
            for (snapshot in listOf(prior, candidate, replacement)) {
                val rows = snapshot.catalogBytes(); val image = snapshot.settingsBytes()
                try {
                    val relationships = bindings(snapshot).sortedBy { it.profileRecordId }
                    val expectedRoom = ProtectedProjectionEntity(storeEpoch = snapshot.storeId().hexString(),
                        operationId = snapshot.operationId().hexString(), revision = snapshot.revision,
                        imageDigest = ProfileCatalogProjectionCodec.imageDigest(ProfileCatalogProjectionCodec.decode(rows), relationships))
                    val expectedSettings = SettingsProjectionIdentity.capture(snapshot.storeId().hexString(),
                        snapshot.operationId().hexString(), snapshot.revision, image)
                    val actualRows = catalogInExpectedFormat(room, rows)
                    try { roomMatches = roomMatches || (MessageDigest.isEqual(actualRows, rows) && room.witness == expectedRoom && room.bindings == relationships) }
                    finally { actualRows.fill(0) }
                    settingsMatch = settingsMatch || (MessageDigest.isEqual(actualSettings, image) && settings.witness == expectedSettings)
                } finally { rows.fill(0); image.fill(0) }
            }
            if (!roomMatches || !settingsMatch) throw ProjectionSchemaRejected("UNBOUND_RECOVERY_PROJECTION")
        } finally { actualSettings.fill(0) }
    }

    private fun catalogInExpectedFormat(room: CatalogProjection, expected: ByteArray): ByteArray {
        // The expected descriptor is authenticated. Room supplies only the independently observed one.
        if (!org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.isProduct(expected) && room.operation == null) {
            return ProfileCatalogProjectionCodec.encode(room.rows)
        }
        return org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.encode(room.rows, room.operation)
    }

    private fun <T> withOwners(withSettings: Boolean, permit: ProductProjectionSchemaMigration.Permit? = null,
        action: (ProjectionStoreSession) -> T): T {
        val ownership = ProjectionOwnership()
        var failure: Throwable? = null
        try { return action(if (permit == null) owners.open(ownership, withSettings) else owners.openMigrating(ownership, withSettings, permit)) }
        catch (error: Throwable) { failure = error; throw error }
        finally {
            try { ownership.close() }
            catch (error: Throwable) {
                poisoned = true; unprovenOwners += ownership
                if (failure != null) failure.addSuppressed(error) else throw error
            }
        }
    }

    private fun requireMatchingIdentities(room: CatalogProjection, settings: SettingsProjection) {
        val a = checkNotNull(room.witness) { "ROOM_WITNESS_MISSING" }
        val b = checkNotNull(settings.witness) { "SETTINGS_WITNESS_MISSING" }
        check(a.storeEpoch == b.storeEpoch && a.operationId == b.operationId && a.revision == b.revision) {
            "CROSS_STORE_COMMIT_MISMATCH"
        }
    }
}

private fun ByteArray.hexString(): String = try { joinToString("") { "%02x".format(it) } } finally { fill(0) }

/** The only permitted schema step, checked again immediately before Room delegates migration. */
internal class PermittedProjectionCallback(private val delegate: androidx.sqlite.db.SupportSQLiteOpenHelper.Callback,
    private val permit: ProductProjectionSchemaMigration.Permit) : androidx.sqlite.db.SupportSQLiteOpenHelper.Callback(delegate.version) {
    override fun onConfigure(db: androidx.sqlite.db.SupportSQLiteDatabase) = delegate.onConfigure(db)
    override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase): Unit = error("SCHEMA_MIGRATION_CANNOT_INITIALIZE")
    override fun onOpen(db: androidx.sqlite.db.SupportSQLiteDatabase) = delegate.onOpen(db)
    override fun onUpgrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
        check(oldVersion == 2 && newVersion == 3) { "PROJECTION_SCHEMA_STEP_REJECTED" }
        permit.requireCurrentWriterAndDirtySchemaOperation()
        delegate.onUpgrade(db, oldVersion, newVersion)
    }
    override fun onDowngrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int): Unit = error("PROJECTION_DOWNGRADE_NOT_SUPPORTED")
    override fun onCorruption(db: androidx.sqlite.db.SupportSQLiteDatabase): Unit = error("PROJECTION_CORRUPTION_PRESERVED")
}

/** Default SQLite corruption recovery deletes files. Projection evidence must instead be preserved. */
internal class NonDestructiveProjectionCallback(private val delegate: androidx.sqlite.db.SupportSQLiteOpenHelper.Callback) :
    androidx.sqlite.db.SupportSQLiteOpenHelper.Callback(delegate.version) {
    override fun onConfigure(db: androidx.sqlite.db.SupportSQLiteDatabase) = delegate.onConfigure(db)
    override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) = delegate.onCreate(db)
    override fun onOpen(db: androidx.sqlite.db.SupportSQLiteDatabase) = delegate.onOpen(db)
    override fun onUpgrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int): Unit =
        error("PROJECTION_MIGRATION_REQUIRES_EXPLICIT_BROKER_REBUILD")
    override fun onDowngrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int): Unit =
        error("PROJECTION_DOWNGRADE_NOT_SUPPORTED")
    override fun onCorruption(db: androidx.sqlite.db.SupportSQLiteDatabase): Unit = error("PROJECTION_CORRUPT_PRESERVE_FOR_RECOVERY")
}

/** Reads only an exact, journal-owned copy of the v1 catalog. It never opens an original path. */
private object LegacyCopiedCatalogReader {
    fun read(copy: java.io.File): List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity> {
        require(copy.isAbsolute && copy.name == "migration-legacy-metadata.db" && copy.isFile)
        val database = SQLiteDatabase.openDatabase(copy.absolutePath, null,
            SQLiteDatabase.OPEN_READONLY or SQLiteDatabase.NO_LOCALIZED_COLLATORS,
            DatabaseErrorHandler { error("LEGACY_COPY_CORRUPT_PRESERVED") })
        try {
            check(database.isReadOnly) { "LEGACY_COPY_NOT_READ_ONLY" }
            database.rawQuery("PRAGMA journal_mode", null).use { cursor ->
                check(cursor.moveToFirst() && cursor.getString(0).equals("delete", ignoreCase = true)) {
                    "LEGACY_COPY_JOURNAL_UNQUALIFIED"
                }
            }
            return database.rawQuery(
                "SELECT localRecordId, transactionState, envelopeVersion, keyGeneration, health FROM profile_catalog ORDER BY localRecordId",
                null,
            ).use { cursor ->
                buildList {
                    while (cursor.moveToNext()) add(org.kurdistanvpn.data.metadata.ProfileCatalogEntity(
                        localRecordId = cursor.getString(0), transactionState = cursor.getString(1),
                        envelopeVersion = cursor.getInt(2), keyGeneration = cursor.getInt(3), health = cursor.getString(4),
                    ))
                }
            }.also { rows ->
                require(rows.size <= 1024 && rows.map { it.localRecordId }.toSet().size == rows.size)
            }
        } finally { database.close() }
    }
}

/**
 * A one-batch legacy reader. Every payload is native-FD read after the journal is DIRTY.
 * The metadata database is copied to one fixed, reset-recognized leaf only while it is queried;
 * its original is neither opened by path nor modified.
 */
private class FdSnapshotLegacyMigrationAccess(
    private val primitives: DurableFilePrimitives,
    private val metadata: DurableDirectory?,
    private val settings: DurableDirectory?,
    private val blobs: DurableDirectory?,
    private val target: DurableDirectory,
    private val targetRoot: java.io.File,
    private val storage: EncryptedJournalStorage,
) : LegacyMigrationReadAccess, AutoCloseable {
    private data class Batch(
        val rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, val settings: ByteArray,
        val objects: LinkedHashMap<LegacyObjectName, ByteArray>, val witness: ByteArray,
    ) {
        fun close() { settings.fill(0); objects.values.forEach { it.fill(0) }; witness.fill(0) }
    }
    private var batch: Batch? = null

    override fun rows(): List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity> {
        batch?.close()
        batch = capture()
        return checkNotNull(batch).rows
    }
    override fun settingsImage(): ByteArray = checkNotNull(batch) { "LEGACY_BATCH_NOT_STARTED" }.settings.clone()
    override fun objects(): List<LegacyObjectName> = checkNotNull(batch) { "LEGACY_BATCH_NOT_STARTED" }.objects.keys.toList()
    override fun envelope(name: LegacyObjectName): ByteArray = checkNotNull(batch) { "LEGACY_BATCH_NOT_STARTED" }.objects.getValue(name).clone()
    override fun sourceWitness(): ByteArray = checkNotNull(batch) { "LEGACY_BATCH_NOT_STARTED" }.witness.clone()
    override fun close() { batch?.close(); batch = null }

    private fun capture(): Batch {
        val metadataEntries = metadata?.let { listMetadata(it) }.orEmpty()
        val database = metadata?.let { readRequired(it, LEGACY_DATABASE) }
        val settingsBytes = settings?.let { readOptional(it, LEGACY_SETTINGS) }
        val blobBytes = readBlobs()
        try {
            val listedDatabase = metadataEntries.singleOrNull { it.leaf == LEGACY_DATABASE }
            check((database == null && listedDatabase == null) ||
                (database != null && listedDatabase != null && database.identity == listedDatabase.identity &&
                    database.size.toLong() == listedDatabase.length)) { "LEGACY_DATABASE_IDENTITY_CHANGED" }
            val rows = database?.let { snapshot -> readCopiedRows(snapshot) } ?: emptyList()
            val preferences = settingsBytes?.let { snapshot ->
                val stored = snapshot.bytes
                try { runBlocking { SettingsProjectionCodec.captureLegacyStoredBytes(stored).image() } }
                finally { stored.fill(0) }
            } ?: SettingsProjectionCodec.fromModel(ProductSettings())
            val objects = LinkedHashMap<LegacyObjectName, ByteArray>()
            for ((name, snapshot) in blobBytes) objects[name] = snapshot.bytes
            val witness = witness(database, settingsBytes, blobBytes, metadataEntries)
            return Batch(rows, preferences, objects, witness)
        } catch (failure: Throwable) {
            throw failure
        }
    }

    private fun listMetadata(directory: DurableDirectory): List<org.kurdistanvpn.core.nativeapi.DurableDirectoryEntry> {
        val listed = primitives.list(directory, DurableBounds.MAX_ENTRIES)
        check(listed.code == DurableCode.OK) { "LEGACY_METADATA_LIST_UNPROVEN" }
        val sidecars = setOf("$LEGACY_DATABASE-wal", "$LEGACY_DATABASE-shm", "$LEGACY_DATABASE-journal")
        val entries = checkNotNull(listed.entries)
        check(entries.none { it.leaf in sidecars && it.length != 0L }) { "LEGACY_SQLITE_SIDECAR_PRESENT" }
        return entries.sortedBy { it.leaf }
    }

    private fun readCopiedRows(source: DurableSnapshot): List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity> {
        val writer = checkNotNull(storage.withCurrentWriter { it }) { "MIGRATION_WRITER_NOT_DIRTY" }
        val existing = writer.read(COPY, DurableBounds.MAX_BYTES)
        check(existing.code == DurableCode.ABSENT) { "MIGRATION_COPY_ALREADY_PRESENT" }
        val sourceBytes = source.bytes
        try {
            check(writer.replace(COPY, COPY_PENDING, null, sourceBytes, DurableBounds.MAX_BYTES).code == DurableCode.OK) {
                "MIGRATION_COPY_UNPROVEN"
            }
            val copied = writer.read(COPY, DurableBounds.MAX_BYTES)
            val copiedSnapshot = checkNotNull(copied.snapshot)
            try {
                val copiedBytes = copiedSnapshot.bytes
                try {
                    check(copied.code == DurableCode.OK && MessageDigest.isEqual(sourceBytes, copiedBytes)) {
                        "MIGRATION_COPY_MISMATCH"
                    }
                } finally { copiedBytes.fill(0) }
                val observedRoot = Os.lstat(targetRoot.absolutePath)
                check(OsConstants.S_ISDIR(observedRoot.st_mode) && observedRoot.st_dev == target.identity.device &&
                    observedRoot.st_ino == target.identity.inode && observedRoot.st_uid.toLong() == target.expectedUid) {
                    "MIGRATION_COPY_ROOT_SUBSTITUTED"
                }
                val rows = LegacyCopiedCatalogReader.read(java.io.File(targetRoot, COPY))
                val after = writer.read(COPY, DurableBounds.MAX_BYTES)
                val afterSnapshot = checkNotNull(after.snapshot)
                val afterBytes = afterSnapshot.bytes
                try {
                    check(after.code == DurableCode.OK && afterSnapshot.identity == copiedSnapshot.identity &&
                        MessageDigest.isEqual(sourceBytes, afterBytes)) { "MIGRATION_COPY_CHANGED_DURING_READ" }
                    val afterRoot = Os.lstat(targetRoot.absolutePath)
                    check(OsConstants.S_ISDIR(afterRoot.st_mode) && afterRoot.st_dev == target.identity.device &&
                        afterRoot.st_ino == target.identity.inode && afterRoot.st_uid.toLong() == target.expectedUid) {
                        "MIGRATION_COPY_ROOT_CHANGED_DURING_READ"
                    }
                    check(writer.delete(COPY, afterSnapshot, DurableBounds.MAX_BYTES).code == DurableCode.OK) { "MIGRATION_COPY_CLEANUP_UNPROVEN" }
                } finally { afterBytes.fill(0) }
                return rows
            } finally { /* Snapshots expose defensive copies only; no backing buffer is retained here. */ }
        } finally { sourceBytes.fill(0) }
    }

    private fun readBlobs(): LinkedHashMap<LegacyObjectName, DurableSnapshot> {
        val directory = blobs ?: return linkedMapOf()
        val list = primitives.list(directory, JournalLimits.OBJECTS)
        check(list.code == DurableCode.OK) { "LEGACY_BLOB_LIST_UNPROVEN" }
        val result = linkedMapOf<LegacyObjectName, DurableSnapshot>()
        try {
            for (entry in checkNotNull(list.entries).sortedBy { it.leaf }) {
                val match = BLOB.matchEntire(entry.leaf) ?: error("LEGACY_BLOB_NAME_UNPROVEN")
                val role = SecureDataClass.entries.singleOrNull { it.wireValue == match.groupValues[2].toInt() }
                    ?: error("LEGACY_BLOB_ROLE_UNPROVEN")
                val name = LegacyObjectName(match.groupValues[1], role)
                val snapshot = readRequired(directory, entry.leaf)
                check(snapshot.identity == entry.identity && snapshot.size.toLong() == entry.length) { "LEGACY_BLOB_IDENTITY_CHANGED" }
                check(result.put(name, snapshot) == null) { "LEGACY_BLOB_DUPLICATE" }
            }
            return result
        } catch (failure: Throwable) { result.values.forEach { it.bytes.fill(0) }; throw failure }
    }

    private fun readOptional(directory: DurableDirectory, leaf: String): DurableSnapshot? {
        val result = primitives.read(directory, leaf, DurableBounds.MAX_BYTES)
        if (result.code == DurableCode.ABSENT) return null
        check(result.code == DurableCode.OK) { "LEGACY_READ_UNPROVEN" }
        return checkNotNull(result.snapshot)
    }
    private fun readRequired(directory: DurableDirectory, leaf: String): DurableSnapshot =
        checkNotNull(readOptional(directory, leaf)) { "LEGACY_REQUIRED_SOURCE_ABSENT" }

    private fun witness(database: DurableSnapshot?, settings: DurableSnapshot?, blobSnapshots: Map<LegacyObjectName, DurableSnapshot>,
        metadataSidecars: List<org.kurdistanvpn.core.nativeapi.DurableDirectoryEntry>): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update("kurdistan-legacy-fd-snapshot-v1\u0000".encodeToByteArray())
            fun directory(label: String, value: DurableDirectory?) {
                update(label.encodeToByteArray())
                if (value == null) update(0) else {
                    update(1); update(java.nio.ByteBuffer.allocate(16).putLong(value.identity.device).putLong(value.identity.inode).array())
                }
            }
            fun add(label: String, snapshot: DurableSnapshot?) {
                update(label.encodeToByteArray())
                if (snapshot == null) update(0) else {
                    update(1); update(java.nio.ByteBuffer.allocate(16).putLong(snapshot.identity.device).putLong(snapshot.identity.inode).array())
                    update(java.nio.ByteBuffer.allocate(4).putInt(snapshot.size).array()); update(snapshot.bytes)
                }
            }
            directory("metadata-directory", metadata); directory("settings-directory", this@FdSnapshotLegacyMigrationAccess.settings)
            directory("blob-directory", this@FdSnapshotLegacyMigrationAccess.blobs)
            add(LEGACY_DATABASE, database); add(LEGACY_SETTINGS, settings)
            metadataSidecars.filter { it.leaf in setOf("$LEGACY_DATABASE-wal", "$LEGACY_DATABASE-shm", "$LEGACY_DATABASE-journal") }
                .forEach { entry ->
                update(entry.leaf.encodeToByteArray()); update(java.nio.ByteBuffer.allocate(24)
                    .putLong(entry.identity.device).putLong(entry.identity.inode).putLong(entry.length).array())
            }
            blobSnapshots.toSortedMap(compareBy<LegacyObjectName> { it.role.wireValue }.thenBy { it.logicalId }).forEach { (name, snapshot) ->
                add("${name.logicalId}.${name.role.wireValue}.blob", snapshot)
            }
            digest()
        }

    private companion object {
        const val LEGACY_DATABASE = "phase9-metadata.db"
        const val LEGACY_SETTINGS = "phase9_nonsecret_settings.preferences_pb"
        const val COPY = "migration-legacy-metadata.db"
        const val COPY_PENDING = "migration-legacy-copy-pending"
        val BLOB = Regex("([a-z0-9-]{1,64})\\.([0-9]{1,2})\\.blob")
    }
}

internal fun projectionRootIdentityMatches(isAbsolute: Boolean, isDirectory: Boolean,
    device: Long, inode: Long, uid: Long, mode: Int, expected: DurableDirectory): Boolean =
    isAbsolute && isDirectory && device == expected.identity.device && inode == expected.identity.inode &&
        uid == expected.expectedUid && mode == 448

internal data class ProjectionRootObservation(val isAbsolute: Boolean, val isDirectory: Boolean,
    val device: Long, val inode: Long, val uid: Long, val mode: Int)

internal fun canonicalProjectionRootForBoundIdentity(root: java.io.File, expected: DurableDirectory,
    observe: (java.io.File) -> ProjectionRootObservation): java.io.File {
    check(root.isAbsolute)
    val absolute = root.absoluteFile
    val canonical = root.canonicalFile
    val candidates = if (absolute == canonical) listOf(absolute) else listOf(absolute, canonical)
    check(candidates.all { candidate ->
        val observed = observe(candidate)
        projectionRootIdentityMatches(observed.isAbsolute, observed.isDirectory, observed.device,
            observed.inode, observed.uid, observed.mode, expected)
    }) { "PROJECTION_ROOT_IDENTITY_MISMATCH" }
    return canonical
}

/** Android owners are confined to an already verified broker root. No parent is created. */
internal class AndroidProjectionStoreOwnerFactory(private val context: android.content.Context,
    private val root: java.io.File, private val directory: DurableDirectory,
    private val layout: ProjectionLeafLayout) : ProjectionStoreOwnerFactory {
    private fun observe(candidate: java.io.File): ProjectionRootObservation {
        val stat = android.system.Os.lstat(candidate.absolutePath)
        return ProjectionRootObservation(candidate.isAbsolute,
            android.system.OsConstants.S_ISDIR(stat.st_mode), stat.st_dev, stat.st_ino,
            stat.st_uid.toLong(), stat.st_mode and 511)
    }
    private fun verifiedCanonicalRoot(): java.io.File =
        canonicalProjectionRootForBoundIdentity(root, directory, ::observe)
    override fun requireRootIdentity() { verifiedCanonicalRoot() }
    override fun inspectClosed(writer: DurableWriter, files: ClosedProjectionFiles): ClosedSchemaProjection {
        val verifiedRoot = verifiedCanonicalRoot()
        val before = files.observe(writer)
        val version = files.roomVersion(before, writer)
        val path = java.io.File(verifiedRoot, layout.room).absolutePath
        val db = android.database.sqlite.SQLiteDatabase.openDatabase(path, null,
            android.database.sqlite.SQLiteDatabase.OPEN_READONLY or android.database.sqlite.SQLiteDatabase.NO_LOCALIZED_COLLATORS,
            android.database.DatabaseErrorHandler { error("PROJECTION_CORRUPTION_PRESERVED") })
        val catalog = try {
            check(db.isReadOnly)
            ProductProjectionSchemaMigration.inspect(version) { sql, columns, bound ->
                db.rawQuery(sql, null).use { cursor ->
                    ProductProjectionSchemaMigration.readRows(cursor, columns, bound)
                }
            }
        } finally { db.close() }
        verifiedCanonicalRoot()
        val after = files.observe(writer)
        requireSameProjectionFiles(before, after)
        val settings = files.settingsBytes(after, writer)
        return try { ClosedSchemaProjection(version, catalog, runBlocking { SettingsProjectionCodec.fromStoredBytes(settings) }, after) }
        finally { settings.fill(0) }
    }
    override fun open(ownership: ProjectionOwnership, withSettings: Boolean): ProjectionStoreSession = openInternal(ownership, withSettings, null)
    override fun openMigrating(ownership: ProjectionOwnership, withSettings: Boolean,
        permit: ProductProjectionSchemaMigration.Permit): ProjectionStoreSession {
        permit.claimOpen()
        return openInternal(ownership, withSettings, permit)
    }
    private fun openInternal(ownership: ProjectionOwnership, withSettings: Boolean,
        permit: ProductProjectionSchemaMigration.Permit?): ProjectionStoreSession {
        // Room and DataStore accept path names rather than directory descriptors. Bind both the
        // Android alias and its canonical spelling to the already verified directory capability
        // before either path-based owner receives the canonical spelling.
        val verifiedRoot = verifiedCanonicalRoot()
        val room = ownership.own(AndroidRoomOwner(context, java.io.File(verifiedRoot, layout.room)))
        room.open(permit)
        val settings = if (withSettings) ownership.own(AndroidSettingsOwner(java.io.File(verifiedRoot, layout.settings))).also { it.open() } else null
        verifiedCanonicalRoot()
        return object : ProjectionStoreSession {
            override fun readCatalog(): CatalogProjection = room.read()
            override fun publishCatalog(expected: CatalogProjection, next: ProtectedProjectionEntity,
                rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
                operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) =
                room.publish(expected, next, rows, bindings, operation)
            override fun readSettings(): SettingsProjection = checkNotNull(settings).read()
            override fun publishSettings(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) =
                checkNotNull(settings).publish(expected, replacement, next)
            override fun recoverCatalog(expected: CatalogProjection, next: ProtectedProjectionEntity,
                rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
                operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) =
                room.recover(expected, next, rows, bindings, operation)
            override fun recoverSettings(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) =
                checkNotNull(settings).recover(expected, replacement, next)
        }
    }

    private class AndroidRoomOwner(private val context: android.content.Context, private val file: java.io.File) : AutoCloseable {
        private var database: KurdistanMetadataDatabase? = null
        private var executor: java.util.concurrent.ExecutorService? = null
        private var closed = false
        fun open(permit: ProductProjectionSchemaMigration.Permit? = null) {
            check(!closed && database == null && executor == null)
            executor = java.util.concurrent.Executors.newSingleThreadExecutor()
            val worker = checkNotNull(executor)
            database = androidx.room.Room.databaseBuilder(context, KurdistanMetadataDatabase::class.java, file.absolutePath)
                .addMigrations(KurdistanMetadataDatabase.MIGRATION_1_2, KurdistanMetadataDatabase.MIGRATION_2_3)
                .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
                .openHelperFactory { configuration ->
                    check(configuration.name == file.absolutePath) { "PROJECTION_PATH_SUBSTITUTION" }
                    androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory().create(
                        androidx.sqlite.db.SupportSQLiteOpenHelper.Configuration.builder(configuration.context)
                            .name(file.absolutePath).callback(if (permit == null) NonDestructiveProjectionCallback(configuration.callback)
                                else PermittedProjectionCallback(configuration.callback, permit))
                            .noBackupDirectory(false).allowDataLossOnRecovery(false).build())
                }
                .setQueryExecutor(worker).setTransactionExecutor(worker).build()
            val db = checkNotNull(database).openHelper.writableDatabase
            db.query("PRAGMA journal_mode").use { cursor ->
                check(cursor.moveToFirst() && cursor.getString(0).equals("truncate", ignoreCase = true) && !cursor.moveToNext()) {
                    "UNQUALIFIED_SQLITE_JOURNAL_MODE"
                }
            }
            db.execSQL("PRAGMA synchronous=FULL")
            db.query("PRAGMA synchronous").use { cursor -> check(cursor.moveToFirst() && cursor.getInt(0) == 2) }
        }
        fun read(): CatalogProjection { check(!closed); return runBlocking { checkNotNull(database).protectedProjection().read() } }
        fun publish(expected: CatalogProjection, next: ProtectedProjectionEntity,
            rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
            operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) {
            check(!closed); runBlocking { checkNotNull(database).protectedProjection().publish(expected, next, rows, bindings, operation) }
        }
        fun recover(expected: CatalogProjection, next: ProtectedProjectionEntity,
            rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
            operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) {
            check(!closed); runBlocking { checkNotNull(database).protectedProjection().recover(expected, next, rows, bindings, operation) }
        }
        override fun close() {
            closed = true
            var failure: Throwable? = null
            try { database?.close(); database = null } catch (error: Throwable) { failure = error }
            try {
                executor?.let { it.shutdown(); check(it.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) { "ROOM_WORKERS_NOT_QUIESCENT" } }
                executor = null
            } catch (error: Throwable) { if (failure == null) failure = error else failure.addSuppressed(error) }
            if (failure != null) throw failure
        }
    }
    private class AndroidSettingsOwner(private val file: java.io.File) : AutoCloseable {
        private var store: ProductSettingsStore? = null
        private var closed = false
        fun open() { check(!closed && store == null); store = ProductSettingsStore.openOwnedProjection(file) }
        fun read(): SettingsProjection { check(!closed); return runBlocking { checkNotNull(store).readProjection() } }
        fun publish(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) {
            check(!closed); runBlocking { checkNotNull(store).publishProjection(expected, replacement, next) }
        }
        fun recover(expected: SettingsProjection, replacement: ByteArray, next: SettingsProjectionIdentity) {
            check(!closed); runBlocking { checkNotNull(store).recoverProjection(expected, replacement, next) }
        }
        override fun close() {
            closed = true
            runBlocking { withTimeout(5000) { store?.closeOwned() } }
            store = null
        }
    }
}

/**
 * Process-lifetime bridge between the runtime provider and the mutation broker.
 *
 * It deliberately exposes revision handles rather than the policy, stores, or durable
 * capabilities. A final lease blocks security mutations until it is released, expires,
 * or the active registration is invalidated.
 */
class ProtectedStateProcessOwner(private val acquireMutationQuiescence: (() -> AutoCloseable?)? = null,
    private val monotonicMillis: () -> Long) : AutoCloseable {
    private val monitor = Any()
    private val policy = ActiveSessionMutationPolicy(acquireMutationQuiescence, monotonicMillis)
    private val registrations = linkedSetOf<ProtectedRuntimeRevisionRegistration>()
    private var closed = false
    private var closeFailure: Throwable? = null

    fun registerRuntimeRevision(epoch: String, generation: Long, revision: Long): ProtectedRuntimeRevisionRegistration? {
        val invalidation = RuntimeRegistrationOwner()
        val session = synchronized(monitor) {
            if (closed) return null
            policy.register(epoch, generation, revision, invalidation)
        } ?: return null
        val registration = ProtectedRuntimeRevisionRegistration(this, policy, session, invalidation, revision)
        val admitted = synchronized(monitor) {
            if (closed) false else {
                registrations += registration
                true
            }
        }
        if (admitted) return registration
        try { registration.close() } catch (_: Throwable) { }
        return null
    }

    internal fun release(registration: ProtectedRuntimeRevisionRegistration) {
        synchronized(monitor) { registrations -= registration }
    }

    internal fun mutationPolicy(): ActiveSessionMutationPolicy = policy

    override fun close() {
        val current = synchronized(monitor) {
            if (closed) {
                closeFailure?.let { throw it }
                return
            }
            closed = true
            registrations.toList().also { registrations.clear() }
        }
        var failure: Throwable? = null
        current.forEach {
            try { it.close() } catch (error: Throwable) {
                if (failure == null) failure = error else checkNotNull(failure).addSuppressed(error)
            }
        }
        synchronized(monitor) { closeFailure = failure }
        failure?.let { throw it }
    }

    internal class RuntimeRegistrationOwner : AutoCloseable {
        private val monitor = Any()
        private enum class State { OPEN, CLOSING, CLEAN, UNPROVEN }
        private var state = State.OPEN
        private var invalidated: (() -> Unit)? = null
        private var finalizeRegistration: (() -> Unit)? = null
        private var retired: ((Boolean) -> Unit)? = null
        private var completing = false

        fun installInvalidation(callback: () -> Unit, finalize: () -> Unit,
            onRetired: (Boolean) -> Unit): java.io.Closeable {
            val callNow = synchronized(monitor) {
                val late = if (state == State.CLEAN && !completing) {
                    state = State.OPEN
                    true
                }
                else if (state != State.OPEN) throw IllegalStateException("ACTIVE_REGISTRATION_CLEANUP_UNPROVEN")
                else false
                check(invalidated == null) { "ACTIVE_REGISTRATION_ALREADY_INSTALLED" }
                invalidated = callback; finalizeRegistration = finalize; retired = onRetired
                late
            }
            if (callNow) close()
            return java.io.Closeable {
                // Detach only. The containing registration retires the policy session, whose
                // owner close runs the same completion path without calling this callback.
                synchronized(monitor) {
                    if (invalidated === callback) invalidated = null
                }
            }
        }

        override fun close() {
            val callback = synchronized(monitor) {
                when (state) {
                    State.CLEAN -> {
                        check(!completing) { "ACTIVE_REGISTRATION_CLEANUP_UNPROVEN" }
                        return
                    }
                    State.OPEN -> {
                        state = State.CLOSING
                        invalidated.also { invalidated = null }
                    }
                    State.CLOSING, State.UNPROVEN -> throw IllegalStateException("ACTIVE_REGISTRATION_CLEANUP_UNPROVEN")
                }
            }
            try {
                callback?.invoke()
                val completion = synchronized(monitor) {
                    state = State.CLEAN
                    completing = true
                    finalizeRegistration.also { finalizeRegistration = null }
                }
                completion?.invoke()
                val acknowledgement = synchronized(monitor) {
                    completing = false
                    retired.also { retired = null }
                }
                acknowledgement?.invoke(true)
            } catch (failure: Throwable) {
                val acknowledgement = synchronized(monitor) {
                    state = State.UNPROVEN; completing = false; finalizeRegistration = null
                    retired.also { retired = null }
                }
                try { acknowledgement?.invoke(false) } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                throw IllegalStateException("ACTIVE_REGISTRATION_CLEANUP_UNPROVEN", failure)
            }
        }

        fun callbackProven(): Boolean = synchronized(monitor) { state == State.CLEAN }
        fun registeredOpen(): Boolean = synchronized(monitor) {
            state == State.OPEN && !completing && invalidated != null
        }
        fun cleanupProven(): Boolean = synchronized(monitor) { state == State.CLEAN && !completing }
    }
}

/** One registered runtime revision. Closing it retires the active registration exactly once. */
class ProtectedRuntimeRevisionRegistration internal constructor(
    private val process: ProtectedStateProcessOwner,
    private val policy: ActiveSessionMutationPolicy,
    private val session: ActiveSessionMutationPolicy.OwnedSession,
    private val invalidation: ProtectedStateProcessOwner.RuntimeRegistrationOwner,
    val revision: Long,
) : AutoCloseable {
    private val monitor = Any()
    private enum class State { OPEN, CLOSING, CLEAN, UNPROVEN }
    private var state = State.OPEN
    private var finalIssued = false
    private var releaseClaimed = false

    fun acquireFinalLease(deadlineElapsedMillis: Long): ProtectedRuntimeRevisionLease? {
        val lease = synchronized(monitor) {
            if (state != State.OPEN || finalIssued) return null
            policy.acquireFinalLease(session, revision, deadlineElapsedMillis)?.also { finalIssued = true }
        } ?: return null
        return ProtectedRuntimeRevisionLease(this, lease, invalidation, revision)
    }

    internal fun isClosed(): Boolean = synchronized(monitor) { state != State.OPEN }

    /** No owner monitor spans the fresh facade observation. Neither check issues a lease. */
    fun isRegisteredCurrent(observe: () -> Boolean): Boolean {
        fun admitted(): Boolean = synchronized(monitor) {
            state == State.OPEN && finalIssued && invalidation.registeredOpen() &&
                policy.isRegisteredCurrent(session, revision)
        }
        if (!admitted()) return false
        // Preserve the observation owner's cleanup failure for its boundary to latch.
        val fresh = observe()
        return fresh && admitted()
    }

    internal fun installActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): java.io.Closeable =
        invalidation.installInvalidation(onInvalidated, ::finalizeRetirement, onRetired)

    /** Only the successfully returned invalidation owner may enter this metadata phase. */
    private fun finalizeRetirement() {
        synchronized(monitor) {
            check(state != State.UNPROVEN && invalidation.callbackProven()) { "RUNTIME_REGISTRATION_CLEANUP_UNPROVEN" }
            if (state == State.CLEAN) return
            state = State.CLOSING
        }
        try {
            // On policy-owned cleanup this does not remove the closing entry. Only the
            // original cleanOwned finally block can do so after this finalizer returns.
            session.close()
            releaseProcessReference()
            synchronized(monitor) {
                check(state != State.UNPROVEN) { "RUNTIME_REGISTRATION_CLEANUP_UNPROVEN" }
                state = State.CLEAN
            }
        } catch (failure: Throwable) {
            synchronized(monitor) { state = State.UNPROVEN }
            throw failure
        }
    }

    private fun releaseProcessReference() {
        synchronized(monitor) {
            if (releaseClaimed) return
            releaseClaimed = true
        }
        process.release(this)
    }

    override fun close() {
        val shouldClose = synchronized(monitor) {
            when (state) {
                State.OPEN -> { state = State.CLOSING; true }
                State.CLEAN -> {
                    check(invalidation.cleanupProven()) { "RUNTIME_REGISTRATION_CLEANUP_UNPROVEN" }
                    false
                }
                State.CLOSING, State.UNPROVEN -> throw IllegalStateException("RUNTIME_REGISTRATION_CLEANUP_UNPROVEN")
            }
        }
        if (shouldClose) {
            try {
                session.close()
                synchronized(monitor) {
                    if (state == State.UNPROVEN || !invalidation.cleanupProven()) {
                        state = State.UNPROVEN
                        error("RUNTIME_REGISTRATION_CLEANUP_UNPROVEN")
                    }
                    state = State.CLEAN
                }
            } catch (failure: Throwable) {
                synchronized(monitor) { state = State.UNPROVEN }
                throw failure
            } finally { releaseProcessReference() }
        }
    }
}

/** A bounded final-activation lease. close releases only the activation barrier. */
class ProtectedRuntimeRevisionLease internal constructor(
    private val registration: ProtectedRuntimeRevisionRegistration,
    private val lease: ActiveSessionMutationPolicy.FinalLease,
    private val invalidation: ProtectedStateProcessOwner.RuntimeRegistrationOwner,
    val revision: Long,
) : java.io.Closeable {
    private val monitor = Any()
    private var closed = false
    private var activeRegistered = false

    fun isCurrent(): Boolean = synchronized(monitor) {
        !closed && !registration.isClosed() && lease.validate(revision)
    }

    /** The returned closeable owns the active registration, not the final lease. */
    fun registerActive(onInvalidated: () -> Unit): java.io.Closeable = registerActive(onInvalidated) { }

    /** onRetired publishes bounded provider-local state only; it must not throw, close
     * resources, invoke IPC/native code, or call other callbacks. */
    fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): java.io.Closeable {
        synchronized(monitor) {
            check(!closed && !registration.isClosed() && !activeRegistered && lease.validate(revision)) {
                "FINAL_LEASE_NOT_CURRENT"
            }
            activeRegistered = true
        }
        val installed = try { registration.installActive(onInvalidated, onRetired) }
        catch (failure: Throwable) {
            try { registration.close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            throw failure
        }
        return java.io.Closeable {
            try { installed.close() } finally { registration.close() }
        }
    }

    override fun close() {
        synchronized(monitor) {
            if (closed) return
            closed = true
        }
        lease.close()
    }
}

/** Closed application result vocabulary, including failures raised when a broker lease closes. */
internal fun <T> protectedCommandResult(action: () -> BrokerMutation<T>?): ProtectedStateApplicationFacade.CommandResult<T> = try {
    val value = action()
    when (value?.status) {
        ProtectedMutationStatus.COMMITTED -> ProtectedStateApplicationFacade.CommandResult.Committed(checkNotNull(value.value))
        ProtectedMutationStatus.NO_MUTATION -> ProtectedStateApplicationFacade.CommandResult.Rejected(value.error ?: OperationError.RECOVERY_REQUIRED)
        ProtectedMutationStatus.DIRTY, ProtectedMutationStatus.MUTATION_UNPROVEN,
        ProtectedMutationStatus.QUARANTINED -> ProtectedStateApplicationFacade.CommandResult.Unproven
        ProtectedMutationStatus.CAPACITY_EXHAUSTED -> ProtectedStateApplicationFacade.CommandResult.Rejected(OperationError.RESOURCE_LIMIT)
        null -> ProtectedStateApplicationFacade.CommandResult.Busy
    }
} catch (cancelled: java.util.concurrent.CancellationException) { throw cancelled }
catch (_: Throwable) { ProtectedStateApplicationFacade.CommandResult.Unproven }

/** Single-attempt authenticated aggregate read. Every collaborator is read-only. */
internal fun readProductStorageProjection(snapshots: ProtectedStateSnapshotReader,
    projections: ProtectedProjectionReadAccess, readEncrypted: (String) -> ByteArray?,
    codec: SecureEnvelopeCodec, key: KeyEncryptionKey, profileId: String?, isClosed: () -> Boolean,
): ProtectedStateApplicationFacade.ProductStorageReadProjection? = try {
    check(!isClosed())
    profileId?.let { CatalogId(it) }
    val snapshot = snapshots.readVerified()
    check(snapshot.disposition == ProtectedStateDisposition.VERIFIED)
    val before = snapshot.encode()
    try {
        val observed = projections.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        val catalog = snapshot.catalogBytes()
        val content = try { org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(catalog) }
            finally { catalog.fill(0) }
        val ids = content.rows.map { it.localRecordId }.toSet()
        check(profileId == null || profileId in ids)
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key)
        validateProductRecordScopes(snapshot.objects(), ids, blobs)
        validateProductProfileRelationships(snapshot.objects(), ids, blobs)
        readProductSettings(snapshot, blobs) // Includes legacy-aware revision and policy mirror validation.
        val trust = TrustedNetworkStore.readOnly(blobs).load()?.use {
            ProtectedStateApplicationFacade.TrustedNetworkStorageSummary(it.settingsRevision, it.rules.size, it.selectedRuleIds)
        }
        val result = ProtectedStateApplicationFacade.ProductStorageReadProjection(snapshot.revision, profileId,
            profileId?.let { ProfileProjectionStore.readOnly(blobs).load(it) },
            DeploymentDisplayMetadataStore.readOnly(blobs).load(),
            profileId?.let { UpdateStateStore.readOnly(blobs).load(it) },
            profileId?.let { ProbeHistoryStore.readOnly(blobs).load(it) }, trust,
            UsageAggregatesStore.readOnly(blobs).load(), AppLockStateStore.readOnly(blobs).load(),
            LocalProxyPolicyStore.readOnly(blobs).load(), CrashSafeModeStore.readOnly(blobs).load(), content.operation,
            PauseStateStore.readOnly(blobs).load(),
            profileId?.let { snapshot.objectFor(it, SecureDataClass.ACTIVATION_ACTIVE.wireValue)?.binding?.revision })
        val current = snapshots.readCheckpointSnapshot()
        val after = current.encode()
        try { check(MessageDigest.isEqual(before, after)) { "TRUSTED_STATE_CHANGED" } }
        finally { after.fill(0) }
        val fresh = projections.read()
        fresh.requireMatches(current)
        snapshots.requirePhysicalProjection(current, fresh.physical())
        requireSameProjectionFiles(observed.physical(), fresh.physical())
        check(!isClosed())
        result
    } finally { before.fill(0) }
} catch (_: Throwable) { null }

/** Public default-process boundary. It owns every directory capability and exposes no store. */
class ProtectedStateApplicationFacade private constructor(
    private val owners: List<DurableOwnedDirectory>,
    private val storage: EncryptedJournalStorage,
    private val snapshots: ProtectedStateSnapshotReader,
    private val projectionReads: ProtectedProjectionReadAccess,
    private val broker: ProtectedStateMutationBroker?,
    private val codec: SecureEnvelopeCodec,
    private val key: KeyEncryptionKey,
    private val native: KurdNativeCore,
    val processOwner: ProtectedStateProcessOwner,
    private val completeReset: ProtectedStateResetRecoveryCoordinator? = null,
    private val requireResetScope: (() -> Unit)? = null,
) : AutoCloseable {
    data class Snapshot(val revision: Long, val disposition: Int, val selectedProfileId: String?)
    data class ReadProjection(val revision: Long, val settings: ProductSettings,
        val profiles: List<ProfileSummary>, val health: CatalogHealth,
        val operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity? = null,
        val runtimeProfile: org.kurdistanvpn.runtime.api.RuntimeProfilePresentation? = null)
    class TrustedNetworkStorageSummary internal constructor(val settingsRevision: Long, val ruleCount: Int,
        selectedRuleIds: Set<CatalogId>) {
        val selectedRuleIds: Set<CatalogId> = java.util.Collections.unmodifiableSet(LinkedHashSet(selectedRuleIds))
        override fun toString(): String = "TrustedNetworkStorageSummary(redacted)"
    }
    class ProductStorageReadProjection internal constructor(val revision: Long, val profileId: String?,
        val profile: StoredProfileProjection?, val deploymentDisplay: DeploymentDisplayMetadata?,
        val update: StoredUpdateState?, val probeHistory: StoredProbeHistory?,
        val trustedNetworks: TrustedNetworkStorageSummary?, val usage: StoredUsageAggregates?,
        val appLock: StoredAppLockState?, val proxyPolicy: StoredProxyPolicy?,
        val crashSafeMode: StoredCrashSafeMode?,
        val operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?,
        val pause: StoredPauseState? = null, val profileTrustRevision: Long? = null) {
        override fun toString(): String = "ProductStorageReadProjection(redacted)"
    }
    sealed interface CommandResult<out T> {
        data class Committed<T>(val value: T) : CommandResult<T>
        data class Rejected(val error: OperationError) : CommandResult<Nothing>
        data object Busy : CommandResult<Nothing>
        data object Unproven : CommandResult<Nothing>
    }
    sealed interface OpenResult {
        data class Ready(val facade: ProtectedStateApplicationFacade) : OpenResult
        data object Locked : OpenResult
        data object Missing : OpenResult
        data object MigrationRequired : OpenResult
        data object KeyInvalidated : OpenResult
        data object Unproven : OpenResult
    }
    @Volatile private var closed = false
    private var closeFailure: Throwable? = null
    private val productSettings: SettingsRepository? by lazy { createSettingsRepository(null) }
    private fun createSettingsRepository(runtime: org.kurdistanvpn.data.settings.SettingsRuntimePort?): SettingsRepository? =
        broker?.let { owner ->
            val commands = owner.settingsPort()
            val port = object : SettingsMutationPort {
                override suspend fun read() = settingsAccess { commands.read() }
                override suspend fun validate(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings) =
                    settingsAccess { commands.validate(expectedJournal, expectedApplied, requested) }
                override suspend fun apply(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings) =
                    settingsAccess { commands.apply(expectedJournal, expectedApplied, requested) }
                override suspend fun rollback(expectedJournal: Long) = settingsAccess { commands.rollback(expectedJournal) }
            }
            SettingsApplyCoordinator(port, runtime ?: owner.inactiveRuntimePort(), ProtectedUiDraftStore(storage))
        }

    /** Manual DI, inactive-session application only. No unavailable runtime is treated as success. */
    fun settingsRepository(): SettingsRepository? = if (closed) null else productSettings
    fun settingsRepository(runtime: org.kurdistanvpn.data.settings.SettingsRuntimePort): SettingsRepository? =
        if (closed) null else createSettingsRepository(runtime)

    private suspend fun <T> settingsAccess(action: suspend () -> SettingsPortResult<T>): SettingsPortResult<T> =
        withContext(Dispatchers.IO) {
            if (closed) SettingsPortResult.Rejected(ProductFailureCode.STORAGE_DEGRADED) else action()
        }

    fun snapshot(): Snapshot? = try {
        val value = snapshots.readCheckpointSnapshot()
        Snapshot(value.revision, value.disposition.wire, value.selectedProfile)
    } catch (_: Throwable) { null }

    fun readProductStorage(profileId: String? = null): ProductStorageReadProjection? = try {
        run {
            val base = readProductStorageProjection(snapshots, projectionReads, storage::readObject, codec, key, profileId) { closed }
                ?: return@run null
            val history = if (profileId != null && base.profileTrustRevision != null)
                ProtectedProbeHistoryStore(storage).read(CatalogId(profileId), base.profileTrustRevision) else null
            val update = if (profileId != null && base.profileTrustRevision != null)
                ProtectedProbeHistoryStore(storage).readUpdate(CatalogId(profileId), base.profileTrustRevision) else null
            check(snapshots.readCheckpointSnapshot().revision == base.revision && !closed)
            if (history == null && update == null) base else ProductStorageReadProjection(base.revision, base.profileId, base.profile,
                base.deploymentDisplay, update ?: base.update, history ?: base.probeHistory, base.trustedNetworks, base.usage, base.appLock,
                base.proxyPolicy, base.crashSafeMode, base.operation, base.pause, base.profileTrustRevision)
        }
    } catch (_: Exception) { null }

    /** Fresh, authenticated UI projection. It cannot repair, bootstrap, or acquire a writer. */
    fun readProjection(): ReadProjection? = try { readProjectionChecked() } catch (_: Throwable) { null }

    internal fun readProjectionChecked(): ReadProjection {
        val snapshot = snapshots.readCheckpointSnapshot()
        val observed = projectionReads.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        val settings = readPresentedProductSettings(snapshot,
            ReadOnlyProtectedBlobView(snapshot.objects(), storage::readObject, codec, key), storage::read)
        val catalogBytes = snapshot.catalogBytes()
        val content = try { org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.decode(catalogBytes) } finally { catalogBytes.fill(0) }
        val catalog = PreparedCatalog(content.rows)
        try {
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), storage::readObject, codec, key)
            val admission = org.kurdistanvpn.data.secure.ProfileAdmissionJournal.readOnly(native, catalog, blobs, false)
            val profiles = runBlocking { admission.listProfiles() }
            val selected = profiles.singleOrNull { it.localRecordId == snapshot.selectedProfile }
            val image = snapshot.settingsBytes()
            val settingsRevision = try {
                if (org.kurdistanvpn.data.settings.ProductSettingsImage.isVersionTwo(image))
                    org.kurdistanvpn.data.settings.ProductSettingsImage.decode(image).revision else 0L
            } finally { image.fill(0) }
            val trust = selected?.let { snapshot.objectFor(it.localRecordId, SecureDataClass.ACTIVATION_ACTIVE.wireValue) }
            val runtimeProfile = if (selected == null || trust == null || selected.generation == 0uL) null else
                org.kurdistanvpn.runtime.api.RuntimeProfilePresentation(selected.localRecordId, selected.generation,
                    trust.binding.revision, settingsRevision)
            return ReadProjection(snapshot.revision, settings, profiles, runBlocking { admission.storageHealth() }, content.operation, runtimeProfile)
        } finally { catalog.close() }
    }

    /**
     * Read-only eligibility check for the one explicit presentation-recovery command. A null
     * result means the status itself could not be proven and must remain fail-closed.
     */
    fun presentationRecoveryRequired(): Boolean? = try {
        val snapshot = snapshots.readCheckpointSnapshot()
        val observed = projectionReads.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        ProtectedPresentationOverlay.requiresExplicitRecovery(storage::read, snapshot.storeId())
    } catch (_: Throwable) { null }

    fun reconstructAuthority(environment: ProtectedAuthorityEnvironment): AuthorityReadResult =
        ProtectedStateAuthorityFactory(snapshots, storage::readObject, codec, key, native, projectionReads, environment).reconstruct()

    fun reconstructProductionCapture(environment: ProtectedAuthorityEnvironment): ProductionCaptureReadResult {
        if (closed) return ProductionCaptureReadResult.Rejected(AuthorityReadFailure.STATE_UNPROVEN)
        val fresh = ProtectedStateAuthorityFactory(snapshots, storage::readObject, codec, key, native, projectionReads, environment)
        val committed = projectionReads as? ReadOnlyCheckpointProjectionAccess ?: return fresh.reconstructProductionCapture()
        return storage.captureReadScope().use { scope ->
            val journal = ProtectedStateOperationJournal(scope)
            val scopedSnapshots = ProtectedStateSnapshotReader(journal) { reference ->
                checkNotNull(storage.readObject(reference.physicalId))
            }
            val physical = committed.withReaders(scopedSnapshots::readCheckpointSnapshot, journal::readProjectionWitness)
            // Material transfer can occur later. Its final read must not capture the disposed scope.
            ProtectedStateAuthorityFactory(scopedSnapshots, storage::readObject, codec, key, native, physical,
                environment, fresh::requireCurrent).reconstructProductionCapture()
        }
    }

    /** Validates fresh committed authority then destroys it without ever exposing its bytes to UI. */
    fun validateManualStart(config: VpnRuntimeConfig, environment: ProtectedAuthorityEnvironment): OperationError? = try {
        config.validatedForLiveTransport()
        when (val result = reconstructAuthority(environment)) {
            is AuthorityReadResult.Ready -> {
                try {
                    if (result.committedConfig == config) null else OperationError.POLICY_REJECTED
                } finally { result.authority.close() }
            }
            is AuthorityReadResult.Rejected -> result.error ?: OperationError.POLICY_REJECTED
        }
    } catch (_: Throwable) { OperationError.RECOVERY_REQUIRED }

    /**
     * Mutations are deliberately suspend-only.  The process-owner may need a synchronous
     * cross-process quiescence proof, so keeping this boundary on Dispatchers.IO prevents a
     * UI or ServiceConnection callback from blocking the main thread on Binder.
     */
    suspend fun replaceRouting(packages: Set<String>): Boolean = withContext(Dispatchers.IO) {
        broker?.replaceRouting(packages) == ProtectedMutationStatus.COMMITTED
    }

    fun previewExternalImport(input: ByteArray, isCancelled: () -> Boolean, elapsedMillis: () -> Long): ProtectedExternalPreviewResult =
        ProtectedStatePreviewBackupReader(snapshots, storage::readObject, codec, key, native, projectionReads,
            isCancelled, elapsedMillis).previewExternal(input)

    fun enumerateBackup(selectedProfileId: String?, isCancelled: () -> Boolean,
        elapsedMillis: () -> Long): ProtectedBackupEnumeration =
        ProtectedStatePreviewBackupReader(snapshots, storage::readObject, codec, key, native, projectionReads,
            isCancelled, elapsedMillis).enumerateOrdinaryBackup(selectedProfileId)

    suspend fun confirmImport(confirmed: ConfirmedProtectedImport): CommandResult<String> =
        mutation { it.importProfile(confirmed) }

    suspend fun restoreConfirmedBackup(payload: ByteArray): CommandResult<Int> =
        mutation { it.restoreBackup(payload) }

    suspend fun deleteProfile(id: String, expectedRevision: Long? = null): CommandResult<Unit> =
        mutation { it.deleteProfile(id, expectedRevision) }

    suspend fun resetProfiles(ids: Set<String>, expectedRevision: Long? = null): CommandResult<Unit> = mutation { it.resetProfiles(ids, expectedRevision) }

    /** Called only after the separate pending-credential reset confirmation. */
    suspend fun resetPendingCredentialsConfirmed(expectedRevision: Long? = null): CommandResult<Int> = mutation { it.resetPendingCredentials(expectedRevision) }

    /** Explicit user-confirmed action only. Restore readers have neither capability. */
    suspend fun resetProtectedStateConfirmed(recoverPending: Boolean = false): CommandResult<Unit> =
        withContext(Dispatchers.IO) {
            synchronized(this@ProtectedStateApplicationFacade) {
                if (closed || broker == null) return@synchronized CommandResult.Busy
                val reset = completeReset ?: return@synchronized CommandResult.Unproven
                val scope = requireResetScope ?: return@synchronized CommandResult.Unproven
                val operation = ByteArray(JournalLimits.OPERATION_BYTES)
                try {
                    scope()
                    val outcome = if (recoverPending) reset.resume() else {
                        java.security.SecureRandom().nextBytes(operation)
                        reset.start(operation)
                    }
                    when (outcome) {
                        ResetRecoveryResult.COMPLETED -> {
                            // Key erasure and every target deletion have already been reread.
                            // Directory ownership must also terminate before success reaches UI.
                            close()
                            CommandResult.Committed(Unit)
                        }
                        ResetRecoveryResult.NO_RESET_PENDING -> CommandResult.Rejected(OperationError.RECOVERY_REQUIRED)
                        ResetRecoveryResult.RECOVERY_REQUIRED -> CommandResult.Busy
                        ResetRecoveryResult.DIRTY, ResetRecoveryResult.MUTATION_UNPROVEN,
                        ResetRecoveryResult.QUARANTINED -> CommandResult.Unproven
                    }
                } catch (_: Throwable) { CommandResult.Unproven }
                finally { operation.fill(0) }
            }
        }

    suspend fun createEnrollment(validitySeconds: Int, nowEpochSeconds: Long): CommandResult<ClientKeySummary> =
        mutation { it.createEnrollment(validitySeconds, nowEpochSeconds) }

    suspend fun markEnrollmentExported(id: String): CommandResult<Unit> = mutation { it.markEnrollmentExported(id) }

    suspend fun deleteEnrollment(id: String): CommandResult<Unit> = mutation { it.deleteCredential(id) }

    suspend fun replaceSettings(expectedRevision: Long, settings: ProductSettings,
        residuePolicy: org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy = org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.PRESERVE,
    ): CommandResult<Unit> = mutation { it.replaceSettings(expectedRevision, settings, residuePolicy) }

    /** Explicit production upgrade; subsequent settings drafts retain the authenticated bootstrap format. */
    suspend fun applyProductionSettings(expectedRevision: Long, expectedSettingsRevision: Long,
        requested: ProductSettings): CommandResult<ProductSettingsCommit> =
        mutation { it.applyProductionSettings(expectedRevision, expectedSettingsRevision, requested) }

    suspend fun applyPause(expectedRevision: Long, expectedSettingsRevision: Long,
        timer: StoredPauseState?): CommandResult<ProductSettingsCommit> =
        mutation { it.applyPause(expectedRevision, expectedSettingsRevision, timer) }

    suspend fun replaceDiagnostics(events: List<DiagnosticEvent>): CommandResult<Unit> =
        presentation { it.replaceDiagnostics(events) }

    /** Separate explicit recovery command. Read-only UI/backup/restoration never invoke it. */
    suspend fun recoverPresentationConfirmed(): CommandResult<Unit> = presentation { it.recoverPresentationConfirmed() }

    suspend fun migrateProductProjectionConfirmed(expectedRevision: Long): CommandResult<Unit> =
        mutation { it.migrateProductProjectionConfirmed(expectedRevision) }

    suspend fun recoverProductSchemaConfirmed(rollback: Boolean = false): CommandResult<Unit> =
        mutation { it.recoverProductSchemaConfirmed(rollback) }

    suspend fun recoverProductOperationConfirmed(rollback: Boolean = false): CommandResult<Unit> =
        mutation { it.recoverProductOperationConfirmed(rollback) }

    suspend fun recoverProductSettingsConfirmed(rollback: Boolean): CommandResult<ProductSettingsCommit> =
        mutation { it.recoverProductSettingsConfirmed(rollback) }

    suspend fun setDeploymentDisplay(expectedRevision: Long, value: DeploymentDisplayMetadata): CommandResult<Unit> =
        mutation { it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.SetDeploymentDisplay(value)) }

    suspend fun recordUpdate(expectedRevision: Long, profileId: String, value: StoredUpdateState): CommandResult<Unit> =
        presentation { it.recordUpdatePresentation(expectedRevision, profileId, value) }

    suspend fun recordProbe(expectedRevision: Long, profileId: String, value: StoredProbeHistory): CommandResult<Unit> =
        presentation { it.recordProbePresentation(expectedRevision, profileId, value) }

    suspend fun replaceTrustedRules(expectedRevision: Long, value: StoredTrustedNetworks): CommandResult<Unit> =
        mutation { it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.ReplaceTrustedRules(value)) }

    suspend fun recordUsage(expectedRevision: Long, value: StoredUsageAggregates): CommandResult<Unit> =
        mutation { it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.RecordUsage(value)) }

    suspend fun recordAppLockFailure(expectedRevision: Long, expectedSettingsRevision: Long,
        nextEligibleEpochMinute: Long): CommandResult<Unit> = mutation {
        it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.RecordAppLockFailure(expectedSettingsRevision, nextEligibleEpochMinute))
    }

    suspend fun recordCleanStop(expectedRevision: Long, epochHour: Long): CommandResult<Unit> =
        mutation { it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.RecordCleanStop(epochHour)) }

    suspend fun recordStart(expectedRevision: Long, epochHour: Long): CommandResult<Unit> =
        mutation { it.applyProductStoreCommand(expectedRevision, ProductStoreCommand.RecordStart(epochHour)) }

    fun diagnostics(): List<DiagnosticEvent>? = try {
        val snapshot = snapshots.readCheckpointSnapshot()
        val observed = projectionReads.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        ProtectedPresentationOverlay.read(storage::read, snapshot.storeId())?.use { it.events() }
            ?: org.kurdistanvpn.data.secure.EncryptedDiagnosticEventStore.readOnly(
            ReadOnlyProtectedBlobView(snapshot.objects(), storage::readObject, codec, key),
        ).load()
    } catch (_: Throwable) { null }

    fun enrollmentSummaries(): List<ClientKeySummary>? = withReadKeys { it.list() }

    fun enrollmentRequest(id: String): ByteArray? = withReadKeys { it.publicRequest(id) }

    private fun <T> withReadKeys(block: (org.kurdistanvpn.data.secure.ClientKeyBundleStore) -> T): T? = try {
        val snapshot = snapshots.readCheckpointSnapshot()
        val observed = projectionReads.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        block(org.kurdistanvpn.data.secure.ClientKeyBundleStore.readOnly(
            ReadOnlyProtectedBlobView(snapshot.objects(), storage::readObject, codec, key),
            org.kurdistanvpn.data.secure.KurdRecipientKeyNative(native),
        ))
    } catch (_: Throwable) { null }

    private suspend fun <T> mutation(block: (ProtectedStateMutationBroker) -> BrokerMutation<T>): CommandResult<T> =
        withContext(Dispatchers.IO) { if (closed) CommandResult.Busy else protectedCommandResult { broker?.let(block) } }

    /** IO dispatch only; the selected broker methods never reserve or retire an ACTIVE authority owner. */
    private suspend fun <T> presentation(block: (ProtectedStateMutationBroker) -> BrokerMutation<T>): CommandResult<T> =
        withContext(Dispatchers.IO) { if (closed) CommandResult.Busy else protectedCommandResult { broker?.let(block) } }

    @Synchronized override fun close() {
        if (closed) {
            closeFailure?.let { throw it }
            return
        }
        closed = true
        var failure: Throwable? = null
        for (owner in owners.asReversed()) {
            val result = owner.closeResult()
            if (result != DurableCode.OK && result != DurableCode.CLOSED) {
                val error = IllegalStateException("PROTECTED_DIRECTORY_CLOSE_UNPROVEN")
                if (failure == null) failure = error else failure.addSuppressed(error)
            }
        }
        closeFailure = failure
        if (failure != null) throw failure
    }

    companion object {
        private const val NO_BACKUP = "no_backup"
        private const val ROOT = "protected-state-v1"
        private const val LOCK = "protected-state.lock"
        private const val KEY_ALIAS = "kurdistan-phase9-availability-kek-v1"
        // Android is Linux-based and Bionic exposes this native open flag on API 26;
        // the public Java OsConstants field was added only in API 27. Supplying it to
        // Os.open keeps close-on-exec atomic with descriptor creation.
        private const val LINUX_O_CLOEXEC = 0x00080000
        private val layout = ProjectionLeafLayout("protected-metadata.db", "protected-settings.preferences_pb")
        private class OpenFailure(val result: OpenResult) : IllegalStateException()

        /** Opens only already-existing CE state. It never creates directories, locks, keys or projections. */
        fun openExistingReadOnly(context: Context, primitives: DurableFilePrimitives, native: KurdNativeCore,
            processOwner: ProtectedStateProcessOwner): OpenResult =
            open(context, primitives, native, processOwner, interactive = false)

        /** Existing initialized state only. Writer acquisition is deferred to typed broker commands. */
        fun openForInteractiveMutation(context: Context, primitives: DurableFilePrimitives, native: KurdNativeCore,
            processOwner: ProtectedStateProcessOwner): OpenResult =
            open(context, primitives, native, processOwner, interactive = true)

        /**
         * Explicit first-use or post-complete-reset provisioning only. Only an absent root or
         * an existing root containing exactly its empty known lock can be initialized. Any
         * existing key, legacy state, partial record, or ambiguity requires separate recovery.
         */
        fun initializeForExplicitInteraction(context: Context, primitives: DurableFilePrimitives,
            native: KurdNativeCore, processOwner: ProtectedStateProcessOwner): OpenResult {
            if (!context.getSystemService(UserManager::class.java).isUserUnlocked) return OpenResult.Locked
            var ce: DurableOwnedDirectory? = null
            var backup: DurableOwnedDirectory? = null
            var root: DurableOwnedDirectory? = null
            var transferred = false
            var result: OpenResult = OpenResult.Unproven
            try {
                ce = openCredentialParent(context) ?: throw OpenFailure(OpenResult.Unproven)
                val existingKey = try {
                    AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1)
                    true
                } catch (_: MissingKeyException) { false }
                catch (_: KeyInvalidatedException) { throw OpenFailure(OpenResult.KeyInvalidated) }
                if (existingKey) throw OpenFailure(OpenResult.MigrationRequired)
                prepareFrameworkParentsForFirstUse(checkNotNull(ce.borrow()))
                if (knownLegacyStateExists(primitives, checkNotNull(ce.borrow())))
                    throw OpenFailure(OpenResult.MigrationRequired)
                backup = openOrCreateChild(primitives, checkNotNull(ce.borrow()), NO_BACKUP)
                val existing = primitives.openChildDirectory(checkNotNull(backup.borrow()), ROOT)
                val created = existing.code == DurableCode.ABSENT
                root = when (existing.code) {
                    DurableCode.OK -> checkNotNull(existing.owner)
                    DurableCode.ABSENT -> primitives.createChildDirectoryExclusive(checkNotNull(backup.borrow()), ROOT).owner
                        ?: throw OpenFailure(OpenResult.Unproven)
                    else -> throw OpenFailure(OpenResult.Unproven)
                }
                val directory = checkNotNull(root.borrow())
                val lockIdentity = if (created) {
                    val lock = primitives.bootstrapLock(directory, LOCK)
                    if (lock.code != DurableCode.OK) throw OpenFailure(OpenResult.Unproven)
                    checkNotNull(lock.identity)
                } else {
                    val lock = primitives.read(directory, LOCK, 1)
                    if (lock.code != DurableCode.OK || lock.snapshot?.size != 0) throw OpenFailure(OpenResult.Unproven)
                    checkNotNull(lock.snapshot).identity
                }
                val key = initializeUnderEmptyRootLease(primitives, directory, lockIdentity,
                    requireAbsentSource = {
                        val present = try { AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1); true }
                            catch (_: MissingKeyException) { false }
                            catch (_: KeyInvalidatedException) { throw OpenFailure(OpenResult.KeyInvalidated) }
                        if (present || knownLegacyStateExists(primitives, checkNotNull(ce.borrow())))
                            throw OpenFailure(OpenResult.MigrationRequired)
                    },
                    create = { AndroidKeystoreKek.createForFirstUse(KEY_ALIAS, 1, preferStrongBox = true) })
                val storage = EncryptedJournalStorage.writer(directory, primitives, SecureEnvelopeCodec(), key,
                    lockIdentity)
                val store = ByteArray(16).also(java.security.SecureRandom()::nextBytes)
                val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(java.security.SecureRandom()::nextBytes)
                try {
                    require(store.any { it != 0.toByte() } && operation.any { it != 0.toByte() })
                    storage.provisionStoreIdentity(store)
                    val journal = ProtectedStateOperationJournal(storage)
                    journal.initialize(store)
                    val files = ClosedProjectionFiles(directory, primitives, layout)
                    val snapshots = ProtectedStateSnapshotReader(journal) { reference -> checkNotNull(storage.readObject(reference.physicalId)) }
                    val committed = ReadOnlyCheckpointProjectionAccess(files, snapshots::readCheckpointSnapshot, journal::readProjectionWitness)
                    val projections = ClosedStoreProjectionAccess(
                        AndroidProjectionStoreOwnerFactory(context, java.io.File(credentialProtectedDataDir(context),
                            "$NO_BACKUP/$ROOT"), directory, layout), files,
                        object : ProjectionWriterLeaseAccess { override fun <T> withCurrentWriter(block: (DurableWriter) -> T): T? = storage.withCurrentWriter(block) },
                        journal::readControl, committed, { snapshot -> recipientBindings(snapshot, storage, key, native) })
                    val settings = SettingsProjectionCodec.fromModel(ProductSettings())
                    val catalog = ProfileCatalogProjectionCodec.encode(emptyList())
                    val initial = ProtectedStateSnapshot.create(store, 2, null, emptyList(), settings, catalog, operation)
                    try {
                        val expected = initial.encode()
                        try {
                            check(journal.mutate(MutationKind.MIGRATION, operation, expected, mutation = {
                                projections.initialize(initial)
                            }, reconstruct = {
                                val observed = projections.read()
                                observed.requireMatches(initial)
                                journal.bindProjection(initial, PhysicalProjectionWitness.capture(initial, observed.physical()))
                                initial.encode()
                            }) == ProtectedMutationStatus.COMMITTED)
                        } finally { expected.fill(0) }
                    } finally { settings.fill(0); catalog.fill(0) }
                    val broker = ProtectedStateMutationBroker.compose(storage, storage::readObject, storage::objectWriter,
                        SecureEnvelopeCodec(), key, projections, native, processOwner.mutationPolicy(), storage.garbageObjects())
                    transferred = true
                    result = OpenResult.Ready(ProtectedStateApplicationFacade(listOf(ce, backup, root), storage, snapshots,
                        projections, broker, SecureEnvelopeCodec(), key, native, processOwner,
                        composeCompleteReset(storage, directory, lockIdentity, processOwner,
                            { check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }),
                        { check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }))
                } finally { store.fill(0); operation.fill(0) }
            } catch (failure: OpenFailure) {
                result = failure.result
            } catch (_: Throwable) {
                result = OpenResult.Unproven
            } finally {
                if (!transferred) {
                    val closes = listOf(root, backup, ce).mapNotNull { owner -> owner?.closeResult() }
                    if (closes.any { it != DurableCode.OK && it != DurableCode.CLOSED }) result = OpenResult.Unproven
                }
            }
            return result
        }

        /** Explicit confirmation is required. No restoration path calls this or creates a legacy reader. */
        fun migrateLegacyForExplicitInteraction(context: Context, primitives: DurableFilePrimitives,
            native: KurdNativeCore, processOwner: ProtectedStateProcessOwner): OpenResult {
            if (!context.getSystemService(UserManager::class.java).isUserUnlocked) return OpenResult.Locked
            var ce: DurableOwnedDirectory? = null
            var backup: DurableOwnedDirectory? = null
            var root: DurableOwnedDirectory? = null
            var legacyBlobs: DurableOwnedDirectory? = null
            var databases: DurableOwnedDirectory? = null
            var files: DurableOwnedDirectory? = null
            var datastore: DurableOwnedDirectory? = null
            var legacy: FdSnapshotLegacyMigrationAccess? = null
            var transferred = false
            var result: OpenResult = OpenResult.Unproven
            try {
                ce = openCredentialParent(context) ?: throw OpenFailure(OpenResult.Unproven)
                val key = try { AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1) }
                catch (_: MissingKeyException) { throw OpenFailure(OpenResult.MigrationRequired) }
                catch (_: KeyInvalidatedException) { throw OpenFailure(OpenResult.KeyInvalidated) }
                backup = primitives.openChildDirectory(checkNotNull(ce.borrow()), NO_BACKUP).owner
                    ?: throw OpenFailure(OpenResult.MigrationRequired)
                if (!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) {
                    throw OpenFailure(OpenResult.MigrationRequired)
                }
                fun optionalChild(parent: DurableDirectory, leaf: String): DurableOwnedDirectory? {
                    val opened = primitives.openChildDirectory(parent, leaf)
                    return when (opened.code) {
                        DurableCode.OK -> checkNotNull(opened.owner)
                        DurableCode.ABSENT -> null
                        else -> throw OpenFailure(OpenResult.Unproven)
                    }
                }
                legacyBlobs = optionalChild(checkNotNull(backup.borrow()), "phase9-v1")
                databases = optionalChild(checkNotNull(ce.borrow()), "databases")
                files = optionalChild(checkNotNull(ce.borrow()), "files")
                datastore = files?.let { optionalChild(checkNotNull(it.borrow()), "datastore") }
                val existing = primitives.openChildDirectory(checkNotNull(backup.borrow()), ROOT)
                check(existing.code == DurableCode.ABSENT) { "MIGRATION_TARGET_ALREADY_EXISTS" }
                root = primitives.createChildDirectoryExclusive(checkNotNull(backup.borrow()), ROOT).owner
                    ?: throw OpenFailure(OpenResult.Unproven)
                val directory = checkNotNull(root.borrow())
                val lockIdentity = primitives.bootstrapLock(directory, LOCK).let { boot ->
                    check(boot.code == DurableCode.OK); checkNotNull(boot.identity)
                }
                val storage = EncryptedJournalStorage.writer(directory, primitives, SecureEnvelopeCodec(), key, lockIdentity)
                val store = ByteArray(16).also(SecureRandom()::nextBytes)
                try {
                    require(store.any { it != 0.toByte() })
                    storage.provisionStoreIdentity(store)
                    val journal = ProtectedStateOperationJournal(storage)
                    journal.initialize(store)
                    val filesAdapter = ClosedProjectionFiles(directory, primitives, layout)
                    val snapshots = ProtectedStateSnapshotReader(journal) { reference -> checkNotNull(storage.readObject(reference.physicalId)) }
                    val committed = ReadOnlyCheckpointProjectionAccess(filesAdapter, snapshots::readCheckpointSnapshot, journal::readProjectionWitness)
                    val projections = ClosedStoreProjectionAccess(
                        AndroidProjectionStoreOwnerFactory(context, java.io.File(credentialProtectedDataDir(context), "$NO_BACKUP/$ROOT"), directory, layout), filesAdapter,
                        object : ProjectionWriterLeaseAccess { override fun <T> withCurrentWriter(block: (DurableWriter) -> T): T? = storage.withCurrentWriter(block) },
                        journal::readControl, committed, { snapshot -> recipientBindings(snapshot, storage, key, native) })
                    legacy = FdSnapshotLegacyMigrationAccess(primitives, databases?.borrow(), datastore?.borrow(),
                        legacyBlobs?.borrow(), directory, java.io.File(credentialProtectedDataDir(context), "$NO_BACKUP/$ROOT"), storage)
                    val migration = ProtectedStateMigrationCoordinator(storage, checkNotNull(legacy), storage::objectWriter, storage::readObject,
                        projections, SecureEnvelopeCodec(), key, native).migrateConfirmed()
                    check(migration.status == ProtectedMutationStatus.COMMITTED) { "MIGRATION_NOT_COMMITTED_${migration.status}" }
                    legacy.close()
                    legacy = null
                    val sourceCloses = listOf(datastore, files, databases, legacyBlobs).mapNotNull { it?.closeResult() }
                    datastore = null; files = null; databases = null; legacyBlobs = null
                    check(sourceCloses.all { it == DurableCode.OK || it == DurableCode.CLOSED }) { "LEGACY_SOURCE_CLEANUP_UNPROVEN" }
                    val broker = ProtectedStateMutationBroker.compose(storage, storage::readObject, storage::objectWriter,
                        SecureEnvelopeCodec(), key, projections, native, processOwner.mutationPolicy(), storage.garbageObjects())
                    transferred = true
                    result = OpenResult.Ready(ProtectedStateApplicationFacade(listOf(ce, backup, root), storage, snapshots,
                        projections, broker, SecureEnvelopeCodec(), key, native, processOwner,
                        composeCompleteReset(storage, directory, lockIdentity, processOwner,
                            { check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }),
                        { check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }))
                } finally { store.fill(0) }
            } catch (failure: OpenFailure) {
                result = failure.result
            } catch (_: Throwable) {
                result = OpenResult.Unproven
            } finally {
                try { legacy?.close() } catch (_: Throwable) { result = OpenResult.Unproven }
                val sourceCloses = listOf(datastore, files, databases, legacyBlobs).mapNotNull { it?.closeResult() }
                if (sourceCloses.any { it != DurableCode.OK && it != DurableCode.CLOSED }) result = OpenResult.Unproven
                if (!transferred) {
                    val closes = listOf(root, backup, ce).mapNotNull { it?.closeResult() }
                    if (closes.any { it != DurableCode.OK && it != DurableCode.CLOSED }) result = OpenResult.Unproven
                }
            }
            return result
        }

        private fun open(context: Context, primitives: DurableFilePrimitives, native: KurdNativeCore,
            processOwner: ProtectedStateProcessOwner, interactive: Boolean): OpenResult {
            if (!context.getSystemService(UserManager::class.java).isUserUnlocked) return OpenResult.Locked
            var ce: DurableOwnedDirectory? = null
            var backup: DurableOwnedDirectory? = null
            var root: DurableOwnedDirectory? = null
            var transferred = false
            var result: OpenResult = OpenResult.Unproven
            try {
                ce = openCredentialParent(context) ?: throw OpenFailure(OpenResult.Unproven)
                val parent = checkNotNull(ce.borrow())
                val backupOpen = primitives.openChildDirectory(parent, NO_BACKUP)
                if (backupOpen.code != DurableCode.OK) {
                    if (backupOpen.code !in setOf(DurableCode.ABSENT, DurableCode.UNSAFE))
                        throw OpenFailure(OpenResult.Unproven)
                    // A framework 0771 parent is not an absent protected store. Prove
                    // absence/legacy state without repairing permissions during startup.
                    inspectFrameworkParents(parent, prepare = false)
                    throw OpenFailure(OpenResult.Missing)
                }
                backup = checkNotNull(backupOpen.owner)
                val rootOpen = primitives.openChildDirectory(checkNotNull(backup.borrow()), ROOT)
                if (rootOpen.code != DurableCode.OK) {
                    if (rootOpen.code != DurableCode.ABSENT) throw OpenFailure(OpenResult.Unproven)
                    inspectFrameworkParents(parent, prepare = false)
                    throw OpenFailure(OpenResult.Missing)
                }
                root = checkNotNull(rootOpen.owner)
                val directory = checkNotNull(root.borrow())
                val existingKey = try { AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1) }
                catch (_: MissingKeyException) { throw OpenFailure(OpenResult.Unproven) }
                catch (_: KeyInvalidatedException) { throw OpenFailure(OpenResult.KeyInvalidated) }
                val lock = primitives.read(directory, LOCK, 1)
                if (lock.code != DurableCode.OK || checkNotNull(lock.snapshot).size != 0)
                    throw OpenFailure(OpenResult.Unproven)
                val lockIdentity = checkNotNull(lock.snapshot).identity
                val storage = if (interactive) EncryptedJournalStorage.writer(directory, primitives, SecureEnvelopeCodec(), existingKey, lockIdentity)
                    else EncryptedJournalStorage.readOnly(directory, primitives, SecureEnvelopeCodec(), existingKey)
                val journal = ProtectedStateOperationJournal(storage)
                val snapshots = ProtectedStateSnapshotReader(journal) { reference -> checkNotNull(storage.readObject(reference.physicalId)) }
                val files = ClosedProjectionFiles(directory, primitives, layout)
                val committed = ReadOnlyCheckpointProjectionAccess(files, snapshots::readCheckpointSnapshot, journal::readProjectionWitness)
                val reads: ProtectedProjectionReadAccess
                val writer: ProtectedStateMutationBroker?
                if (interactive) {
                    val projections = ClosedStoreProjectionAccess(
                        AndroidProjectionStoreOwnerFactory(context, java.io.File(credentialProtectedDataDir(context),
                            "$NO_BACKUP/$ROOT"), directory, layout), files,
                        object : ProjectionWriterLeaseAccess { override fun <T> withCurrentWriter(block: (DurableWriter) -> T): T? = storage.withCurrentWriter(block) },
                        journal::readControl, committed, { snapshot -> recipientBindings(snapshot, storage, existingKey, native) })
                    reads = projections
                    writer = ProtectedStateMutationBroker.compose(storage, storage::readObject, storage::objectWriter,
                        SecureEnvelopeCodec(), existingKey, projections, native, processOwner.mutationPolicy(),
                        storage.garbageObjects())
                } else { reads = committed; writer = null }
                val facade = ProtectedStateApplicationFacade(listOf(ce, backup, root), storage, snapshots, reads, writer,
                    SecureEnvelopeCodec(), existingKey, native, processOwner,
                    if (interactive) composeCompleteReset(storage, directory, lockIdentity, processOwner,
                        { check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }) else null,
                    if (interactive) ({ check(!knownLegacyStateExists(primitives, checkNotNull(ce.borrow()))) { "LEGACY_RESET_SCOPE_UNPROVEN" } }) else null)
                transferred = true
                result = OpenResult.Ready(facade)
            } catch (failure: OpenFailure) {
                result = failure.result
            } catch (_: Throwable) {
                result = OpenResult.Unproven
            } finally {
                if (!transferred) {
                    val closes = listOf(root, backup, ce).mapNotNull { owner -> owner?.closeResult() }
                    if (closes.any { it != DurableCode.OK && it != DurableCode.CLOSED }) result = OpenResult.Unproven
                }
            }
            return result
        }

        private fun composeCompleteReset(storage: EncryptedJournalStorage, directory: DurableDirectory,
            lockIdentity: DurableFileIdentity, owner: ProtectedStateProcessOwner,
            requireScope: () -> Unit): ProtectedStateResetRecoveryCoordinator {
            // Every access borrows the currently held journal writer for this call only.
            // Neither the coordinator nor application code receives or closes the real lease.
            val access = DurableResetFileAccess(listOf(ResetDirectoryBinding(ResetDirectoryRole.JOURNAL,
                directory, LOCK, lockIdentity))) { role ->
                check(role == ResetDirectoryRole.JOURNAL)
                object : DurableWriter {
                    override fun read(leaf: String, maxBytes: Int) = checkNotNull(storage.withCurrentWriter { it.read(leaf, maxBytes) })
                    override fun list(maxEntries: Int) = checkNotNull(storage.withCurrentWriter { it.list(maxEntries) })
                    override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int) =
                        checkNotNull(storage.withCurrentWriter { it.delete(leaf, expectedOld, maxBytes) })
                    override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int): DurableMutationResult =
                        error("RESET_CANNOT_REPLACE_PRODUCT_FILES")
                    override fun closeResult(): DurableCode = error("JOURNAL_OWNS_WRITER_LEASE")
                    override fun close(): Unit = error("JOURNAL_OWNS_WRITER_LEASE")
                }
            }
            val existing = object : ExistingResetKeyAccess {
                override fun observe(): ResetKeyObservation = try {
                    requireScope()
                    ResetKeyObservation.Present(AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1).generation)
                } catch (_: MissingKeyException) { ResetKeyObservation.Absent }
                catch (_: Throwable) { ResetKeyObservation.Unavailable }
                override fun eraseExisting(expectedGeneration: Int) {
                    requireScope()
                    check(AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1).generation == expectedGeneration)
                    AndroidKeystoreKek.deleteForExplicitReset(KEY_ALIAS)
                }
            }
            return ProtectedStateResetRecoveryCoordinator(storage, access, existing, owner.mutationPolicy())
        }

        /** Android can create databases and no_backup as 0771 before explicit first use.
         * Tighten only these empty-of-product-state framework parents. Native protected
         * directory checks remain exact 0700; existing state and read-only opens never repair modes. */
        private fun prepareFrameworkParentsForFirstUse(parent: DurableDirectory) =
            inspectFrameworkParents(parent, prepare = true)

        private fun inspectFrameworkParents(parent: DurableDirectory, prepare: Boolean) {
            val anchor = "/proc/self/fd/${parent.directoryFd}"
            val parentStat = Os.stat(anchor)
            if (!OsConstants.S_ISDIR(parentStat.st_mode) || parentStat.st_mode and 4095 != 448 ||
                parentStat.st_uid.toLong() != parent.expectedUid ||
                parentStat.st_dev != parent.identity.device || parentStat.st_ino != parent.identity.inode)
                throw OpenFailure(OpenResult.Unproven)
            fun statOrAbsent(path: String): android.system.StructStat? = try { Os.lstat(path) }
                catch (error: ErrnoException) {
                    if (error.errno != OsConstants.ENOENT) throw error
                    null
                }
            fun sameDirectory(left: android.system.StructStat, right: android.system.StructStat): Boolean =
                OsConstants.S_ISDIR(right.st_mode) && right.st_uid.toLong() == parent.expectedUid &&
                    right.st_dev == parentStat.st_dev && right.st_ino != parentStat.st_ino &&
                    right.st_nlink >= 1 && left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
                    left.st_uid == right.st_uid && left.st_mode == right.st_mode
            data class FrameworkParent(val name: String, val owner: ParcelFileDescriptor,
                var observed: android.system.StructStat)
            val names = listOf("databases", NO_BACKUP)
            val opened = mutableListOf<FrameworkParent>()
            var mutationAttempted = false
            try {
                for (name in names) {
                    val path = "$anchor/$name"
                    val named = statOrAbsent(path) ?: continue
                    if (!sameDirectory(named, named) || named.st_mode and 4095 !in setOf(448, 505))
                        throw OpenFailure(OpenResult.Unproven)
                    val fd = Os.open(path, credentialParentOpenFlags(), 0)
                    try {
                        val actual = Os.fstat(fd)
                        if (!sameDirectory(named, actual) || !sameDirectory(actual, Os.lstat(path)))
                            throw OpenFailure(OpenResult.Unproven)
                        opened += FrameworkParent(name, ParcelFileDescriptor.dup(fd), actual)
                    } finally { Os.close(fd) }
                }
                val requiresPreparation = opened.any { it.observed.st_mode and 4095 == 505 }
                fun validateAll() {
                    val currentParent = Os.stat(anchor)
                    if (currentParent.st_dev != parentStat.st_dev || currentParent.st_ino != parentStat.st_ino ||
                        currentParent.st_uid != parentStat.st_uid || currentParent.st_mode != parentStat.st_mode)
                        throw OpenFailure(OpenResult.Unproven)
                    // Never classify an existing/partial protected root as fresh or legacy
                    // merely because its framework parent could not be opened natively.
                    if (!prepare) {
                        val backup = opened.singleOrNull { it.name == NO_BACKUP }
                        if (backup != null && statOrAbsent("/proc/self/fd/${backup.owner.fd}/$ROOT") != null)
                            throw OpenFailure(OpenResult.Unproven)
                    }
                    for (name in names) {
                        val directory = opened.singleOrNull { it.name == name }
                        val named = statOrAbsent("$anchor/$name")
                        if (directory == null) {
                            if (named != null) throw OpenFailure(OpenResult.Unproven)
                            continue
                        }
                        val actual = Os.fstat(directory.owner.fileDescriptor)
                        if (named == null || !sameDirectory(directory.observed, actual) || !sameDirectory(actual, named))
                            throw OpenFailure(OpenResult.Unproven)
                        // Product-state absence is checked through the held directory, not a reopened name.
                        val held = "/proc/self/fd/${directory.owner.fd}"
                        val legacy = if (name == "databases") "phase9-metadata.db" else "phase9-v1"
                        if (statOrAbsent("$held/$legacy") != null) throw OpenFailure(OpenResult.MigrationRequired)
                        if (requiresPreparation && name == NO_BACKUP && statOrAbsent("$held/$ROOT") != null)
                            throw OpenFailure(OpenResult.Unproven)
                    }
                }
                validateAll()
                if (!prepare) return
                // Prove both directory handles support durability before changing either mode.
                opened.forEach { Os.fsync(it.owner.fileDescriptor) }
                validateAll()
                for (directory in opened.filter { it.observed.st_mode and 4095 == 505 }) {
                    validateAll()
                    mutationAttempted = true
                    Os.fchmod(directory.owner.fileDescriptor, 448)
                    Os.fsync(directory.owner.fileDescriptor)
                    val prepared = Os.fstat(directory.owner.fileDescriptor)
                    if (prepared.st_mode and 4095 != 448 || prepared.st_dev != directory.observed.st_dev ||
                        prepared.st_ino != directory.observed.st_ino || prepared.st_uid != directory.observed.st_uid)
                        throw OpenFailure(OpenResult.Unproven)
                    directory.observed = prepared
                    validateAll()
                }
            } catch (failure: Throwable) {
                throw frameworkPreparationFailure(mutationAttempted, failure)
            } finally {
                var closeUnproven = false
                opened.asReversed().forEach {
                    try { it.owner.close() } catch (_: Throwable) { closeUnproven = true }
                }
                // A failure after one chmod is unproven; this does not promise atomic rollback.
                if (closeUnproven) throw OpenFailure(OpenResult.Unproven)
            }
        }

        private fun frameworkPreparationFailure(mutationAttempted: Boolean, failure: Throwable): Throwable =
            if (mutationAttempted) OpenFailure(OpenResult.Unproven) else failure

        private fun openOrCreateChild(primitives: DurableFilePrimitives, parent: DurableDirectory,
            leaf: String): DurableOwnedDirectory {
            val existing = primitives.openChildDirectory(parent, leaf)
            if (existing.code == DurableCode.OK) return checkNotNull(existing.owner)
            if (existing.code != DurableCode.ABSENT) throw OpenFailure(OpenResult.Unproven)
            return checkNotNull(primitives.createChildDirectoryExclusive(parent, leaf).owner) {
                "INTERACTIVE_DIRECTORY_CREATE_UNPROVEN"
            }
        }

        /** Exact legacy locations only. This neither traverses nor creates caller-controlled paths. */
        private fun knownLegacyStateExists(primitives: DurableFilePrimitives, ce: DurableDirectory): Boolean {
            fun child(parent: DurableDirectory, leaf: String): DurableOwnedDirectory? {
                val opened = primitives.openChildDirectory(parent, leaf)
                if (opened.code == DurableCode.ABSENT) return null
                if (opened.code != DurableCode.OK) throw OpenFailure(OpenResult.Unproven)
                return checkNotNull(opened.owner)
            }
            var noBackup: DurableOwnedDirectory? = null
            var databases: DurableOwnedDirectory? = null
            var outcome = false
            try {
                noBackup = child(ce, NO_BACKUP)
                if (noBackup != null) {
                    val legacy = child(checkNotNull(noBackup.borrow()), "phase9-v1")
                    if (legacy != null) {
                        try { outcome = true } finally {
                            if (legacy.closeResult() != DurableCode.OK) throw OpenFailure(OpenResult.Unproven)
                        }
                    }
                }
                databases = child(ce, "databases")
                if (databases != null) {
                    val old = primitives.read(checkNotNull(databases.borrow()), "phase9-metadata.db", JournalLimits.OBJECT_BYTES)
                    if (old.code == DurableCode.OK) outcome = true
                    else if (old.code != DurableCode.ABSENT) throw OpenFailure(OpenResult.Unproven)
                }
                return outcome
            } finally {
                val closes = listOf(databases, noBackup).mapNotNull { it?.closeResult() }
                if (closes.any { it != DurableCode.OK && it != DurableCode.CLOSED }) throw OpenFailure(OpenResult.Unproven)
            }
        }

        private fun openCredentialParent(context: Context): DurableOwnedDirectory? {
            val path = credentialProtectedDataDir(context)
            var fd: java.io.FileDescriptor? = null
            var owned: ParcelFileDescriptor? = null
            return try {
                val before = Os.lstat(path)
                if (!OsConstants.S_ISDIR(before.st_mode) || before.st_uid != context.applicationInfo.uid || before.st_mode and 511 != 448) return null
                fd = Os.open(path, credentialParentOpenFlags(), 0)
                val actual = Os.fstat(checkNotNull(fd))
                if (!OsConstants.S_ISDIR(actual.st_mode) || actual.st_uid != before.st_uid || actual.st_dev != before.st_dev || actual.st_ino != before.st_ino || actual.st_mode and 511 != 448) return null
                owned = ParcelFileDescriptor.dup(checkNotNull(fd))
                val raw = checkNotNull(fd); fd = null
                try { Os.close(raw) } catch (_: Throwable) { return null }
                FrameworkDirectory(owned, DurableDirectory(owned.fd.toLong(), actual.st_uid.toLong(), DurableFileIdentity(actual.st_dev, actual.st_ino))).also { owned = null }
            } catch (_: Throwable) { null }
            finally { try { if (fd != null) Os.close(fd) } catch (_: Throwable) { }; try { owned?.close() } catch (_: Throwable) { } }
        }

        private fun credentialParentOpenFlags(): Int =
            credentialParentOpenFlags(OsConstants.O_NOFOLLOW)

        private fun credentialParentOpenFlags(noFollow: Int): Int {
            // Bionic's ARM and x86 flag families differ. The public O_NOFOLLOW value
            // identifies the loaded ABI without reflecting a hidden O_DIRECTORY field.
            // NDK asm/fcntl.h: ARM64 uses 0x4000; 0x10000 is O_DIRECT there.
            val directory = when (noFollow) {
                0x00008000 -> 0x00004000
                0x00020000 -> 0x00010000
                else -> error("UNSUPPORTED_DIRECTORY_OPEN_FLAG_FAMILY")
            }
            return OsConstants.O_RDONLY or directory or LINUX_O_CLOEXEC or noFollow
        }

        private fun credentialProtectedDataDir(context: Context): String =
            checkNotNull(context.applicationInfo::class.java.getField("credentialProtectedDataDir")
                .get(context.applicationInfo) as? String) { "CREDENTIAL_PROTECTED_DIRECTORY_UNAVAILABLE" }

        private fun recipientBindings(snapshot: ProtectedStateSnapshot, storage: EncryptedJournalStorage,
            key: KeyEncryptionKey, native: KurdNativeCore): List<RecipientBindingEntity> {
            val view = ReadOnlyProtectedBlobView(snapshot.objects(), storage::readObject, SecureEnvelopeCodec(), key)
            val records = org.kurdistanvpn.data.secure.ClientKeyBundleStore.readOnly(view,
                org.kurdistanvpn.data.secure.KurdRecipientKeyNative(native)).backupRecords()
            val operation = snapshot.operationId().joinToString("") { "%02x".format(it) }
            try {
                return records.flatMap { record ->
                    try {
                        if (record.sourceProfileRecordIds.isEmpty()) emptyList() else {
                        require(record.sourceStatus == org.kurdistanvpn.data.secure.ClientKeyStatus.PROFILE_VERIFIED)
                        record.sourceProfileRecordIds.map { profile ->
                            RecipientBindingEntity(profile, record.sourceRecordId, operation, snapshot.revision)
                        }}
                    } finally { record.destroy() }
                }.sortedBy { it.profileRecordId }
            } finally { records.forEach { it.destroy() } }
        }
    }
}

private class FrameworkDirectory(private var descriptor: ParcelFileDescriptor?, private val directory: DurableDirectory) : DurableOwnedDirectory {
    @Synchronized override fun borrow(): DurableDirectory? = descriptor?.let { directory }
    @Synchronized override fun <T> withBorrow(block: (DurableDirectory) -> T): T? = descriptor?.let { block(directory) }
    @Synchronized override fun closeResult(): DurableCode {
        val current = descriptor ?: return DurableCode.CLOSED
        descriptor = null
        return try { current.close(); DurableCode.OK } catch (_: Throwable) { DurableCode.CLOSE_UNPROVEN }
    }
    override fun close() { closeResult() }
}

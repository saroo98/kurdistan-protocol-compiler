// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.secure.WrappedKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.kurdistanvpn.core.nativeapi.*

class ProtectedStateCrashMatrixTest {
    @Test fun encryptedProductionAdapterPersistsAndReopensCompensationResolution() {
        val raw = MemoryDurablePrimitives()
        val codec = SecureEnvelopeCodec()
        val key = JournalTestKey()
        val storage = EncryptedJournalStorage.writer(raw.directory, raw, codec, key, raw.lock)
        storage.provisionStoreIdentity(ByteArray(16) { 1 })
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        val operation = ByteArray(JournalLimits.OPERATION_BYTES) { 2 }
        assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.RESTORE,
            operation, byteArrayOf(9), { error("interrupted") }, { byteArrayOf(9) }))
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.recover(operation, byteArrayOf(8),
            {}, { byteArrayOf(8) }, RecoveryResolution.QUARANTINE))
        val readOnly = EncryptedJournalStorage.readOnly(raw.directory, raw, codec, key)
        assertArrayEquals(byteArrayOf(8), ProtectedStateOperationJournal(readOnly).readCheckpoint())
        assertEquals(2L, journal.readControl().revision)
    }

    @Test fun productionObjectAdapterRequiresItsCurrentDurableDirtyOperationAndWriterLease() {
        val raw = MemoryDurablePrimitives()
        val storage = EncryptedJournalStorage.writer(raw.directory, raw, SecureEnvelopeCodec(), JournalTestKey(), raw.lock)
        storage.provisionStoreIdentity(ByteArray(16) { 1 })
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        val operation = ByteArray(JournalLimits.OPERATION_BYTES) { 2 }
        val objects = storage.objectWriter(operation)
        assertThrows(IllegalStateException::class.java) { objects.create("object-test", byteArrayOf(1)) }
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.PROFILE_IMPORT, operation,
            byteArrayOf(9), {
                assertThrows(IllegalStateException::class.java) { objects.requireDirtyOperation(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }) }
                objects.create("object-test", byteArrayOf(7))
                assertArrayEquals(byteArrayOf(7), objects.read("object-test"))
                assertThrows(IllegalStateException::class.java) { objects.create("object-test", byteArrayOf(8)) }
            }, { byteArrayOf(9) }))
        assertThrows(IllegalStateException::class.java) { objects.create("object-late", byteArrayOf(1)) }
        assertEquals(3, raw.closes) // Provisioning, control initialization, and mutation each close once.
        assertArrayEquals(byteArrayOf(7), storage.readObject("object-test"))
    }

    @Test fun writerCloseUncertaintyCannotReturnCommittedOrAuthorizeAnotherWrite() {
        val raw = MemoryDurablePrimitives()
        val storage = EncryptedJournalStorage.writer(raw.directory, raw, SecureEnvelopeCodec(), JournalTestKey(), raw.lock)
        storage.provisionStoreIdentity(ByteArray(16) { 1 })
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        raw.closeFailure = true
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), {}, { byteArrayOf(9) }))
        var called = false
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), { called = true }, { byteArrayOf(8) }))
        assertFalse(called)
    }
    @Test fun immutableReplacementRetainsOldCiphertextAndReadOnlyViewCannotWrite() {
        val disk = TestImmutableObjects()
        val key = JournalTestKey()
        val first = MutableProtectedBlobView(emptyList(), ByteArray(JournalLimits.OPERATION_BYTES) { 1 }, 2, disk, SecureEnvelopeCodec(), key)
        first.stage("profile-one", SecureDataClass.IMPORT_REQUEST, byteArrayOf(1, 2))
        val original = first.references().single()
        val retained = disk.read(original.physicalId)!!
        val next = MutableProtectedBlobView(first.references(), ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, 4, disk, SecureEnvelopeCodec(), key)
        next.stage("profile-one", SecureDataClass.IMPORT_REQUEST, byteArrayOf(3, 4))
        assertNotEquals(original.physicalId, next.references().single().physicalId)
        assertArrayEquals(retained, disk.read(original.physicalId))
        val readOnly = ReadOnlyProtectedBlobView(first.references(), disk::read, SecureEnvelopeCodec(), key)
        assertArrayEquals(byteArrayOf(1, 2), readOnly.reopen("profile-one", SecureDataClass.IMPORT_REQUEST))
        assertFalse(org.kurdistanvpn.data.secure.SecureBlobAccess::class.java.isAssignableFrom(readOnly.javaClass))
        retained.fill(0)
    }

    @Test fun objectWriteOrRereadFailureCannotPublishANewReference() {
        for (stage in listOf("before", "after", "reread")) {
            val disk = TestImmutableObjects()
            val view = MutableProtectedBlobView(emptyList(), ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, 2, disk, SecureEnvelopeCodec(), JournalTestKey())
            disk.failure = stage
            assertThrows(Exception::class.java) { view.stage("profile-one", SecureDataClass.IMPORT_REQUEST, byteArrayOf(1)) }
            assertTrue(view.references().isEmpty())
            // A durable but unacknowledged object remains operation-owned, never silently deleted.
            if (stage != "before") assertEquals(1, disk.values.size)
        }
    }

    @Test fun deletionOnlyChangesTheOperationViewUntilJournalCommitAndGarbageCollection() {
        val disk = TestImmutableObjects()
        val key = JournalTestKey()
        val view = MutableProtectedBlobView(emptyList(), ByteArray(JournalLimits.OPERATION_BYTES) { 1 }, 2, disk, SecureEnvelopeCodec(), key)
        view.stage("profile-one", SecureDataClass.IMPORT_REQUEST, byteArrayOf(1))
        val previous = view.references()
        val deleting = MutableProtectedBlobView(previous, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, 4, disk, SecureEnvelopeCodec(), key)
        deleting.delete("profile-one", SecureDataClass.IMPORT_REQUEST)
        assertTrue(deleting.references().isEmpty())
        assertNotNull(disk.read(previous.single().physicalId))
        assertArrayEquals(byteArrayOf(1), ReadOnlyProtectedBlobView(previous, disk::read, SecureEnvelopeCodec(), key)
            .reopen("profile-one", SecureDataClass.IMPORT_REQUEST))
    }
}

private class TestImmutableObjects : ImmutableProtectedObjectWriter {
    val values = linkedMapOf<String, ByteArray>()
    var failure: String? = null
    override fun requireDirtyOperation(operation: ByteArray) { check(operation.size == JournalLimits.OPERATION_BYTES) }
    override fun read(name: String): ByteArray? = values[name]?.clone()?.also {
        if (failure == "reread") it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
    }
    override fun create(name: String, bytes: ByteArray) {
        check(failure != "before")
        check(!values.containsKey(name))
        values[name] = bytes.clone()
        check(failure != "after")
    }
}

internal class JournalTestKey : KeyEncryptionKey {
    override val generation = 1
    override val hardwareSecurityLevel = "SYNTHETIC"
    private val key = SecretKeySpec(ByteArray(32) { (it + 1).toByte() }, "AES")
    override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey {
        val nonce = ByteArray(12) { (it + 1).toByte() }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, this.key, GCMParameterSpec(128, nonce))
        cipher.updateAAD("$recordId:${dataClass.wireValue}".toByteArray())
        return WrappedKey(nonce, cipher.doFinal(key))
    }
    override fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, wrapped.nonce))
        cipher.updateAAD("$recordId:${dataClass.wireValue}".toByteArray())
        return cipher.doFinal(wrapped.ciphertext)
    }
}

private class MemoryDurablePrimitives : DurableFilePrimitives {
    val directory = DurableDirectory(90, 1000, DurableFileIdentity(1, 2))
    val lock = DurableFileIdentity(1, 3)
    private val files = linkedMapOf<String, DurableSnapshot>(EncryptedJournalStorage.LOCK to DurableSnapshot(lock, byteArrayOf()))
    private var inode = 4L
    var closes = 0
    var closeFailure = false
    override fun read(directory: DurableDirectory, leaf: String, maxBytes: Int): DurableReadResult = files[leaf]?.let {
        check(it.size <= maxBytes); DurableReadResult(DurableCode.OK, DurableSnapshot(it.identity, it.bytes))
    } ?: DurableReadResult(DurableCode.ABSENT)
    override fun list(directory: DurableDirectory, maxEntries: Int): DurableListResult =
        DurableListResult(DurableCode.OK, files.map { (name, value) -> DurableDirectoryEntry(name, value.identity, value.size.toLong()) })
    override fun bootstrapLock(directory: DurableDirectory, lockLeaf: String) = DurableIdentityResult(DurableCode.OK, lock)
    override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity) =
        DurableOpenResult(DurableCode.OK, object : DurableWriter {
            private var closed = false
            override fun read(leaf: String, maxBytes: Int) = this@MemoryDurablePrimitives.read(directory, leaf, maxBytes)
            override fun list(maxEntries: Int) = this@MemoryDurablePrimitives.list(directory, maxEntries)
            override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int): DurableMutationResult {
                check(!closed)
                val actual = files[leaf]
                check(if (expectedOld == null) actual == null else actual?.identity == expectedOld.identity && actual.bytes.contentEquals(expectedOld.bytes))
                files[leaf] = DurableSnapshot(DurableFileIdentity(1, inode++), bytes)
                return DurableMutationResult(DurableCode.OK)
            }
            override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult {
                check(!closed && files[leaf]?.identity == expectedOld.identity)
                files.remove(leaf)
                return DurableMutationResult(DurableCode.OK)
            }
            override fun closeResult(): DurableCode { if (!closed) { closed = true; closes++ }; return if (closeFailure) DurableCode.CLOSE_UNPROVEN else DurableCode.OK }
            override fun close() { closeResult() }
        })
}

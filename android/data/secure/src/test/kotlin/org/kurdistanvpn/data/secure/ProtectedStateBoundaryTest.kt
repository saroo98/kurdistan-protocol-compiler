// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.nativeapi.ActivationCommand
import org.kurdistanvpn.core.nativeapi.ActivationCommandKind
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.DiagnosticPreviewHandle
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeActivationSession
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.VerifiedPreviewHandle
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.metadata.ProfileCatalogDao
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.TransactionState

class ProtectedStateBoundaryTest {
    @Test
    fun runtimeAuthorityReopensOnlyFinalizedEncryptedActivationAndWipesOnClose() = runBlocking {
        val native = FakeNativeCore(preview())
        val journal = ProfileAdmissionJournal(
            nativeCore = native,
            catalog = FakeCatalog(),
            blobs = FakeBlobs(),
            productionTrust = false,
            random = FixedSecureRandom(),
        )
        val verifyRequest = byteArrayOf(9, 8, 7)
        val admitted = journal.admit(verifyRequest, preview()) as AdmissionResult.Success
        val opened = journal.openRuntimeAuthority(admitted.outcome.localRecordId)
        val material = (opened as RuntimeAuthorityResult.Success).material
        assertArrayEquals(verifyRequest, material.verifyRequest)
        assertTrue(material.activationRecord.isNotEmpty())
        material.close()
        assertTrue(material.verifyRequest.all { it == 0.toByte() })
        assertTrue(material.activationRecord.all { it == 0.toByte() })
    }

    @Test
    fun runtimeAuthorityFailsClosedForUnknownRecord() = runBlocking {
        val journal = ProfileAdmissionJournal(
            nativeCore = FakeNativeCore(preview()),
            catalog = FakeCatalog(),
            blobs = FakeBlobs(),
            productionTrust = false,
        )
        assertEquals(
            OperationError.POLICY_REJECTED,
            (journal.openRuntimeAuthority("missing-record") as RuntimeAuthorityResult.Failure).error,
        )
    }
    @Test
    fun previewCodecRejectsTruncationAndInvalidState() {
        val encoded = ProfilePreviewCodec.encode(preview(), "Kurd profile")
        val decoded = ProfilePreviewCodec.decode(encoded)
        assertEquals(preview(), decoded.first)
        assertEquals("Kurd profile", decoded.second)

        for (length in 0 until encoded.size) {
            assertFails { ProfilePreviewCodec.decode(encoded.copyOf(length)) }
        }
        val invalidSealed = encoded.clone().also { it[it.size - 17] = 2 }
        assertFails { ProfilePreviewCodec.decode(invalidSealed) }
    }

    @Test
    fun backupPayloadIsBoundedAndRejectsMalformedRecords() {
        val records = listOf(
            BackupProfileRecord("01234567-89ab-4cde-8fab-0123456789ab", 7u, byteArrayOf(1, 2, 3)),
        )
        val encoded = BackupPayloadCodec.encode(records)
        assertEquals(records.first().localRecordId, BackupPayloadCodec.decode(encoded).single().localRecordId)
        assertArrayEquals(records.first().verifyRequest, BackupPayloadCodec.decode(encoded).single().verifyRequest)

        assertFails {
            BackupPayloadCodec.encode(listOf(BackupProfileRecord("../escape", 1u, byteArrayOf(1))))
        }
        assertFails {
            BackupPayloadCodec.encode(listOf(BackupProfileRecord("record-1", 0u, byteArrayOf(1))))
        }
        for (length in 0 until encoded.size) {
            assertFails { BackupPayloadCodec.decode(encoded.copyOf(length)) }
        }
    }

    @Test
    fun envelopeBindsRecordClassGenerationAndCiphertext() {
        val codec = SecureEnvelopeCodec(FixedSecureRandom())
        val kek = TestKek(1)
        val plaintext = "exact profile bytes".encodeToByteArray()
        val encoded = codec.seal("record-1", SecureDataClass.PROFILE_ARTIFACT, plaintext, kek)
        assertArrayEquals(
            plaintext,
            codec.open(encoded, "record-1", kek).plaintext,
        )
        assertFails { codec.open(encoded, "record-2", kek) }
        assertFails { codec.open(encoded, "record-1", TestKek(2)) }
        val corrupted = encoded.clone().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }
        assertFails { codec.open(corrupted, "record-1", kek) }
    }

    @Test
    fun journalRequiresMatchingPreviewAndFinalizesExactRecord() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        val request = byteArrayOf(9, 8, 7)

        val rejected = journal.admit(request, preview().copy(generation = 8u))
        assertEquals(
            OperationError.TRUST_REJECTED,
            (rejected as AdmissionResult.Failure).error,
        )
        assertTrue(catalog.rows.isEmpty())

        val admitted = journal.admit(request, preview())
        assertTrue(admitted is AdmissionResult.Success)
        val row = catalog.rows.values.single()
        assertEquals(TransactionState.FINALIZED.name, row.transactionState)
        assertEquals(CatalogHealth.AVAILABLE.name, row.health)
        assertTrue(blobs.exists(row.localRecordId, SecureDataClass.ACTIVATION_ACTIVE))
        assertFalse(blobs.exists(row.localRecordId, SecureDataClass.ACTIVATION_STAGED))
        assertArrayEquals(
            request,
            blobs.reopen(row.localRecordId, SecureDataClass.IMPORT_REQUEST),
        )
        assertEquals(2, native.released)

        val duplicate = journal.admit(request, preview())
        assertEquals(OperationError.DUPLICATE, (duplicate as AdmissionResult.Failure).error)
        assertEquals(3, native.released)
    }

    @Test
    fun journalReplaysPreparedImportAfterProcessDeath() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val recordId = "01234567-89ab-4cde-8fab-0123456789ab"
        val request = byteArrayOf(4, 5, 6)
        blobs.stage(recordId, SecureDataClass.IMPORT_REQUEST, request)
        catalog.upsert(
            ProfileCatalogEntity(
                recordId,
                TransactionState.PREPARED.name,
                1,
                1,
                CatalogHealth.AVAILABLE.name,
            ),
        )

        val results = ProfileAdmissionJournal(native, catalog, blobs, false).recoverIncomplete()
        assertTrue(results.single() is AdmissionResult.Success)
        assertEquals(TransactionState.FINALIZED.name, catalog.rows.getValue(recordId).transactionState)
    }

    @Test
    fun journalRejectsRollbackAndSupersedesOlderLineage() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        assertTrue(journal.admit(byteArrayOf(1), preview()) is AdmissionResult.Success)

        native.preview = preview().copy(
            contentFingerprint = "different-older",
            generation = 6u,
        )
        val rollback = journal.admit(byteArrayOf(2), native.preview)
        assertEquals(OperationError.POLICY_REJECTED, (rollback as AdmissionResult.Failure).error)

        native.preview = preview().copy(
            contentFingerprint = "different-newer",
            generation = 8u,
        )
        assertTrue(journal.admit(byteArrayOf(3), native.preview) is AdmissionResult.Success)
        assertEquals(
            1,
            catalog.rows.values.count { it.health == CatalogHealth.SUPERSEDED.name },
        )
        assertEquals(
            1,
            catalog.rows.values.count { it.health == CatalogHealth.AVAILABLE.name },
        )
    }

    @Test
    fun profileExportContainsOnlyTheSelectedVerifiedRecord() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        val first = journal.admit(byteArrayOf(1), preview()) as AdmissionResult.Success
        native.preview = preview().copy(
            contentFingerprint = "different-lineage",
            lineageFingerprint = "second-lineage",
        )
        val second = journal.admit(byteArrayOf(2), native.preview) as AdmissionResult.Success

        val reopenCount = blobs.reopenedValues.size
        val exported = BackupPayloadCodec.decode(
            journal.backupPayload(first.outcome.localRecordId),
        )
        assertEquals(1, exported.size)
        assertEquals(first.outcome.localRecordId, exported.single().localRecordId)
        assertFalse(exported.single().localRecordId == second.outcome.localRecordId)
        assertArrayEquals(byteArrayOf(1), exported.single().verifyRequest)
        assertTrue(
            blobs.reopenedValues.drop(reopenCount).all { bytes ->
                bytes.all { it == 0.toByte() }
            },
        )
    }

    @Test
    fun deleteAndResetKeepCatalogEvidenceWhenBlobDeletionFails() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        val admitted = journal.admit(byteArrayOf(1), preview()) as AdmissionResult.Success
        val recordId = admitted.outcome.localRecordId

        blobs.failDelete = recordId to SecureDataClass.PROFILE_ARTIFACT
        assertFalse(journal.delete(recordId))
        assertTrue(catalog.rows.containsKey(recordId))

        blobs.failDeleteAll = true
        assertFalse(journal.resetAll())
        assertTrue(catalog.rows.containsKey(recordId))

        blobs.failDelete = null
        blobs.failDeleteAll = false
        assertTrue(journal.resetAll())
        assertTrue(catalog.rows.isEmpty())
    }

    @Test
    fun corruptStoredPreviewIsQuarantinedInsteadOfDisappearing() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        val admitted = journal.admit(byteArrayOf(1), preview()) as AdmissionResult.Success
        blobs.stage(
            admitted.outcome.localRecordId,
            SecureDataClass.PROFILE_PREVIEW,
            byteArrayOf(0),
        )

        assertTrue(journal.listProfiles().isEmpty())
        assertEquals(CatalogHealth.QUARANTINED, journal.storageHealth())
    }

    @Test
    fun restoreBatchIsInvisibleUntilAtomicPublicationAndRecoversAfterProcessDeath() = runBlocking {
        val native = FakeNativeCore(preview())
        val catalog = FakeCatalog()
        val blobs = FakeBlobs()
        val journal = ProfileAdmissionJournal(native, catalog, blobs, productionTrust = false)
        val records = listOf(
            BackupProfileRecord("source-record", 7u, byteArrayOf(9, 8, 7)),
        )

        val encoded = BackupPayloadCodec.encode(records)
        blobs.stage("restore-current", SecureDataClass.RESTORE_BATCH, encoded)
        val recovered = journal.recoverPendingRestore()

        assertEquals(1, (recovered as RestoreResult.Success).restoredProfiles)
        assertFalse(blobs.exists("restore-current", SecureDataClass.RESTORE_BATCH))
        assertEquals(
            listOf(CatalogHealth.AVAILABLE.name),
            catalog.rows.values.map { it.health },
        )
        assertEquals(1, journal.listProfiles().size)
    }

    private fun preview() = RedactedProfilePreview(
        artifactClass = "signed-public",
        audienceClass = "public",
        contentFingerprint = "0123456789abcdef",
        lineageFingerprint = "abcdef0123456789",
        generation = 7u,
        validUntilEpochSeconds = 2_000_000_000,
        sealed = false,
    )

    private fun assertFails(block: () -> Unit) {
        var failed = false
        try {
            block()
        } catch (_: Throwable) {
            failed = true
        }
        assertTrue("operation unexpectedly succeeded", failed)
    }
}

private class FixedSecureRandom : SecureRandom() {
    private var value = 1
    override fun nextBytes(bytes: ByteArray) {
        bytes.indices.forEach { index -> bytes[index] = (value++ and 0xff).toByte() }
    }
}

private class TestKek(
    override val generation: Int,
) : KeyEncryptionKey {
    override val hardwareSecurityLevel = "test"
    private val key = SecretKeySpec(ByteArray(32) { (it + generation).toByte() }, "AES")

    override fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey {
        val nonce = ByteArray(12) { (it + 1).toByte() }
        return WrappedKey(
            nonce,
            aesGcmEncrypt(this.key, nonce, "$recordId:${dataClass.wireValue}".encodeToByteArray(), key),
        )
    }

    override fun unwrap(
        recordId: String,
        dataClass: SecureDataClass,
        wrapped: WrappedKey,
    ): ByteArray = aesGcmDecrypt(
        key,
        wrapped.nonce,
        "$recordId:${dataClass.wireValue}".encodeToByteArray(),
        wrapped.ciphertext,
    )
}

private class FakeBlobs : SecureBlobAccess {
    private val values = mutableMapOf<Pair<String, SecureDataClass>, ByteArray>()
    val reopenedValues = mutableListOf<ByteArray>()
    var failDelete: Pair<String, SecureDataClass>? = null
    var failDeleteAll = false

    override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        values[localRecordId to dataClass] = exactBytes.clone()
    }

    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        val reopened = values.getValue(localRecordId to dataClass).clone()
        reopenedValues += reopened
        return reopened
    }

    override fun delete(localRecordId: String, dataClass: SecureDataClass) {
        check(failDelete != (localRecordId to dataClass))
        values.remove(localRecordId to dataClass)
    }

    override fun deleteAll() {
        check(!failDeleteAll)
        values.clear()
    }

    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean =
        values.containsKey(localRecordId to dataClass)
}

private class FakeCatalog : ProfileCatalogDao {
    val rows = linkedMapOf<String, ProfileCatalogEntity>()
    override fun observeAll(): Flow<List<ProfileCatalogEntity>> = flowOf(rows.values.toList())
    override suspend fun get(localRecordId: String): ProfileCatalogEntity? = rows[localRecordId]
    override suspend fun listAll(): List<ProfileCatalogEntity> = rows.values.toList()
    override suspend fun upsert(entity: ProfileCatalogEntity) {
        rows[entity.localRecordId] = entity
    }

    override suspend fun delete(localRecordId: String) {
        rows.remove(localRecordId)
    }

    override suspend fun deleteAll() {
        rows.clear()
    }

    override suspend fun updateHealth(recordIds: List<String>, health: String) {
        recordIds.forEach { recordId ->
            rows[recordId]?.let { rows[recordId] = it.copy(health = health) }
        }
    }
}

private class FakeNativeCore(
    var preview: RedactedProfilePreview,
) : KurdNativeCore {
    var released = 0
    override fun verifyPreview(request: ByteArray): NativeResult<VerifiedPreviewHandle> =
        NativeResult.Success(VerifiedPreviewHandle(41, preview))

    override fun openActivation(
        verified: VerifiedPreviewHandle,
    ): NativeResult<NativeActivationSession> = NativeResult.Success(FakeActivationSession())

    override fun releaseVerified(verified: VerifiedPreviewHandle): NativeResult<Unit> {
        released++
        return NativeResult.Success(Unit)
    }

    override fun compatibility(): NativeResult<NativeCompatibility> =
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun prepareDiagnostic(request: ByteArray): NativeResult<DiagnosticPreviewHandle> =
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun confirmAndBuildDiagnostic(
        preview: DiagnosticPreviewHandle,
    ): NativeResult<ByteArray> = NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun createBackup(
        payload: ByteArray,
        passphrase: ByteArray,
    ): NativeResult<ByteArray> = NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun openBackup(
        backup: ByteArray,
        passphrase: ByteArray,
    ): NativeResult<BackupPreviewHandle> = NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun restoreBackup(preview: BackupPreviewHandle): NativeResult<ByteArray> =
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun phase11RoundTrip(payload: ByteArray): NativeResult<ByteArray> =
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun openRuntimeSession(
        request: ByteArray,
    ): NativeResult<org.kurdistanvpn.core.nativeapi.NativeRuntimeSession> =
        NativeResult.Failure(OperationError.INTERNAL_FAILURE)

    override fun releaseDiagnostic(preview: DiagnosticPreviewHandle): NativeResult<Unit> =
        NativeResult.Success(Unit)

    override fun releaseBackup(preview: BackupPreviewHandle): NativeResult<Unit> =
        NativeResult.Success(Unit)
}

private class FakeActivationSession : NativeActivationSession {
    private val record = byteArrayOf(1, 3, 3, 7)
    private val commands = listOf(
        ActivationCommand(1, ActivationCommandKind.SNAPSHOT),
        ActivationCommand(2, ActivationCommandKind.STAGE_CANDIDATE, record.copyOf()),
        ActivationCommand(3, ActivationCommandKind.REOPEN_CANDIDATE),
        ActivationCommand(4, ActivationCommandKind.MARK_ACTIVATION),
        ActivationCommand(5, ActivationCommandKind.COMMIT_MARKED),
        ActivationCommand(6, ActivationCommandKind.FINALIZE_ACTIVATION),
        ActivationCommand(7, ActivationCommandKind.COMPLETE, record.copyOf()),
    )
    private var index = 0

    override fun next(): NativeResult<ActivationCommand> = NativeResult.Success(commands[index])

    override fun submit(
        command: ActivationCommand,
        storageSucceeded: Boolean,
        active: ByteArray,
        lastKnownGood: ByteArray,
        reopened: ByteArray,
    ): NativeResult<Unit> {
        if (!storageSucceeded || command != commands[index]) {
            return NativeResult.Failure(OperationError.STORAGE_FAILURE)
        }
        index++
        return NativeResult.Success(Unit)
    }

    override fun cancel(): NativeResult<Unit> = NativeResult.Success(Unit)
    override fun close() = Unit
}

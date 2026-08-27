// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeRecipient
import org.kurdistanvpn.core.nativeapi.NativeResult

class ClientKeyBundleStoreTest {
    @Test
    fun requestExportTransitionBeforeDuringAndAfterIndexReplacementCannotInventAuthority() {
        for (point in listOf("before", "during", "after")) {
            val disk = MemorySecureBlobs()
            val native = FakeRecipientNative()
            val original = ClientKeyBundleStore(disk, native, deterministicIds())
            val key = (original.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
            val materialBefore = disk.reopen(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
            val inputs = mutableListOf<ByteArray>()
            var attempts = 0
            val interrupted = object : SecureBlobAccess by disk {
                override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
                    check(localRecordId == "recipient-index" && dataClass == SecureDataClass.RECIPIENT_KEY_INDEX)
                    attempts++
                    inputs += exactBytes
                    if (point == "before") error("synthetic before replacement")
                    val copy = exactBytes.clone()
                    try {
                        if (point == "during") error("synthetic uncommitted replacement")
                        disk.stage(localRecordId, dataClass, copy)
                        error("synthetic replacement durable but acknowledgement lost")
                    } finally { copy.fill(0) }
                }
            }
            val result = runCatching { ClientKeyBundleStore(interrupted, native).markRequestExported(key.localRecordId) }
            assertTrue(point, result.isFailure)
            assertEquals(point, 1, attempts)
            assertTrue(point, inputs.all { it.all { byte -> byte == 0.toByte() } })
            val reread = ClientKeyBundleStore.readOnly(disk, native).list().single()
            assertEquals(point, key.localRecordId, reread.localRecordId)
            assertEquals(point, key.requestFingerprint, reread.requestFingerprint)
            assertEquals(point, if (point == "after") ClientKeyStatus.AWAITING_PROFILE else ClientKeyStatus.REQUEST_READY, reread.status)
            assertEquals(point, 0, reread.boundProfileCount)
            assertEquals(point, null, ClientKeyBundleStore.readOnly(disk, native).credentialsForProfile("never-bound-profile"))
            val materialAfter = disk.reopen(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
            try { assertArrayEquals(point, materialBefore, materialAfter) }
            finally { materialBefore.fill(0); materialAfter.fill(0) }
            // Reissue is an explicit idempotent action, not an inferred binding or enrollment.
            original.markRequestExported(key.localRecordId)
            assertEquals(ClientKeyStatus.AWAITING_PROFILE, original.list().single().status)
            assertEquals(0, original.list().single().boundProfileCount)
        }
    }

    @Test
    fun everyTruncatedBundleIsRejectedByExplicitBoundsBeforeNativeValidation() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val writer = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (writer.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        val valid = blobs.reopen(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        val opened = mutableListOf<ByteArray>()
        val reader = ClientKeyBundleStore.readOnly(recordingReader(blobs, opened), native)
        try {
            for (length in 0 until valid.size) {
                val truncated = valid.copyOf(length)
                try { blobs.stage(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, truncated) }
                finally { truncated.fill(0) }
                opened.clear()
                val failure = runCatching { reader.credentials(key.localRecordId).close() }.exceptionOrNull()
                assertTrue("length=$length must reject through explicit bounds, got ${failure?.javaClass?.simpleName}",
                    failure is IllegalArgumentException)
                assertEquals(0, native.validations.get())
                assertTrue(opened.isNotEmpty())
                assertTrue(opened.all { bytes -> bytes.all { it == 0.toByte() } })
            }
        } finally { valid.fill(0) }
    }

    @Test
    fun malformedMaterialLengthsAndTrailingBytesRejectWithoutNativeValidationOrRepair() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val writer = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (writer.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        val valid = blobs.reopen(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        val requestLengthOffset = 6 + key.localRecordId.length + 16
        val privateLengthOffset = requestLengthOffset + 2 + native.publicRequest.size
        val malformed = listOf(
            valid.copyOf().also { it[requestLengthOffset] = 0; it[requestLengthOffset + 1] = 0 },
            valid.copyOf().also { it[requestLengthOffset] = 2; it[requestLengthOffset + 1] = 1 },
            valid.copyOf().also { it[privateLengthOffset] = 0; it[privateLengthOffset + 1] = 0 },
            valid.copyOf().also { it[privateLengthOffset] = 0; it[privateLengthOffset + 1] = 129.toByte() },
            valid + byteArrayOf(1),
        )
        val opened = mutableListOf<ByteArray>()
        val reader = ClientKeyBundleStore.readOnly(recordingReader(blobs, opened), native)
        try {
            for (frame in malformed) {
                blobs.stage(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, frame)
                opened.clear()
                assertTrue(runCatching { reader.credentials(key.localRecordId).close() }.exceptionOrNull() is IllegalArgumentException)
                assertEquals(0, native.validations.get())
                assertTrue(opened.all { bytes -> bytes.all { it == 0.toByte() } })
                val persisted = blobs.reopen(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
                try { assertArrayEquals(frame, persisted) } finally { persisted.fill(0) }
            }
        } finally { valid.fill(0); malformed.forEach { it.fill(0) } }
    }

    @Test
    fun throwingNativeValidationWipesOwnedSlicesAndAllEarlierCandidateLeases() {
        val delegate = MultiRecipientNative()
        val retained = mutableListOf<ByteArray>()
        var validations = 0
        var throwAt = 1
        val native = object : RecipientKeyNative {
            override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = delegate.create(validitySeconds)
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit> {
                retained += publicRequest
                retained += privateBundle
                validations++
                if (validations == throwAt) error("synthetic validation exception")
                return delegate.validate(publicRequest, privateBundle)
            }
        }
        val blobs = MemorySecureBlobs()
        val writer = ClientKeyBundleStore(blobs, native, deterministicIds())
        val first = (writer.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        writer.create(600, 1_800_000_001)
        val opened = mutableListOf<ByteArray>()
        val reader = ClientKeyBundleStore.readOnly(recordingReader(blobs, opened), native)
        assertTrue(runCatching { reader.credentials(first.localRecordId).close() }.isFailure)
        assertEquals(2, retained.size)
        assertTrue(retained.all { bytes -> bytes.all { it == 0.toByte() } })
        assertTrue(opened.all { bytes -> bytes.all { it == 0.toByte() } })
        retained.clear(); opened.clear(); validations = 0; throwAt = 2
        assertTrue(runCatching { reader.credentialCandidates().forEach(RecipientCredentialLease::close) }.isFailure)
        assertEquals(4, retained.size)
        assertTrue(retained.all { bytes -> bytes.all { it == 0.toByte() } })
        assertTrue(opened.all { bytes -> bytes.all { it == 0.toByte() } })
    }

    @Test
    fun throwingPrivateMaterialAcquisitionWipesTheAlreadyOwnedRequestAndClosesTheHandle() {
        val request = "synthetic-public-request".encodeToByteArray()
        var closed = 0
        val native = object : RecipientKeyNative {
            override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = NativeResult.Success(
                object : NativeRecipient {
                    override fun publicRequest(): NativeResult<ByteArray> = NativeResult.Success(request)
                    override fun privateBundle(): NativeResult<ByteArray> = error("synthetic acquisition failure")
                    override fun cancel(): NativeResult<Unit> = NativeResult.Success(Unit)
                    override fun close() { closed++ }
                },
            )
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit> =
                error("validation must not begin")
        }
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val result = runCatching { store.create(600, 1_800_000_000) }
        assertTrue("owned request leaked on partial acquisition", request.all { it == 0.toByte() })
        assertEquals(1, closed)
        assertEquals(OperationError.STORAGE_FAILURE, (result.getOrThrow() as ClientKeyResult.Failure).error)
        assertFalse(blobs.exists("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
    }

    @Test
    fun committedSnapshotRejectsRecipientBindingToAnUnsealedProfileWithoutMutation() {
        val blobs = MemorySecureBlobs()
        val native = MultiRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.bindProfile(key.localRecordId, "profile-one")
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        try {
            assertTrue(runCatching {
                store.requireConsistentBindings(setOf("profile-one"), emptySet(), setOf(key.localRecordId))
            }.isFailure)
            assertArrayEquals(before, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
            assertTrue(native.validatedPrivateReferences.all { bytes -> bytes.all { it == 0.toByte() } })
            store.requireConsistentBindings(setOf("profile-one"), setOf("profile-one"), setOf(key.localRecordId))
        } finally { before.fill(0) }
    }

    @Test
    fun legacySharedKeyBindingRejectsAtReadBoundaryWithoutChoosingOrDeletingEitherProfile() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.bindProfile(key.localRecordId, "profile-one")
        val encoded = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        val second = "profile-two".encodeToByteArray()
        val legacy = encoded + byteArrayOf(second.size.toByte()) + second
        encoded.fill(0)
        // KCI1's single synthetic entry: header, ID, status, two timestamps, fingerprint.
        legacy[89 + key.localRecordId.length] = 2
        blobs.stage("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX, legacy)
        try {
            assertTrue(runCatching { store.credentialsForProfile("profile-one")?.close() }.isFailure)
            assertTrue(runCatching { store.credentialsForProfile("profile-two")?.close() }.isFailure)
            assertTrue(runCatching { store.list() }.isFailure)
            assertTrue(runCatching { store.unbindProfile("profile-one") }.isFailure)
            assertArrayEquals(legacy, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
            assertTrue(blobs.exists(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL))
        } finally { legacy.fill(0); second.fill(0) }
    }

    @Test
    fun crossObjectValidationRejectsMissingOrOrphanMaterialWithoutRepair() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.requireConsistentBindings(emptySet(), emptySet(), setOf(key.localRecordId))
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        assertTrue(runCatching { store.requireConsistentBindings(emptySet(), emptySet(), setOf(key.localRecordId, "orphan-one")) }.isFailure)
        blobs.delete(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        assertTrue(runCatching { store.requireConsistentBindings(emptySet(), emptySet(), emptySet()) }.isFailure)
        assertArrayEquals(before, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
        before.fill(0)
    }

    @Test
    fun crossObjectValidationRejectsDeletedProfileAndUnboundSealedProfile() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        assertTrue(runCatching { store.requireConsistentBindings(setOf("profile-one"), setOf("profile-one"), setOf(key.localRecordId)) }.isFailure)
        store.bindProfile(key.localRecordId, "profile-one")
        store.requireConsistentBindings(setOf("profile-one"), setOf("profile-one"), setOf(key.localRecordId))
        assertTrue(runCatching { store.requireConsistentBindings(emptySet(), emptySet(), setOf(key.localRecordId)) }.isFailure)
        assertEquals(1, store.list().single().boundProfileCount)
    }

    @Test
    fun preparedStateCannotPassCommittedSnapshotValidationOrBePromotedByIt() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        makePrepared(blobs, key.localRecordId)
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        assertTrue(runCatching { store.requireConsistentBindings(emptySet(), emptySet(), setOf(key.localRecordId)) }.isFailure)
        assertArrayEquals(before, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
        before.fill(0)
    }
    @Test
    fun readOnlyRecipientViewCannotBecomeAWriterAfterInteractiveInitialization() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val reader = ClientKeyBundleStore.readOnly(blobs, native)
        val interactive = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (interactive.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        assertEquals(key, reader.list().single())
        assertTrue(runCatching { reader.markRequestExported(key.localRecordId) }.isFailure)
        assertTrue(runCatching { reader.bindProfile(key.localRecordId, "profile-one") }.isFailure)
        assertTrue(runCatching { reader.delete(key.localRecordId) }.isFailure)
        assertTrue(runCatching { reader.recoverPreparedExplicitly() }.isFailure)
        assertArrayEquals(before, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
        before.fill(0)
    }
    @Test
    fun preparedKeysCannotSupplyCredentialsOrEnrollmentExports() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        makePrepared(blobs, key.localRecordId)
        assertTrue(runCatching { store.credentials(key.localRecordId).close() }.isFailure)
        assertTrue(runCatching { store.publicRequest(key.localRecordId).fill(0) }.isFailure)
    }

    @Test
    fun verifiedStatusWithoutMaterialCannotBeListedAsHealthy() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.bindProfile(key.localRecordId, "profile-one")
        blobs.delete(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        assertTrue(runCatching { store.list() }.isFailure)
        assertArrayEquals(before, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
        before.fill(0)
    }

    @Test
    fun authenticatedButSemanticallyInvalidStatusBindingCombinationsRejectWithoutRepair() {
        for (status in listOf(ClientKeyStatus.PREPARED, ClientKeyStatus.REQUEST_READY, ClientKeyStatus.AWAITING_PROFILE)) {
            val blobs = MemorySecureBlobs()
            val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
            val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
            store.bindProfile(key.localRecordId, "profile-one")
            val encoded = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
            try {
                encoded[7 + key.localRecordId.length] = status.wireValue.toByte()
                blobs.stage("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX, encoded)
                assertTrue("status=$status", runCatching { store.list() }.isFailure)
                assertArrayEquals(encoded, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
            } finally { encoded.fill(0) }
        }
    }

    @Test
    fun rollbackNeverDeletesPrivateMaterialStillBoundToAProfile() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, FakeRecipientNative(), deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.bindProfile(key.localRecordId, "profile-existing")
        assertTrue(runCatching { store.rollbackRestored(listOf(key.localRecordId)) }.isFailure)
        assertTrue(blobs.exists(key.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL))
        store.credentialsForProfile("profile-existing")!!.close()
    }

    @Test
    fun ordinaryBackupExcludesUnboundAndPendingEnrollmentKeys() {
        val blobs = MemorySecureBlobs()
        val store = ClientKeyBundleStore(blobs, MultiRecipientNative(), deterministicIds())
        val pending = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.markRequestExported(pending.localRecordId)
        store.create(600, 1_800_000_001)
        assertTrue(store.backupRecords().isEmpty())
        store.bindProfile(pending.localRecordId, "profile-one")
        val backup = store.backupRecords()
        try { assertEquals(listOf(pending.localRecordId), backup.map { it.sourceRecordId }) }
        finally { backup.forEach(ClientKeyBackupRecord::destroy) }
    }

    @Test
    fun twoKeysCannotAcquireTheSameProfileBinding() {
        val store = ClientKeyBundleStore(MemorySecureBlobs(), MultiRecipientNative(), deterministicIds())
        val first = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        val second = (store.create(600, 1_800_000_001) as ClientKeyResult.Success).summary
        store.bindProfile(first.localRecordId, "profile-one")
        assertTrue(runCatching { store.bindProfile(second.localRecordId, "profile-one") }.isFailure)
        store.credentialsForProfile("profile-one")!!.use { assertEquals(first.localRecordId, it.localRecordId) }
    }

    @Test
    fun constructionListingPreviewAndBackupNeverRecoverPreparedState() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val first = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (first.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        makePrepared(blobs, key.localRecordId)
        val before = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        val reopened = ClientKeyBundleStore(blobs, native, deterministicIds(10))
        reopened.list()
        reopened.credentialCandidates().forEach(RecipientCredentialLease::close)
        reopened.backupRecords().forEach(ClientKeyBackupRecord::destroy)
        val after = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        try { assertArrayEquals(before, after) } finally { before.fill(0); after.fill(0) }
    }
    @Test
    fun createPersistsPrivateBundleBeforePublishingReadyRequestAndSurvivesReopen() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val first = ClientKeyBundleStore(blobs, native, deterministicIds())

        val created = first.create(validitySeconds = 3600, nowEpochSeconds = 1_800_000_000)
        assertTrue(created is ClientKeyResult.Success)
        val summary = (created as ClientKeyResult.Success).summary
        assertEquals(ClientKeyStatus.REQUEST_READY, summary.status)
        assertEquals(1_800_003_600, summary.expiresAtEpochSeconds)
        assertTrue(blobs.exists(summary.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL))
        assertFalse(blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX).containsCanary(native.privateBundle))

        val reopened = ClientKeyBundleStore(blobs, native, deterministicIds(start = 10))
        assertEquals(summary, reopened.list().single())
        assertArrayEquals(native.publicRequest, reopened.publicRequest(summary.localRecordId))
        reopened.markRequestExported(summary.localRecordId)
        assertEquals(ClientKeyStatus.AWAITING_PROFILE, reopened.list().single().status)
    }

    @Test
    fun preparedRecordRequiresExplicitLosslessRecoveryAndMissingPayloadIsPreserved() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val created = (store.create(60, 1_800_000_000) as ClientKeyResult.Success).summary

        makePrepared(blobs, created.localRecordId)
        val recovered = ClientKeyBundleStore(blobs, native, deterministicIds(start = 5))
        assertTrue(recovered.list().isEmpty())
        recovered.recoverPreparedExplicitly()
        assertEquals(ClientKeyStatus.REQUEST_READY, recovered.list().single().status)

        makePrepared(blobs, created.localRecordId)
        blobs.delete(created.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        val quarantined = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        val pruned = ClientKeyBundleStore(blobs, native, deterministicIds(start = 9))
        pruned.recoverPreparedExplicitly()
        assertTrue(pruned.list().isEmpty())
        assertArrayEquals(quarantined, blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX))
        quarantined.fill(0)
    }

    @Test
    fun leasesWipeOnCloseAndSecondProfileBindingIsRefusedWithoutChangingTheFirst() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary

        val lease = store.credentials(key.localRecordId)
        val requestReference = lease.publicRequest
        val privateReference = lease.privateBundle
        store.bindProfile(key.localRecordId, "profile-one")
        assertTrue(runCatching { store.bindProfile(key.localRecordId, "profile-two") }.isFailure)
        store.credentialsForProfile("profile-one")!!.use { assertEquals(key.localRecordId, it.localRecordId) }
        assertEquals(null, store.credentialsForProfile("profile-two"))
        lease.close()
        assertTrue(requestReference.all { it == 0.toByte() })
        assertTrue(privateReference.all { it == 0.toByte() })

        val offered = store.unbindProfile("profile-one")
        assertEquals(key.localRecordId, offered?.localRecordId)
        assertTrue(store.list().single().status == ClientKeyStatus.REQUEST_READY)
        assertTrue(store.delete(key.localRecordId))
        assertTrue(store.list().isEmpty())
    }

    @Test
    fun profileCredentialLookupReturnsOnlyTheBoundKeyAndWipesItsLease() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary

        assertEquals(null, store.credentialsForProfile("profile-one"))
        store.bindProfile(key.localRecordId, "profile-one")
        val lease = requireNotNull(store.credentialsForProfile("profile-one"))
        val requestReference = lease.publicRequest
        val privateReference = lease.privateBundle
        assertArrayEquals(native.publicRequest, requestReference)
        assertArrayEquals(native.privateBundle, privateReference)

        lease.close()
        assertTrue(requestReference.all { it == 0.toByte() })
        assertTrue(privateReference.all { it == 0.toByte() })
        assertEquals(null, store.credentialsForProfile("profile-two"))
    }

    @Test
    fun backupRestoreRewrapsValidPairsRejectsTamperingAndAvoidsSourceIds() {
        val sourceBlobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val source = ClientKeyBundleStore(sourceBlobs, native, deterministicIds())
        val original = (source.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        source.bindProfile(original.localRecordId, "profile-one")
        val records = source.backupRecords("profile-one")
        val encodedPayload = BackupPayloadCodec.encode(
            DecodedBackupPayload(
                profiles = listOf(BackupProfileRecord("profile-one", 7u, byteArrayOf(1, 2, 3))),
                clientKeys = records,
            ),
        )
        val decodedPayload = BackupPayloadCodec.decodePayload(encodedPayload)
        assertEquals(1, decodedPayload.profiles.size)
        assertEquals(1, decodedPayload.clientKeys.size)
        encodedPayload.fill(0)
        decodedPayload.profiles.forEach { it.verifyRequest.fill(0) }
        decodedPayload.clientKeys.forEach { it.destroy() }

        val destinationBlobs = MemorySecureBlobs()
        val destination = ClientKeyBundleStore(destinationBlobs, native, deterministicIds(start = 20))
        val receipt = destination.restore(records)
        assertTrue(receipt is ClientKeyRestoreResult.Success)
        val restored = destination.list().single()
        assertNotEquals(original.localRecordId, restored.localRecordId)
        assertEquals(original.requestFingerprint, restored.requestFingerprint)
        assertTrue(native.validations.get() >= 1)

        val corrupt = records.single().copy(
            privateBundle = records.single().privateBundle.clone().also { it[0] = (it[0].toInt() xor 0x7f).toByte() },
        )
        assertEquals(
            OperationError.TRUST_REJECTED,
            (destination.restore(listOf(corrupt)) as ClientKeyRestoreResult.Failure).error,
        )
        records.forEach { it.destroy() }
        corrupt.destroy()
    }

    @Test
    fun wrongRecordBindingAndCorruptionFailClosed() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val created = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        val exact = blobs.reopen(created.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        blobs.stage("other-record", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, exact)
        exact.fill(0)

        val other = runCatching { store.credentials("other-record") }
        assertTrue(other.isFailure)
        val corrupted = blobs.reopen(created.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 1).toByte()
        blobs.stage(created.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, corrupted)
        corrupted.fill(0)
        assertTrue(runCatching { store.credentials(created.localRecordId) }.isFailure)
    }

    @Test
    fun candidateFailureWipesEveryPreviouslyOpenedPrivateBundle() {
        val blobs = MemorySecureBlobs()
        val native = MultiRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val older = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary
        store.create(600, 1_800_000_001)
        val corrupted = blobs.reopen(older.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 1).toByte()
        blobs.stage(older.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, corrupted)
        corrupted.fill(0)

        assertTrue(runCatching { store.credentialCandidates() }.isFailure)
        assertTrue(native.validatedPrivateReferences.isNotEmpty())
        assertTrue(native.validatedPrivateReferences.all { value -> value.all { it == 0.toByte() } })
    }

    private fun deterministicIds(start: Int = 1): () -> String {
        var next = start
        return { "recipient-local-${next++}" }
    }

    private fun recordingReader(blobs: SecureBlobReadAccess, opened: MutableList<ByteArray>): SecureBlobReadAccess =
        object : SecureBlobReadAccess {
            override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray =
                blobs.reopen(localRecordId, dataClass).also { opened += it }
            override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean =
                blobs.exists(localRecordId, dataClass)
        }

    private fun makePrepared(blobs: MemorySecureBlobs, localId: String) {
        val bytes = blobs.reopen("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX)
        try {
            // A single synthetic index entry. No mutation helper exists in production composition.
            assertEquals(1, bytes[5].toInt())
            assertEquals(localId.length, bytes[6].toInt())
            bytes[7 + localId.length] = ClientKeyStatus.PREPARED.wireValue.toByte()
            blobs.stage("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX, bytes)
        } finally { bytes.fill(0) }
    }
}

private class FakeRecipientNative : RecipientKeyNative {
    val publicRequest = "public-enrollment-request".encodeToByteArray()
    val privateBundle = "private-enrollment-canary".encodeToByteArray()
    val validations = AtomicInteger()

    override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = NativeResult.Success(
        object : NativeRecipient {
            override fun publicRequest(): NativeResult<ByteArray> = NativeResult.Success(publicRequest.clone())
            override fun privateBundle(): NativeResult<ByteArray> = NativeResult.Success(privateBundle.clone())
            override fun cancel(): NativeResult<Unit> = NativeResult.Success(Unit)
            override fun close() = Unit
        },
    )

    override fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit> {
        validations.incrementAndGet()
        return if (
            publicRequest.contentEquals(this.publicRequest) &&
            privateBundle.contentEquals(this.privateBundle)
        ) NativeResult.Success(Unit) else NativeResult.Failure(OperationError.TRUST_REJECTED)
    }
}

private class MultiRecipientNative : RecipientKeyNative {
    private var next = 1
    val validatedPrivateReferences = mutableListOf<ByteArray>()

    override fun create(validitySeconds: Int): NativeResult<NativeRecipient> {
        val id = next++
        val request = "public-request-$id".encodeToByteArray()
        val privateBundle = "private-bundle-$id".encodeToByteArray()
        return NativeResult.Success(
            object : NativeRecipient {
                override fun publicRequest(): NativeResult<ByteArray> = NativeResult.Success(request.clone())
                override fun privateBundle(): NativeResult<ByteArray> = NativeResult.Success(privateBundle.clone())
                override fun cancel(): NativeResult<Unit> = NativeResult.Success(Unit)
                override fun close() = Unit
            },
        )
    }

    override fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit> {
        validatedPrivateReferences += privateBundle
        val suffix = publicRequest.toString(Charsets.UTF_8).removePrefix("public-request-")
        val valid = suffix.isNotEmpty() &&
            privateBundle.contentEquals("private-bundle-$suffix".encodeToByteArray())
        return if (valid) NativeResult.Success(Unit)
        else NativeResult.Failure(OperationError.TRUST_REJECTED)
    }
}

private class MemorySecureBlobs : SecureBlobAccess {
    private val values = mutableMapOf<Pair<String, SecureDataClass>, ByteArray>()

    override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        values[localRecordId to dataClass] = exactBytes.clone()
    }

    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray =
        values[localRecordId to dataClass]?.clone() ?: error("missing blob")

    override fun delete(localRecordId: String, dataClass: SecureDataClass) {
        values.remove(localRecordId to dataClass)?.fill(0)
    }

    override fun deleteAll() {
        values.values.forEach { it.fill(0) }
        values.clear()
    }

    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean =
        values.containsKey(localRecordId to dataClass)
}

private fun ByteArray.containsCanary(canary: ByteArray): Boolean {
    if (canary.isEmpty() || canary.size > size) return false
    return indices.any { start ->
        start + canary.size <= size && canary.indices.all { this[start + it] == canary[it] }
    }
}

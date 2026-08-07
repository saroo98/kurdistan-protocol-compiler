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
    fun preparedRecordRecoversAfterProcessDeathAndMissingPayloadIsRemoved() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val created = (store.create(60, 1_800_000_000) as ClientKeyResult.Success).summary

        store.forcePreparedForTesting(created.localRecordId)
        val recovered = ClientKeyBundleStore(blobs, native, deterministicIds(start = 5))
        assertEquals(ClientKeyStatus.REQUEST_READY, recovered.list().single().status)

        recovered.forcePreparedForTesting(created.localRecordId)
        blobs.delete(created.localRecordId, SecureDataClass.RECIPIENT_PRIVATE_MATERIAL)
        val pruned = ClientKeyBundleStore(blobs, native, deterministicIds(start = 9))
        assertTrue(pruned.list().isEmpty())
    }

    @Test
    fun leasesAreIndependentWipeOnCloseAndBindingNeverAutoDeletesSharedKey() {
        val blobs = MemorySecureBlobs()
        val native = FakeRecipientNative()
        val store = ClientKeyBundleStore(blobs, native, deterministicIds())
        val key = (store.create(600, 1_800_000_000) as ClientKeyResult.Success).summary

        val lease = store.credentials(key.localRecordId)
        val requestReference = lease.publicRequest
        val privateReference = lease.privateBundle
        store.bindProfile(key.localRecordId, "profile-one")
        store.bindProfile(key.localRecordId, "profile-two")
        lease.close()
        assertTrue(requestReference.all { it == 0.toByte() })
        assertTrue(privateReference.all { it == 0.toByte() })

        assertEquals(null, store.unbindProfile("profile-one"))
        val offered = store.unbindProfile("profile-two")
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeRecipient
import org.kurdistanvpn.core.nativeapi.NativeResult

class BackupPayloadCodecV2Test {
    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test fun recipientV2MatchesSharedGoGoldenAndRejectsEveryTruncation() {
        val golden = hex("4b42503200020100000000000000010161000000017803000000000000000011726563697069656e742d6b6579732d7633000000224b434b330301016b0400000000000000010000000000000002010161000101000102")
        val record = key(id = "k")
        try {
            assertArrayEquals(golden, BackupPayloadCodec.encode(DecodedBackupPayload(listOf(BackupProfileRecord("a", 1u, byteArrayOf(0x78))), listOf(record))))
            val decoded = BackupPayloadCodec.decodePayload(golden)
            try { assertArrayEquals(golden, BackupPayloadCodec.encode(decoded)) }
            finally { decoded.clientKeys.forEach(ClientKeyBackupRecord::destroy) }
            golden.indices.forEach { length ->
                assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.decodePayload(golden.copyOf(length)) }
            }
            listOf(4, 16, 17, 18, 19, 49, 50, 51, 52, 53, 57, 61, 78, 80, 81, 84).forEach { offset ->
                val corrupted = golden.copyOf().also { it[offset] = 0xff.toByte() }
                try { assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.decodePayload(corrupted) } }
                finally { corrupted.fill(0) }
            }
        } finally { record.destroy(); golden.fill(0) }
    }

    @Test fun legacyKeySourceHasNoInventedBindingsAndCannotBeOrdinarilyReexported() {
        val golden = hex("4b425031000103000000000000000011726563697069656e742d6b6579732d76320000001e4b434b320201016b00000000000000010000000000000002000101000102")
        val decoded = BackupPayloadCodec.decodePayload(golden)
        try {
            assertEquals(1, decoded.sourceVersion)
            assertNull(decoded.clientKeys.single().sourceStatus)
            assertEquals(emptyList<String>(), decoded.clientKeys.single().sourceProfileRecordIds)
            assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.encode(decoded) }
        } finally { decoded.clientKeys.forEach(ClientKeyBackupRecord::destroy); golden.fill(0) }
    }

    @Test fun materialCallbackWipesCopiesOnFailureWithoutDestroyingOwner() {
        val record = key()
        var request: ByteArray? = null; var privateBytes: ByteArray? = null
        assertThrows(IllegalStateException::class.java) {
            record.withMaterial { a, b -> request = a; privateBytes = b; error("synthetic callback failure") }
        }
        assertArrayEquals(byteArrayOf(0), request)
        assertArrayEquals(byteArrayOf(0), privateBytes)
        assertArrayEquals(byteArrayOf(2), record.privateBundle)
        record.destroy()
    }

    @Test fun restoreRevalidatesBothVersionsAndReturnsOnlyUntrustedSourceAssociations() {
        for (version in listOf(1, 2)) {
            val blobs = BackupMemoryBlobs()
            val native = BackupRecipientNative()
            val store = ClientKeyBundleStore(blobs, native) { "local-key" }
            val record = if (version == 1) ClientKeyBackupRecord("source-key", 1, 2, byteArrayOf(1), byteArrayOf(2)) else key("source-key")
            try {
                val result = store.restore(listOf(record)) as ClientKeyRestoreResult.Success
                assertTrue(native.validated.isNotEmpty())
                assertTrue(native.validated.all { it.all { byte -> byte == 0.toByte() } })
                assertEquals(ClientKeyStatus.AWAITING_PROFILE, store.list().single().status)
                assertTrue(store.backupRecords().isEmpty())
                assertEquals("local-key", result.associations.single().localRecordId)
                assertEquals(version, result.associations.single().sourceVersion)
                assertEquals(if (version == 1) emptyList<String>() else listOf("a"), result.associations.single().sourceProfileRecordIds)
                val repeated = store.restore(listOf(record)) as ClientKeyRestoreResult.Success
                assertEquals(0, repeated.restored)
                assertEquals("local-key", repeated.associations.single().localRecordId)
            } finally { record.destroy(); blobs.deleteAll() }
        }
    }

    @Test fun restoreRejectsUnvalidatedPairAndDuplicateInputWithoutStoringPrivateMaterial() {
        val blobs = BackupMemoryBlobs()
        val store = ClientKeyBundleStore(blobs, BackupRecipientNative()) { "local-key" }
        val invalid = ClientKeyBackupRecord("legacy", 1, 2, byteArrayOf(1), byteArrayOf(9))
        val duplicate = key()
        try {
            assertTrue(store.restore(listOf(invalid)) is ClientKeyRestoreResult.Failure)
            assertTrue(store.restore(listOf(duplicate, duplicate)) is ClientKeyRestoreResult.Failure)
            assertFalse(blobs.exists("local-key", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL))
            assertTrue(store.list().isEmpty())
        } finally { invalid.destroy(); duplicate.destroy(); blobs.deleteAll() }
    }

    @Test fun ordinaryProfileExportUsesExactV2WireAndLegacyV1RemainsReadable() {
        val profile = BackupProfileRecord("a", 1u, byteArrayOf(0x78))
        val v2 = hex("4b425032000101000000000000000101610000000178")
        assertArrayEquals(v2, BackupPayloadCodec.encode(listOf(profile)))
        assertArrayEquals(v2, BackupPayloadCodec.encode(BackupPayloadCodec.decodePayload(v2)))
        val v1 = hex("4b425031000101000000000000000101610000000178")
        val legacy = BackupPayloadCodec.decodePayload(v1)
        assertEquals("a", legacy.profiles.single().localRecordId)
        assertArrayEquals(byteArrayOf(0x78), legacy.profiles.single().verifyRequest)
    }

    @Test fun duplicateProfilesAndUnknownVersionCannotBeExportedOrImported() {
        val profile = BackupProfileRecord("a", 1u, byteArrayOf(0x78))
        assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.encode(listOf(profile, profile)) }
        val unknown = hex("4b425033000101000000000000000101610000000178")
        assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.decodePayload(unknown) }
    }

    private fun key(id: String = "key-a", profiles: List<String> = listOf("a"), request: ByteArray = byteArrayOf(1),
        privateBytes: ByteArray = byteArrayOf(2), status: ClientKeyStatus = ClientKeyStatus.PROFILE_VERIFIED) =
        ClientKeyBackupRecord(id, 1, 2, request, privateBytes, status, profiles, 2)

    @Test fun v2PreservesExplicitValidatedLifecycleAndSourceProfileBinding() {
        val original = key()
        val encoded = BackupPayloadCodec.encode(DecodedBackupPayload(listOf(BackupProfileRecord("a", 1u, byteArrayOf(3))), listOf(original)))
        val decoded = BackupPayloadCodec.decodePayload(encoded)
        assertEquals(2, decoded.sourceVersion)
        assertEquals(ClientKeyStatus.PROFILE_VERIFIED, decoded.clientKeys.single().sourceStatus)
        assertEquals(listOf("a"), decoded.clientKeys.single().sourceProfileRecordIds)
        assertArrayEquals(encoded, BackupPayloadCodec.encode(decoded))
        original.destroy(); decoded.clientKeys.forEach(ClientKeyBackupRecord::destroy); encoded.fill(0)
    }

    @Test fun pendingUnboundMissingProfileDuplicateKeyAndAmbiguousBindingsCannotExport() {
        val profiles = listOf(BackupProfileRecord("a", 1u, byteArrayOf(3)))
        val invalid = listOf(
            listOf(key(status = ClientKeyStatus.PREPARED)), listOf(key(status = ClientKeyStatus.REQUEST_READY)),
            listOf(key(status = ClientKeyStatus.AWAITING_PROFILE)), listOf(key(profiles = emptyList())),
            listOf(key(profiles = listOf("missing"))), listOf(key(), key()),
            listOf(key(), key("key-b", request = byteArrayOf(9), privateBytes = byteArrayOf(8))),
            listOf(ClientKeyBackupRecord("legacy", 1, 2, byteArrayOf(1), byteArrayOf(2))),
        )
        invalid.forEach { records ->
            try { assertThrows(IllegalArgumentException::class.java) { BackupPayloadCodec.encode(DecodedBackupPayload(profiles, records)) } }
            finally { records.forEach(ClientKeyBackupRecord::destroy) }
        }
    }

    @Test fun backupKeyMaterialAndBindingsHaveDefensiveOwnership() {
        val request = byteArrayOf(1); val privateBytes = byteArrayOf(2); val bindings = mutableListOf("a")
        val record = key(profiles = bindings, request = request, privateBytes = privateBytes)
        request[0] = 9; privateBytes[0] = 9; bindings[0] = "other"
        record.publicRequest[0] = 8; record.privateBundle[0] = 8
        assertArrayEquals(byteArrayOf(1), record.publicRequest)
        assertArrayEquals(byteArrayOf(2), record.privateBundle)
        assertEquals(listOf("a"), record.sourceProfileRecordIds)
        record.destroy()
        assertThrows(IllegalStateException::class.java) { record.publicRequest }
    }
}

private class BackupRecipientNative : RecipientKeyNative {
    val validated = mutableListOf<ByteArray>()
    override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = error("creation outside restore test")
    override fun validate(publicRequest: ByteArray, privateBundle: ByteArray): NativeResult<Unit> {
        validated += privateBundle
        return if (publicRequest.contentEquals(byteArrayOf(1)) && privateBundle.contentEquals(byteArrayOf(2))) NativeResult.Success(Unit)
        else NativeResult.Failure(OperationError.TRUST_REJECTED)
    }
}

private class BackupMemoryBlobs : SecureBlobAccess {
    private val values = mutableMapOf<Pair<String, SecureDataClass>, ByteArray>()
    override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        values.put(localRecordId to dataClass, exactBytes.copyOf())?.fill(0)
    }
    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray = values[localRecordId to dataClass]?.copyOf() ?: error("missing blob")
    override fun delete(localRecordId: String, dataClass: SecureDataClass) { values.remove(localRecordId to dataClass)?.fill(0) }
    override fun deleteAll() { values.values.forEach { it.fill(0) }; values.clear() }
    override fun exists(localRecordId: String, dataClass: SecureDataClass) = values.containsKey(localRecordId to dataClass)
}

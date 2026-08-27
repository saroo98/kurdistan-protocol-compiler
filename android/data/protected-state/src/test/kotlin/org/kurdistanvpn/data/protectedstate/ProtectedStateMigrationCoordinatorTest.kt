// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.settings.SettingsProjectionCodec

class ProtectedStateMigrationCoordinatorTest {
    @Test fun unmarkedAwaitingKeyIsQuarantinedWithoutGuessingEnrollmentOrInterruptedRestore() {
        val state = MigrationFixture()
        state.addUnboundRecipient(org.kurdistanvpn.data.secure.ClientKeyStatus.AWAITING_PROFILE)
        val originals = state.legacy.mapValues { it.value.clone() }
        val result = state.coordinator().migrateConfirmed()
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(ProtectedStateDisposition.QUARANTINED, result.disposition)
        val snapshot = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        assertEquals(ProtectedStateDisposition.QUARANTINED, snapshot.disposition)
        assertEquals(2, snapshot.objects().size)
        assertNull(snapshot.selectedProfile)
        for ((name, bytes) in originals) assertArrayEquals(bytes, state.legacy.getValue(name))
        val reader = org.kurdistanvpn.data.secure.ClientKeyBundleStore.readOnly(
            ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key),
            org.kurdistanvpn.data.secure.KurdRecipientKeyNative(state.native()))
        assertEquals(org.kurdistanvpn.data.secure.ClientKeyStatus.AWAITING_PROFILE, reader.list().single().status)
        val control = state.journal.readControl().encode()
        assertEquals(ProtectedMutationStatus.NO_MUTATION, state.coordinator().migrateConfirmed().status)
        assertArrayEquals(control, state.journal.readControl().encode())
    }

    @Test fun authenticatedRequestReadyEnrollmentCanMigrateWithoutRecoveryOrChangingItsLifecycle() {
        val state = MigrationFixture()
        state.addUnboundRecipient(org.kurdistanvpn.data.secure.ClientKeyStatus.REQUEST_READY)
        val originals = state.legacy.mapValues { it.value.clone() }
        val result = state.coordinator().migrateConfirmed()
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(ProtectedStateDisposition.VERIFIED, result.disposition)
        assertEquals(2, ProtectedStateSnapshot.decode(state.journal.readCheckpoint()).objects().size)
        for ((name, bytes) in originals) assertArrayEquals(bytes, state.legacy.getValue(name))
    }

    @Test fun confirmedEmptyMigrationCommitsWithoutInventingAProfileKeyOrAuthority() {
        val state = MigrationFixture()
        val result = state.coordinator().migrateConfirmed()
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(ProtectedStateDisposition.VERIFIED, result.disposition)
        val snapshot = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        assertTrue(snapshot.objects().isEmpty())
        assertNull(snapshot.selectedProfile)
        assertEquals(2L, snapshot.revision)
        assertEquals(0, state.nativeCalls)
        assertEquals(1, state.projectionWrites)
    }

    @Test fun confirmedMigrationDoesNotReadLegacyBytesUntilItsDurableReservationIsDirty() {
        val state = MigrationFixture()
        state.requireDirtyBeforeLegacyRead = true

        assertEquals(ProtectedMutationStatus.COMMITTED, state.coordinator().migrateConfirmed().status)
        assertTrue(state.legacyReadCount >= 2)
    }

    @Test fun legacyObjectIsReencryptedWithOperationBindingWithoutChangingLegacyBytes() {
        val state = MigrationFixture()
        state.add("diagnostics", SecureDataClass.DIAGNOSTIC_EVENTS, byteArrayOf(7, 8, 9))
        val before = state.legacy.values.single().clone()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.coordinator().migrateConfirmed().status)
        assertArrayEquals(before, state.legacy.values.single())
        val snapshot = ProtectedStateSnapshot.decode(state.journal.readCheckpoint())
        val ref = snapshot.objects().single()
        assertEquals(2L, ref.binding.revision)
        assertArrayEquals(snapshot.operationId(), ref.binding.operationId())
        assertArrayEquals(byteArrayOf(7, 8, 9), ReadOnlyProtectedBlobView(snapshot.objects(),
            { state.objects[it]?.clone() }, state.codec, state.key).reopen("diagnostics", SecureDataClass.DIAGNOSTIC_EVENTS))
    }

    @Test fun orphanPrivateMaterialIsPreservedButCanOnlyProduceAnAuthenticatedQuarantine() {
        val state = MigrationFixture()
        state.add("orphan-key", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, byteArrayOf(1, 2, 3))
        val before = state.legacy.values.single().clone()
        val result = state.coordinator().migrateConfirmed()
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertEquals(ProtectedStateDisposition.QUARANTINED, result.disposition)
        assertEquals(ProtectedStateDisposition.QUARANTINED,
            ProtectedStateSnapshot.decode(state.journal.readCheckpoint()).disposition)
        assertArrayEquals(before, state.legacy.values.single())
        assertEquals(1, state.objects.size)
    }

    @Test fun corruptEnvelopeCannotBeAdoptedDeletedOrSilentlyReplaced() {
        val state = MigrationFixture()
        state.add("diagnostics", SecureDataClass.DIAGNOSTIC_EVENTS, byteArrayOf(7))
        state.legacy.values.single().let { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val before = state.legacy.values.single().clone()
        assertEquals(ProtectedMutationStatus.DIRTY, state.coordinator().migrateConfirmed().status)
        assertTrue(state.journal.readControl().dirty)
        assertEquals(0, state.projectionWrites)
        assertTrue(state.objects.isEmpty())
        assertArrayEquals(before, state.legacy.values.single())
    }

    @Test fun interruptedPublicationAndChangedLegacySourceCannotPublishClean() {
        for (failure in listOf("object", "projection", "source")) {
            val state = MigrationFixture()
            state.add("diagnostics", SecureDataClass.DIAGNOSTIC_EVENTS, byteArrayOf(7))
            val original = state.legacy.values.single().clone()
            state.failure = failure
            val result = state.coordinator().migrateConfirmed()
            assertTrue(result.status == ProtectedMutationStatus.DIRTY || result.status == ProtectedMutationStatus.MUTATION_UNPROVEN)
            assertTrue(state.journal.readControl().dirty)
            assertThrows(IllegalStateException::class.java) { state.journal.readCheckpoint() }
            if (failure != "source") assertArrayEquals(original, state.legacy.values.single())
            val writes = state.projectionWrites
            assertEquals(ProtectedMutationStatus.DIRTY, state.coordinator().migrateConfirmed().status)
            assertEquals(writes, state.projectionWrites)
        }
    }

    @Test fun alreadyCommittedMigrationCannotRepeatOrReplaceTheJournalEpoch() {
        val state = MigrationFixture()
        assertEquals(ProtectedMutationStatus.COMMITTED, state.coordinator().migrateConfirmed().status)
        val before = state.journal.readControl().encode()
        assertEquals(ProtectedMutationStatus.NO_MUTATION, state.coordinator().migrateConfirmed().status)
        assertArrayEquals(before, state.journal.readControl().encode())
    }
}

private class MigrationFixture {
    val storage = MemoryJournalStorage()
    val journal = ProtectedStateOperationJournal(storage).also { it.initialize(ByteArray(16) { 1 }) }
    val codec = SecureEnvelopeCodec()
    val key = JournalTestKey()
    val legacy = linkedMapOf<LegacyObjectName, ByteArray>()
    val objects = linkedMapOf<String, ByteArray>()
    var nativeCalls = 0
    var projectionWrites = 0
    var failure: String? = null
    var current: ProjectionImages? = null
    var requireDirtyBeforeLegacyRead = false
    var legacyReadCount = 0
    fun add(id: String, role: SecureDataClass, plain: ByteArray) {
        legacy[LegacyObjectName(id, role)] = codec.seal(id, role, plain, key)
    }
    /** Fixed v1 wire fixture, intentionally independent of the production index/bundle encoder. */
    fun addUnboundRecipient(status: org.kurdistanvpn.data.secure.ClientKeyStatus) {
        val id = "legacy-key".encodeToByteArray()
        val request = byteArrayOf(11, 12)
        val material = byteArrayOf(13, 14)
        val fingerprint = java.security.MessageDigest.getInstance("SHA-256").digest(request)
            .joinToString("") { "%02x".format(it) }.encodeToByteArray()
        val index = java.nio.ByteBuffer.allocate(6 + 1 + id.size + 1 + 8 + 8 + 1 + 64 + 1)
            .order(java.nio.ByteOrder.BIG_ENDIAN).apply {
                putInt(0x4b434931); put(1); put(1); put(id.size.toByte()); put(id); put(status.wireValue.toByte())
                putLong(1_800_000_000); putLong(1_800_000_600); put(64); put(fingerprint); put(0)
            }.array()
        val bundle = java.nio.ByteBuffer.allocate(6 + id.size + 8 + 8 + 2 + request.size + 2 + material.size)
            .order(java.nio.ByteOrder.BIG_ENDIAN).apply {
                putInt(0x4b434231); put(1); put(id.size.toByte()); put(id); putLong(1_800_000_000)
                putLong(1_800_000_600); putShort(request.size.toShort()); put(request)
                putShort(material.size.toShort()); put(material)
            }.array()
        try {
            add("recipient-index", SecureDataClass.RECIPIENT_KEY_INDEX, index)
            add("legacy-key", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, bundle)
        } finally { index.fill(0); bundle.fill(0); material.fill(0) }
    }
    fun native(): org.kurdistanvpn.core.nativeapi.KurdNativeCore = java.lang.reflect.Proxy.newProxyInstance(
        org.kurdistanvpn.core.nativeapi.KurdNativeCore::class.java.classLoader,
        arrayOf(org.kurdistanvpn.core.nativeapi.KurdNativeCore::class.java)) { _, method, _ ->
            nativeCalls++
            when (method.name) {
                "validateRecipient" -> org.kurdistanvpn.core.nativeapi.NativeResult.Success(Unit)
                else -> error("Unexpected native call: ${method.name}")
            }
        } as org.kurdistanvpn.core.nativeapi.KurdNativeCore
    fun coordinator(): ProtectedStateMigrationCoordinator {
        val native = native()
        val source = object : LegacyMigrationReadAccess {
            private fun requireAdmittedRead() {
                legacyReadCount++
                if (requireDirtyBeforeLegacyRead) assertTrue(journal.readControl().dirty)
            }
            override fun rows(): List<ProfileCatalogEntity> = emptyList<ProfileCatalogEntity>().also { requireAdmittedRead() }
            override fun settingsImage(): ByteArray = SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.Phase9Settings())
                .also { requireAdmittedRead() }
            override fun objects(): List<LegacyObjectName> = legacy.keys.toList().also { requireAdmittedRead() }
            override fun envelope(name: LegacyObjectName): ByteArray = legacy.getValue(name).clone().also { requireAdmittedRead() }
            override fun sourceWitness(): ByteArray = java.security.MessageDigest.getInstance("SHA-256").run {
                legacy.entries.sortedBy { it.key.role.wireValue.toString() + it.key.logicalId }.forEach { (name, bytes) ->
                    update(name.logicalId.encodeToByteArray()); update(name.role.wireValue.toByte()); update(bytes)
                }
                digest()
            }.also { requireAdmittedRead() }
        }
        val projections = object : ProtectedProjectionAccess {
            override fun read(): ProjectionImages = checkNotNull(current).copyOwned()
            override fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot) = error("Initial migration must not guess old projection")
            override fun initialize(replacement: ProtectedStateSnapshot) {
                assertTrue(journal.readControl().dirty)
                projectionWrites++
                if (failure == "projection") error("synthetic projection failure")
                if (failure == "source") legacy.values.single()[0] = 0
                current = ProjectionImages(replacement.catalogBytes(), replacement.settingsBytes(),
                    ProjectionImageWitness.reconstruct(replacement.storeId(), replacement.operationId(), replacement.revision,
                        replacement.catalogBytes(), replacement.settingsBytes()), syntheticProjectionObservations(replacement))
            }
        }
        return ProtectedStateMigrationCoordinator(storage, source, { ownedOperation -> object : ImmutableProtectedObjectWriter {
            override fun requireDirtyOperation(operation: ByteArray) {
                check(journal.readControl().dirty && operation.contentEquals(ownedOperation))
            }
            override fun create(name: String, bytes: ByteArray) {
                requireDirtyOperation(ownedOperation)
                if (failure == "object") error("synthetic object failure")
                check(objects.putIfAbsent(name, bytes.clone()) == null)
            }
            override fun read(name: String): ByteArray? = objects[name]?.clone()
        } }, { objects[it]?.clone() }, projections, codec, key, native)
    }
}

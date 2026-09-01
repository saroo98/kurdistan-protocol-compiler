// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.settings.SettingsProjectionCodec
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.secure.*

class ProtectedStateAuthorityFactoryTest {
    @Test fun selectedReadBoundsRejectBeforeAdditionalIoAndWipeRejectedBytes() {
        val refs = (1..17).map { ProtectedObjectReference.fromEncryptedObject(1, "profile-$it", "object-$it", 1, byteArrayOf(it.toByte()), syntheticObjectBinding()) }
        var reads = 0
        val reader = SelectedAuthorityObjectReader(refs, { name -> reads++; byteArrayOf(name.substringAfterLast('-').toByte()) }, {})
        repeat(16) { reader.read("object-${it + 1}")!!.fill(0) }
        assertThrows(IllegalStateException::class.java) { reader.read("object-17") }
        assertEquals(16, reads)
        val corrupt = byteArrayOf(99)
        val rejecting = SelectedAuthorityObjectReader(refs, { corrupt }, {})
        assertThrows(IllegalStateException::class.java) { rejecting.read("object-1") }
        assertTrue(corrupt.all { it == 0.toByte() })
        val eightMiB = ByteArray(8 * 1024 * 1024)
        val large = listOf(
            ProtectedObjectReference.fromEncryptedObject(1, "first", "object-first", 1, eightMiB, syntheticObjectBinding()),
            ProtectedObjectReference.fromEncryptedObject(1, "second", "object-second", 1, eightMiB, syntheticObjectBinding()),
            ProtectedObjectReference.fromEncryptedObject(1, "third", "object-third", 1, byteArrayOf(1), syntheticObjectBinding()))
        var largeReads = 0
        val bounded = SelectedAuthorityObjectReader(large, { largeReads++; eightMiB.clone() }, {})
        bounded.read("object-first")!!.fill(0); bounded.read("object-second")!!.fill(0)
        assertThrows(IllegalStateException::class.java) { bounded.read("object-third") }
        assertEquals(2, largeReads)
        eightMiB.fill(0)
    }

    @Test fun changedPhysicalProjectionIsRejectedBeforeNativeAuthorityValidation() {
        val fixture = AuthorityFixture(withProfile = true)
        val snapshot = ProtectedStateSnapshot.decode(fixture.journal.readCheckpoint())
        fixture.projection = ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(),
            fixture.projection.witness, syntheticProjectionObservations(ProtectedStateSnapshot.create(
                snapshot.storeId(), 4, snapshot.selectedProfile, snapshot.objects(), snapshot.settingsBytes(),
                snapshot.catalogBytes(), ByteArray(JournalLimits.OPERATION_BYTES) { 3 })))
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(0, fixture.nativeOpens)
    }

    @Test fun everyReconstructionRevalidatesNativeAuthorityWithoutOpeningASocketAndOwnsItsWire() {
        val fixture = AuthorityFixture(withProfile = true)
        repeat(2) {
            val before = fixture.journal.readControl().encode()
            val ready = (fixture.factory().reconstruct() as AuthorityReadResult.Ready).authority
            assertEquals(2L, ready.revision)
            assertEquals(3, ready.signedRetryBudget)
            var borrowed: ByteArray? = null
            val output = java.io.ByteArrayOutputStream()
            ready.writeTo(object : java.io.OutputStream() {
                override fun write(value: Int) = error("bounded bulk write required")
                override fun write(bytes: ByteArray, offset: Int, length: Int) {
                    borrowed = bytes; output.write(bytes, offset, length)
                }
            })
            assertEquals("KRV2", output.toByteArray().copyOfRange(0, 4).toString(Charsets.US_ASCII))
            assertTrue(borrowed!!.all { it == 0.toByte() })
            assertThrows(IllegalStateException::class.java) { ready.writeTo(output) }
            ready.close()
            assertArrayEquals(before, fixture.journal.readControl().encode())
        }
        assertEquals(2, fixture.nativeOpens)
        assertEquals(2, fixture.nativeCloses)
        assertTrue(fixture.borrowedNativeWire!!.all { it == 0.toByte() })
    }

    @Test fun nativeRejectionCancellationAndUncertainCleanupNeverReleaseWire() {
        for (failure in listOf(OperationError.TRUST_REJECTED, OperationError.KEY_INVALIDATED, OperationError.POLICY_REJECTED)) {
            val fixture = AuthorityFixture(withProfile = true)
            fixture.nativeFailure = failure
            val rejected = fixture.factory().reconstruct() as AuthorityReadResult.Rejected
            assertEquals(AuthorityReadFailure.AUTHORITY_REJECTED, rejected.category)
            assertEquals(failure, rejected.error)
            assertTrue(fixture.borrowedNativeWire!!.all { it == 0.toByte() })
        }
        val cancelled = AuthorityFixture(withProfile = true)
        cancelled.onOpen = { cancelled.environment.cancelled = true }
        assertEquals(AuthorityReadFailure.CANCELLED,
            (cancelled.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(1, cancelled.nativeCloses)
        val unproven = AuthorityFixture(withProfile = true)
        unproven.closeThrows = true
        assertEquals(AuthorityReadFailure.CLEANUP_UNPROVEN,
            (unproven.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(1, unproven.nativeCloses)
    }

    @Test fun staleProjectionOrExpiredReadDeadlineIsNotReleasedAfterNativeValidation() {
        val stale = AuthorityFixture(withProfile = true)
        stale.onOpen = { stale.projection = ProjectionImages(byteArrayOf(1), byteArrayOf(2), null) }
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (stale.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        val expired = AuthorityFixture(withProfile = true)
        expired.onOpen = { expired.environment.now = 5200 }
        assertEquals(AuthorityReadFailure.EXPIRED,
            (expired.factory().reconstruct() as AuthorityReadResult.Rejected).category)
    }

    @Test fun lockedAndUnpreparedStartsCannotReadAnyProtectedState() {
        for (locked in listOf(true, false)) {
            val fixture = AuthorityFixture()
            fixture.environment.unlocked = !locked
            fixture.environment.prepared = locked
            val result = fixture.factory().reconstruct()
            assertEquals(if (locked) AuthorityReadFailure.LOCKED else AuthorityReadFailure.CONSENT_REQUIRED,
                (result as AuthorityReadResult.Rejected).category)
            assertEquals(0, fixture.projectionReads)
            assertEquals(0, fixture.objectReads)
            assertEquals(0, fixture.nativeCalls)
        }
    }

    @Test fun missingSelectionDoesNotCreateDefaultsOrRepairState() {
        val fixture = AuthorityFixture()
        val before = fixture.journal.readControl().encode()
        val result = fixture.factory().reconstruct() as AuthorityReadResult.Rejected
        assertEquals(AuthorityReadFailure.POLICY_REJECTED, result.category)
        assertArrayEquals(before, fixture.journal.readControl().encode())
        assertEquals(0, fixture.nativeCalls)
    }

    @Test fun dirtyOrMismatchedProjectionCannotProduceAuthority() {
        val fixture = AuthorityFixture()
        fixture.projection = ProjectionImages(byteArrayOf(1), byteArrayOf(2), null)
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        fixture.journal.mutate(MutationKind.SETTINGS, ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(9),
            { error("interrupted mutation") }, { byteArrayOf(9) })
        assertEquals(AuthorityReadFailure.STATE_UNPROVEN,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertTrue(fixture.journal.readControl().dirty)
        assertEquals(0, fixture.nativeCalls)
    }

    @Test fun cancellationIsTerminalBeforeAnyProtectedRead() {
        val fixture = AuthorityFixture()
        fixture.environment.cancelled = true
        assertEquals(AuthorityReadFailure.CANCELLED,
            (fixture.factory().reconstruct() as AuthorityReadResult.Rejected).category)
        assertEquals(0, fixture.projectionReads)
    }
}

private class AuthorityFixture(withProfile: Boolean = false) {
    val storage = MemoryJournalStorage()
    val journal = ProtectedStateOperationJournal(storage)
    val codec = SecureEnvelopeCodec()
    val key = JournalTestKey()
    val environment = AuthorityEnvironment()
    var projectionReads = 0
    var objectReads = 0
    var nativeCalls = 0
    var nativeOpens = 0
    var nativeCloses = 0
    var closeThrows = false
    var nativeFailure: OperationError? = null
    var borrowedNativeWire: ByteArray? = null
    var onOpen: () -> Unit = {}
    val objects = linkedMapOf<String, ByteArray>()
    var projection: ProjectionImages
    val native = java.lang.reflect.Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader,
        arrayOf(KurdNativeCore::class.java)) { _, method, args ->
        nativeCalls++
        when (method.name) {
            "validateRecipient" -> NativeResult.Success(Unit)
            "openLiveRuntimeSession" -> {
                nativeOpens++; borrowedNativeWire = args!![0] as ByteArray; onOpen()
                nativeFailure?.let { NativeResult.Failure(it) } ?: NativeResult.Success(nativeSession())
            }
            else -> error("Unexpected native operation: ${method.name}")
        }
    } as KurdNativeCore
    init {
        journal.initialize(ByteArray(16) { 1 })
        val refs = if (withProfile) profileObjects() else emptyList()
        val settings = Phase9Settings(profiles = org.kurdistanvpn.core.model.ProfilePreferences(
            activeLocalRecordId = if (withProfile) "synthetic-profile" else null))
        val rows = if (withProfile) listOf(ProfileCatalogEntity("synthetic-profile", "FINALIZED", 1, 1, "AVAILABLE")) else emptyList()
        val state = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, settings.profiles.activeLocalRecordId, refs,
            SettingsProjectionCodec.fromModel(settings), ProfileCatalogProjectionCodec.encode(rows), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        val raw = state.encode()
        check(journal.mutate(MutationKind.MIGRATION, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, raw, {}, {
            bindSyntheticProjection(journal, raw); raw.clone()
        }) == ProtectedMutationStatus.COMMITTED)
        projection = ProjectionImages(state.catalogBytes(), state.settingsBytes(), ProjectionImageWitness.reconstruct(
            state.storeId(), state.operationId(), 2, state.catalogBytes(), state.settingsBytes()),
            syntheticProjectionObservations(state))
    }
    fun factory() = ProtectedStateAuthorityFactory(
        ProtectedStateSnapshotReader(journal) { objectReads++; objects[it.physicalId]!!.clone() },
        { objectReads++; objects[it]?.clone() }, codec, key, native,
        object : ProtectedProjectionReadAccess { override fun read(): ProjectionImages { projectionReads++; return projection.copyOwned() } },
        environment,
    )

    private fun nativeSession(): NativeLiveRuntimeSession = object : NativeLiveRuntimeSession {
        override val snapshot = NativeLiveRuntimeSessionSnapshot(1, ByteArray(32) { 1 }, ByteArray(16), ByteArray(16), ByteArray(16),
            org.kurdistanvpn.core.model.SelectionMode.AUTOMATIC, org.kurdistanvpn.core.model.PerAppSelectionMode.ALL_APPS,
            emptyList(), org.kurdistanvpn.core.model.IpMode.AUTO, org.kurdistanvpn.core.model.DnsMode.INTERNAL_TUN, 1500, false,
            ByteArray(4), ByteArray(4), ByteArray(16), ByteArray(16), emptyList(), emptySet(), 32, 8, 3, 3000, 300000)
        override fun prepareSocket(): NativeResult<Int> = error("Reissue must not create network resources")
        override fun commitProtected(protectedSocket: Boolean): NativeResult<Unit> = error("Reissue must not connect")
        override fun attachTun(fileDescriptor: Int): NativeResult<Unit> = error("Reissue cannot own TUN")
        override fun status() = NativeResult.Success(NativeRuntimeState.VERIFIED)
        override fun stop() = NativeResult.Success(Unit)
        override fun close() { nativeCloses++; if (closeThrows) error("synthetic close uncertainty") }
    }

    private fun profileObjects(): List<ProtectedObjectReference> {
        val values = linkedMapOf<Pair<String, SecureDataClass>, ByteArray>()
        val blobs = object : SecureBlobAccess {
            override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) { values[localRecordId to dataClass] = exactBytes.clone() }
            override fun reopen(localRecordId: String, dataClass: SecureDataClass) = values[localRecordId to dataClass]!!.clone()
            override fun exists(localRecordId: String, dataClass: SecureDataClass) = values.containsKey(localRecordId to dataClass)
            override fun delete(localRecordId: String, dataClass: SecureDataClass) { values.remove(localRecordId to dataClass)?.fill(0) }
            override fun deleteAll() { error("No reset in authority fixture") }
        }
        val recipient = object : RecipientKeyNative {
            override fun create(validitySeconds: Int): NativeResult<NativeRecipient> = NativeResult.Success(object : NativeRecipient {
                override fun publicRequest() = NativeResult.Success(byteArrayOf(11, 12))
                override fun privateBundle() = NativeResult.Success(byteArrayOf(13, 14))
                override fun cancel() = NativeResult.Success(Unit)
                override fun close() = Unit
            })
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray) = NativeResult.Success(Unit)
        }
        val keys = ClientKeyBundleStore(blobs, recipient) { "synthetic-recipient" }
        val created = keys.create(600, 1_800_000_000) as ClientKeyResult.Success
        keys.bindProfile(created.summary.localRecordId, "synthetic-profile")
        blobs.stage("synthetic-profile", SecureDataClass.IMPORT_REQUEST, byteArrayOf(21, 22))
        blobs.stage("synthetic-profile", SecureDataClass.ACTIVATION_ACTIVE, byteArrayOf(23, 24))
        // Independent fixture of the existing KPR2 layout, not verifier-generated output.
        val preview = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(preview).use { out ->
            out.writeInt(0x4b505232)
            listOf("sealed-device", "device-recipient", "synthetic-content", "synthetic-lineage", "", "", "", "", "Synthetic").forEach {
                val raw = it.toByteArray(Charsets.UTF_8); out.writeByte(raw.size); out.write(raw)
            }
            out.writeByte(1); out.writeLong(1); out.writeLong(2_000_000_000)
        }
        blobs.stage("synthetic-profile", SecureDataClass.PROFILE_PREVIEW, preview.toByteArray())
        return values.entries.mapIndexed { index, (identity, plaintext) ->
            val name = "object-synthetic-$index"
            val encrypted = codec.sealForOperation(identity.first, identity.second, plaintext, key, syntheticObjectBinding())
            objects[name] = encrypted
            plaintext.fill(0)
            ProtectedObjectReference.fromEncryptedObject(identity.second.wireValue, identity.first, name, 1, encrypted, syntheticObjectBinding())
        }
    }
}

private class AuthorityEnvironment : ProtectedAuthorityEnvironment {
    var unlocked = true
    var prepared = true
    var cancelled = false
    var now = 100L
    override fun isUserUnlocked() = unlocked
    override fun isConsentPrepared() = prepared
    override fun isCancelled() = cancelled
    override fun elapsedRealtimeMillis() = now
}

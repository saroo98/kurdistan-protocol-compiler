// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.settings.SettingsProjectionCodec

class ProtectedStatePreviewBackupPolicyTest {
    @Test fun externalPreviewOwnsInputClosesNativeAndConfirmsOnlyOnceWithoutWrites() {
        val fixture = PreviewFixture()
        val borrowed = byteArrayOf(41, 42)
        val before = fixture.journal.readControl().encode()
        val result = fixture.reader().previewExternal(borrowed) as ProtectedExternalPreviewResult.Ready
        borrowed.fill(99)
        assertEquals(1, fixture.releases)
        assertTrue(fixture.nativeInputs.all { bytes -> bytes.all { it == 0.toByte() } })
        val confirmed = result.preview.confirm()
        assertEquals(2L, confirmed.revision)
        assertNull(confirmed.recipientKeyId)
        val owned = confirmed.takeRequest()
        try { assertArrayEquals(byteArrayOf(41, 42), owned) } finally { owned.fill(0) }
        assertThrows(IllegalStateException::class.java) { confirmed.takeRequest() }
        assertThrows(IllegalStateException::class.java) { result.preview.confirm() }
        confirmed.close(); result.preview.close()
        assertArrayEquals(before, fixture.journal.readControl().encode())
        fixture.assertReadOnly()
    }

    @Test fun cancellationRejectionAndCleanupFailureNeverReleaseConfirmableBytes() {
        val cancelled = PreviewFixture()
        cancelled.onVerify = { cancelled.cancelled = true }
        assertEquals(ProtectedReadFailure.CANCELLED,
            (cancelled.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(1, cancelled.releases)
        cancelled.assertReadOnly()
        val failed = PreviewFixture(); failed.publicFailure = true
        assertEquals(ProtectedReadFailure.REJECTED,
            (failed.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        failed.assertReadOnly()
        val cleanup = PreviewFixture(); cleanup.releaseFailure = true
        assertEquals(ProtectedReadFailure.CLEANUP_UNPROVEN,
            (cleanup.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(1, cleanup.releases)
        assertTrue(cleanup.nativeInputs.all { it.all { b -> b == 0.toByte() } })
    }

    @Test fun cancellationAndOversizeRejectBeforeAnyProtectedRead() {
        val fixture = PreviewFixture(); fixture.cancelled = true
        assertTrue(fixture.reader().previewExternal(byteArrayOf(1)) is ProtectedExternalPreviewResult.Rejected)
        fixture.cancelled = false
        assertTrue(fixture.reader().previewExternal(ByteArray(1024 * 1024 + 1)) is ProtectedExternalPreviewResult.Rejected)
        assertEquals(0, fixture.projectionReads)
        assertEquals(0, fixture.nativeInputs.size)
        fixture.assertReadOnly()
    }

    @Test fun cancellationDuringProjectionReadRejectsBeforeFirstNativeCall() {
        val fixture = PreviewFixture()
        fixture.onProjectionRead = { fixture.cancelled = true }
        assertEquals(ProtectedReadFailure.CANCELLED,
            (fixture.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(0, fixture.nativeInputs.size)
        fixture.assertReadOnly()
    }

    @Test fun recipientCandidatesAreReadOnlyAndEveryLeaseIsWipedEvenAfterEarlySuccess() {
        val fixture = PreviewFixture(keyCount = 3); fixture.publicFailure = true; fixture.recipientAccept = true
        val ready = fixture.reader().previewExternal(byteArrayOf(7)) as ProtectedExternalPreviewResult.Ready
        assertEquals(1, fixture.recipientVerifications)
        assertEquals(1, fixture.releases)
        assertTrue(fixture.nativeSecrets.isNotEmpty())
        assertTrue(fixture.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        ready.preview.close()
        assertThrows(IllegalStateException::class.java) { ready.preview.confirm() }
        fixture.assertReadOnly()
    }

    @Test fun expiredOrChangedCheckpointInvalidatesConfirmationWithoutNormalization() {
        val fixture = PreviewFixture()
        val ready = fixture.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Ready
        fixture.projectionChanged = true
        assertThrows(IllegalStateException::class.java) { ready.preview.confirm() }
        assertThrows(IllegalStateException::class.java) { ready.preview.confirm() }
        ready.preview.close(); fixture.assertReadOnly()
        val expired = PreviewFixture(); expired.onVerify = { expired.now += 5_001 }
        assertEquals(ProtectedReadFailure.EXPIRED,
            (expired.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(1, expired.releases)
    }

    @Test fun ordinaryBackupEnumeratesOnlyIncludedBoundKeysAndNeverWrapsBeforeConfirmation() {
        val fixture = PreviewFixture(keyCount = 3, withProfiles = true)
        val result = fixture.reader().enumerateOrdinaryBackup() as ProtectedBackupEnumeration.Ready
        assertEquals(2, result.plan.profileCount)
        assertEquals(1, result.plan.keyCount)
        assertEquals(0, fixture.backupCalls)
        assertTrue(fixture.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        result.plan.close()
        assertThrows(IllegalStateException::class.java) { result.plan.confirmEncryptedExport(byteArrayOf(1)) }
        fixture.assertReadOnly()
    }

    @Test fun emptyFullBackupIsCanonicalWhileMissingExplicitSelectionFailsClosed() {
        val fixture = PreviewFixture()
        val result = fixture.reader().enumerateOrdinaryBackup() as ProtectedBackupEnumeration.Ready
        assertEquals(0, result.plan.profileCount)
        assertEquals(0, result.plan.keyCount)
        assertEquals(0, fixture.backupCalls)

        val passphrase = "synthetic-passphrase".encodeToByteArray()
        assertTrue(result.plan.confirmEncryptedExport(passphrase) is NativeResult.Failure)
        assertEquals(1, fixture.backupCalls)
        assertTrue(fixture.wrappedProfiles.isEmpty())
        assertTrue(fixture.wrappedKeyStatuses.isEmpty())
        assertTrue(fixture.wrappedBindings.isEmpty())
        assertEquals(2, fixture.wrappedVersion)
        assertArrayEquals("synthetic-passphrase".encodeToByteArray(), passphrase)
        fixture.assertReadOnly()

        val missing = PreviewFixture()
        assertEquals(ProtectedReadFailure.STATE_UNPROVEN,
            (missing.reader().enumerateOrdinaryBackup("profile-missing") as ProtectedBackupEnumeration.Rejected).category)
        assertEquals(0, missing.backupCalls)
        missing.assertReadOnly()
    }

    @Test fun explicitBackupRevalidatesSelectionUsesV2AndWipesPassphraseOnNativeFailure() {
        val fixture = PreviewFixture(keyCount = 3, withProfiles = true)
        val result = fixture.reader().enumerateOrdinaryBackup("profile-sealed") as ProtectedBackupEnumeration.Ready
        assertEquals(1, result.plan.profileCount); assertEquals(1, result.plan.keyCount)
        val passphrase = "synthetic-passphrase".encodeToByteArray()
        assertTrue(result.plan.confirmEncryptedExport(passphrase) is NativeResult.Failure)
        assertEquals(1, fixture.backupCalls)
        assertEquals(listOf("profile-sealed"), fixture.wrappedProfiles)
        assertEquals(listOf(ClientKeyStatus.PROFILE_VERIFIED), fixture.wrappedKeyStatuses)
        assertEquals(listOf(listOf("profile-sealed")), fixture.wrappedBindings)
        assertEquals(2, fixture.wrappedVersion)
        assertTrue(fixture.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        assertArrayEquals("synthetic-passphrase".encodeToByteArray(), passphrase)
        assertThrows(IllegalStateException::class.java) { result.plan.confirmEncryptedExport(passphrase) }
        fixture.assertReadOnly()
    }

    @Test fun quarantinedSelectionAndTamperedCommittedBytesCannotBecomeBackupMaterial() {
        val fixture = PreviewFixture(keyCount = 3, withProfiles = true)
        assertTrue(fixture.reader().enumerateOrdinaryBackup("profile-quarantined") is ProtectedBackupEnumeration.Rejected)
        fixture.corruptObjects = true
        assertTrue(fixture.reader().enumerateOrdinaryBackup() is ProtectedBackupEnumeration.Rejected)
        assertEquals(0, fixture.backupCalls)
        fixture.assertReadOnly()
    }

    @Test fun preparedKeyCannotBePromotedDeletedOrOpenedDuringExternalPreview() {
        val fixture = PreviewFixture(keyCount = 1, prepared = true); fixture.publicFailure = true
        assertTrue(fixture.reader().previewExternal(byteArrayOf(1)) is ProtectedExternalPreviewResult.Rejected)
        assertEquals(0, fixture.recipientVerifications)
        assertTrue(fixture.nativeSecrets.isEmpty())
        fixture.assertReadOnly()
    }

    @Test fun failedCandidateAndThrowingNativeReleaseWipeAllOpenedRecipientCopies() {
        val failed = PreviewFixture(keyCount = 3); failed.publicFailure = true
        assertTrue(failed.reader().previewExternal(byteArrayOf(1)) is ProtectedExternalPreviewResult.Rejected)
        assertEquals(3, failed.recipientVerifications)
        assertTrue(failed.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        val throwing = PreviewFixture(keyCount = 3); throwing.publicFailure = true
        throwing.recipientAccept = true; throwing.releaseThrows = true
        assertEquals(ProtectedReadFailure.CLEANUP_UNPROVEN,
            (throwing.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(1, throwing.releases)
        assertTrue(throwing.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        failed.assertReadOnly(); throwing.assertReadOnly()
    }

    @Test fun thirtyTwoCandidatesAreBoundedAndNoCancellationFallsThroughToAnotherCandidate() {
        val fixture = PreviewFixture(keyCount = 32); fixture.publicFailure = true
        assertTrue(fixture.reader().previewExternal(byteArrayOf(1)) is ProtectedExternalPreviewResult.Rejected)
        assertEquals(32, fixture.recipientVerifications)
        assertTrue(fixture.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        val cancelled = PreviewFixture(keyCount = 3); cancelled.publicFailure = true
        cancelled.onVerify = { if (cancelled.recipientVerifications > 0) cancelled.cancelled = true }
        assertEquals(ProtectedReadFailure.CANCELLED,
            (cancelled.reader().previewExternal(byteArrayOf(1)) as ProtectedExternalPreviewResult.Rejected).category)
        assertEquals(1, cancelled.recipientVerifications)
        assertTrue(cancelled.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
    }

    @Test fun backupConfirmationRejectsStaleOrCancelledCheckpointBeforeNativeWrapping() {
        for (cancel in listOf(false, true)) {
            val fixture = PreviewFixture(keyCount = 3, withProfiles = true)
            val plan = (fixture.reader().enumerateOrdinaryBackup() as ProtectedBackupEnumeration.Ready).plan
            fixture.cancelled = cancel; fixture.projectionChanged = !cancel
            assertTrue(plan.confirmEncryptedExport("synthetic".encodeToByteArray()) is NativeResult.Failure)
            assertEquals(0, fixture.backupCalls)
            fixture.assertReadOnly()
        }
    }

    @Test fun publicInputCannotBeSubstitutedByCallerWhileVerificationRuns() {
        val fixture = PreviewFixture()
        val input = byteArrayOf(31, 32)
        fixture.onVerify = { input.fill(99) }
        val pending = (fixture.reader().previewExternal(input) as ProtectedExternalPreviewResult.Ready).preview
        val confirmed = pending.confirm()
        val owned = confirmed.takeRequest()
        try { assertArrayEquals(byteArrayOf(31, 32), owned) } finally { owned.fill(0); confirmed.close() }
        assertTrue(fixture.nativeInputs.all { it.all { b -> b == 0.toByte() } })
        fixture.assertReadOnly()
    }

    @Test fun backupNativeExceptionStillWipesPlaintextAndPassphraseCopies() {
        val fixture = PreviewFixture(keyCount = 3, withProfiles = true); fixture.backupThrows = true
        val plan = (fixture.reader().enumerateOrdinaryBackup() as ProtectedBackupEnumeration.Ready).plan
        assertTrue(plan.confirmEncryptedExport("synthetic-passphrase".encodeToByteArray()) is NativeResult.Failure)
        assertEquals(1, fixture.backupCalls)
        assertTrue(fixture.nativeSecrets.all { it.all { b -> b == 0.toByte() } })
        fixture.assertReadOnly()
    }

    @Test fun settingsProjectionNeverPromotesLegacyRoutesOrMutatesSource() {
        val legacyPackages = mutableSetOf("org.legacy.app")
        val persisted = Phase9Settings(
            connection = ConnectionPreferences(selectionMode = SelectionMode.MANUAL_STRATEGY, autoConnectOnBoot = true, reconnectOnFailure = true),
            tunnel = TunnelPreferences(ipMode = IpMode.DUAL_STACK, dnsMode = DnsMode.CUSTOM, customDns = "192.0.2.1"),
            routing = RoutingPreferences(mode = PerAppSelectionMode.INCLUDE_ONLY, packages = legacyPackages),
            updates = UpdatePreferences(automatic = true),
            probes = ProbePreferences(method = ProbeMethod.HTTP_GET, testUrl = "https://example.invalid/"),
        )
        val view = ProtectedStatePreviewBackupPolicy.projectSettings(persisted, emptySet())
        assertEquals(SelectionMode.AUTOMATIC, view.connection.selectionMode)
        assertFalse(view.connection.autoConnectOnBoot)
        assertFalse(view.connection.reconnectOnFailure)
        assertEquals(IpMode.AUTO, view.tunnel.ipMode)
        assertEquals(DnsMode.INTERNAL_TUN, view.tunnel.dnsMode)
        assertEquals("", view.tunnel.customDns)
        assertTrue(view.routing.packages.isEmpty())
        assertFalse(view.updates.automatic)
        assertEquals(ProbeMethod.KURD_SESSION, view.probes.method)
        assertTrue(persisted.connection.autoConnectOnBoot)
        assertEquals(setOf("org.legacy.app"), persisted.routing.packages)
        assertEquals("192.0.2.1", persisted.tunnel.customDns)
        // Empty INCLUDE_ONLY remains invalid, never widened to ALL_APPS for runtime.
        assertThrows(IllegalArgumentException::class.java) { view.routing.validated() }
    }

    @Test fun committedPackageProjectionTakesDefensiveCopyAndKeepsSupportedSettings() {
        val packages = mutableSetOf("org.committed.app")
        val persisted = Phase9Settings(connection = ConnectionPreferences(selectionMode = SelectionMode.KURD_ONLY), tunnel = TunnelPreferences(ipMode = IpMode.IPV4_ONLY, mtu = 1400))
        val view = ProtectedStatePreviewBackupPolicy.projectSettings(persisted, packages)
        packages.clear()
        assertEquals(setOf("org.committed.app"), view.routing.packages)
        assertEquals(SelectionMode.KURD_ONLY, view.connection.selectionMode)
        assertEquals(1400, view.tunnel.mtu)
        assertEquals(IpMode.IPV4_ONLY, view.tunnel.ipMode)
    }

    @Test fun cancelProfileProjectionFiltersOnlyInMemoryAndDoesNotAuthorizeSelection() {
        val favorites = mutableSetOf("known", "missing")
        val persisted = ProfilePreferences("missing", favorites)
        val view = ProtectedStatePreviewBackupPolicy.projectProfiles(persisted, listOf("known", "second"))
        assertEquals(ProfilePreferences("known", setOf("known")), view)
        assertEquals(ProfilePreferences("missing", setOf("known", "missing")), persisted)
        favorites.clear()
        assertEquals(setOf("known"), view.favoriteLocalRecordIds)
        assertEquals(ProfilePreferences(), ProtectedStatePreviewBackupPolicy.projectProfiles(persisted, emptyList()))
    }

    @Test fun malformedOrDuplicateProfileProjectionFailsClosed() {
        assertThrows(IllegalArgumentException::class.java) { ProtectedStatePreviewBackupPolicy.projectProfiles(ProfilePreferences(), listOf("a", "a")) }
        assertThrows(IllegalArgumentException::class.java) { ProtectedStatePreviewBackupPolicy.projectProfiles(ProfilePreferences(), listOf("../a")) }
    }
}

/** Synthetic encrypted read fixture. Native verification is replaced at the JNI boundary only;
 * real snapshot, encrypted-object, recipient-index, binding and backup codecs are exercised. */
private class PreviewFixture(keyCount: Int = 0, withProfiles: Boolean = false, prepared: Boolean = false) {
    private val delegate = MemoryJournalStorage()
    private var frozen = false
    private var mutationCalls = 0
    private val storage = object : JournalStorage {
        override fun <T> exclusive(block: () -> T): T { if (frozen) { mutationCalls++; error("preview acquired writer") }; return delegate.exclusive(block) }
        override fun read(name: String, maximum: Int) = delegate.read(name, maximum)
        override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
            if (frozen) { mutationCalls++; error("preview wrote journal") }; delegate.compareAndReplace(name, expected, replacement)
        }
        override fun delete(name: String, expected: ByteArray) { if (frozen) { mutationCalls++; error("preview deleted journal") }; delegate.delete(name, expected) }
        override fun inventory(maximum: Int) = delegate.inventory(maximum)
    }
    val journal = ProtectedStateOperationJournal(storage)
    private val codec = SecureEnvelopeCodec()
    private val key = JournalTestKey()
    private val ciphertext = linkedMapOf<String, ByteArray>()
    private val snapshot: ProtectedStateSnapshot
    var cancelled = false; var now = 10L; var projectionChanged = false; var corruptObjects = false
    var projectionReads = 0; var releases = 0; var recipientVerifications = 0; var backupCalls = 0
    var publicFailure = false; var recipientAccept = false; var releaseFailure = false; var releaseThrows = false; var backupThrows = false
    var onVerify: () -> Unit = {}
    var onProjectionRead: () -> Unit = {}
    val nativeInputs = mutableListOf<ByteArray>()
    val nativeSecrets = mutableListOf<ByteArray>()
    var wrappedProfiles = emptyList<String>(); var wrappedKeyStatuses = emptyList<ClientKeyStatus?>()
    var wrappedBindings = emptyList<List<String>>(); var wrappedVersion = 0
    private fun preview(sealed: Boolean) = RedactedProfilePreview(if (sealed) "sealed-device" else "public", "synthetic",
        "synthetic-content", "synthetic-lineage", 1uL, 2_000_000_000L, sealed)
    private val native = java.lang.reflect.Proxy.newProxyInstance(KurdNativeCore::class.java.classLoader,
        arrayOf(KurdNativeCore::class.java)) { _, method, args ->
        when (method.name) {
            "validateRecipient" -> { nativeSecrets += args!![0] as ByteArray; nativeSecrets += args[1] as ByteArray; NativeResult.Success(Unit) }
            "verifyPreview" -> {
                val input = args!![0] as ByteArray; nativeInputs += input; onVerify()
                if (publicFailure || input.firstOrNull() == 71.toByte()) NativeResult.Failure(OperationError.TRUST_REJECTED)
                else NativeResult.Success(VerifiedPreviewHandle(1, preview(false)))
            }
            "verifyPreviewWithRecipient" -> {
                recipientVerifications++; val input = args!![0] as ByteArray; nativeInputs += input
                nativeSecrets += args[1] as ByteArray; nativeSecrets += args[2] as ByteArray; onVerify()
                if (recipientAccept || input.firstOrNull() == 71.toByte()) NativeResult.Success(VerifiedPreviewHandle(2, preview(true)))
                else NativeResult.Failure(OperationError.TRUST_REJECTED)
            }
            "releaseVerified" -> { releases++; if (releaseThrows) error("synthetic release uncertainty")
                if (releaseFailure) NativeResult.Failure(OperationError.INTERNAL_FAILURE) else NativeResult.Success(Unit) }
            "createBackup" -> {
                backupCalls++; nativeSecrets += args!![0] as ByteArray; nativeSecrets += args[1] as ByteArray
                if (backupThrows) error("synthetic native wrapping failure")
                val decoded = BackupPayloadCodec.decodePayload(args[0] as ByteArray)
                try {
                    wrappedProfiles = decoded.profiles.map { it.localRecordId }
                    wrappedKeyStatuses = decoded.clientKeys.map { it.sourceStatus }
                    wrappedBindings = decoded.clientKeys.map { it.sourceProfileRecordIds }
                    wrappedVersion = decoded.sourceVersion
                } finally { decoded.profiles.forEach { it.verifyRequest.fill(0) }; decoded.clientKeys.forEach { it.destroy() } }
                // Deliberately no successful artifact: native packaging/filter support is a separate gate.
                NativeResult.Failure(OperationError.INCOMPATIBLE_NATIVE_CORE)
            }
            else -> error("Read-only policy reached forbidden native operation: ${method.name}")
        }
    } as KurdNativeCore
    init {
        val plain = linkedMapOf<Pair<String, SecureDataClass>, ByteArray>()
        val writableFixture = object : SecureBlobAccess {
            override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) { check(!frozen); plain[localRecordId to dataClass] = exactBytes.clone() }
            override fun reopen(localRecordId: String, dataClass: SecureDataClass) = plain[localRecordId to dataClass]!!.clone()
            override fun exists(localRecordId: String, dataClass: SecureDataClass) = plain.containsKey(localRecordId to dataClass)
            override fun delete(localRecordId: String, dataClass: SecureDataClass) { error("fixture has no deletion") }
            override fun deleteAll() { error("fixture has no reset") }
        }
        var created = 0
        val keys = ClientKeyBundleStore(writableFixture, object : RecipientKeyNative {
            override fun create(validitySeconds: Int) = NativeResult.Success(object : NativeRecipient {
                private val index = ++created
                override fun publicRequest() = NativeResult.Success(byteArrayOf(index.toByte(), 11))
                override fun privateBundle() = NativeResult.Success(byteArrayOf(index.toByte(), 12))
                override fun cancel() = NativeResult.Success(Unit)
                override fun close() = Unit
            })
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray) = NativeResult.Success(Unit)
        }) { "recipient-$created" }
        repeat(keyCount) { assertTrue(keys.create(600, 1_800_000_000 + it.toLong()) is ClientKeyResult.Success) }
        if (prepared) {
            // Fixed KCI1 field layout: six-byte header, then length-prefixed local ID, then status.
            val index = checkNotNull(plain["recipient-index" to SecureDataClass.RECIPIENT_KEY_INDEX])
            val localIdLength = index[6].toInt() and 255
            index[7 + localIdLength] = 1
        }
        if (keyCount > 1) keys.markRequestExported("recipient-2")
        if (withProfiles) {
            keys.bindProfile("recipient-1", "profile-sealed")
            writableFixture.stage("profile-sealed", SecureDataClass.IMPORT_REQUEST, byteArrayOf(71, 1))
            writableFixture.stage("profile-public", SecureDataClass.IMPORT_REQUEST, byteArrayOf(72, 1))
        }
        val refs = plain.entries.mapIndexed { index, (identity, bytes) ->
            val physical = "object-preview-$index"
            val binding = SecureOperationBinding(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, 2)
            val encrypted = codec.sealForOperation(identity.first, identity.second, bytes, key, binding)
            ciphertext[physical] = encrypted; bytes.fill(0)
            ProtectedObjectReference.fromEncryptedObject(identity.second.wireValue, identity.first, physical, key.generation, encrypted, binding)
        }
        val rows = if (withProfiles) listOf(
            ProfileCatalogEntity("profile-sealed", "FINALIZED", 1, 1, "AVAILABLE"),
            ProfileCatalogEntity("profile-public", "FINALIZED", 1, 1, "AVAILABLE"),
            ProfileCatalogEntity("profile-quarantined", "QUARANTINED", 1, 1, "QUARANTINED")) else emptyList()
        snapshot = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, refs,
            SettingsProjectionCodec.fromModel(Phase9Settings()), ProfileCatalogProjectionCodec.encode(rows), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        journal.initialize(ByteArray(16) { 1 })
        val raw = snapshot.encode()
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.MIGRATION, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, raw, {}, {
            bindSyntheticProjection(journal, raw); raw.clone()
        }))
        raw.fill(0); frozen = true
    }
    fun reader() = ProtectedStatePreviewBackupReader(
        ProtectedStateSnapshotReader(journal) { reference -> ciphertext[reference.physicalId]!!.clone() },
        { name -> ciphertext[name]?.clone()?.also { if (corruptObjects) it[0] = 0 } }, codec, key, native,
        object : ProtectedProjectionReadAccess { override fun read(): ProjectionImages {
            projectionReads++; onProjectionRead()
            return ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(), ProjectionImageWitness.reconstruct(
                snapshot.storeId(), snapshot.operationId(), snapshot.revision, snapshot.catalogBytes(), snapshot.settingsBytes()),
                if (projectionChanged) emptyList() else syntheticProjectionObservations(snapshot))
        } }, { cancelled }, { now })
    fun assertReadOnly() { assertEquals(0, mutationCalls); assertFalse(journal.readControl().dirty) }
}

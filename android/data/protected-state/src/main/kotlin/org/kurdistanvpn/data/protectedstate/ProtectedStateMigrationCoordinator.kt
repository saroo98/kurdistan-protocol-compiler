// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.metadata.CatalogQuarantineReason
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.TransactionState
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.ClientKeyBundleStore
import org.kurdistanvpn.data.secure.ClientKeyStatus
import org.kurdistanvpn.data.secure.KurdRecipientKeyNative
import org.kurdistanvpn.data.secure.ProfileAdmissionJournal
import org.kurdistanvpn.data.secure.RuntimeAuthorityResult
import org.kurdistanvpn.data.secure.SecureBlobReadAccess
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.settings.SettingsProjectionCodec

internal data class LegacyObjectName(val logicalId: String, val role: SecureDataClass) {
    init { require(logicalId.validRecordId() && role.wireValue in 1..13) }
}

/** Only the closed, explicitly admitted legacy reader implements this in production.
 * There is no recovery, key creation, default population, or writable adapter capability. */
internal interface LegacyMigrationReadAccess {
    fun rows(): List<ProfileCatalogEntity>
    fun settingsImage(): ByteArray
    fun objects(): List<LegacyObjectName>
    fun envelope(name: LegacyObjectName): ByteArray
    /** Exact source identities and bytes captured for the current read batch. */
    fun sourceWitness(): ByteArray
}

internal data class ProtectedMigrationResult(val status: ProtectedMutationStatus,
    val disposition: ProtectedStateDisposition? = null)

/**
 * One-way confirmed adoption of v1 bytes. The original directory is never modified or collected.
 * Invalid authenticated relationships are retained in an explicitly non-connectable checkpoint.
 * Unauthenticated bytes cannot be re-encrypted as trusted objects: those leave migration blocked
 * with the original bytes intact. An interrupted migration is never automatically replayed.
 */
internal class ProtectedStateMigrationCoordinator(
    private val storage: JournalStorage,
    private val legacy: LegacyMigrationReadAccess,
    private val writer: (ByteArray) -> ImmutableProtectedObjectWriter,
    private val encryptedObject: (String) -> ByteArray?,
    private val projections: ProtectedProjectionAccess,
    private val codec: SecureEnvelopeCodec,
    private val key: KeyEncryptionKey,
    private val native: KurdNativeCore,
) {
    private val journal = ProtectedStateOperationJournal(storage)
    private val monitor = Any()

    fun migrateConfirmed(): ProtectedMigrationResult = synchronized(monitor) {
        val before = try { journal.readControl() }
        catch (_: Exception) { return@synchronized ProtectedMigrationResult(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        if (before.dirty) return@synchronized ProtectedMigrationResult(ProtectedMutationStatus.DIRTY)
        if (before.revision != 0L) return@synchronized ProtectedMigrationResult(ProtectedMutationStatus.NO_MUTATION)
        val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(SecureRandom()::nextBytes)
        try {
            require(operation.any { it != 0.toByte() })
            val oldControl = before.encode()
            try {
                var plannedDisposition: ProtectedStateDisposition? = null
                val result = journal.mutateAfterReservation(MutationKind.MIGRATION, operation, oldControl) { observed, reservation ->
                    prepareConfirmedMigration(observed, reservation, operation) { plannedDisposition = it }
                }
                ProtectedMigrationResult(result, if (result == ProtectedMutationStatus.COMMITTED) plannedDisposition else null)
            } finally { oldControl.fill(0) }
        } catch (_: Exception) { ProtectedMigrationResult(ProtectedMutationStatus.QUARANTINED) }
        finally { operation.fill(0) }
    }

    /** Source bytes are captured only after [reservation] is durably DIRTY. */
    private fun prepareConfirmedMigration(
        before: JournalControl,
        reservation: JournalControl,
        operation: ByteArray,
        recordDisposition: (ProtectedStateDisposition) -> Unit,
    ): DeferredJournalMutation {
        val source = captureLegacy()
        try {
            val target = reservation.reservedCleanRevision
            val staged = StagedProtectedBlobView(emptyList(), operation, target, encryptedObject, codec, key)
            try {
                for (name in source.names) {
                    val plaintext = source.open(name)
                    try { staged.stage(name.logicalId, name.role, plaintext) } finally { plaintext.fill(0) }
                }
                check(ProtectedStateJournalLifecycle.admission(before, storage.inventory(JournalLimits.OBJECTS),
                    staged.additionalBytes()) == JournalAdmission.ADMIT) { "MIGRATION_CAPACITY_AFTER_RESERVATION" }
                val disposition = source.disposition()
                recordDisposition(disposition)
                val rows = source.committedRows(operation, target, disposition)
                val catalog = ProfileCatalogProjectionCodec.encode(rows)
                val settings = source.settings()
                try {
                    val selected = SettingsProjectionCodec.toModel(settings).profiles.activeLocalRecordId
                    val next = ProtectedStateSnapshot.create(before.storeId(), target, selected, staged.references(),
                        settings, catalog, operation, disposition)
                    val expected = next.encode()
                    try {
                        return DeferredJournalMutation(expected, apply = {
                            staged.persist(writer(operation.clone()))
                            projections.initialize(next)
                        }, reconstruct = {
                            captureLegacy().use { fresh ->
                                check(source.same(fresh)) { "LEGACY_SOURCE_CHANGED_DURING_MIGRATION" }
                                check(fresh.disposition() == disposition)
                                val actual = projections.read()
                                actual.requireMatches(next)
                                val refs = next.objects().map { reference ->
                                    val encrypted = checkNotNull(encryptedObject(reference.physicalId))
                                    try {
                                        check(reference.matches(encrypted))
                                        val role = SecureDataClass.entries.single { it.wireValue == reference.dataClass }
                                        val opened = codec.openForOperation(encrypted, reference.logicalId, role, key, reference.binding)
                                        val original = fresh.open(LegacyObjectName(reference.logicalId, role))
                                        try { check(MessageDigest.isEqual(opened.plaintext, original)) }
                                        finally { opened.plaintext.fill(0); original.fill(0) }
                                        ProtectedObjectReference.fromEncryptedObject(reference.dataClass, reference.logicalId,
                                            reference.physicalId, key.generation, encrypted, reference.binding)
                                    } finally { encrypted.fill(0) }
                                }
                                val reconstructed = ProtectedStateSnapshot.create(before.storeId(), target, selected, refs,
                                    actual.settings(), actual.catalog(), operation, disposition)
                                journal.bindProjection(reconstructed, PhysicalProjectionWitness.capture(reconstructed, actual.physical()))
                                reconstructed.encode()
                            }
                        }, cleanup = {
                            try { staged.close() } finally { source.close() }
                        })
                    } finally { expected.fill(0) }
                } finally { catalog.fill(0); settings.fill(0) }
            } catch (failure: Throwable) {
                staged.close()
                throw failure
            }
        } catch (failure: Throwable) {
            source.close()
            throw failure
        }
    }

    private fun captureLegacy(): LegacyCapture {
        val rows = legacy.rows().toTypedArray().toList()
        require(rows.size <= 1024 && rows.map { it.localRecordId }.toSet().size == rows.size)
        require(rows.all { it.committedRevision == 0L && it.operationId.isEmpty() }) { "LEGACY_FORMAT_MISMATCH" }
        val catalog = ProfileCatalogProjectionCodec.encode(rows)
        val settings = legacy.settingsImage().clone()
        val blobs = LinkedHashMap<LegacyObjectName, ByteArray>()
        try {
            SettingsProjectionCodec.toModel(settings)
            val names = legacy.objects().toTypedArray().toList()
            require(names.size <= JournalLimits.OBJECTS && names.toSet().size == names.size)
            var total = 0L
            for (name in names.sortedWith(compareBy<LegacyObjectName> { it.role.wireValue }.thenBy { it.logicalId })) {
                val raw = legacy.envelope(name)
                try {
                    require(raw.size in 1..JournalLimits.OBJECT_BYTES)
                    total = Math.addExact(total, raw.size.toLong())
                    require(total <= JournalLimits.LIVE_OBJECT_BYTES)
                    val opened = codec.open(raw, name.logicalId, key)
                    try { require(opened.dataClass == name.role && opened.keyGeneration == key.generation) }
                    finally { opened.plaintext.fill(0) }
                    blobs[name] = raw.clone()
                } finally { raw.fill(0) }
            }
            val suppliedWitness = legacy.sourceWitness()
            val witness = suppliedWitness.clone()
            try {
                require(witness.size in 32..JournalLimits.CHECKPOINT_BYTES)
                return LegacyCapture(rows, catalog, settings, blobs, witness)
            } catch (failure: Throwable) {
                witness.fill(0)
                throw failure
            } finally { suppliedWitness.fill(0) }
        } catch (failure: Throwable) {
            catalog.fill(0); settings.fill(0); blobs.values.forEach { it.fill(0) }; throw failure
        }
    }

    private inner class LegacyCapture(
        private val rows: List<ProfileCatalogEntity>, private val catalog: ByteArray,
        private val preferences: ByteArray, private val blobs: Map<LegacyObjectName, ByteArray>, private val witness: ByteArray,
    ) : SecureBlobReadAccess, AutoCloseable {
        val names: List<LegacyObjectName> get() = blobs.keys.toList()
        fun settings(): ByteArray = preferences.clone()
        fun same(other: LegacyCapture): Boolean = MessageDigest.isEqual(catalog, other.catalog) &&
            MessageDigest.isEqual(preferences, other.preferences) && blobs.keys == other.blobs.keys &&
            blobs.all { (name, value) -> MessageDigest.isEqual(value, other.blobs.getValue(name)) } &&
            MessageDigest.isEqual(witness, other.witness)
        fun open(name: LegacyObjectName): ByteArray = reopen(name.logicalId, name.role)
        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
            val encoded = checkNotNull(blobs[LegacyObjectName(localRecordId, dataClass)])
            val opened = codec.open(encoded, localRecordId, key)
            try { check(opened.dataClass == dataClass); return opened.plaintext.clone() }
            finally { opened.plaintext.fill(0) }
        }
        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean =
            blobs.containsKey(LegacyObjectName(localRecordId, dataClass))
        fun disposition(): ProtectedStateDisposition = try {
            check(names.none { it.role == SecureDataClass.RESTORE_BATCH || it.role == SecureDataClass.ACTIVATION_STAGED })
            val model = SettingsProjectionCodec.toModel(preferences)
            check(model.profiles.favoriteLocalRecordIds.all { id -> rows.any { it.localRecordId == id } })
            model.profiles.activeLocalRecordId?.let { id -> check(rows.any { it.localRecordId == id &&
                it.transactionState == TransactionState.FINALIZED.name && it.health == CatalogHealth.AVAILABLE.name }) }
            val catalogView = PreparedCatalog(rows)
            try {
                val admission = ProfileAdmissionJournal.readOnly(native, catalogView, this, false)
                runBlocking {
                    admission.requireCommittedRelationships(names.filter { it.role == SecureDataClass.RECIPIENT_PRIVATE_MATERIAL }
                        .map { it.logicalId }.toSet())
                    // V1 did not bind this status to an authenticated enrollment or restore
                    // operation. Identical valid bytes can describe either an exported request
                    // or an interrupted restore. Preservation is safe; guessing its history is not.
                    val keys = ClientKeyBundleStore.readOnly(this@LegacyCapture, KurdRecipientKeyNative(native))
                    check(keys.list().none { it.status == ClientKeyStatus.AWAITING_PROFILE }) {
                        "LEGACY_AWAITING_ORIGIN_UNPROVEN"
                    }
                    for (row in rows) {
                        when (val result = admission.openRuntimeAuthority(row.localRecordId)) {
                            is RuntimeAuthorityResult.Success -> result.material.close()
                            is RuntimeAuthorityResult.Failure -> error("LEGACY_AUTHORITY_UNPROVEN")
                        }
                    }
                }
            } finally { catalogView.close() }
            ProtectedStateDisposition.VERIFIED
        } catch (_: Exception) { ProtectedStateDisposition.QUARANTINED }
        fun committedRows(operation: ByteArray, revision: Long, disposition: ProtectedStateDisposition): List<ProfileCatalogEntity> {
            val id = operation.joinToString("") { "%02x".format(it) }
            return rows.map { row ->
                if (disposition == ProtectedStateDisposition.VERIFIED) row.stampCommitted(id, revision, CatalogQuarantineReason.NONE)
                else row.copy(transactionState = TransactionState.QUARANTINED.name, health = CatalogHealth.QUARANTINED.name)
                    .stampCommitted(id, revision, CatalogQuarantineReason.INCONSISTENT_STATE)
            }
        }
        override fun close() { catalog.fill(0); preferences.fill(0); blobs.values.forEach { it.fill(0) }; witness.fill(0) }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.SecureBlobAccess
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import org.kurdistanvpn.data.secure.SecureOperationBinding
import java.util.Collections
import org.kurdistanvpn.data.secure.SecureBlobReadAccess
import org.kurdistanvpn.data.secure.SecureRoutingPolicyStore
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.PausePolicy
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.metadata.ProfileCatalogDao
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.TransactionState
import org.kurdistanvpn.data.secure.AdmissionResult
import org.kurdistanvpn.data.secure.BackupPayloadCodec
import org.kurdistanvpn.data.secure.ClientKeyBundleStore
import org.kurdistanvpn.data.secure.ClientKeyResult
import org.kurdistanvpn.data.secure.ClientKeyRestoreResult
import org.kurdistanvpn.data.secure.ClientKeySummary
import org.kurdistanvpn.data.secure.ClientKeyStatus
import org.kurdistanvpn.data.secure.KurdRecipientKeyNative
import org.kurdistanvpn.data.secure.EncryptedDiagnosticEventStore
import org.kurdistanvpn.data.secure.ProfileAdmissionJournal
import org.kurdistanvpn.data.secure.RestoreResult
import org.kurdistanvpn.data.settings.SettingsProjectionCodec
import org.kurdistanvpn.data.settings.ProductSettingsImage
import org.kurdistanvpn.data.secure.ProductSettingsMetadata
import org.kurdistanvpn.data.secure.RuntimeBootstrapRecord
import org.kurdistanvpn.data.secure.SettingsOperationState
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.model.SettingsIdentifiers
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeBootstrapValidator
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.data.settings.*
import org.kurdistanvpn.domain.SettingsEffectiveValues

internal data class BrokerMutation<out T>(val status: ProtectedMutationStatus, val value: T? = null,
    val error: OperationError? = null)
private class MutationRejected(val category: OperationError) : IllegalStateException(category.name)

data class ProductSettingsCommit(val settingsRevision: Long, val effectiveMtu: Int? = null,
    val effectiveReconnectMaximum: Int? = null)

/** borrowedBootstrap must come from this snapshot's authenticated blob view; the caller owns its wipe. */
internal fun readProductSettings(snapshot: ProtectedStateSnapshot, blobs: SecureBlobReadAccess,
    borrowedBootstrap: ByteArray? = null): ProductSettings {
    val bytes = snapshot.settingsBytes()
    return try { readProductSettings(bytes, snapshot.selectedProfile, blobs, borrowedBootstrap) } finally { bytes.fill(0) }
}

internal fun readPresentedProductSettings(snapshot: ProtectedStateSnapshot, blobs: SecureBlobReadAccess,
    read: (String, Int) -> ByteArray?): ProductSettings {
    val base = readProductSettings(snapshot, blobs)
    val image = snapshot.settingsBytes()
    return try {
        if (ProductSettingsImage.isVersionTwo(image)) base
        else ProtectedPresentationOverlay.read(read, snapshot.storeId())?.use { it.merge(base) } ?: base
    } finally { image.fill(0) }
}

private fun readProductSettings(bytes: ByteArray, selected: String?, blobs: SecureBlobReadAccess,
    borrowedBootstrap: ByteArray? = null): ProductSettings {
    if (!ProductSettingsImage.isVersionTwo(bytes)) return validateProductPolicyMirrors(SettingsProjectionCodec.toModel(bytes).also {
        check(it.profiles.activeLocalRecordId == selected)
    }, 0, blobs)
    val image = ProductSettingsImage.decode(bytes)
    val raw = blobs.reopen(ProductSettingsMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA)
    val metadata = try { ProductSettingsMetadata.decode(raw) } finally { raw.fill(0) }
    check(metadata.settingsRevision == image.revision)
    val bootstrapBytes = borrowedBootstrap ?: blobs.reopen(RuntimeBootstrapRecord.RECORD_ID, SecureDataClass.RUNTIME_BOOTSTRAP)
    try {
        val binding = when(bootstrapBytes.getOrNull(4)?.toInt()) {
            1 -> RuntimeBootstrapRecord.decode(bootstrapBytes).let { it.settingsRevision to it.profileId }
            2 -> RuntimeProductionBootstrapRecord.decode(bootstrapBytes).let { it.settingsRevision to it.profileId }
            else -> error("UNKNOWN_BOOTSTRAP_VERSION")
        }
        check(binding.first == image.revision && binding.second == selected)
    } finally { if (borrowedBootstrap == null) bootstrapBytes.fill(0) }
    val partial = image.resolve(metadata.identifiers)
    return validateProductPolicyMirrors(partial.copy(profiles = ProfilePreferences(selected, metadata.favoriteIds),
        routing = partial.routing.copy(packages = SecureRoutingPolicyStore.readOnly(blobs).loadPackages())), image.revision, blobs)
}

/** Immutable non-authority value. Its codec cannot carry routing, credentials or policy fields. */
internal class ProtectedPresentationValues private constructor(
    val theme: org.kurdistanvpn.core.model.ThemePreference, val highContrast: Boolean,
    val reducedMotion: Boolean, private val diagnosticBytes: ByteArray,
) : AutoCloseable {
    fun merge(settings: ProductSettings): ProductSettings = settings.copy(theme = theme,
        highContrast = highContrast, reducedMotion = reducedMotion)
    fun events(): List<DiagnosticEvent> = DiagnosticMemory(diagnosticBytes).use {
        Collections.unmodifiableList(ArrayList(EncryptedDiagnosticEventStore.readOnly(it).load()))
    }
    fun copyOwned(): ProtectedPresentationValues = ProtectedPresentationValues(theme, highContrast, reducedMotion, diagnosticBytes.clone())
    fun withSettings(settings: ProductSettings) = ProtectedPresentationValues(settings.theme,
        settings.highContrast, settings.reducedMotion, diagnosticBytes.clone())
    fun withEvents(events: List<DiagnosticEvent>): ProtectedPresentationValues =
        create(ProductSettings(theme = theme, highContrast = highContrast, reducedMotion = reducedMotion), events)
    fun encode(): ByteArray = java.nio.ByteBuffer.allocate(7 + diagnosticBytes.size).apply {
        put(theme.ordinal.toByte()); put(if (highContrast) 1 else 0); put(if (reducedMotion) 1 else 0)
        putInt(diagnosticBytes.size); put(diagnosticBytes)
    }.array()
    fun same(other: ProtectedPresentationValues): Boolean {
        val left = encode(); val right = other.encode()
        return try { MessageDigest.isEqual(left, right) } finally { left.fill(0); right.fill(0) }
    }
    fun sameAppearance(other: ProtectedPresentationValues): Boolean =
        theme == other.theme && highContrast == other.highContrast && reducedMotion == other.reducedMotion
    fun sameEvents(other: ProtectedPresentationValues): Boolean = MessageDigest.isEqual(diagnosticBytes, other.diagnosticBytes)
    override fun close() { diagnosticBytes.fill(0) }

    companion object {
        const val MAXIMUM = 32700
        const val MAXIMUM_EVENTS = 200
        fun create(settings: ProductSettings, events: List<DiagnosticEvent>): ProtectedPresentationValues {
            require(events.size in 0..MAXIMUM_EVENTS)
            val owned = events.map(DiagnosticEvent::copy)
            return DiagnosticMemory().use {
                EncryptedDiagnosticEventStore(it).save(owned)
                val bytes = it.reopen(DIAGNOSTIC_ID, SecureDataClass.DIAGNOSTIC_EVENTS)
                check(bytes.size <= MAXIMUM - 7)
                ProtectedPresentationValues(settings.theme, settings.highContrast, settings.reducedMotion, bytes)
            }
        }
        fun decode(input: ByteArray): ProtectedPresentationValues {
            val owned = input.clone()
            try {
                require(owned.size in 13..MAXIMUM)
                val reader = java.nio.ByteBuffer.wrap(owned)
                val theme = requireNotNull(org.kurdistanvpn.core.model.ThemePreference.entries.getOrNull(reader.get().toInt() and 255))
                val contrast = reader.get().toInt(); val motion = reader.get().toInt()
                require(contrast in 0..1 && motion in 0..1)
                val size = reader.int
                require(size in 6..MAXIMUM - 7 && size == reader.remaining())
                val bytes = ByteArray(size).also(reader::get)
                try {
                    DiagnosticMemory(bytes).use { EncryptedDiagnosticEventStore.readOnly(it).load() }
                    return ProtectedPresentationValues(theme, contrast == 1, motion == 1, bytes.clone())
                } finally { bytes.fill(0) }
            } finally { owned.fill(0) }
        }
        private const val DIAGNOSTIC_ID = "diagnostic-events-current"
    }

    /** Private, owned encoding scratch space. Never a filesystem/store capability or caller callback. */
    private class DiagnosticMemory(initial: ByteArray? = null) : SecureBlobAccess, AutoCloseable {
        private var bytes = initial?.clone()
        private fun requireIdentity(id: String, role: SecureDataClass) {
            require(id == DIAGNOSTIC_ID && role == SecureDataClass.DIAGNOSTIC_EVENTS)
        }
        override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
            val owned = exactBytes.clone()
            try {
                requireIdentity(localRecordId, dataClass); require(owned.size in 6..MAXIMUM - 7)
                bytes?.fill(0); bytes = owned.clone()
            } finally { owned.fill(0) }
        }
        override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
            requireIdentity(localRecordId, dataClass); return checkNotNull(bytes).clone()
        }
        override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean {
            requireIdentity(localRecordId, dataClass); return bytes != null
        }
        override fun delete(localRecordId: String, dataClass: SecureDataClass) = error("ENCODING_IS_NOT_A_STORE")
        override fun deleteAll() = error("ENCODING_IS_NOT_A_STORE")
        override fun close() { bytes?.fill(0); bytes = null }
    }
}

/** One bounded authenticated maintenance record. Never an S1/authority checkpoint or boot token. */
internal object ProtectedPresentationOverlay {
    const val NAME = "journal-presentation"
    private const val PENDING = 1
    private const val COMMITTED = 2
    private const val APPEARANCE = 1
    private const val DIAGNOSTICS = 2

    /** Read-only status used to decide whether the explicit recovery command may be offered. */
    fun requiresExplicitRecovery(
        read: (String, Int) -> ByteArray?,
        expectedStore: ByteArray,
    ): Boolean {
        val ownedStore = expectedStore.clone()
        val bytes = try {
            read(NAME, JournalLimits.RECORD_BYTES)
        } catch (failure: Throwable) {
            ownedStore.fill(0)
            throw failure
        }
        if (bytes == null) {
            ownedStore.fill(0)
            return false
        }
        return try {
            Record.decode(bytes).use { record ->
                require(MessageDigest.isEqual(ownedStore, record.store))
                record.state == PENDING
            }
        } finally {
            bytes.fill(0)
            ownedStore.fill(0)
        }
    }

    fun read(read: (String, Int) -> ByteArray?, expectedStore: ByteArray): ProtectedPresentationValues? {
        val ownedStore = expectedStore.clone()
        val bytes = try { read(NAME, JournalLimits.RECORD_BYTES) }
            catch (failure: Throwable) { ownedStore.fill(0); throw failure }
        if (bytes == null) { ownedStore.fill(0); return null }
        return try { Record.decode(bytes).use {
            require(MessageDigest.isEqual(ownedStore, it.store))
            (if (it.state == COMMITTED) it.candidate else it.prior).copyOwned()
        } } finally { bytes.fill(0); ownedStore.fill(0) }
    }

    /** Called only while the broker owns JournalStorage.exclusive. No active-session policy access. */
    fun replace(storage: JournalStorage, store: ByteArray, base: ProtectedPresentationValues,
        settings: ProductSettings?, events: List<DiagnosticEvent>?, random: SecureRandom,
        revalidate: () -> Unit): ProtectedMutationStatus {
        require((settings == null) != (events == null))
        val previous = storage.read(NAME, JournalLimits.RECORD_BYTES)
        val priorRecord = previous?.let(Record::decode)
        try {
            if (priorRecord != null) {
                require(MessageDigest.isEqual(store, priorRecord.store))
                if (priorRecord.state != COMMITTED) return ProtectedMutationStatus.MUTATION_UNPROVEN
            }
            val prior = priorRecord?.candidate ?: base
            val next = if (settings != null) prior.withSettings(settings) else prior.withEvents(checkNotNull(events))
            next.use {
                revalidate()
                if (prior.same(next)) return ProtectedMutationStatus.COMMITTED
                val sequence = priorRecord?.sequence ?: 0
                require(sequence < Long.MAX_VALUE)
                val operation = ByteArray(32).also(random::nextBytes)
                try {
                    Record.create(PENDING, store, sequence + 1, operation, if (settings != null) APPEARANCE else DIAGNOSTICS,
                        prior, next).use { pending ->
                        val raw = pending.encode()
                        try {
                            replaceVerified(storage, previous, raw)
                            revalidate()
                            val terminal = pending.committed().use { it.encode() }
                            try { replaceVerified(storage, raw, terminal); revalidate() }
                            finally { terminal.fill(0) }
                        } finally { raw.fill(0) }
                    }
                } finally { operation.fill(0) }
            }
            return ProtectedMutationStatus.COMMITTED
        } finally { priorRecord?.close(); previous?.fill(0) }
    }

    fun recover(storage: JournalStorage, expectedStore: ByteArray, revalidate: () -> Unit): ProtectedMutationStatus {
        val raw = storage.read(NAME, JournalLimits.RECORD_BYTES) ?: return ProtectedMutationStatus.NO_MUTATION
        return try { Record.decode(raw).use { pending ->
            require(MessageDigest.isEqual(expectedStore, pending.store))
            revalidate()
            // A same-value CAS also lets explicit recovery obtain fresh durability/closure evidence
            // after a lost acknowledgement. It does not invent a newer security revision.
            val terminal = pending.committed().use { it.encode() }
            try { replaceVerified(storage, raw, terminal); revalidate(); ProtectedMutationStatus.COMMITTED }
            finally { terminal.fill(0) }
        } } finally { raw.fill(0) }
    }

    private fun replaceVerified(storage: JournalStorage, expected: ByteArray?, replacement: ByteArray) {
        storage.compareAndReplace(NAME, expected, replacement)
        val actual = checkNotNull(storage.read(NAME, JournalLimits.RECORD_BYTES))
        try {
            check(MessageDigest.isEqual(replacement, actual)) { "PRESENTATION_REOPEN_MISMATCH" }
            Record.decode(actual).close()
        } finally { actual.fill(0) }
    }

    private class Record private constructor(val state: Int, val store: ByteArray, val sequence: Long,
        private val operation: ByteArray, private val kind: Int, val prior: ProtectedPresentationValues,
        val candidate: ProtectedPresentationValues) : AutoCloseable {
        fun committed(): Record = create(COMMITTED, store, sequence, operation, kind, prior, candidate)
        fun encode(): ByteArray {
            val a = prior.encode(); val b = candidate.encode()
            return try { java.nio.ByteBuffer.allocate(71 + a.size + b.size).apply {
                putInt(0x4b504d31); put(1); put(state.toByte()); put(store); putLong(sequence); put(operation); put(kind.toByte())
                putInt(a.size); put(a); putInt(b.size); put(b)
            }.array() } finally { a.fill(0); b.fill(0) }
        }
        override fun close() { store.fill(0); operation.fill(0); prior.close(); candidate.close() }
        companion object {
            fun create(state: Int, store: ByteArray, sequence: Long, operation: ByteArray, kind: Int,
                prior: ProtectedPresentationValues, candidate: ProtectedPresentationValues): Record {
                val s = store.clone(); val o = operation.clone()
                try {
                    require(state == PENDING || state == COMMITTED)
                    require(s.size == 16 && s.any { it != 0.toByte() } && sequence > 0)
                    require(o.size == 32 && o.any { it != 0.toByte() })
                    require((kind == APPEARANCE && prior.sameEvents(candidate)) ||
                        (kind == DIAGNOSTICS && prior.sameAppearance(candidate))) { "PRESENTATION_EFFECT_MISMATCH" }
                    return Record(state, s, sequence, o, kind, prior.copyOwned(), candidate.copyOwned())
                } catch (failure: Throwable) { s.fill(0); o.fill(0); throw failure }
            }
            fun decode(input: ByteArray): Record {
                val owned = input.clone()
                try {
                    require(owned.size in 97..JournalLimits.RECORD_BYTES)
                    val reader = java.nio.ByteBuffer.wrap(owned)
                    require(reader.int == 0x4b504d31 && reader.get().toInt() == 1)
                    val state = reader.get().toInt()
                    val store = ByteArray(16).also(reader::get)
                    val sequence = reader.long
                    val operation = ByteArray(32).also(reader::get)
                    val kind = reader.get().toInt()
                    try {
                        fun values(): ProtectedPresentationValues {
                            require(reader.remaining() >= 4)
                            val length = reader.int
                            require(length in 13..ProtectedPresentationValues.MAXIMUM && length <= reader.remaining())
                            val raw = ByteArray(length).also(reader::get)
                            return try { ProtectedPresentationValues.decode(raw) } finally { raw.fill(0) }
                        }
                        return values().use { prior -> values().use { candidate ->
                            require(!reader.hasRemaining())
                            create(state, store, sequence, operation, kind, prior, candidate)
                        } }
                    } finally { store.fill(0); operation.fill(0) }
                } finally { owned.fill(0) }
            }
        }
    }
}

/** Actual observed projection images. No success flag or caller-selected digest is accepted. */
internal class ProjectionImages(catalog: ByteArray, settings: ByteArray, val witness: ProjectionImageWitness?,
    physical: List<ProjectionFileObservation> = emptyList()) {
    private val catalogImage = catalog.clone()
    private val settingsImage = settings.clone()
    private val physicalImages = physical.toTypedArray().toList()
    init { require(catalogImage.size in 1..512 * 1024 && settingsImage.size in 1..64 * 1024) }
    fun catalog(): ByteArray = catalogImage.clone()
    fun settings(): ByteArray = settingsImage.clone()
    fun copyOwned(): ProjectionImages = ProjectionImages(catalogImage, settingsImage, witness, physicalImages)
    fun physical(): List<ProjectionFileObservation> = Collections.unmodifiableList(ArrayList(physicalImages))
    fun sameContent(other: ProjectionImages): Boolean = MessageDigest.isEqual(catalogImage, other.catalogImage) &&
        MessageDigest.isEqual(settingsImage, other.settingsImage)
    fun requireMatches(snapshot: ProtectedStateSnapshot) {
        checkNotNull(witness) { "PROJECTION_WITNESS_MISSING" }.requireMatches(snapshot)
        val catalog = snapshot.catalogBytes(); val settings = snapshot.settingsBytes()
        try { check(MessageDigest.isEqual(catalogImage, catalog) && MessageDigest.isEqual(settingsImage, settings)) }
        finally { catalog.fill(0); settings.fill(0) }
    }
}

/** Only the default-process composition root owns this writer. Restoration never receives it. */
internal interface ProtectedProjectionReadAccess {
    fun read(): ProjectionImages
    /** Caller supplies a freshly authenticated checkpoint, never cached across observations. */
    fun readForCheckpoint(snapshot: ProtectedStateSnapshot): ProjectionImages = read()
}

internal interface ProtectedProjectionAccess : ProtectedProjectionReadAccess {
    fun migrateSchema(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot, replacement: ProtectedStateSnapshot,
        verifyEvidence: () -> Unit) { error("SCHEMA_MIGRATION_UNSUPPORTED") }
    fun requireClosedSchema(expected: ProtectedStateSnapshot, version: Int) {
        val observed = read()
        observed.requireMatches(expected)
        check(observed.physical().isEmpty() && version == 3) { "CLOSED_SCHEMA_INSPECTION_UNSUPPORTED" }
    }
    fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot)
    fun recover(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot, replacement: ProtectedStateSnapshot) {
        throw IllegalStateException("TYPED_PROJECTION_RECOVERY_UNAVAILABLE")
    }
    fun initialize(replacement: ProtectedStateSnapshot) { throw IllegalStateException("PROJECTION_INITIALIZATION_UNAVAILABLE") }
}

/**
 * Closed transaction executor. Public application callers receive typed domain operations, not
 * its storage, mutable view, projection writer, arbitrary callbacks, receipts or operation IDs.
 * Class visibility is an accidental-bypass control, not a sandbox against same-UID code.
 */
internal class ProtectedStateMutationBroker private constructor(
    private val storage: JournalStorage,
    private val readEncrypted: (String) -> ByteArray?,
    private val objectWriter: (ByteArray) -> ImmutableProtectedObjectWriter,
    private val codec: SecureEnvelopeCodec,
    private val key: KeyEncryptionKey,
    private val projections: ProtectedProjectionAccess,
    private val native: KurdNativeCore,
    private val sessions: ActiveSessionMutationPolicy,
    private val garbageObjects: JournalObjectAccess,
) {
    private val journal = ProtectedStateOperationJournal(storage)
    private val random = SecureRandom()

    fun replaceRouting(packages: Set<String>): ProtectedMutationStatus {
        val owned = packages.toTypedArray().toSet()
        try {
            val current = readCurrent(); val bytes = current.settingsBytes()
            try { if (ProductSettingsImage.isVersionTwo(bytes)) {
                val requested = readProductSettings(current, ReadOnlyProtectedBlobView(current.objects(), readEncrypted, codec, key))
                return applyProductSettings(current.revision, ProductSettingsImage.decode(bytes).revision,
                    requested.copy(routing = requested.routing.copy(packages = owned))).status
            } } finally { bytes.fill(0) }
        } catch (_: Exception) { return ProtectedMutationStatus.MUTATION_UNPROVEN }
        return mutate(MutationKind.ROUTING) { state -> SecureRoutingPolicyStore(state.view).savePackages(owned) }.status
    }

    fun createEnrollment(validitySeconds: Int, nowEpochSeconds: Long): BrokerMutation<ClientKeySummary> =
        mutate(MutationKind.ENROLLMENT_CREATE) { state ->
            when (val result = state.keys.create(validitySeconds, nowEpochSeconds)) {
                is ClientKeyResult.Success -> result.summary
                is ClientKeyResult.Failure -> throw MutationRejected(result.error)
            }
        }

    fun markEnrollmentExported(id: String): BrokerMutation<Unit> = mutate(MutationKind.ENROLLMENT_EXPORT) {
        require(id.validRecordId()); it.keys.markRequestExported(id)
    }

    fun deleteCredential(id: String): BrokerMutation<Unit> = mutate(MutationKind.CREDENTIAL_DELETE) {
        require(id.validRecordId())
        if (!it.keys.delete(id)) throw MutationRejected(OperationError.POLICY_REJECTED)
    }

    /** Explicit pending-enrollment reset, not profile reset or implicit recovery. The common
     * mutation path validates the entire committed index/material/profile relationship before
     * this read-only selection. All deletions are staged together before durable DIRTY and
     * prior-session retirement; no old encrypted object is eagerly deleted. */
    fun resetPendingCredentials(expectedRevision: Long? = null): BrokerMutation<Int> = mutate(MutationKind.CREDENTIAL_DELETE, expectedRevision) { state ->
        val pending = state.keys.list().filter {
            it.status == ClientKeyStatus.REQUEST_READY || it.status == ClientKeyStatus.AWAITING_PROFILE
        }
        if (pending.any { it.boundProfileCount != 0 }) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        for (entry in pending) if (!state.keys.delete(entry.localRecordId))
            throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        pending.size
    }

    fun deleteProfile(id: String, expectedRevision: Long? = null): BrokerMutation<Unit> = mutateProfileSettings(MutationKind.PROFILE_DELETE, expectedRevision) { state ->
        require(id.validRecordId())
        if (!runBlocking { state.admission.delete(id) }) throw MutationRejected(OperationError.POLICY_REJECTED)
        state.removeProfilePreferences(setOf(id))
    }

    fun resetProfiles(ids: Set<String>, expectedRevision: Long? = null): BrokerMutation<Unit> {
        val owned = ids.toTypedArray().toSet()
        require(owned.isNotEmpty() && owned.size <= 1024 && owned.all { it.validRecordId() })
        return mutateProfileSettings(MutationKind.SCOPED_RESET, expectedRevision) { state ->
            val exclusiveKeys = state.keys.keysExclusivelyBoundTo(owned)
            for (id in owned) if (!runBlocking { state.admission.delete(id) }) throw MutationRejected(OperationError.POLICY_REJECTED)
            for (id in exclusiveKeys) if (!state.keys.delete(id)) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
            state.removeProfilePreferences(owned)
        }
    }

    private fun <T> mutateProfileSettings(kind: MutationKind, expectedRevision: Long? = null,
        interpret: (PreparedDomainState) -> T): BrokerMutation<T> = try {
        val current = readCurrent(); val bytes = current.settingsBytes()
        try {
            if (expectedRevision != null && current.revision != expectedRevision)
                BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
            else mutate(kind, current.revision, settingsTransaction = ProductSettingsImage.isVersionTwo(bytes), interpret = interpret)
        }
        finally { bytes.fill(0) }
    } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }

    /** Complete product command; the journal revision and semantic settings revision are distinct. */
    fun settingsPort(): SettingsMutationPort = object : SettingsMutationPort {
        override suspend fun read() = settingsResult { settingsState(readCurrent()) }
        override suspend fun validate(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings) = settingsResult {
            val before = readCurrent()
            check(before.revision == expectedJournal && settingsState(before).appliedRevision == expectedApplied)
            val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(random::nextBytes)
            try {
                StagedProtectedBlobView(before.objects(), operation, before.revision + 2, readEncrypted, codec, key).use { view ->
                    PreparedDomainState(before, view, native).use { state ->
                        val result = state.applyProductSettings(expectedApplied, requested)
                        state.validate()
                        check(readCurrent().revision == expectedJournal)
                        SettingsEffectiveValues(result.effectiveMtu, result.effectiveReconnectMaximum)
                    }
                }
            } finally { operation.fill(0) }
        }
        override suspend fun apply(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings) = settingsResult {
            val result = applyProductSettings(expectedJournal, expectedApplied, requested, requireInactive = true)
            if (result.status != ProtectedMutationStatus.COMMITTED) throw MutationRejected(result.error ?: OperationError.RECOVERY_REQUIRED)
            val commit = checkNotNull(result.value)
            // The broker already independently reopened this exact committed snapshot. Do not
            // erase its terminal outcome by starting another fallible native validation here.
            SettingsStoreState(expectedJournal + 2, commit.settingsRevision, requested,
                SettingsEffectiveValues(commit.effectiveMtu, commit.effectiveReconnectMaximum))
        }
        override suspend fun rollback(expectedJournal: Long) = settingsResult {
            val result = rollbackLastProductSettings(expectedJournal, requireInactive = true)
            check(result.status == ProtectedMutationStatus.COMMITTED)
            settingsState(readCurrent()).also {
                check(it.journalRevision == expectedJournal + 2 && it.appliedRevision == result.value?.settingsRevision)
            }
        }
    }

    /** No active reconnect adapter is installed here. Admission is rechecked atomically by apply. */
    fun inactiveRuntimePort(): SettingsRuntimePort = object : SettingsRuntimePort {
        override suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent> =
            if (sessions.inactive()) SettingsPortResult.Success(SettingsRuntimeIntent.ALREADY_STOPPED)
            else SettingsPortResult.Rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> =
            if (intent == SettingsRuntimeIntent.ALREADY_STOPPED) SettingsPortResult.Success(Unit)
            else SettingsPortResult.Rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
    }

    private fun settingsState(snapshot: ProtectedStateSnapshot): SettingsStoreState {
        val bytes = snapshot.settingsBytes()
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key)
        try {
            if (ProductSettingsImage.isVersionTwo(bytes)) {
                val effective = freshSettingsProof(snapshot)
                check(readCurrent().revision == snapshot.revision)
                return SettingsStoreState(snapshot.revision, ProductSettingsImage.decode(bytes).revision,
                    readProductSettings(snapshot, blobs), SettingsEffectiveValues(effective.effectiveMtu, effective.effectiveReconnectMaximum))
            }
            val legacy = SettingsMigration.planLegacyImage(bytes, snapshot.selectedProfile,
                SecureRoutingPolicyStore.readOnly(blobs).loadPackages(), true)
            if (legacy !is SettingsMigration.Ready) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
            val requested = ProtectedPresentationOverlay.read(storage::read, snapshot.storeId())?.use { it.merge(legacy.requested) }
                ?: legacy.requested
            return SettingsStoreState(snapshot.revision, 0, requested)
        } finally { bytes.fill(0) }
    }

    private fun freshSettingsProof(snapshot: ProtectedStateSnapshot): ProductSettingsCommit {
        val operation = snapshot.operationId()
        try { return StagedProtectedBlobView(snapshot.objects(), operation, snapshot.revision + 2, readEncrypted, codec, key).use { view ->
            PreparedDomainState(snapshot, view, native).use { it.restoreProductSettings(snapshot) }
        } } finally { operation.fill(0) }
    }

    private fun <T> settingsResult(action: () -> T): SettingsPortResult<T> = try { SettingsPortResult.Success(action()) }
    catch (failure: MutationRejected) { SettingsPortResult.Rejected(if (failure.category == OperationError.RECOVERY_REQUIRED)
        ProductFailureCode.MIGRATION_REQUIRED else ProductFailureCode.PROFILE_INCOMPATIBLE) }
    catch (_: IllegalArgumentException) { SettingsPortResult.Rejected(ProductFailureCode.INVALID_INPUT) }
    catch (_: Exception) { SettingsPortResult.Rejected(ProductFailureCode.STORAGE_DEGRADED) }

    fun applyProductSettings(expectedRevision: Long, expectedSettingsRevision: Long,
        requested: ProductSettings, requireInactive: Boolean = false): BrokerMutation<ProductSettingsCommit> =
        mutate(MutationKind.SETTINGS, expectedRevision, settingsTransaction = true, requireInactive = requireInactive) { state ->
            state.applyProductSettings(expectedSettingsRevision, requested)
        }

    fun applyProductionSettings(expectedRevision: Long, expectedSettingsRevision: Long,
        requested: ProductSettings, requireInactive: Boolean = false): BrokerMutation<ProductSettingsCommit> =
        mutate(MutationKind.SETTINGS, expectedRevision, settingsTransaction = true, requireInactive = requireInactive) { state ->
            state.applyProductionSettings(expectedSettingsRevision, requested)
        }

    fun applyPause(expectedRevision: Long, expectedSettingsRevision: Long, timer: StoredPauseState?): BrokerMutation<ProductSettingsCommit> =
        mutate(MutationKind.SETTINGS, expectedRevision, settingsTransaction = true, requireInactive = true) {
            it.applyPause(expectedSettingsRevision, timer)
        }

    internal fun applyProductStoreCommand(expectedRevision: Long, command: ProductStoreCommand): BrokerMutation<Unit> =
        mutate(MutationKind.PRODUCT_STATE, expectedRevision, requireInactive = true, productCommand = command) {
            it.applyProductCommand(command)
            Unit
        }

    internal fun migrateProductProjectionConfirmed(expectedRevision: Long): BrokerMutation<Unit> =
        mutate(MutationKind.PROJECTION_SCHEMA, expectedRevision, requireInactive = true, schemaMigration = true) { Unit }

    internal fun recoverProductSchemaConfirmed(rollback: Boolean): BrokerMutation<Unit> = recoverProductOperation(rollback, true)
    internal fun recoverProductOperationConfirmed(rollback: Boolean): BrokerMutation<Unit> = recoverProductOperation(rollback, false)
    private fun recoverProductOperation(rollback: Boolean, schema: Boolean): BrokerMutation<Unit> =
        sessions.reserveMutation(true)?.use { reservation ->
            try {
                val control = journal.readControl()
                if (!control.dirty) {
                    val current = readCurrent()
                    journal.requireLatestCompletedProduct(current.operationId(), rollback, schema)
                    return@use BrokerMutation(ProtectedMutationStatus.COMMITTED, Unit)
                }
                val kind = if (schema) MutationKind.PROJECTION_SCHEMA else MutationKind.PRODUCT_STATE
                check(control.kind == kind)
                val operation = control.operationId()
                val encrypted = checkNotNull(readEncrypted(operationObjectLeaf(operation, 1)))
                val opened = try { codec.openForOperation(encrypted, ProductOperationState.RECORD_ID,
                    SecureDataClass.OPERATION_STATE, key, SecureOperationBinding(operation, control.reservedCleanRevision)) }
                finally { encrypted.fill(0) }
                try { ProductOperationState.decode(opened.plaintext).use { record ->
                    check(record.internalMutationKind == kind.wire &&
                        record.matches(operation, control.checkpointRevision, control.reservedCleanRevision))
                    val priorBytes = record.priorSnapshot(); val candidateBytes = record.candidateSnapshot()
                    val authenticatedPrior = journal.readPriorCheckpointForExplicitRecovery()
                    try {
                        check(MessageDigest.isEqual(priorBytes, authenticatedPrior))
                        journal.requireProductRecoveryCandidate(operation, candidateBytes, schema)
                        val prior = ProtectedStateSnapshot.decode(priorBytes)
                        val candidate = ProtectedStateSnapshot.decode(candidateBytes)
                        check(prior.revision == record.journalRevisionBefore && candidate.revision == record.journalRevisionAfter &&
                            candidate.operationId().contentEquals(operation) && prior.storeId().contentEquals(candidate.storeId()))
                        check(productSettingsRevision(prior) == record.settingsRevisionBefore &&
                            productSettingsRevision(candidate) == record.settingsRevisionAfter)
                        check(prior.selectedProfile == candidate.selectedProfile)
                        val a = prior.settingsBytes(); val b = candidate.settingsBytes()
                        try { check(MessageDigest.isEqual(a, b)) } finally { a.fill(0); b.fill(0) }
                        val authorityRoles = (1..13).toSet() + setOf(26)
                        fun authority(snapshot: ProtectedStateSnapshot) = snapshot.objects().filter { it.dataClass in authorityRoles }
                            .associate { (it.dataClass to it.logicalId) to it.physicalId }
                        check(authority(prior) == authority(candidate))
                        if (schema) {
                            check(record.displayKind == null && record.scopeRecordId == null)
                            val exact = ProductProjectionSchemaMigration.candidate(prior, candidate.revision, operation).encode()
                            try { check(MessageDigest.isEqual(exact, candidateBytes)) } finally { exact.fill(0) }
                        } else validateProductOperationTransition(record, prior, candidate)
                        validateRelationships(prior); validateRelationships(candidate)
                        val next = if (!rollback) candidate else if (schema) ProductProjectionSchemaMigration.candidate(prior, candidate.revision, operation) else {
                            val catalog = prior.catalogBytes(); val settings = prior.settingsBytes()
                            try {
                                val rows = encodeProductCatalog(ProfileCatalogProjectionCodec.decode(catalog).map {
                                    it.stampCommitted(operation.joinToString("") { byte -> "%02x".format(byte) },
                                        control.reservedCleanRevision, org.kurdistanvpn.data.metadata.CatalogQuarantineReason.NONE)
                                }, productOperationDescriptor(operation, record.displayKind, record.scopeRecordId,
                                    record.attempt, record.startedEpochHour, record.settingsRevisionBefore, record.settingsRevisionAfter, true))
                                try { ProtectedStateSnapshot.create(prior.storeId(), control.reservedCleanRevision,
                                    prior.selectedProfile, prior.objects(), settings, rows, operation) } finally { rows.fill(0) }
                            } finally { catalog.fill(0); settings.fill(0) }
                        }
                        validateRelationships(next)
                        if (productSettingsRevision(next) > 0 || next.selectedProfile != null) freshSettingsProof(next)
                        val expected = next.encode()
                        var schemaRejected = false
                        try {
                            val outcome = journal.recover(operation, expected, recovery = {
                                reservation.retirePriorOwners(); reservation.requireCurrent()
                                if (schema) try { projections.migrateSchema(prior, candidate, next) { requireSchemaEvidence(prior, candidate) } }
                                catch (failure: ProjectionSchemaRejected) {
                                    schemaRejected = failure.suppressed.isEmpty()
                                    throw failure
                                }
                                else projections.recover(prior, candidate, next)
                                reservation.requireCurrent()
                            }, reconstruct = { reservation.requireCurrent(); independentlyReconstruct(next).encode() },
                                resolution = if (rollback) RecoveryResolution.ROLLBACK else RecoveryResolution.RESUME)
                            val classified = if (schemaRejected && outcome == ProtectedMutationStatus.DIRTY) ProtectedMutationStatus.QUARANTINED else outcome
                            BrokerMutation(classified, if (classified == ProtectedMutationStatus.COMMITTED) Unit else null)
                        } finally { expected.fill(0) }
                    } finally { priorBytes.fill(0); candidateBytes.fill(0); authenticatedPrior.fill(0) }
                } } finally { opened.plaintext.fill(0); operation.fill(0) }
            } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN, error = OperationError.RECOVERY_REQUIRED) }
        } ?: BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)

    fun rollbackLastProductSettings(expectedRevision: Long, requireInactive: Boolean = false): BrokerMutation<ProductSettingsCommit> {
        return try {
            val current = readCurrent()
            if (current.revision != expectedRevision) return BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
            val operation = current.operationId()
            val encrypted = checkNotNull(readEncrypted(operationObjectLeaf(operation, 1)))
            val opened = try { codec.openForOperation(encrypted, SettingsOperationState.RECORD_ID, SecureDataClass.OPERATION_STATE,
                key, SecureOperationBinding(operation, current.revision)) } finally { encrypted.fill(0) }
            try { SettingsOperationState.decode(opened.plaintext).use { record ->
                check(record.matches(operation, current.revision - 2, current.revision))
                val actual = current.encode(); val candidate = record.candidateSnapshot()
                val prior = record.priorSnapshot(); val authenticatedPrior = journal.readPriorCheckpointForCompletedSettingsRollback(operation)
                try {
                    check(MessageDigest.isEqual(actual, candidate) && MessageDigest.isEqual(prior, authenticatedPrior))
                    val previous = ProtectedStateSnapshot.decode(prior)
                    mutate(MutationKind.SETTINGS, expectedRevision, settingsTransaction = true, requireInactive = requireInactive) { it.restoreProductSettings(previous) }
                } finally { actual.fill(0); candidate.fill(0); prior.fill(0); authenticatedPrior.fill(0) }
            } } finally { opened.plaintext.fill(0); operation.fill(0) }
        } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
    }

    fun recoverProductSettingsConfirmed(rollback: Boolean): BrokerMutation<ProductSettingsCommit> =
        sessions.reserveMutation()?.use { reservation ->
            try {
                val control = journal.readControl()
                check(control.dirty && control.kind in setOf(MutationKind.SETTINGS, MutationKind.PROFILE_DELETE, MutationKind.SCOPED_RESET))
                val operation = control.operationId()
                val encrypted = checkNotNull(readEncrypted(operationObjectLeaf(operation, 1)))
                val opened = try { codec.openForOperation(encrypted, SettingsOperationState.RECORD_ID,
                    SecureDataClass.OPERATION_STATE, key, SecureOperationBinding(operation, control.reservedCleanRevision)) }
                finally { encrypted.fill(0) }
                try { SettingsOperationState.decode(opened.plaintext).use { record ->
                    check(record.matches(operation, control.checkpointRevision, control.reservedCleanRevision))
                    val recordedPrior = record.priorSnapshot(); val recordedCandidate = record.candidateSnapshot()
                    val actualPrior = journal.readPriorCheckpointForExplicitRecovery()
                    try {
                        check(MessageDigest.isEqual(actualPrior, recordedPrior))
                        journal.requireSettingsRecoveryCandidate(operation, recordedCandidate)
                        val prior = ProtectedStateSnapshot.decode(recordedPrior)
                        val candidate = ProtectedStateSnapshot.decode(recordedCandidate)
                        check(candidate.revision == control.reservedCleanRevision && candidate.operationId().contentEquals(operation) &&
                            prior.storeId().contentEquals(candidate.storeId()))
                        fun settingsRevision(snapshot: ProtectedStateSnapshot): Long {
                            val bytes = snapshot.settingsBytes()
                            return try { if (ProductSettingsImage.isVersionTwo(bytes)) ProductSettingsImage.decode(bytes).revision else 0 }
                            finally { bytes.fill(0) }
                        }
                        check(settingsRevision(prior) == record.settingsBefore && settingsRevision(candidate) == record.settingsAfter)
                        val next = if (!rollback) candidate else {
                            val catalog = prior.catalogBytes(); val settings = prior.settingsBytes()
                            try {
                                val rows = ProfileCatalogProjectionCodec.encode(ProfileCatalogProjectionCodec.decode(catalog).map {
                                    it.stampCommitted(operation.joinToString("") { byte -> "%02x".format(byte) },
                                        control.reservedCleanRevision, org.kurdistanvpn.data.metadata.CatalogQuarantineReason.NONE)
                                })
                                try { ProtectedStateSnapshot.create(prior.storeId(), control.reservedCleanRevision,
                                    prior.selectedProfile, prior.objects(), settings, rows, operation) } finally { rows.fill(0) }
                            } finally { catalog.fill(0); settings.fill(0) }
                        }
                        validateRelationships(next)
                        // Recovery reproduces native proof before any projection publication. The
                        // temporary view never persists or replaces the authenticated references.
                        freshSettingsProof(next)
                        val expected = next.encode()
                        val outcome = try { journal.recover(operation, expected, recovery = {
                            reservation.retirePriorOwners(); reservation.requireCurrent()
                            projections.recover(prior, candidate, next)
                            reservation.requireCurrent()
                        }, reconstruct = {
                            reservation.requireCurrent(); independentlyReconstruct(next).encode()
                        }, resolution = if (rollback) RecoveryResolution.ROLLBACK else RecoveryResolution.RESUME) }
                        finally { expected.fill(0) }
                        BrokerMutation(outcome, if (outcome == ProtectedMutationStatus.COMMITTED)
                            ProductSettingsCommit(if (rollback) record.settingsBefore else record.settingsAfter) else null)
                    } finally { recordedPrior.fill(0); recordedCandidate.fill(0); actualPrior.fill(0) }
                } } finally { opened.plaintext.fill(0); operation.fill(0) }
            } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        } ?: BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)

    fun replaceSettings(expectedRevision: Long, value: ProductSettings,
        residuePolicy: org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy = org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.PRESERVE,
    ): BrokerMutation<Unit> {
        try {
            val bytes = readCurrent().settingsBytes()
            try { if (ProductSettingsImage.isVersionTwo(bytes)) {
                val result = mutate(MutationKind.SETTINGS, expectedRevision, settingsTransaction = true) {
                    it.applyProductSettings(ProductSettingsImage.decode(bytes).revision, value, allowSelectionChange = true)
                }
                return BrokerMutation(result.status, if (result.status == ProtectedMutationStatus.COMMITTED) Unit else null, result.error)
            } } finally { bytes.fill(0) }
        } catch (_: Exception) { return BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        val owned = try { SettingsProjectionCodec.fromModel(value) }
        catch (_: IllegalArgumentException) { return BrokerMutation(ProtectedMutationStatus.NO_MUTATION,
            error = OperationError.INVALID_INPUT) }
        return try {
            val normalized = SettingsProjectionCodec.toModel(owned)
            val before = readCurrent()
            if (before.revision != expectedRevision) return BrokerMutation(ProtectedMutationStatus.NO_MUTATION,
                error = OperationError.RECOVERY_REQUIRED)
            val currentBytes = before.settingsBytes()
            val residue = try { SettingsProjectionCodec.legacyResidue(currentBytes) }
                catch (failure: Throwable) { currentBytes.fill(0); throw failure }
            val current = try { SettingsProjectionCodec.toModel(currentBytes) } finally { currentBytes.fill(0) }
            val nextResidue = if (residuePolicy == org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.PRESERVE) residue else null
            // The allowlist is deliberately only visual state. Privacy, probe/update policy,
            // selection, routing and every other settings field stay security mutations.
            val securityOnly = normalized.copy(theme = current.theme, highContrast = current.highContrast,
                reducedMotion = current.reducedMotion)
            val securityBytes = SettingsProjectionCodec.fromModel(securityOnly, nextResidue)
            val oldBytes = SettingsProjectionCodec.fromModel(current, residue)
            val presentationOnly = try { MessageDigest.isEqual(securityBytes, oldBytes) }
            finally { securityBytes.fill(0); oldBytes.fill(0) }
            if (presentationOnly) mutatePresentation(expectedRevision, normalized, null)
            else {
                val replacement = SettingsProjectionCodec.fromModel(normalized, nextResidue)
                val result = try { mutate(MutationKind.SETTINGS, expectedRevision) { it.replaceSettings(replacement) } }
                    finally { replacement.fill(0) }
                // Mixed explicit settings reset may also change visual preferences. Only report
                // complete success after both independent, typed updates are durably observed.
                if (result.status != ProtectedMutationStatus.COMMITTED) result
                else mutatePresentation(null, normalized, null)
            }
        } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        finally { owned.fill(0) }
    }

    fun recordUpdatePresentation(expectedRevision: Long, profileId: String, value: StoredUpdateState): BrokerMutation<Unit> =
        recordMaintenancePresentation(expectedRevision, profileId) { snapshot, revision ->
            UpdateStateStore.readOnly(ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key)).load(profileId)?.let { old ->
                old.publicationGeneration?.let { prior -> require(value.publicationGeneration?.let { it >= prior } == true) }
                old.profileGeneration?.let { prior -> require(value.profileGeneration?.let { it >= prior } == true) }
            }
            ProtectedProbeHistoryStore(storage).writeUpdate(org.kurdistanvpn.core.model.CatalogId(profileId), revision, value)
        }

    fun recordProbePresentation(expectedRevision: Long, profileId: String, value: StoredProbeHistory): BrokerMutation<Unit> =
        recordMaintenancePresentation(expectedRevision, profileId) { _, revision ->
            ProtectedProbeHistoryStore(storage).write(org.kurdistanvpn.core.model.CatalogId(profileId), revision, value)
        }

    private fun recordMaintenancePresentation(expectedRevision: Long, profileId: String,
        write: (ProtectedStateSnapshot, Long) -> Unit): BrokerMutation<Unit> = try {
        storage.exclusive {
            val snapshot = readCurrent()
            if (snapshot.revision != expectedRevision)
                return@exclusive BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
            val activation = snapshot.objectFor(profileId, SecureDataClass.ACTIVATION_ACTIVE.wireValue)
                ?: return@exclusive BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.INVALID_INPUT)
            write(snapshot, activation.binding.revision)
            BrokerMutation(ProtectedMutationStatus.COMMITTED, Unit)
        }
    } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }

    fun replaceDiagnostics(events: List<DiagnosticEvent>): BrokerMutation<Unit> {
        val owned = try {
            val claimedSize = events.size
            require(claimedSize in 0..ProtectedPresentationValues.MAXIMUM_EVENTS)
            val result = ArrayList<DiagnosticEvent>(claimedSize)
            val iterator = events.iterator()
            while (iterator.hasNext()) {
                require(result.size < ProtectedPresentationValues.MAXIMUM_EVENTS)
                result += iterator.next().copy()
            }
            require(result.size == claimedSize)
            Collections.unmodifiableList(result)
        } catch (_: RuntimeException) {
            return BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.INVALID_INPUT)
        }
        try { ProtectedPresentationValues.create(ProductSettings(), owned).close() }
        catch (_: IllegalArgumentException) { return BrokerMutation(ProtectedMutationStatus.NO_MUTATION,
            error = OperationError.INVALID_INPUT) }
        return mutatePresentation(null, null, owned)
    }

    /** Explicit recovery only; normal reads and automatic diagnostic writes never resolve PENDING. */
    fun recoverPresentationConfirmed(): BrokerMutation<Unit> = try {
        storage.exclusive {
            val snapshot = readCurrent()
            val before = journal.readControl().encode()
            try {
                val outcome = ProtectedPresentationOverlay.recover(storage, snapshot.storeId()) {
                    check(MessageDigest.isEqual(before, journal.readControl().encode()))
                }
                BrokerMutation(outcome, if (outcome == ProtectedMutationStatus.COMMITTED) Unit else null)
            } finally { before.fill(0) }
        }
    } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }

    private fun mutatePresentation(expectedRevision: Long?, settings: ProductSettings?,
        events: List<DiagnosticEvent>?): BrokerMutation<Unit> = try {
        // Same exclusive native directory lease as security mutations, but no runtime retirement,
        // DIRTY security reservation, projection update, authority object or S1 publication.
        storage.exclusive {
            val snapshot = readCurrent()
            if (expectedRevision != null && snapshot.revision != expectedRevision)
                return@exclusive BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
            val before = journal.readControl().encode()
            val bytes = snapshot.settingsBytes()
            try {
                val baseSettings = readProductSettings(snapshot, ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key))
                val baseEvents = EncryptedDiagnosticEventStore.readOnly(ReadOnlyProtectedBlobView(snapshot.objects(),
                    readEncrypted, codec, key)).load()
                ProtectedPresentationValues.create(baseSettings, baseEvents).use { base ->
                    val outcome = ProtectedPresentationOverlay.replace(storage, snapshot.storeId(), base, settings, events, random) {
                        check(MessageDigest.isEqual(before, journal.readControl().encode()))
                        projections.read().requireMatches(snapshot)
                    }
                    BrokerMutation(outcome, if (outcome == ProtectedMutationStatus.COMMITTED) Unit else null)
                }
            } finally { before.fill(0); bytes.fill(0) }
        }
    } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }

    fun importProfile(confirmation: ConfirmedProtectedImport): BrokerMutation<String> {
        val store = confirmation.storeId()
        val owned = try { confirmation.takeRequest() }
        catch (_: IllegalStateException) {
            store.fill(0)
            return BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
        }
        val preview = confirmation.display
        val recipientId = confirmation.recipientKeyId
        return try {
            require(owned.size in 1..1024 * 1024 && (recipientId == null || recipientId.validRecordId()))
            mutate(MutationKind.PROFILE_IMPORT, confirmation.revision, store) { state ->
                when (val result = runBlocking { state.admission.admit(owned, preview, recipientId) }) {
                    is AdmissionResult.Success -> result.outcome.localRecordId
                    is AdmissionResult.Failure -> throw MutationRejected(result.error)
                }
            }
        } finally { owned.fill(0); store.fill(0); confirmation.close() }
    }

    fun restoreBackup(payload: ByteArray): BrokerMutation<Int> {
        val owned = payload.clone()
        return try {
            require(owned.size in 6..8 * 1024 * 1024)
            mutate(MutationKind.RESTORE) { state ->
                val decoded = BackupPayloadCodec.decodePayload(owned)
                try {
                    when (val keys = state.keys.restore(decoded.clientKeys)) {
                        is ClientKeyRestoreResult.Failure -> throw MutationRejected(keys.error)
                        is ClientKeyRestoreResult.Success -> Unit
                    }
                    when (val profiles = runBlocking { state.admission.restore(decoded.profiles) }) {
                        is RestoreResult.Failure -> throw MutationRejected(profiles.error)
                        is RestoreResult.Success -> profiles.restoredProfiles
                    }
                } finally {
                    decoded.profiles.forEach { it.verifyRequest.fill(0) }
                    decoded.clientKeys.forEach { it.destroy() }
                }
            }
        } finally { owned.fill(0) }
    }

    /** All interpretation is private. No caller-supplied mutation or reconstruction function escapes. */
    private fun <T> mutate(kind: MutationKind, expectedRevision: Long? = null, expectedStore: ByteArray? = null,
        settingsTransaction: Boolean = false, requireInactive: Boolean = false, productCommand: ProductStoreCommand? = null,
        schemaMigration: Boolean = false,
        interpret: (PreparedDomainState) -> T): BrokerMutation<T> = sessions.reserveMutation(requireInactive)?.use { reservation ->
        run mutation@ {
        val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(random::nextBytes)
        if (operation.all { it == 0.toByte() }) return@mutation BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)
        try {
            var before = readCurrent()
            if ((expectedRevision != null && before.revision != expectedRevision) ||
                (expectedStore != null && !MessageDigest.isEqual(before.storeId(), expectedStore)))
                return@mutation BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
            try { storage.exclusive { requireCleanSchema(before, if (schemaMigration) 2 else 3) } }
            catch (_: Exception) { return@mutation BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED) }
            if (productCommand != null) {
                StagedProtectedBlobView(before.objects(), operation, before.revision + 2, readEncrypted, codec, key,
                    reserveSettingsOperation = true).use { view ->
                    PreparedDomainState(before, view, native).use { state ->
                        val changed = state.applyProductCommand(productCommand)
                        state.validate()
                        if (!changed) return@mutation BrokerMutation(ProtectedMutationStatus.NO_MUTATION)
                    }
                }
            }
            val collector = ProtectedStateGarbageCollector(storage, journal, garbageObjects)
            if (collector.resume(emptySet(), emptySet(), emptySet()) != GarbageResult.COMPLETE)
                return@mutation BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)
            val capacity = ProtectedStateJournalLifecycle.admission(journal.readControl(), storage.inventory(JournalLimits.OBJECTS), 0)
            if (capacity == JournalAdmission.COMPACT_FIRST) {
                if (journal.compact { readCurrent().encode() } != ProtectedMutationStatus.COMMITTED)
                    return@mutation BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)
                before = readCurrent()
                val maintenance = ByteArray(JournalLimits.OPERATION_BYTES).also(random::nextBytes)
                try {
                    if (collector.collect(maintenance, emptySet(), emptySet(), emptySet()) != GarbageResult.COMPLETE)
                        return@mutation BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)
                } finally { maintenance.fill(0) }
            } else if (capacity != JournalAdmission.ADMIT) return@mutation BrokerMutation(ProtectedMutationStatus.CAPACITY_EXHAUSTED)
            val oldControl = journal.readControl().encode()
            val oldProjection = projections.read().also { it.requireMatches(before) }
            try {
                val current = JournalControl.decode(oldControl)
                check(current.revision == before.revision && current.storeId().contentEquals(before.storeId()))
                val target = current.reserve(operation, kind).reservedCleanRevision
                StagedProtectedBlobView(before.objects(), operation, target, readEncrypted, codec, key,
                    reserveSettingsOperation = settingsTransaction || productCommand != null || schemaMigration).use { view ->
                    val state = PreparedDomainState(before, view, native)
                    try {
                    if (settingsTransaction) ProtectedPresentationOverlay.read(storage::read, before.storeId())?.close()
                    val result = interpret(state)
                    state.validate()
                    val startedHour = if (productCommand != null || schemaMigration) System.currentTimeMillis() / 3_600_000L else 0L
                    val descriptor = productCommand?.let { productOperationDescriptor(operation, it.displayKind,
                        it.scopeRecordId, 0, startedHour, productSettingsRevision(before), productSettingsRevision(before)) }
                    val next = state.snapshot(before.storeId(), target, operation, descriptor, schemaMigration)
                    if (schemaMigration) {
                        val exact = ProductProjectionSchemaMigration.candidate(before, target, operation).encode()
                        val actual = next.encode()
                        try { check(MessageDigest.isEqual(exact, actual)) } finally { exact.fill(0); actual.fill(0) }
                    }
                    if (settingsTransaction) {
                        val prior = before.encode()
                        val candidate = next.encode()
                        val oldSettings = before.settingsBytes()
                        val newSettings = next.settingsBytes()
                        try {
                            val oldRevision = if (ProductSettingsImage.isVersionTwo(oldSettings)) ProductSettingsImage.decode(oldSettings).revision else 0
                            val newRevision = if (ProductSettingsImage.isVersionTwo(newSettings)) ProductSettingsImage.decode(newSettings).revision else 0
                            SettingsOperationState(operation, before.revision, target, oldRevision,
                                newRevision, prior, candidate).use(view::stageSettingsOperation)
                        } finally { prior.fill(0); candidate.fill(0); oldSettings.fill(0); newSettings.fill(0) }
                    }
                    if (productCommand != null || schemaMigration) {
                        val prior = before.encode(); val candidate = next.encode()
                        try {
                            ProductOperationState(operation, kind.wire, productCommand?.displayKind, productCommand?.scopeRecordId,
                                0, startedHour, before.revision, target,
                                productSettingsRevision(before), productSettingsRevision(next), prior, candidate).use {
                                    if (!schemaMigration) validateProductOperationTransition(it, before, next)
                                    view.stageProductOperation(it)
                                }
                        } finally { prior.fill(0); candidate.fill(0) }
                    }
                    val additionalBytes = view.additionalBytes()
                    if (ProtectedStateJournalLifecycle.admission(current, storage.inventory(JournalLimits.OBJECTS), additionalBytes) != JournalAdmission.ADMIT)
                        return@mutation BrokerMutation(ProtectedMutationStatus.CAPACITY_EXHAUSTED)
                    val expected = next.encode()
                    try {
                        val outcome = journal.mutate(kind, operation, expected, mutation = {
                            // This callback is admitted only after durable DIRTY and intent rereads.
                            // Failed retirement therefore leaves DIRTY without any product write.
                            reservation.retirePriorOwners()
                            reservation.requireCurrent()
                            val writer = objectWriter(operation.clone())
                            view.persist(writer)
                            reservation.requireCurrent()
                            if (schemaMigration) projections.migrateSchema(before, next, next) { requireSchemaEvidence(before, next) }
                            else projections.publish(oldProjection, next)
                            reservation.requireCurrent()
                        }, reconstruct = {
                            reservation.requireCurrent()
                            val reconstructed = independentlyReconstruct(next).encode()
                            try { reservation.requireCurrent(); reconstructed }
                            catch (failure: Throwable) { reconstructed.fill(0); throw failure }
                        }, expectedOldControl = oldControl, beforeReservation = { requireCleanSchema(before, if (schemaMigration) 2 else 3) })
                        BrokerMutation(outcome, if (outcome == ProtectedMutationStatus.COMMITTED) result else null,
                            if (outcome == ProtectedMutationStatus.NO_MUTATION) OperationError.RECOVERY_REQUIRED else null)
                    } finally { expected.fill(0) }
                    } finally { state.close() }
                }
            } finally { oldControl.fill(0) }
        } catch (failure: MutationRejected) { BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = failure.category) }
        catch (_: IllegalArgumentException) { BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.INVALID_INPUT) }
        catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        finally { operation.fill(0) }
        }
    } ?: BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)

    private fun readCurrent(): ProtectedStateSnapshot {
        val current = ProtectedStateSnapshotReader(journal) { reference ->
            checkNotNull(readEncrypted(reference.physicalId))
        }.readVerified()
        val observed = projections.read()
        observed.requireMatches(current)
        journal.readProjectionWitness(current).requireMatches(current, observed.physical())
        validateRelationships(current)
        return current
    }

    /** Called only under the journal storage's current exclusive writer, never reacquires it. */
    private fun requireCleanSchema(expected: ProtectedStateSnapshot, version: Int) {
        val control = journal.readControl()
        check(!control.dirty && control.revision == expected.revision && control.storeId().contentEquals(expected.storeId()))
        val checkpoint = journal.readCheckpoint(); val expectedBytes = expected.encode()
        try { check(MessageDigest.isEqual(checkpoint, expectedBytes)) } finally { checkpoint.fill(0); expectedBytes.fill(0) }
        projections.requireClosedSchema(expected, version)
    }

    private fun requireSchemaEvidence(prior: ProtectedStateSnapshot, candidate: ProtectedStateSnapshot) {
        val operation = candidate.operationId()
        val candidateBytes = candidate.encode(); val priorBytes = prior.encode()
        try {
            journal.requireProductRecoveryCandidate(operation, candidateBytes, true)
            val authenticatedPrior = journal.readPriorCheckpointForExplicitRecovery()
            try { check(MessageDigest.isEqual(priorBytes, authenticatedPrior)) } finally { authenticatedPrior.fill(0) }
            val exact = ProductProjectionSchemaMigration.candidate(prior, candidate.revision, operation).encode()
            try { check(MessageDigest.isEqual(exact, candidateBytes)) } finally { exact.fill(0) }
            val encrypted = checkNotNull(readEncrypted(operationObjectLeaf(operation, 1)))
            val opened = try { codec.openForOperation(encrypted, ProductOperationState.RECORD_ID,
                SecureDataClass.OPERATION_STATE, key, SecureOperationBinding(operation, candidate.revision)) }
            finally { encrypted.fill(0) }
            try { ProductOperationState.decode(opened.plaintext).use { record ->
                check(record.internalMutationKind == MutationKind.PROJECTION_SCHEMA.wire && record.displayKind == null &&
                    record.scopeRecordId == null && record.matches(operation, prior.revision, candidate.revision) &&
                    record.settingsRevisionBefore == productSettingsRevision(prior) && record.settingsRevisionAfter == productSettingsRevision(candidate))
                val a = record.priorSnapshot(); val b = record.candidateSnapshot()
                try { check(MessageDigest.isEqual(a, priorBytes) && MessageDigest.isEqual(b, candidateBytes)) }
                finally { a.fill(0); b.fill(0) }
            } } finally { opened.plaintext.fill(0) }
        } finally { operation.fill(0); candidateBytes.fill(0); priorBytes.fill(0) }
    }

    private fun validateRelationships(snapshot: ProtectedStateSnapshot) {
        check(snapshot.disposition == ProtectedStateDisposition.VERIFIED) { "EXPLICIT_QUARANTINE_RECOVERY_REQUIRED" }
        val view = ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key)
        snapshot.objects().forEach { reference ->
            val role = SecureDataClass.entries.single { it.wireValue == reference.dataClass }
            view.reopen(reference.logicalId, role).fill(0)
        }
        val rows = snapshot.catalogBytes().let { bytes ->
            try { ProfileCatalogProjectionCodec.decode(bytes) } finally { bytes.fill(0) }
        }
        val settings = readProductSettings(snapshot, view)
        validateProductRecordScopes(snapshot.objects(), rows.map { it.localRecordId }.toSet(), view)
        check(settings.profiles.activeLocalRecordId == snapshot.selectedProfile)
        snapshot.selectedProfile?.let { id -> check(rows.any { it.localRecordId == id &&
            it.transactionState == TransactionState.FINALIZED.name && it.health == CatalogHealth.AVAILABLE.name }) }
        val reader = ProfileAdmissionJournal.readOnly(native, PreparedCatalog(rows), view, false)
        runBlocking { reader.requireCommittedRelationships(snapshot.objects().filter { it.dataClass == 4 }.map { it.logicalId }.toSet()) }
        validateProductProfileRelationships(snapshot.objects(), rows.map { it.localRecordId }.toSet(), view)
    }

    private fun independentlyReconstruct(expected: ProtectedStateSnapshot): ProtectedStateSnapshot {
        val observed = projections.read()
        observed.requireMatches(expected)
        val refs = expected.objects().map { reference ->
            val bytes = checkNotNull(readEncrypted(reference.physicalId))
            try {
                check(reference.matches(bytes))
                check(codec.keyGeneration(bytes) == key.generation && reference.keyGeneration == key.generation)
                val role = SecureDataClass.entries.single { it.wireValue == reference.dataClass }
                val opened = codec.openForOperation(bytes, reference.logicalId, role, key, reference.binding)
                try { check(opened.dataClass.wireValue == reference.dataClass) } finally { opened.plaintext.fill(0) }
                ProtectedObjectReference.fromEncryptedObject(reference.dataClass, reference.logicalId,
                    reference.physicalId, reference.keyGeneration, bytes, reference.binding)
            } finally { bytes.fill(0) }
        }
        val control = journal.readControl()
        check(control.dirty && control.reservedCleanRevision == expected.revision &&
            control.storeId().contentEquals(expected.storeId()) && control.operationId().contentEquals(expected.operationId()))
        return ProtectedStateSnapshot.create(expected.storeId(), expected.revision, expected.selectedProfile, refs,
            observed.settings(), observed.catalog(), expected.operationId()).also { reconstructed ->
                validateRelationships(reconstructed)
                journal.bindProjection(reconstructed, PhysicalProjectionWitness.capture(reconstructed, observed.physical()))
            }
    }

    companion object {
        internal fun compose(storage: JournalStorage, readEncrypted: (String) -> ByteArray?,
            objectWriter: (ByteArray) -> ImmutableProtectedObjectWriter, codec: SecureEnvelopeCodec,
            key: KeyEncryptionKey, projections: ProtectedProjectionAccess, native: KurdNativeCore,
            sessions: ActiveSessionMutationPolicy, garbageObjects: JournalObjectAccess): ProtectedStateMutationBroker =
            ProtectedStateMutationBroker(storage, readEncrypted, objectWriter, codec, key, projections, native, sessions, garbageObjects)
    }
}

/** No public writer/DAO escapes this in-memory preparation. A failed command discards it entirely. */
private class PreparedDomainState(before: ProtectedStateSnapshot, val view: StagedProtectedBlobView,
    private val native: KurdNativeCore) : AutoCloseable {
    private var settings = before.settingsBytes()
    private var selected = before.selectedProfile
    private val catalog = before.catalogBytes().let { raw ->
        try { PreparedCatalog(ProfileCatalogProjectionCodec.decode(raw)) } finally { raw.fill(0) }
    }
    val keys = ClientKeyBundleStore(view, KurdRecipientKeyNative(native))
    val admission = ProfileAdmissionJournal(native, catalog, view, false, keys)
    fun applyProductCommand(command: ProductStoreCommand): Boolean {
        val model = readProductSettings(settings, selected, view)
        val revision = if (ProductSettingsImage.isVersionTwo(settings)) ProductSettingsImage.decode(settings).revision else 0L
        val ids = runBlocking { catalog.listAll() }.map { it.localRecordId }.toSet()
        fun save(id: String, role: SecureDataClass, bytes: ByteArray): Boolean = try {
            if (view.exists(id, role)) {
                val old = view.reopen(id, role)
                try { if (MessageDigest.isEqual(old, bytes)) return false } finally { old.fill(0) }
            }
            view.stage(id, role, bytes); true
        } finally { bytes.fill(0) }
        return when (command) {
            is ProductStoreCommand.SetDeploymentDisplay -> {
                require(command.value.entries.all { it.profileId.value in ids })
                var changed = save(DeploymentDisplayMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA, command.value.encode())
                val retained = command.value.entries.map { it.profileId.value }.toSet()
                view.referenceSnapshot().filter { it.dataClass == 19 && it.logicalId !in retained }.forEach {
                    view.delete(it.logicalId, SecureDataClass.PROFILE_PROJECTION); changed = true
                }
                for (entry in command.value.entries) {
                    val id = entry.profileId.value
                    val material = when (val result = runBlocking { admission.openRuntimeAuthority(id) }) {
                        is RuntimeAuthorityResult.Success -> result.material
                        is RuntimeAuthorityResult.Failure -> throw MutationRejected(result.error)
                    }
                    val preview = material.use {
                        val result = if (it.recipientPrivate.isEmpty()) native.verifyPreview(it.verifyRequest)
                            else native.verifyPreviewWithRecipient(it.verifyRequest, it.recipientRequest, it.recipientPrivate)
                        val verified = when (result) {
                            is NativeResult.Success -> result.value
                            is NativeResult.Failure -> throw MutationRejected(result.error)
                        }
                        try { verified.preview } finally { try { check(native.releaseVerified(verified) is NativeResult.Success) }
                            finally { verified.close() } }
                    }
                    val profile = org.kurdistanvpn.core.model.ProfileProjection(entry.profileId, entry.alias, preview.generation,
                        preview.validUntilEpochSeconds, org.kurdistanvpn.core.model.ProjectionStatus.VERIFIED)
                    val deployment = org.kurdistanvpn.core.model.DeploymentProjection(entry.alias, profileGeneration = preview.generation,
                        profileExpiryEpochSeconds = preview.validUntilEpochSeconds)
                    changed = save(id, SecureDataClass.PROFILE_PROJECTION, StoredProfileProjection(profile, deployment).encode()) || changed
                }
                changed
            }
            is ProductStoreCommand.RecordUpdate -> {
                require(command.profileId in ids)
                UpdateStateStore.readOnly(view).load(command.profileId)?.let { old ->
                    old.publicationGeneration?.let { prior -> require(command.value.publicationGeneration?.let { it >= prior } == true) }
                    old.profileGeneration?.let { prior -> require(command.value.profileGeneration?.let { it >= prior } == true) }
                }
                save(command.profileId, SecureDataClass.UPDATE_STATE, command.value.encode())
            }
            is ProductStoreCommand.RecordProbe -> {
                require(command.profileId in ids)
                save(command.profileId, SecureDataClass.PROBE_HISTORY, command.value.encode())
            }
            is ProductStoreCommand.ReplaceTrustedRules -> {
                require(command.value.settingsRevision == revision)
                require(command.value.selectedRuleIds == model.networkTrust.protectedRuleIds)
                save(StoredTrustedNetworks.RECORD_ID, SecureDataClass.TRUSTED_NETWORK_RULES, command.value.encode())
            }
            is ProductStoreCommand.RecordUsage -> {
                require(model.privacy.collectUsageAggregates)
                save(StoredUsageAggregates.RECORD_ID, SecureDataClass.USAGE_AGGREGATES,
                    command.value.retained(model.privacy.usageRetentionDays).encode())
            }
            is ProductStoreCommand.RecordAppLockFailure -> {
                require(command.expectedSettingsRevision == revision && model.privacy.appLockEnabled)
                val old = AppLockStateStore.readOnly(view).load()
                val next = StoredAppLockState(revision, true, model.privacy.allowedAuthenticators,
                    minOf(10, (old?.failedAttempts ?: 0) + 1), command.nextEligibleEpochMinute)
                save(StoredAppLockState.RECORD_ID, SecureDataClass.APP_LOCK_STATE, next.encode())
            }
            is ProductStoreCommand.RecordStart -> {
                val old = CrashSafeModeStore.readOnly(view).load() ?: StoredCrashSafeMode(command.epochHour, true, 0, false)
                save(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE, old.started(command.epochHour).encode())
            }
            is ProductStoreCommand.RecordCleanStop -> {
                require(command.epochHour >= 0)
                val old = CrashSafeModeStore.readOnly(view).load() ?: return false
                save(StoredCrashSafeMode.RECORD_ID, SecureDataClass.CRASH_SAFE_MODE_STATE, old.cleanStopped().encode())
            }
        }
    }
    fun restoreProductSettings(prior: ProtectedStateSnapshot): ProductSettingsCommit {
        val currentRows = runBlocking { catalog.listAll() }.map { it.localRecordId }.toSet()
        val priorCatalog = prior.catalogBytes()
        try { check(ProfileCatalogProjectionCodec.decode(priorCatalog).map { it.localRecordId }.toSet() == currentRows) }
        finally { priorCatalog.fill(0) }
        view.restoreReferences(prior.objects())
        settings.fill(0); settings = prior.settingsBytes(); selected = prior.selectedProfile
        validate()
        val revision = if (ProductSettingsImage.isVersionTwo(settings)) ProductSettingsImage.decode(settings).revision else 0L
        val requested = readProductSettings(settings, selected, view)
        if (revision == 0L) return validateRuntime(requested, 1).second.copy(settingsRevision = 0)
        val bytes = view.reopen(RuntimeBootstrapRecord.RECORD_ID, SecureDataClass.RUNTIME_BOOTSTRAP)
        try {
            // Dispatch solely from authenticated restored bytes. No decoder fallback or upconversion.
            val proof = when(bytes.getOrNull(4)?.toInt()) {
                1 -> {
                    RuntimeBootstrapRecord.decode(bytes)
                    validateLegacyBootstrapRuntime(requested, revision).let { it.first::encode to it.second }
                }
                2 -> {
                    RuntimeProductionBootstrapRecord.decode(bytes)
                    validateProductionRuntime(requested, revision).let { it.first::encode to it.second }
                }
                else -> throw MutationRejected(OperationError.RECOVERY_REQUIRED)
            }
            val verified = proof.first()
            try { check(MessageDigest.isEqual(bytes, verified)) { "BOOTSTRAP_MISMATCH" } }
            finally { verified.fill(0) }
            return proof.second
        } finally { bytes.fill(0) }
    }
    fun applyProductSettings(expected: Long, requested: ProductSettings, allowSelectionChange: Boolean = false): ProductSettingsCommit {
        val production = if (!ProductSettingsImage.isVersionTwo(settings)) false else {
            val bytes = view.reopen(RuntimeBootstrapRecord.RECORD_ID, SecureDataClass.RUNTIME_BOOTSTRAP)
            try {
                when (bytes.getOrNull(4)?.toInt()) {
                    1 -> { RuntimeBootstrapRecord.decode(bytes); false }
                    2 -> { RuntimeProductionBootstrapRecord.decode(bytes); true }
                    else -> throw MutationRejected(OperationError.RECOVERY_REQUIRED)
                }
            } finally { bytes.fill(0) }
        }
        return applyBoundSettings(expected, requested, allowSelectionChange, production)
    }
    fun applyProductionSettings(expected: Long, requested: ProductSettings): ProductSettingsCommit =
        applyBoundSettings(expected, requested, allowSelectionChange = false, production = true)

    fun applyPause(expected: Long, timer: StoredPauseState?): ProductSettingsCommit {
        val current = readProductSettings(settings, selected, view)
        val result = applyProductSettings(expected, current.copy(pausePolicy =
            if (timer == null) PausePolicy.NOT_PAUSED else PausePolicy.UNTIL_RESUMED))
        if (timer != null) PauseStateStore(view).save(timer)
        return result
    }

    private fun applyBoundSettings(expected: Long, requested: ProductSettings, allowSelectionChange: Boolean,
        production: Boolean): ProductSettingsCommit {
        val revision = if (ProductSettingsImage.isVersionTwo(settings)) ProductSettingsImage.decode(settings).revision else 0L
        if (revision != expected || revision == Long.MAX_VALUE) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        if (revision == 0L && org.kurdistanvpn.data.settings.SettingsMigration.planLegacyImage(
                settings, selected, SecureRoutingPolicyStore.readOnly(view).loadPackages(), true)
            !is org.kurdistanvpn.data.settings.SettingsMigration.Ready) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        require(requested.tunnel.validated() == requested.tunnel && requested.routing.validated() == requested.routing)
        requested.profiles.validated(); requested.updates.validated(); requested.probes.validated(); requested.expert.validated()
        require(allowSelectionChange || requested.profiles.activeLocalRecordId == selected)
        selected = requested.profiles.activeLocalRecordId
        val nextRevision = revision + 1
        val (bootstrapRecord, effective) = if (production) validateProductionRuntime(requested, nextRevision).let { it.first::encode to it.second }
            else validateRuntime(requested, nextRevision).let { it.first::encode to it.second }
        val oldTrust = TrustedNetworkStore.readOnly(view).load()
        try { StoredTrustedNetworks(nextRevision, oldTrust?.rules.orEmpty(), requested.networkTrust.protectedRuleIds).use {
            TrustedNetworkStore(view).save(it)
        } } finally { oldTrust?.close() }
        val oldLock = AppLockStateStore.readOnly(view).load()
        AppLockStateStore(view).save(StoredAppLockState(nextRevision, requested.privacy.appLockEnabled,
            requested.privacy.allowedAuthenticators, if (requested.privacy.appLockEnabled) oldLock?.failedAttempts ?: 0 else 0,
            if (requested.privacy.appLockEnabled) oldLock?.nextEligibleEpochMinute ?: 0 else 0))
        LocalProxyPolicyStore(view).save(StoredProxyPolicy(nextRevision, requested.localProxy))
        if (requested.pausePolicy == PausePolicy.NOT_PAUSED) PauseStateStore(view).delete()
        if (!requested.privacy.collectUsageAggregates) UsageAggregatesStore(view).delete()
        else UsageAggregatesStore.readOnly(view).load()?.let { UsageAggregatesStore(view).save(it.retained(requested.privacy.usageRetentionDays)) }
        val nonsecret = requested.copy(profiles = ProfilePreferences(), routing = requested.routing.copy(packages = emptySet()),
            networkTrust = requested.networkTrust.copy(protectedRuleIds = emptySet()))
        val image = ProductSettingsImage.create(nonsecret, nextRevision).encode()
        try {
            val metadata = ProductSettingsMetadata(nextRevision, requested.profiles.favoriteLocalRecordIds,
                SettingsIdentifiers.from(requested)).encode()
            try { view.stage(ProductSettingsMetadata.RECORD_ID, SecureDataClass.DEPLOYMENT_METADATA, metadata) }
            finally { metadata.fill(0) }
            SecureRoutingPolicyStore(view).savePackages(requested.routing.packages)
            val bootstrap = bootstrapRecord()
            try { view.stage(RuntimeBootstrapRecord.RECORD_ID, SecureDataClass.RUNTIME_BOOTSTRAP, bootstrap) }
            finally { bootstrap.fill(0) }
            settings.fill(0); settings = image.clone()
            return effective
        } finally { image.fill(0) }
    }
    private fun validateProductionRuntime(requested: ProductSettings, nextRevision: Long): Pair<RuntimeProductionBootstrapRecord, ProductSettingsCommit> {
        if (selected == null) require(requested.connection.selectionMode != org.kurdistanvpn.core.model.SelectionMode.MANUAL_STRATEGY &&
            SettingsIdentifiers.from(requested) == SettingsIdentifiers()) { "PROFILE_DEPENDENT_REQUEST_UNPROVEN" }
        val compatibility = when(val result = native.compatibility()) {
            is NativeResult.Success -> result.value
            is NativeResult.Failure -> throw MutationRejected(OperationError.AUTHORITY_UNAVAILABLE)
        }
        val settingsWire = when(val encoded = encodeProductionSettingsOwnedV1(requested)) {
            is NativeProductResult.Success -> encoded.value
            is NativeProductResult.Failure -> throw MutationRejected(bootstrapOperationErrorV1(encoded.code))
        }
        try {
            if (selected == null) return RuntimeProductionBootstrapRecord(nextRevision, null, 0uL, byteArrayOf(), compatibility) to ProductSettingsCommit(nextRevision)
            val validator = native as? NativeBootstrapValidator ?: throw MutationRejected(OperationError.INCOMPATIBLE_NATIVE_CORE)
            val material = when(val opened = runBlocking { admission.openRuntimeAuthority(checkNotNull(selected)) }) {
                is RuntimeAuthorityResult.Success -> opened.material
                is RuntimeAuthorityResult.Failure -> throw MutationRejected(opened.error)
            }
            return material.use {
                val result = when(val read = validator.readProductionBinding(bootstrapMaterialV1(it), ByteBuffer.wrap(settingsWire))) {
                    is NativeProductResult.Success -> read.value
                    is NativeProductResult.Failure -> throw MutationRejected(bootstrapOperationErrorV1(read.code))
                }
                result.use { read ->
                    val digest=read.facts.planDigest
                    try { RuntimeProductionBootstrapRecord(nextRevision,selected,read.facts.generation,digest,compatibility) to
                        ProductSettingsCommit(nextRevision,read.facts.effectiveMtu,read.facts.effectiveAutomaticReconnectMaximum) }
                    finally { digest.fill(0) }
                }
            }
        } finally { settingsWire.fill(0) }
    }

    private fun validateLegacyBootstrapRuntime(requested: ProductSettings, nextRevision: Long): Pair<RuntimeBootstrapRecord, ProductSettingsCommit> {
        val config=runtimeConfigForSettings(requested,requested.routing.packages)
        if(selected==null) require(requested.connection.selectionMode!=org.kurdistanvpn.core.model.SelectionMode.MANUAL_STRATEGY &&
            SettingsIdentifiers.from(requested)==SettingsIdentifiers())
        val compatibility=when(val result=native.compatibility()) {
            is NativeResult.Success -> result.value
            is NativeResult.Failure -> throw MutationRejected(OperationError.AUTHORITY_UNAVAILABLE)
        }
        if(selected==null)return RuntimeBootstrapRecord(nextRevision,null,0,byteArrayOf(),compatibility) to ProductSettingsCommit(nextRevision)
        val validator=native as? NativeBootstrapValidator ?: throw MutationRejected(OperationError.INCOMPATIBLE_NATIVE_CORE)
        val policy=org.kurdistanvpn.runtime.api.RuntimeStartWire.encodeLegacyBootstrapPolicy(config)
        try {
            val material=when(val opened=runBlocking{admission.openRuntimeAuthority(checkNotNull(selected))}) {
                is RuntimeAuthorityResult.Success -> opened.material
                is RuntimeAuthorityResult.Failure -> throw MutationRejected(opened.error)
            }
            return material.use {
                val facts=when(val read=validator.readLegacyBinding(bootstrapMaterialV1(it),ByteBuffer.wrap(policy))) {
                    is NativeResult.Success -> read.value
                    is NativeResult.Failure -> throw MutationRejected(read.error)
                }
                check(facts.generation<=Long.MAX_VALUE.toULong())
                val digest=facts.planDigest
                try {
                    // Successful native V2 policy and plan validation both require MTU exactly 1280.
                    RuntimeBootstrapRecord(nextRevision,selected,facts.generation.toLong(),digest,compatibility) to
                        ProductSettingsCommit(nextRevision,1280,minOf(requested.connection.reconnectMaximum,facts.signedRetryMaximum))
                } finally{digest.fill(0)}
            }
        } finally{policy.fill(0)}
    }

    private fun validateRuntime(requested: ProductSettings, nextRevision: Long): Pair<RuntimeBootstrapRecord, ProductSettingsCommit> {
        val config = runtimeConfigForSettings(requested, requested.routing.packages)
        if (selected == null) require(requested.connection.selectionMode != org.kurdistanvpn.core.model.SelectionMode.MANUAL_STRATEGY &&
            SettingsIdentifiers.from(requested) == SettingsIdentifiers()) { "PROFILE_DEPENDENT_REQUEST_UNPROVEN" }
        val compatibility = when (val result = native.compatibility()) {
            is NativeResult.Success -> result.value
            is NativeResult.Failure -> throw MutationRejected(OperationError.AUTHORITY_UNAVAILABLE)
        }
        var effectiveMtu: Int? = null
        var effectiveReconnect: Int? = null
        val bootstrapRecord = if (selected == null) RuntimeBootstrapRecord(nextRevision, null, 0, byteArrayOf(), compatibility)
        else {
            val material = when (val result = runBlocking { admission.openRuntimeAuthority(checkNotNull(selected)) }) {
                is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Success -> result.material
                is org.kurdistanvpn.data.secure.RuntimeAuthorityResult.Failure -> throw MutationRejected(result.error)
            }
            val wire = material.use { org.kurdistanvpn.runtime.api.RuntimeStartWire.encode(it.verifyRequest,
                it.activationRecord, it.recipientRequest, it.recipientPrivate, config) }
            try {
                val session = when (val result = native.openLiveRuntimeSession(wire)) {
                    is NativeResult.Success -> result.value
                    is NativeResult.Failure -> throw MutationRejected(result.error)
                }
                try {
                    check((session.status() as? NativeResult.Success)?.value == org.kurdistanvpn.core.nativeapi.NativeRuntimeState.VERIFIED)
                    val proof = session.snapshot
                    effectiveMtu = proof.mtu
                    effectiveReconnect = minOf(requested.connection.reconnectMaximum, proof.maxReconnectAttempts)
                    RuntimeBootstrapRecord(nextRevision, selected, proof.generation, proof.planDigest, compatibility)
                } finally { session.close() }
            } finally { wire.fill(0) }
        }
        return bootstrapRecord to ProductSettingsCommit(nextRevision, effectiveMtu, effectiveReconnect)
    }
    fun replaceSettings(bytes: ByteArray) {
        val owned = bytes.clone()
        try { selected = SettingsProjectionCodec.toModel(owned).profiles.activeLocalRecordId }
        catch (failure: Throwable) { owned.fill(0); throw failure }
        settings.fill(0); settings = owned
    }
    fun removeProfilePreferences(ids: Set<String>) {
        for (id in ids) for (role in listOf(SecureDataClass.PROFILE_PROJECTION, SecureDataClass.UPDATE_STATE, SecureDataClass.PROBE_HISTORY))
            view.delete(id, role)
        DeploymentDisplayMetadataStore.readOnly(view).load()?.let { old ->
            val remaining = old.entries.filter { it.profileId.value !in ids }
            if (remaining.size != old.entries.size) DeploymentDisplayMetadataStore(view).save(DeploymentDisplayMetadata(remaining))
        }
        val old = readProductSettings(settings, selected, view)
        val profiles = old.profiles.copy(activeLocalRecordId = old.profiles.activeLocalRecordId?.takeIf { it !in ids },
            favoriteLocalRecordIds = old.profiles.favoriteLocalRecordIds - ids)
        if (ProductSettingsImage.isVersionTwo(settings)) {
            applyProductSettings(ProductSettingsImage.decode(settings).revision, old.copy(profiles = profiles), allowSelectionChange = true)
            return
        }
        val next = SettingsProjectionCodec.fromModel(old.copy(profiles = profiles), SettingsProjectionCodec.legacyResidue(settings))
        try { replaceSettings(next) } finally { next.fill(0) }
    }
    fun validate() {
        val model = readProductSettings(settings, selected, view)
        val rows = runBlocking { catalog.listAll() }
        validateProductRecordScopes(view.referenceSnapshot(), rows.map { it.localRecordId }.toSet(), view)
        check(model.profiles.favoriteLocalRecordIds.all { id -> rows.any { it.localRecordId == id } })
        model.profiles.activeLocalRecordId?.let { id -> check(rows.any { it.localRecordId == id &&
            it.transactionState == TransactionState.FINALIZED.name && it.health == CatalogHealth.AVAILABLE.name }) }
        runBlocking { admission.requireCommittedRelationships(view.referenceSnapshot().filter { it.dataClass == 4 }.map { it.logicalId }.toSet()) }
        validateProductProfileRelationships(view.referenceSnapshot(), rows.map { it.localRecordId }.toSet(), view)
    }
    fun snapshot(store: ByteArray, revision: Long, operation: ByteArray,
        descriptor: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity? = null,
        preserveQuarantine: Boolean = false): ProtectedStateSnapshot {
        val op = operation.joinToString("") { "%02x".format(it) }
        val catalogBytes = encodeProductCatalog(runBlocking { catalog.listAll() }.map {
            it.stampCommitted(op, revision, if (preserveQuarantine) org.kurdistanvpn.data.metadata.CatalogQuarantineReason.valueOf(it.quarantineReason)
                else org.kurdistanvpn.data.metadata.CatalogQuarantineReason.NONE)
        }, descriptor)
        return try { ProtectedStateSnapshot.create(store, revision, selected,
            view.references(), settings, catalogBytes, operation) } finally { catalogBytes.fill(0) }
    }
    override fun close() { settings.fill(0); catalog.close() }
}

internal class PreparedCatalog(rows: List<ProfileCatalogEntity>) : ProfileCatalogDao, AutoCloseable {
    private val values = rows.toTypedArray().associateBy { it.localRecordId }.toMutableMap()
    private val monitor = Any()
    private var closed = false
    override fun observeAll(): Flow<List<ProfileCatalogEntity>> = synchronized(monitor) { check(!closed); flowOf(values.values.toList()) }
    override suspend fun get(localRecordId: String): ProfileCatalogEntity? = synchronized(monitor) { check(!closed); values[localRecordId] }
    override suspend fun listAll(): List<ProfileCatalogEntity> = synchronized(monitor) { check(!closed); values.values.sortedBy { it.localRecordId } }
    override suspend fun upsert(entity: ProfileCatalogEntity) = synchronized(monitor) {
        check(!closed); ProfileCatalogProjectionCodec.encode(listOf(entity)).fill(0)
        check(values.containsKey(entity.localRecordId) || values.size < 1024); values[entity.localRecordId] = entity
    }
    override suspend fun delete(localRecordId: String) { synchronized(monitor) { check(!closed); values.remove(localRecordId) } }
    override suspend fun deleteAll() { synchronized(monitor) { check(!closed); values.clear() } }
    override suspend fun updateHealth(recordIds: List<String>, health: String) { synchronized(monitor) {
        check(!closed); require(CatalogHealth.entries.any { it.name == health })
        for (id in recordIds.toTypedArray()) values[id]?.let { values[id] = it.copy(health = health) }
    } }
    override fun close() { synchronized(monitor) { closed = true; values.clear() } }
}

/** Pure in-memory preparation. It has no filesystem, Room, DataStore or Keystore-creation capability. */
internal class StagedProtectedBlobView(
    references: List<ProtectedObjectReference>, operation: ByteArray, revision: Long,
    private val readEncrypted: (String) -> ByteArray?, private val codec: SecureEnvelopeCodec,
    private val key: KeyEncryptionKey,
    private val reserveSettingsOperation: Boolean = false,
) : SecureBlobAccess, AutoCloseable {
    private val operation = operation.clone()
    private val binding = SecureOperationBinding(this.operation, revision)
    private val refs = references.toTypedArray().associateBy { it.dataClass to it.logicalId }.toMutableMap()
    private val prepared = LinkedHashMap<String, ByteArray>()
    private var sequence = if (reserveSettingsOperation) 1L else 0L
    private var sealed = false
    private var closed = false
    private var settingsOperation: ByteArray? = null
    private var productOperation = false
    private var productOperationKind: Int? = null
    fun stageProductOperation(value: ProductOperationState) {
        check(!closed && sealed && reserveSettingsOperation && settingsOperation == null)
        check(value.internalMutationKind in setOf(MutationKind.PRODUCT_STATE.wire, MutationKind.PROJECTION_SCHEMA.wire) && value.matches(operation, binding.revision - 2, binding.revision))
        val bytes = value.encode()
        try { settingsOperation = codec.sealForOperation(ProductOperationState.RECORD_ID,
            SecureDataClass.OPERATION_STATE, bytes, key, binding); productOperation = true; productOperationKind = value.internalMutationKind } finally { bytes.fill(0) }
    }
    fun stageSettingsOperation(value: SettingsOperationState) {
        check(!closed && sealed && reserveSettingsOperation && settingsOperation == null)
        check(value.matches(operation, binding.revision - 2, binding.revision))
        val bytes = value.encode()
        try { settingsOperation = codec.sealForOperation(SettingsOperationState.RECORD_ID,
            SecureDataClass.OPERATION_STATE, bytes, key, binding) } finally { bytes.fill(0) }
    }
    fun restoreReferences(references: List<ProtectedObjectReference>) {
        check(!closed && !sealed && prepared.isEmpty())
        val owned = references.toTypedArray()
        require(owned.size <= JournalLimits.OBJECTS && owned.map { it.dataClass to it.logicalId }.toSet().size == owned.size)
        refs.clear(); refs.putAll(owned.associateBy { it.dataClass to it.logicalId })
    }
    override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        val owned = exactBytes.clone()
        try {
            checkMutable(localRecordId, dataClass)
            require(owned.size in 1..JournalLimits.OBJECT_BYTES - 2048)
            check(sequence < Long.MAX_VALUE)
            val name = operationObjectLeaf(operation, ++sequence)
            val encrypted = codec.sealForOperation(localRecordId, dataClass, owned, key, binding)
            try {
                val reference = ProtectedObjectReference.fromEncryptedObject(dataClass.wireValue, localRecordId,
                    name, key.generation, encrypted, binding)
                require(refs.size < JournalLimits.OBJECTS || refs.containsKey(dataClass.wireValue to localRecordId))
                prepared[name] = encrypted.clone()
                val old = refs.put(dataClass.wireValue to localRecordId, reference)
                old?.let { prepared.remove(it.physicalId)?.fill(0) }
                require(refs.values.sumOf { it.length.toLong() } <= JournalLimits.LIVE_OBJECT_BYTES)
            } finally { encrypted.fill(0) }
        } finally { owned.fill(0) }
    }
    override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        check(!closed)
        return ReadOnlyProtectedBlobView(refs.values.toList(), ::read, codec, key).reopen(localRecordId, dataClass)
    }
    override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean {
        check(!closed)
        return ReadOnlyProtectedBlobView(refs.values.toList(), ::read, codec, key).exists(localRecordId, dataClass)
    }
    override fun delete(localRecordId: String, dataClass: SecureDataClass) {
        checkMutable(localRecordId, dataClass)
        refs.remove(dataClass.wireValue to localRecordId)?.let { prepared.remove(it.physicalId)?.fill(0) }
    }
    override fun deleteAll() {
        check(!closed && !sealed)
        prepared.values.forEach { it.fill(0) }; prepared.clear(); refs.clear()
    }
    fun references(): List<ProtectedObjectReference> {
        check(!closed); sealed = true
        return Collections.unmodifiableList(ArrayList(refs.values))
    }
    fun referenceSnapshot(): List<ProtectedObjectReference> {
        check(!closed); return Collections.unmodifiableList(ArrayList(refs.values))
    }
    fun additionalBytes(): Long = prepared.values.sumOf { it.size.toLong() } + (settingsOperation?.size ?: 0)
    fun persist(writer: ImmutableProtectedObjectWriter) {
        check(!closed && sealed)
        writer.requireDirtyOperation(operation.clone())
        if (reserveSettingsOperation) {
            val encrypted = checkNotNull(settingsOperation)
            val name = operationObjectLeaf(operation, 1)
            writer.create(name, encrypted)
            val actual = checkNotNull(writer.read(name))
            try {
                check(MessageDigest.isEqual(encrypted, actual))
                val reopened = codec.openForOperation(actual, if (productOperation) ProductOperationState.RECORD_ID else SettingsOperationState.RECORD_ID,
                    SecureDataClass.OPERATION_STATE, key, binding)
                try { if (productOperation) ProductOperationState.decode(reopened.plaintext).use {
                    check(it.internalMutationKind == productOperationKind && it.matches(operation, binding.revision - 2, binding.revision))
                } else SettingsOperationState.decode(reopened.plaintext).use {
                    check(it.matches(operation, binding.revision - 2, binding.revision))
                } } finally { reopened.plaintext.fill(0) }
            } finally { actual.fill(0) }
            writer.requireDirtyOperation(operation.clone())
        }
        for ((name, encrypted) in prepared) {
            writer.create(name, encrypted)
            val actual = checkNotNull(writer.read(name))
            try { check(MessageDigest.isEqual(encrypted, actual)) } finally { actual.fill(0) }
        }
        writer.requireDirtyOperation(operation.clone())
    }
    private fun read(name: String): ByteArray? = prepared[name]?.clone() ?: readEncrypted(name)
    private fun checkMutable(id: String, role: SecureDataClass) {
        check(!closed && !sealed); require(id.validRecordId() && isLiveProtectedRole(role.wireValue))
    }
    override fun close() {
        if (!closed) { closed = true; prepared.values.forEach { it.fill(0) }; prepared.clear(); refs.clear(); operation.fill(0)
            settingsOperation?.fill(0); settingsOperation = null }
    }
}

/** Held only inside a broker operation under its writer lease, never by an application caller. */
internal interface ImmutableProtectedObjectWriter {
    fun requireDirtyOperation(operation: ByteArray)
    fun read(name: String): ByteArray?
    fun create(name: String, bytes: ByteArray)
}

/** Copy-on-write logical view. No prior encrypted object is overwritten or eagerly deleted. */
internal class MutableProtectedBlobView(
    references: List<ProtectedObjectReference>, operation: ByteArray, revision: Long,
    private val writer: ImmutableProtectedObjectWriter,
    private val codec: SecureEnvelopeCodec, private val key: KeyEncryptionKey,
) : SecureBlobAccess, AutoCloseable {
    private val operation = operation.clone()
    private val binding = SecureOperationBinding(this.operation, revision)
    private val entries = LinkedHashMap<Pair<Int, String>, ProtectedObjectReference>()
    private var counter = 0L
    private var closed = false
    init {
        require(this.operation.size == JournalLimits.OPERATION_BYTES && this.operation.any { it != 0.toByte() })
        val owned = references.toTypedArray()
        require(owned.size <= JournalLimits.OBJECTS)
        for (entry in owned) check(entries.put(entry.dataClass to entry.logicalId, entry) == null)
        require(owned.map { it.physicalId }.toSet().size == owned.size)
    }

    @Synchronized fun references(): List<ProtectedObjectReference> {
        check(!closed)
        return Collections.unmodifiableList(ArrayList(entries.values))
    }

    @Synchronized override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) {
        val owned = exactBytes.clone()
        try {
            requireMutable(localRecordId, dataClass)
            require(owned.isNotEmpty() && owned.size <= JournalLimits.OBJECT_BYTES - 2048)
            val logical = dataClass.wireValue to localRecordId
            require(entries.containsKey(logical) || entries.size < JournalLimits.OBJECTS)
            check(counter < Long.MAX_VALUE)
            // Increment before acquisition. A partial write permanently consumes this name.
            val physical = operationObjectLeaf(operation, ++counter)
            val encoded = codec.sealForOperation(localRecordId, dataClass, owned, key, binding)
            try {
                val retainedLength = entries.values.sumOf { it.length.toLong() } - (entries[logical]?.length ?: 0)
                require(retainedLength + encoded.size <= JournalLimits.LIVE_OBJECT_BYTES)
                writer.create(physical, encoded)
                val observed = checkNotNull(writer.read(physical))
                try {
                    val reference = ProtectedObjectReference.fromEncryptedObject(dataClass.wireValue,
                        localRecordId, physical, key.generation, encoded, binding)
                    check(reference.matches(observed)) { "OBJECT_DURABILITY_UNPROVEN" }
                    val reopened = codec.openForOperation(observed, localRecordId, dataClass, key, binding)
                    try {
                        check(reopened.dataClass == dataClass && reopened.keyGeneration == key.generation)
                        check(java.security.MessageDigest.isEqual(owned, reopened.plaintext))
                    } finally { reopened.plaintext.fill(0) }
                    requireMutable(localRecordId, dataClass)
                    entries[logical] = reference
                } finally { observed.fill(0) }
            } finally { encoded.fill(0) }
        } finally { owned.fill(0) }
    }

    @Synchronized override fun reopen(localRecordId: String, dataClass: SecureDataClass): ByteArray {
        check(!closed)
        return ReadOnlyProtectedBlobView(entries.values.toList(), writer::read, codec, key).reopen(localRecordId, dataClass)
    }

    @Synchronized override fun exists(localRecordId: String, dataClass: SecureDataClass): Boolean {
        check(!closed)
        return ReadOnlyProtectedBlobView(entries.values.toList(), writer::read, codec, key).exists(localRecordId, dataClass)
    }

    @Synchronized override fun delete(localRecordId: String, dataClass: SecureDataClass) {
        requireMutable(localRecordId, dataClass)
        entries.remove(dataClass.wireValue to localRecordId)
    }

    @Synchronized override fun deleteAll() {
        check(!closed)
        val context = operation.clone()
        try { writer.requireDirtyOperation(context) } finally { context.fill(0) }
        entries.clear()
    }

    private fun requireMutable(id: String, role: SecureDataClass) {
        check(!closed)
        require(id.validRecordId() && role.wireValue in 1..13)
        val context = operation.clone()
        try { writer.requireDirtyOperation(context) } finally { context.fill(0) }
    }

    @Synchronized override fun close() {
        if (!closed) { closed = true; entries.clear(); operation.fill(0) }
    }
}

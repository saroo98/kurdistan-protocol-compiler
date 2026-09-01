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
import org.kurdistanvpn.core.model.Phase9Settings
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

internal data class BrokerMutation<out T>(val status: ProtectedMutationStatus, val value: T? = null,
    val error: OperationError? = null)
private class MutationRejected(val category: OperationError) : IllegalStateException(category.name)

/** Immutable non-authority value. Its codec cannot carry routing, credentials or policy fields. */
internal class ProtectedPresentationValues private constructor(
    val theme: org.kurdistanvpn.core.model.ThemePreference, val highContrast: Boolean,
    val reducedMotion: Boolean, private val diagnosticBytes: ByteArray,
) : AutoCloseable {
    fun merge(settings: Phase9Settings): Phase9Settings = settings.copy(theme = theme,
        highContrast = highContrast, reducedMotion = reducedMotion)
    fun events(): List<DiagnosticEvent> = DiagnosticMemory(diagnosticBytes).use {
        Collections.unmodifiableList(ArrayList(EncryptedDiagnosticEventStore.readOnly(it).load()))
    }
    fun copyOwned(): ProtectedPresentationValues = ProtectedPresentationValues(theme, highContrast, reducedMotion, diagnosticBytes.clone())
    fun withSettings(settings: Phase9Settings) = ProtectedPresentationValues(settings.theme,
        settings.highContrast, settings.reducedMotion, diagnosticBytes.clone())
    fun withEvents(events: List<DiagnosticEvent>): ProtectedPresentationValues =
        create(Phase9Settings(theme = theme, highContrast = highContrast, reducedMotion = reducedMotion), events)
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
        fun create(settings: Phase9Settings, events: List<DiagnosticEvent>): ProtectedPresentationValues {
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
        settings: Phase9Settings?, events: List<DiagnosticEvent>?, random: SecureRandom,
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
}

internal interface ProtectedProjectionAccess : ProtectedProjectionReadAccess {
    fun publish(expected: ProjectionImages, replacement: ProtectedStateSnapshot)
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
    fun resetPendingCredentials(): BrokerMutation<Int> = mutate(MutationKind.CREDENTIAL_DELETE) { state ->
        val pending = state.keys.list().filter {
            it.status == ClientKeyStatus.REQUEST_READY || it.status == ClientKeyStatus.AWAITING_PROFILE
        }
        if (pending.any { it.boundProfileCount != 0 }) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        for (entry in pending) if (!state.keys.delete(entry.localRecordId))
            throw MutationRejected(OperationError.RECOVERY_REQUIRED)
        pending.size
    }

    fun deleteProfile(id: String): BrokerMutation<Unit> = mutate(MutationKind.PROFILE_DELETE) { state ->
        require(id.validRecordId())
        if (!runBlocking { state.admission.delete(id) }) throw MutationRejected(OperationError.POLICY_REJECTED)
        state.removeProfilePreferences(setOf(id))
    }

    fun resetProfiles(ids: Set<String>): BrokerMutation<Unit> {
        val owned = ids.toTypedArray().toSet()
        require(owned.isNotEmpty() && owned.size <= 1024 && owned.all { it.validRecordId() })
        return mutate(MutationKind.SCOPED_RESET) { state ->
            val exclusiveKeys = state.keys.keysExclusivelyBoundTo(owned)
            for (id in owned) if (!runBlocking { state.admission.delete(id) }) throw MutationRejected(OperationError.POLICY_REJECTED)
            for (id in exclusiveKeys) if (!state.keys.delete(id)) throw MutationRejected(OperationError.RECOVERY_REQUIRED)
            state.removeProfilePreferences(owned)
        }
    }

    fun replaceSettings(expectedRevision: Long, value: Phase9Settings): BrokerMutation<Unit> {
        val owned = try { SettingsProjectionCodec.fromModel(value) }
        catch (_: IllegalArgumentException) { return BrokerMutation(ProtectedMutationStatus.NO_MUTATION,
            error = OperationError.INVALID_INPUT) }
        return try {
            val normalized = SettingsProjectionCodec.toModel(owned)
            val before = readCurrent()
            if (before.revision != expectedRevision) return BrokerMutation(ProtectedMutationStatus.NO_MUTATION,
                error = OperationError.RECOVERY_REQUIRED)
            val currentBytes = before.settingsBytes()
            val current = try { SettingsProjectionCodec.toModel(currentBytes) } finally { currentBytes.fill(0) }
            // The allowlist is deliberately only visual state. Privacy, probe/update policy,
            // selection, routing and every other settings field stay security mutations.
            val securityOnly = normalized.copy(theme = current.theme, highContrast = current.highContrast,
                reducedMotion = current.reducedMotion)
            val securityBytes = SettingsProjectionCodec.fromModel(securityOnly)
            val oldBytes = SettingsProjectionCodec.fromModel(current)
            val presentationOnly = try { MessageDigest.isEqual(securityBytes, oldBytes) }
            finally { securityBytes.fill(0); oldBytes.fill(0) }
            if (presentationOnly) mutatePresentation(expectedRevision, normalized, null)
            else {
                val result = mutate(MutationKind.SETTINGS, expectedRevision) { it.replaceSettings(owned) }
                // Mixed explicit settings reset may also change visual preferences. Only report
                // complete success after both independent, typed updates are durably observed.
                if (result.status != ProtectedMutationStatus.COMMITTED) result
                else mutatePresentation(null, normalized, null)
            }
        } catch (_: Exception) { BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN) }
        finally { owned.fill(0) }
    }

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
        try { ProtectedPresentationValues.create(Phase9Settings(), owned).close() }
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

    private fun mutatePresentation(expectedRevision: Long?, settings: Phase9Settings?,
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
                val baseSettings = SettingsProjectionCodec.toModel(bytes)
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
        interpret: (PreparedDomainState) -> T): BrokerMutation<T> = sessions.reserveMutation()?.use { reservation ->
        run mutation@ {
        val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(random::nextBytes)
        if (operation.all { it == 0.toByte() }) return@mutation BrokerMutation(ProtectedMutationStatus.MUTATION_UNPROVEN)
        try {
            var before = readCurrent()
            if ((expectedRevision != null && before.revision != expectedRevision) ||
                (expectedStore != null && !MessageDigest.isEqual(before.storeId(), expectedStore)))
                return@mutation BrokerMutation(ProtectedMutationStatus.NO_MUTATION, error = OperationError.RECOVERY_REQUIRED)
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
                StagedProtectedBlobView(before.objects(), operation, target, readEncrypted, codec, key).use { view ->
                    val state = PreparedDomainState(before, view, native)
                    try {
                    val result = interpret(state)
                    state.validate()
                    val additionalBytes = view.additionalBytes()
                    if (ProtectedStateJournalLifecycle.admission(current, storage.inventory(JournalLimits.OBJECTS), additionalBytes) != JournalAdmission.ADMIT)
                        return@mutation BrokerMutation(ProtectedMutationStatus.CAPACITY_EXHAUSTED)
                    val next = state.snapshot(before.storeId(), target, operation)
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
                            projections.publish(oldProjection, next)
                            reservation.requireCurrent()
                        }, reconstruct = {
                            reservation.requireCurrent()
                            val reconstructed = independentlyReconstruct(next).encode()
                            try { reservation.requireCurrent(); reconstructed }
                            catch (failure: Throwable) { reconstructed.fill(0); throw failure }
                        }, expectedOldControl = oldControl)
                        BrokerMutation(outcome, if (outcome == ProtectedMutationStatus.COMMITTED) result else null)
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

    private fun validateRelationships(snapshot: ProtectedStateSnapshot) {
        check(snapshot.disposition == ProtectedStateDisposition.VERIFIED) { "EXPLICIT_QUARANTINE_RECOVERY_REQUIRED" }
        val view = ReadOnlyProtectedBlobView(snapshot.objects(), readEncrypted, codec, key)
        val rows = snapshot.catalogBytes().let { bytes ->
            try { ProfileCatalogProjectionCodec.decode(bytes) } finally { bytes.fill(0) }
        }
        val settings = snapshot.settingsBytes().let { bytes ->
            try { SettingsProjectionCodec.toModel(bytes) } finally { bytes.fill(0) }
        }
        check(settings.profiles.activeLocalRecordId == snapshot.selectedProfile)
        snapshot.selectedProfile?.let { id -> check(rows.any { it.localRecordId == id &&
            it.transactionState == TransactionState.FINALIZED.name && it.health == CatalogHealth.AVAILABLE.name }) }
        val reader = ProfileAdmissionJournal.readOnly(native, PreparedCatalog(rows), view, false)
        runBlocking { reader.requireCommittedRelationships(snapshot.objects().filter { it.dataClass == 4 }.map { it.logicalId }.toSet()) }
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
private class PreparedDomainState(before: ProtectedStateSnapshot, val view: StagedProtectedBlobView, native: KurdNativeCore) : AutoCloseable {
    private var settings = before.settingsBytes()
    private val catalog = before.catalogBytes().let { raw ->
        try { PreparedCatalog(ProfileCatalogProjectionCodec.decode(raw)) } finally { raw.fill(0) }
    }
    val keys = ClientKeyBundleStore(view, KurdRecipientKeyNative(native))
    val admission = ProfileAdmissionJournal(native, catalog, view, false, keys)
    fun replaceSettings(bytes: ByteArray) {
        val owned = bytes.clone()
        try { SettingsProjectionCodec.toModel(owned) } catch (failure: Throwable) { owned.fill(0); throw failure }
        settings.fill(0); settings = owned
    }
    fun removeProfilePreferences(ids: Set<String>) {
        val old = SettingsProjectionCodec.toModel(settings)
        val profiles = old.profiles.copy(activeLocalRecordId = old.profiles.activeLocalRecordId?.takeIf { it !in ids },
            favoriteLocalRecordIds = old.profiles.favoriteLocalRecordIds - ids)
        val next = SettingsProjectionCodec.fromModel(old.copy(profiles = profiles))
        try { replaceSettings(next) } finally { next.fill(0) }
    }
    fun validate() {
        val model = SettingsProjectionCodec.toModel(settings)
        val rows = runBlocking { catalog.listAll() }
        check(model.profiles.favoriteLocalRecordIds.all { id -> rows.any { it.localRecordId == id } })
        model.profiles.activeLocalRecordId?.let { id -> check(rows.any { it.localRecordId == id &&
            it.transactionState == TransactionState.FINALIZED.name && it.health == CatalogHealth.AVAILABLE.name }) }
        runBlocking { admission.requireCommittedRelationships(view.referenceSnapshot().filter { it.dataClass == 4 }.map { it.logicalId }.toSet()) }
    }
    fun snapshot(store: ByteArray, revision: Long, operation: ByteArray): ProtectedStateSnapshot {
        val op = operation.joinToString("") { "%02x".format(it) }
        val catalogBytes = ProfileCatalogProjectionCodec.encode(runBlocking { catalog.listAll() }.map {
            it.stampCommitted(op, revision, org.kurdistanvpn.data.metadata.CatalogQuarantineReason.NONE)
        })
        return try { ProtectedStateSnapshot.create(store, revision, SettingsProjectionCodec.toModel(settings).profiles.activeLocalRecordId,
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
) : SecureBlobAccess, AutoCloseable {
    private val operation = operation.clone()
    private val binding = SecureOperationBinding(this.operation, revision)
    private val refs = references.toTypedArray().associateBy { it.dataClass to it.logicalId }.toMutableMap()
    private val prepared = LinkedHashMap<String, ByteArray>()
    private var sequence = 0L
    private var sealed = false
    private var closed = false
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
    fun additionalBytes(): Long = prepared.values.sumOf { it.size.toLong() }
    fun persist(writer: ImmutableProtectedObjectWriter) {
        check(!closed && sealed)
        writer.requireDirtyOperation(operation.clone())
        for ((name, encrypted) in prepared) {
            writer.create(name, encrypted)
            val actual = checkNotNull(writer.read(name))
            try { check(MessageDigest.isEqual(encrypted, actual)) } finally { actual.fill(0) }
        }
        writer.requireDirtyOperation(operation.clone())
    }
    private fun read(name: String): ByteArray? = prepared[name]?.clone() ?: readEncrypted(name)
    private fun checkMutable(id: String, role: SecureDataClass) {
        check(!closed && !sealed); require(id.validRecordId() && role.wireValue in 1..13)
    }
    override fun close() {
        if (!closed) { closed = true; prepared.values.forEach { it.fill(0) }; prepared.clear(); refs.clear(); operation.fill(0) }
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

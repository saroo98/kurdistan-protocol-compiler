// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.protectedstate

import org.kurdistanvpn.core.model.DnsMode
import org.kurdistanvpn.core.model.IpMode
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProfilePreferences
import org.kurdistanvpn.core.model.SelectionMode
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.VerifiedPreviewHandle
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.metadata.TransactionState
import org.kurdistanvpn.data.secure.BackupPayloadCodec
import org.kurdistanvpn.data.secure.BackupProfileRecord
import org.kurdistanvpn.data.secure.ClientKeyBackupRecord
import org.kurdistanvpn.data.secure.ClientKeyBundleStore
import org.kurdistanvpn.data.secure.ClientKeyStatus
import org.kurdistanvpn.data.secure.DecodedBackupPayload
import org.kurdistanvpn.data.secure.KeyEncryptionKey
import org.kurdistanvpn.data.secure.KeyInvalidatedException
import org.kurdistanvpn.data.secure.KurdRecipientKeyNative
import org.kurdistanvpn.data.secure.RecipientCredentialLease
import org.kurdistanvpn.data.secure.SecureDataClass
import org.kurdistanvpn.data.secure.SecureEnvelopeCodec
import java.security.MessageDigest
import java.util.concurrent.CancellationException

/** Pure display projections shared by preview, cancellation and ordinary refresh.
 * They confer no authority, migrate nothing, and cannot write a settings store.
 * Backup eligibility and current trust remain with their validating readers.
 */
object ProtectedStatePreviewBackupPolicy {
    fun projectSettings(persisted: Phase9Settings, securePackages: Set<String>): Phase9Settings {
        require(securePackages.size <= 64)
        val routing = persisted.routing.copy(packages = securePackages.toSet()).validatedMetadata()
        return persisted.copy(
            connection = persisted.connection.copy(
                selectionMode = when (persisted.connection.selectionMode) {
                    SelectionMode.AUTOMATIC, SelectionMode.KURD_ONLY -> persisted.connection.selectionMode
                    SelectionMode.MANUAL_STRATEGY -> SelectionMode.AUTOMATIC
                },
                autoConnectOnBoot = false,
                autoConnectOnLaunch = false,
                reconnectOnFailure = false,
                killSwitchRequested = false,
                allowLan = false,
                connectOnlyOnUntrustedNetworks = false,
            ),
            tunnel = persisted.tunnel.copy(
                ipMode = when (persisted.tunnel.ipMode) {
                    IpMode.AUTO, IpMode.IPV4_ONLY -> persisted.tunnel.ipMode
                    IpMode.IPV6_ONLY, IpMode.DUAL_STACK -> IpMode.AUTO
                },
                dnsMode = DnsMode.INTERNAL_TUN,
                customDns = "",
                showSpeedInNotification = false,
            ),
            // Never promote a legacy plaintext package list into protected routing.
            routing = routing,
            updates = UpdatePreferences(),
            probes = persisted.probes.copy(method = ProbeMethod.KURD_SESSION, testUrl = ProbePreferences().testUrl),
        )
    }

    fun projectProfiles(persisted: ProfilePreferences, knownProfileIds: List<String>): ProfilePreferences {
        require(knownProfileIds.size <= 1024)
        val known = knownProfileIds.toList()
        require(known.distinct().size == known.size && known.all { it.matches(Regex("[a-z0-9-]{1,64}")) })
        val ids = known.toSet()
        return ProfilePreferences(
            activeLocalRecordId = persisted.activeLocalRecordId?.takeIf(ids::contains) ?: known.firstOrNull(),
            favoriteLocalRecordIds = persisted.favoriteLocalRecordIds.filterTo(linkedSetOf(), ids::contains),
        )
    }
}

sealed interface NativePreviewRequestOutcome {
    data class Ready(val request: ReleasedNativePreviewRequest) : NativePreviewRequestOutcome
    data class Rejected(val error: OperationError) : NativePreviewRequestOutcome
    data object CleanupUnproven : NativePreviewRequestOutcome
}

/** Owns only encoded import bytes after the native preview handle has been released.
 * It is not authority and performs no admission, recovery or persistence. The caller must
 * obtain explicit confirmation before taking the single owned request for fresh admission.
 */
class ReleasedNativePreviewRequest private constructor(
    private val bytes: ByteArray,
    val display: RedactedProfilePreview,
) : AutoCloseable {
    private var terminal = false

    @Synchronized fun takeConfirmedRequest(): ByteArray {
        check(!terminal) { "PREVIEW_REQUEST_ALREADY_CONSUMED" }
        terminal = true
        return try { bytes.clone() } finally { bytes.fill(0) }
    }

    @Synchronized override fun close() { terminal = true; bytes.fill(0) }

    companion object {
        fun resolve(
            input: ByteArray,
            resolve: (ByteArray) -> NativeResult<VerifiedPreviewHandle>,
            release: (VerifiedPreviewHandle) -> NativeResult<Unit>,
        ): NativePreviewRequestOutcome {
            val owned = input.clone()
            try {
                if (owned.size !in 1..1_500_000)
                    return NativePreviewRequestOutcome.Rejected(OperationError.INVALID_INPUT)
                return when (val result = resolve(owned)) {
                    is NativeResult.Failure -> NativePreviewRequestOutcome.Rejected(result.error)
                    is NativeResult.Success -> {
                        val display = releaseOwnedNativePreview(result.value, release) { it }
                        val retained = owned.clone()
                        try {
                            NativePreviewRequestOutcome.Ready(ReleasedNativePreviewRequest(retained, display))
                        } catch (failure: Throwable) { retained.fill(0); throw failure }
                    }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: NativePreviewCleanupUnproven) {
                return NativePreviewRequestOutcome.CleanupUnproven
            }
            catch (_: KeyInvalidatedException) {
                return NativePreviewRequestOutcome.Rejected(OperationError.KEY_INVALIDATED)
            } catch (_: Exception) {
                return NativePreviewRequestOutcome.Rejected(OperationError.INTERNAL_FAILURE)
            } finally { owned.fill(0) }
        }
    }
}

private class NativePreviewCleanupUnproven : IllegalStateException("NATIVE_PREVIEW_CLEANUP_UNPROVEN")

/** Release is attempted once. A failed or throwing native release cannot establish cleanup,
 * and retrying the same numeric handle could target a subsequently reused native slot. */
private fun <T> releaseOwnedNativePreview(
    handle: VerifiedPreviewHandle,
    release: (VerifiedPreviewHandle) -> NativeResult<Unit>,
    block: (RedactedProfilePreview) -> T,
): T = try {
    check(handle.handle > 0) { "NATIVE_PREVIEW_HANDLE_INVALID" }
    block(handle.preview)
} finally {
    val released = try { release(handle) } catch (_: Throwable) { throw NativePreviewCleanupUnproven() }
    if (released !is NativeResult.Success) throw NativePreviewCleanupUnproven()
}

enum class ProtectedReadFailure { CANCELLED, EXPIRED, REJECTED, STATE_UNPROVEN, CLEANUP_UNPROVEN }

sealed interface ProtectedExternalPreviewResult {
    data class Ready(val preview: PendingProtectedImport) : ProtectedExternalPreviewResult
    data class Rejected(val category: ProtectedReadFailure) : ProtectedExternalPreviewResult
}

/** No native handle, recipient secret, mutable store or mutation receipt is exposed. */
sealed interface PendingProtectedImport : AutoCloseable {
    val display: RedactedProfilePreview
    fun confirm(): ConfirmedProtectedImport
}

/** Confirmation is user intent, not authority. The broker must perform fresh admission and
 * expected-revision comparison before its mutation. The single owned request is wiped on close. */
class ConfirmedProtectedImport private constructor(
    private val request: ByteArray, val display: RedactedProfilePreview,
    val recipientKeyId: String?, val revision: Long, private val store: ByteArray,
) : AutoCloseable {
    private var terminal = false
    fun storeId(): ByteArray = store.clone()
    @Synchronized fun takeRequest(): ByteArray {
        check(!terminal) { "CONFIRMED_REQUEST_ALREADY_CONSUMED" }; terminal = true
        return try { request.clone() } finally { request.fill(0) }
    }
    @Synchronized override fun close() { terminal = true; request.fill(0); store.fill(0) }
    companion object {
        internal fun owned(request: ByteArray, display: RedactedProfilePreview, recipientKeyId: String?,
            snapshot: ProtectedStateSnapshot): ConfirmedProtectedImport {
            val copy = request.clone()
            return try { ConfirmedProtectedImport(copy, display, recipientKeyId, snapshot.revision, snapshot.storeId()) }
            catch (failure: Throwable) { copy.fill(0); throw failure }
        }
    }
}

sealed interface ProtectedBackupEnumeration {
    data class Ready(val plan: PendingProtectedBackup) : ProtectedBackupEnumeration
    data class Rejected(val category: ProtectedReadFailure) : ProtectedBackupEnumeration
}

/** Enumeration owns no private key or plaintext backup. Export is a distinct explicit action. */
sealed interface PendingProtectedBackup : AutoCloseable {
    val profileCount: Int
    val keyCount: Int
    fun confirmEncryptedExport(passphrase: ByteArray): NativeResult<ByteArray>
}

private class ReadDenied(val category: ProtectedReadFailure) : IllegalStateException(category.name)

/**
 * Pure read-facing adapter over an already established committed checkpoint. It cannot construct
 * Room/DataStore, bootstrap a key, acquire a journal writer, normalize settings, persist diagnostics,
 * recover PREPARED recipients or perform admission. Composition checks unlock before loading the
 * existing key. The injected object reader transfers owned encrypted bytes, never plaintext.
 *
 * A native verifier returning a handle transfers its ownership to this adapter. A failure to
 * release that handle prevents a confirmable result. The JNI implementation must also clean any
 * handle created internally before it throws; that cannot be established by this host adapter.
 */
internal class ProtectedStatePreviewBackupReader(
    private val snapshots: ProtectedStateSnapshotReader,
    private val encryptedObject: (String) -> ByteArray?,
    private val codec: SecureEnvelopeCodec,
    private val existingKey: KeyEncryptionKey,
    private val native: KurdNativeCore,
    private val projections: ProtectedProjectionReadAccess,
    private val isCancelled: () -> Boolean,
    private val elapsedMillis: () -> Long,
) {
    fun previewExternal(input: ByteArray): ProtectedExternalPreviewResult {
        // Capture before inspecting caller-owned data. No later read of input is permitted.
        val request = input.clone()
        return try {
            require(request.size in 1..MAX_REQUEST)
            val started = elapsedMillis(); checkLive(started)
            val view = readView(started)
            val resolved = resolveExternal(request, view, started)
            checkCurrent(view.snapshot, started)
            ProtectedExternalPreviewResult.Ready(OwnedPendingImport(request, resolved.first, resolved.second,
                view.snapshot) { checkCurrent(view.snapshot, elapsedMillis()) })
        } catch (failure: Exception) { ProtectedExternalPreviewResult.Rejected(category(failure)) }
        finally { request.fill(0) }
    }

    fun enumerateOrdinaryBackup(selectedProfile: String? = null): ProtectedBackupEnumeration = try {
        require(selectedProfile == null || selectedProfile.validRecordId())
        val started = elapsedMillis(); checkLive(started)
        val view = readView(started)
        val encoded = buildOrdinaryBackup(view, selectedProfile, started)
        val counts = try { encoded.profiles to encoded.keys } finally { encoded.close() }
        checkCurrent(view.snapshot, started)
        ProtectedBackupEnumeration.Ready(OwnedPendingBackup(counts.first, counts.second) { password ->
            exportConfirmed(view.snapshot, selectedProfile, password)
        })
    } catch (failure: Exception) { ProtectedBackupEnumeration.Rejected(category(failure)) }

    private fun exportConfirmed(expected: ProtectedStateSnapshot, selected: String?, password: ByteArray): NativeResult<ByteArray> {
        var result: ByteArray? = null
        return try {
            require(password.size in 1..1024)
            val started = elapsedMillis(); checkLive(started)
            val view = readView(started)
            requireSameCheckpoint(expected, view.snapshot)
            buildOrdinaryBackup(view, selected, started).use { backup ->
                checkCurrent(expected, started)
                // Only this explicitly confirmed path reaches the existing authenticated wrapper.
                when (val wrapped = native.createBackup(backup.bytes, password)) {
                    is NativeResult.Failure -> wrapped
                    is NativeResult.Success -> {
                        result = wrapped.value
                        require(wrapped.value.size in 1..MAX_BACKUP_OUTPUT)
                        checkCurrent(expected, started)
                        NativeResult.Success(wrapped.value.clone())
                    }
                }
            }
        } catch (_: ReadDenied) { NativeResult.Failure(OperationError.CANCELLED) }
        catch (_: KeyInvalidatedException) { NativeResult.Failure(OperationError.KEY_INVALIDATED) }
        catch (_: Exception) { NativeResult.Failure(OperationError.RECOVERY_REQUIRED) }
        finally { result?.fill(0) }
    }

    private fun resolveExternal(request: ByteArray, view: ReadView, started: Long): Pair<RedactedProfilePreview, String?> {
        when (val public = native.verifyPreview(request)) {
            is NativeResult.Success -> {
                val safe = releaseAfter(public.value) { checkLive(started); check(!it.sealed); it }
                return safe to null
            }
            is NativeResult.Failure -> checkLive(started)
        }
        // The secure read-only factory excludes PREPARED without promoting or deleting it.
        val candidates = view.keys.credentialCandidates()
        try {
            check(candidates.size <= 32)
            for (candidate in candidates) {
                checkLive(started)
                when (val result = native.verifyPreviewWithRecipient(request, candidate.publicRequest, candidate.privateBundle)) {
                    is NativeResult.Success -> {
                        val safe = releaseAfter(result.value) { checkLive(started); check(it.sealed); it }
                        return safe to candidate.localRecordId
                    }
                    is NativeResult.Failure -> checkLive(started)
                }
            }
            throw ReadDenied(ProtectedReadFailure.REJECTED)
        } finally { candidates.forEach(RecipientCredentialLease::close) }
    }

    private fun buildOrdinaryBackup(view: ReadView, selected: String?, started: Long): EncodedBackup {
        val catalogBytes = view.snapshot.catalogBytes()
        val catalog = try { ProfileCatalogProjectionCodec.decode(catalogBytes) } finally { catalogBytes.fill(0) }
        val included = catalog.filter { it.transactionState == TransactionState.FINALIZED.name &&
            it.health == CatalogHealth.AVAILABLE.name && (selected == null || selected == it.localRecordId) }
        require(included.isNotEmpty() && included.size <= 128 && (selected == null || included.size == 1))
        val profiles = mutableListOf<BackupProfileRecord>()
        val keys = linkedMapOf<String, ClientKeyBackupRecord>()
        var requestBytes = 0L
        try {
            for (row in included) {
                checkLive(started)
                val request = view.blobs.reopen(row.localRecordId, SecureDataClass.IMPORT_REQUEST)
                var transferred = false
                try {
                    require(request.size in 1..MAX_REQUEST)
                    requestBytes += request.size
                    require(requestBytes <= MAX_BACKUP_PAYLOAD)
                    val credential = view.keys.credentialsForProfile(row.localRecordId)
                    val preview = try {
                        val verification = if (credential == null) native.verifyPreview(request)
                        else native.verifyPreviewWithRecipient(request, credential.publicRequest, credential.privateBundle)
                        when (verification) {
                            is NativeResult.Failure -> throw ReadDenied(ProtectedReadFailure.REJECTED)
                            is NativeResult.Success -> releaseAfter(verification.value) {
                                checkLive(started)
                                check(it.sealed == (credential != null)) { "PROFILE_BINDING_MISMATCH" }
                                check(it.generation > 0uL)
                                it
                            }
                        }
                    } finally { credential?.close() }
                    val bound = view.keys.backupRecords(row.localRecordId)
                    try {
                        check(bound.size == if (preview.sealed) 1 else 0) { "PROFILE_BINDING_MISMATCH" }
                        for (key in bound) {
                            check(key.sourceStatus == ClientKeyStatus.PROFILE_VERIFIED && key.sourceVersion == 2 &&
                                key.sourceProfileRecordIds == listOf(row.localRecordId)) { "BACKUP_BINDING_MISMATCH" }
                            val old = keys[key.sourceRecordId]
                            val replacement = if (old == null) key.copy() else {
                                // One key may already be bound to more than one included profile. Preserve
                                // exactly those existing associations, never infer or add a new binding.
                                checkSameKey(old, key)
                                key.copy(sourceProfileRecordIds = (old.sourceProfileRecordIds + row.localRecordId).sorted())
                            }
                            keys[key.sourceRecordId] = replacement
                            old?.destroy()
                        }
                    } finally { bound.forEach(ClientKeyBackupRecord::destroy) }
                    profiles += BackupProfileRecord(row.localRecordId, preview.generation, request)
                    transferred = true
                } finally { if (!transferred) request.fill(0) }
            }
            checkLive(started)
            val bytes = BackupPayloadCodec.encode(DecodedBackupPayload(profiles, keys.values.toList()))
            return EncodedBackup(bytes, profiles.size, keys.size)
        } finally { profiles.forEach { it.verifyRequest.fill(0) }; keys.values.forEach(ClientKeyBackupRecord::destroy) }
    }

    private fun checkSameKey(left: ClientKeyBackupRecord, right: ClientKeyBackupRecord) {
        check(left.createdAtEpochSeconds == right.createdAtEpochSeconds && left.expiresAtEpochSeconds == right.expiresAtEpochSeconds)
        left.withMaterial { leftRequest, leftPrivate -> right.withMaterial { rightRequest, rightPrivate ->
            check(MessageDigest.isEqual(leftRequest, rightRequest) && MessageDigest.isEqual(leftPrivate, rightPrivate))
        } }
    }

    private fun <T> releaseAfter(handle: VerifiedPreviewHandle, block: (RedactedProfilePreview) -> T): T =
        releaseOwnedNativePreview(handle, native::releaseVerified, block)

    private fun readView(started: Long): ReadView {
        checkLive(started)
        val snapshot = snapshots.readCheckpointSnapshot()
        check(snapshot.disposition == ProtectedStateDisposition.VERIFIED) { "EXPLICIT_RECOVERY_REQUIRED" }
        val observed = projections.read()
        observed.requireMatches(snapshot)
        snapshots.requirePhysicalProjection(snapshot, observed.physical())
        checkLive(started)
        val references = snapshot.objects().associateBy { it.physicalId }
        var attempts = 0; var bytes = 0L
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { name ->
            checkLive(started)
            val reference = checkNotNull(references[name]) { "UNCOMMITTED_PREVIEW_OBJECT" }
            check(++attempts <= 1024 && reference.length <= JournalLimits.LIVE_OBJECT_BYTES - bytes) { "READ_BOUND_EXCEEDED" }
            bytes += reference.length
            val owned = checkNotNull(encryptedObject(name))
            try { checkLive(started); check(reference.matches(owned)); owned }
            catch (failure: Throwable) { owned.fill(0); throw failure }
        }, codec, existingKey)
        return ReadView(snapshot, blobs, ClientKeyBundleStore.readOnly(blobs, KurdRecipientKeyNative(native)))
    }

    private fun checkCurrent(expected: ProtectedStateSnapshot, started: Long) {
        checkLive(started)
        val actual = snapshots.readCheckpointSnapshot()
        val observed = projections.read()
        observed.requireMatches(actual)
        snapshots.requirePhysicalProjection(actual, observed.physical())
        requireSameCheckpoint(expected, actual)
        checkLive(started)
    }
    private fun requireSameCheckpoint(expected: ProtectedStateSnapshot, actual: ProtectedStateSnapshot) {
        val old = expected.encode(); val current = actual.encode()
        try { check(MessageDigest.isEqual(old, current)) { "TRUSTED_STATE_CHANGED" } }
        finally { old.fill(0); current.fill(0) }
    }
    private fun checkLive(started: Long) {
        if (isCancelled()) throw ReadDenied(ProtectedReadFailure.CANCELLED)
        val now = elapsedMillis()
        if (started < 0 || now < started || now - started >= JournalLimits.RESTORE_NANOS / 1_000_000)
            throw ReadDenied(ProtectedReadFailure.EXPIRED)
    }
    private fun category(failure: Exception): ProtectedReadFailure = when (failure) {
        is ReadDenied -> failure.category
        is NativePreviewCleanupUnproven -> ProtectedReadFailure.CLEANUP_UNPROVEN
        else -> ProtectedReadFailure.STATE_UNPROVEN
    }
    private class ReadView(val snapshot: ProtectedStateSnapshot, val blobs: ReadOnlyProtectedBlobView, val keys: ClientKeyBundleStore)
    private class EncodedBackup(val bytes: ByteArray, val profiles: Int, val keys: Int) : AutoCloseable {
        override fun close() { bytes.fill(0) }
    }
    private companion object {
        const val MAX_REQUEST = 1024 * 1024
        const val MAX_BACKUP_PAYLOAD = 8 * 1024 * 1024
        const val MAX_BACKUP_OUTPUT = MAX_BACKUP_PAYLOAD + 64 * 1024
    }
}

private class OwnedPendingImport(request: ByteArray, override val display: RedactedProfilePreview,
    private val recipient: String?, private val snapshot: ProtectedStateSnapshot,
    private val revalidate: () -> Unit) : PendingProtectedImport {
    private val owned = request.clone()
    private var terminal = false
    @Synchronized override fun confirm(): ConfirmedProtectedImport {
        check(!terminal) { "PREVIEW_ALREADY_CONSUMED" }; terminal = true
        return try { revalidate(); ConfirmedProtectedImport.owned(owned, display, recipient, snapshot) }
        catch (failure: Exception) {
            throw if (failure is ReadDenied) failure else ReadDenied(ProtectedReadFailure.STATE_UNPROVEN)
        }
        finally { owned.fill(0) }
    }
    @Synchronized override fun close() { terminal = true; owned.fill(0) }
}

private class OwnedPendingBackup(override val profileCount: Int, override val keyCount: Int,
    private val export: (ByteArray) -> NativeResult<ByteArray>) : PendingProtectedBackup {
    private var terminal = false
    @Synchronized override fun confirmEncryptedExport(passphrase: ByteArray): NativeResult<ByteArray> {
        val owned = passphrase.clone()
        try {
            check(!terminal) { "BACKUP_PREVIEW_ALREADY_CONSUMED" }; terminal = true
            return export(owned)
        } finally { owned.fill(0) }
    }
    @Synchronized override fun close() { terminal = true }
}

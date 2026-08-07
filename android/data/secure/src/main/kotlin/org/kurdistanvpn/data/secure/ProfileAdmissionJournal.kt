// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.nativeapi.ActivationCommand
import org.kurdistanvpn.core.nativeapi.ActivationCommandKind
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeActivationSession
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.VerifiedPreviewHandle
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.metadata.ProfileCatalogDao
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.TransactionState

data class AdmissionOutcome(
    val localRecordId: String,
    val summary: ProfileSummary,
)

sealed interface AdmissionResult {
    data class Success(val outcome: AdmissionOutcome) : AdmissionResult
    data class Failure(val error: OperationError) : AdmissionResult
}

sealed interface RestoreResult {
    data class Success(val restoredProfiles: Int) : RestoreResult
    data class Failure(val error: OperationError) : RestoreResult
}

class RuntimeAuthorityMaterial(
    val verifyRequest: ByteArray,
    val activationRecord: ByteArray,
) : AutoCloseable {
    override fun close() {
        verifyRequest.fill(0)
        activationRecord.fill(0)
    }
}

sealed interface RuntimeAuthorityResult {
    data class Success(val material: RuntimeAuthorityMaterial) : RuntimeAuthorityResult
    data class Failure(val error: OperationError) : RuntimeAuthorityResult
}

/**
 * Cross-resource journal for Go activation plus Room metadata and encrypted
 * blob persistence. Every durable boundary is recorded before the next Go
 * command is accepted. Incomplete work is replayed from the encrypted import
 * request after process death.
 */
class ProfileAdmissionJournal(
    private val nativeCore: KurdNativeCore,
    private val catalog: ProfileCatalogDao,
    private val blobs: SecureBlobAccess,
    private val productionTrust: Boolean,
    private val recipientKeys: ClientKeyBundleStore? = null,
    private val random: SecureRandom = SecureRandom(),
) {
    private companion object {
        const val RESTORE_RECORD_ID = "restore-current"
    }

    suspend fun admit(
        verifyRequest: ByteArray,
        expectedPreview: RedactedProfilePreview,
        recipientKeyLocalId: String? = null,
    ): AdmissionResult = withContext(Dispatchers.IO) {
        admitInternal(
            verifyRequest = verifyRequest,
            expectedPreview = expectedPreview,
            finalHealth = CatalogHealth.AVAILABLE,
            publishSuperseded = true,
            recipientKeyLocalId = recipientKeyLocalId,
        )
    }

    suspend fun restore(records: List<BackupProfileRecord>): RestoreResult =
        withContext(Dispatchers.IO) {
            if (blobs.exists(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH)) {
                return@withContext RestoreResult.Failure(OperationError.RECOVERY_REQUIRED)
            }
            val encoded = runCatching { BackupPayloadCodec.encode(records) }
                .getOrElse {
                    return@withContext RestoreResult.Failure(OperationError.INVALID_INPUT)
                }
            try {
                blobs.stage(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH, encoded)
            } catch (_: KeyInvalidatedException) {
                return@withContext RestoreResult.Failure(OperationError.KEY_INVALIDATED)
            } catch (_: Throwable) {
                return@withContext RestoreResult.Failure(OperationError.STORAGE_FAILURE)
            } finally {
                encoded.fill(0)
            }
            resumeRestore()
        }

    suspend fun recoverPendingRestore(): RestoreResult? = withContext(Dispatchers.IO) {
        if (!blobs.exists(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH)) {
            return@withContext null
        }
        resumeRestore()
    }

    private suspend fun admitInternal(
        verifyRequest: ByteArray,
        expectedPreview: RedactedProfilePreview,
        finalHealth: CatalogHealth,
        publishSuperseded: Boolean,
        recipientKeyLocalId: String? = null,
    ): AdmissionResult {
        val resolved = when (val result = resolveVerified(verifyRequest, recipientKeyLocalId)) {
            is NativeResult.Failure -> return AdmissionResult.Failure(result.error)
            is NativeResult.Success -> result.value
        }
        val verified = resolved.verified
        return try {
            if (verified.preview != expectedPreview) {
                return AdmissionResult.Failure(OperationError.TRUST_REJECTED)
            }
            val conflict = admissionConflict(verified)
            if (conflict.error != null) {
                return AdmissionResult.Failure(conflict.error)
            }
            val recordId = newRecordId()
            try {
                blobs.stage(recordId, SecureDataClass.IMPORT_REQUEST, verifyRequest)
                catalog.upsert(entity(recordId, TransactionState.PREPARED))
            } catch (_: KeyInvalidatedException) {
                cleanupFailedPreparation(recordId)
                return AdmissionResult.Failure(OperationError.KEY_INVALIDATED)
            } catch (_: Throwable) {
                cleanupFailedPreparation(recordId)
                return AdmissionResult.Failure(OperationError.STORAGE_FAILURE)
            }
            val result = activate(recordId, verified, finalHealth)
            if (result is AdmissionResult.Success && resolved.recipientKeyLocalId != null) {
                try {
                    recipientKeys?.bindProfile(resolved.recipientKeyLocalId, result.outcome.localRecordId)
                        ?: return AdmissionResult.Failure(OperationError.KEY_INVALIDATED)
                } catch (_: Throwable) {
                    delete(result.outcome.localRecordId)
                    return AdmissionResult.Failure(OperationError.STORAGE_FAILURE)
                }
            }
            if (result is AdmissionResult.Success && publishSuperseded) {
                conflict.superseded.forEach { row ->
                    catalog.upsert(row.copy(health = CatalogHealth.SUPERSEDED.name))
                }
            }
            result
        } finally {
            nativeCore.releaseVerified(verified)
        }
    }

    suspend fun recoverIncomplete(): List<AdmissionResult> = withContext(Dispatchers.IO) {
        catalog.listAll()
            .filter { it.transactionState != TransactionState.FINALIZED.name }
            .map { row ->
                recoverOne(row)
            }
    }

    suspend fun listProfiles(): List<ProfileSummary> = withContext(Dispatchers.IO) {
        val summaries = mutableListOf<ProfileSummary>()
        for (row in catalog.listAll()) {
            if (row.transactionState != TransactionState.FINALIZED.name ||
                row.health != CatalogHealth.AVAILABLE.name
            ) {
                continue
            }
            try {
                val encoded = blobs.reopen(row.localRecordId, SecureDataClass.PROFILE_PREVIEW)
                try {
                    val (preview, alias) = ProfilePreviewCodec.decode(encoded)
                    summaries += ProfilePreviewCodec.summary(
                        row.localRecordId,
                        preview,
                        alias,
                        productionTrust,
                    )
                } finally {
                    encoded.fill(0)
                }
            } catch (_: KeyInvalidatedException) {
                catalog.upsert(row.copy(health = CatalogHealth.KEY_INVALIDATED.name))
            } catch (_: Throwable) {
                catalog.upsert(row.copy(health = CatalogHealth.QUARANTINED.name))
            }
        }
        summaries
    }

    suspend fun storageHealth(): CatalogHealth = withContext(Dispatchers.IO) {
        val values = catalog.listAll().map { it.health }.toSet()
        when {
            CatalogHealth.KEY_INVALIDATED.name in values -> CatalogHealth.KEY_INVALIDATED
            CatalogHealth.QUARANTINED.name in values -> CatalogHealth.QUARANTINED
            CatalogHealth.DEGRADED.name in values -> CatalogHealth.DEGRADED
            else -> CatalogHealth.AVAILABLE
        }
    }

    suspend fun backupPayload(localRecordId: String? = null): ByteArray = withContext(Dispatchers.IO) {
        val records = mutableListOf<BackupProfileRecord>()
        var keyRecords = emptyList<ClientKeyBackupRecord>()
        try {
            catalog.listAll()
                .filter {
                    it.transactionState == TransactionState.FINALIZED.name &&
                        it.health == CatalogHealth.AVAILABLE.name &&
                        (localRecordId == null || it.localRecordId == localRecordId)
                }
                .forEach { row ->
                    val encodedPreview =
                        blobs.reopen(row.localRecordId, SecureDataClass.PROFILE_PREVIEW)
                    val preview = try {
                        ProfilePreviewCodec.decode(encodedPreview).first
                    } finally {
                        encodedPreview.fill(0)
                    }
                    records += BackupProfileRecord(
                        localRecordId = row.localRecordId,
                        generation = preview.generation,
                        verifyRequest =
                            blobs.reopen(row.localRecordId, SecureDataClass.IMPORT_REQUEST),
                    )
                }
            require(localRecordId == null || records.size == 1)
            keyRecords = recipientKeys?.backupRecords(localRecordId).orEmpty()
            BackupPayloadCodec.encode(DecodedBackupPayload(records, keyRecords))
        } finally {
            records.forEach { it.verifyRequest.fill(0) }
            keyRecords.forEach(ClientKeyBackupRecord::destroy)
        }
    }

    suspend fun openRuntimeAuthority(localRecordId: String): RuntimeAuthorityResult =
        withContext(Dispatchers.IO) {
            val row = catalog.get(localRecordId)
                ?: return@withContext RuntimeAuthorityResult.Failure(
                    OperationError.POLICY_REJECTED,
                )
            if (row.transactionState != TransactionState.FINALIZED.name ||
                row.health != CatalogHealth.AVAILABLE.name
            ) {
                return@withContext RuntimeAuthorityResult.Failure(
                    OperationError.POLICY_REJECTED,
                )
            }
            var verifyRequest: ByteArray? = null
            var activationRecord: ByteArray? = null
            try {
                verifyRequest = blobs.reopen(localRecordId, SecureDataClass.IMPORT_REQUEST)
                activationRecord = blobs.reopen(
                    localRecordId,
                    SecureDataClass.ACTIVATION_ACTIVE,
                )
                if (verifyRequest.isEmpty() || activationRecord.isEmpty()) {
                    verifyRequest.fill(0)
                    activationRecord.fill(0)
                    return@withContext RuntimeAuthorityResult.Failure(
                        OperationError.QUARANTINED,
                    )
                }
                RuntimeAuthorityResult.Success(
                    RuntimeAuthorityMaterial(verifyRequest, activationRecord),
                )
            } catch (_: KeyInvalidatedException) {
                verifyRequest?.fill(0)
                activationRecord?.fill(0)
                RuntimeAuthorityResult.Failure(OperationError.KEY_INVALIDATED)
            } catch (_: Throwable) {
                verifyRequest?.fill(0)
                activationRecord?.fill(0)
                RuntimeAuthorityResult.Failure(OperationError.STORAGE_FAILURE)
            }
        }

    suspend fun delete(localRecordId: String): Boolean = withContext(Dispatchers.IO) {
        try {
            SecureDataClass.entries.forEach { dataClass ->
                blobs.delete(localRecordId, dataClass)
            }
            catalog.delete(localRecordId)
            true
        } catch (_: Throwable) {
            false
        }
    }

    suspend fun resetAll(): Boolean = withContext(Dispatchers.IO) {
        try {
            blobs.deleteAll()
            catalog.deleteAll()
            true
        } catch (_: Throwable) {
            false
        }
    }

    private suspend fun recoverOne(row: ProfileCatalogEntity): AdmissionResult {
        val recordId = row.localRecordId
        return try {
            val request = blobs.reopen(recordId, SecureDataClass.IMPORT_REQUEST)
            try {
                clearActivationBlobs(recordId)
                catalog.upsert(entity(recordId, TransactionState.PREPARED))
                val resolved = when (val result = resolveVerified(request, null)) {
                    is NativeResult.Failure -> {
                        quarantine(recordId)
                        return AdmissionResult.Failure(result.error)
                    }
                    is NativeResult.Success -> result.value
                }
                val verified = resolved.verified
                try {
                    val activated = activate(recordId, verified)
                    if (activated is AdmissionResult.Success && resolved.recipientKeyLocalId != null) {
                        recipientKeys?.bindProfile(resolved.recipientKeyLocalId, recordId)
                            ?: return AdmissionResult.Failure(OperationError.KEY_INVALIDATED)
                    }
                    activated
                } finally {
                    nativeCore.releaseVerified(verified)
                }
            } finally {
                request.fill(0)
            }
        } catch (_: KeyInvalidatedException) {
            catalog.upsert(
                entity(
                    recordId,
                    TransactionState.RECOVERY_REQUIRED,
                    CatalogHealth.KEY_INVALIDATED,
                ),
            )
            AdmissionResult.Failure(OperationError.KEY_INVALIDATED)
        } catch (_: Throwable) {
            quarantine(recordId)
            AdmissionResult.Failure(OperationError.QUARANTINED)
        }
    }

    private suspend fun activate(
        recordId: String,
        verified: VerifiedPreviewHandle,
        finalHealth: CatalogHealth = CatalogHealth.AVAILABLE,
    ): AdmissionResult {
        val session = when (val result = nativeCore.openActivation(verified)) {
            is NativeResult.Failure -> return AdmissionResult.Failure(result.error)
            is NativeResult.Success -> result.value
        }
        return session.use {
            driveSession(recordId, verified, session, finalHealth)
        }
    }

    private suspend fun driveSession(
        recordId: String,
        verified: VerifiedPreviewHandle,
        session: NativeActivationSession,
        finalHealth: CatalogHealth,
    ): AdmissionResult {
        while (true) {
            val command = when (val result = session.next()) {
                is NativeResult.Failure -> {
                    quarantine(recordId)
                    return AdmissionResult.Failure(result.error)
                }
                is NativeResult.Success -> result.value
            }
            try {
                if (command.kind == ActivationCommandKind.COMPLETE) {
                    val active = blobs.reopen(recordId, SecureDataClass.ACTIVATION_ACTIVE)
                    try {
                        if (!active.contentEquals(command.opaqueRecord)) {
                            quarantine(recordId)
                            return AdmissionResult.Failure(OperationError.QUARANTINED)
                        }
                    } finally {
                        active.fill(0)
                    }
                    val alias = "Kurd profile ${verified.preview.contentFingerprint.take(8)}"
                    val encodedPreview = ProfilePreviewCodec.encode(verified.preview, alias)
                    try {
                        blobs.stage(
                            recordId,
                            SecureDataClass.PROFILE_PREVIEW,
                            encodedPreview,
                        )
                    } finally {
                        encodedPreview.fill(0)
                    }
                    catalog.upsert(entity(recordId, TransactionState.FINALIZED, finalHealth))
                    return AdmissionResult.Success(
                        AdmissionOutcome(
                            localRecordId = recordId,
                            summary = ProfilePreviewCodec.summary(
                                recordId,
                                verified.preview,
                                alias,
                                productionTrust,
                            ),
                        ),
                    )
                }
                var payloads: StoragePayloads? = null
                val submit = try {
                    val produced = execute(recordId, command)
                    payloads = produced
                    session.submit(
                        command,
                        storageSucceeded = true,
                        active = produced.active,
                        lastKnownGood = produced.lastKnownGood,
                        reopened = produced.reopened,
                    )
                } catch (_: Throwable) {
                    session.submit(command, storageSucceeded = false)
                } finally {
                    payloads?.destroy()
                }
                if (submit is NativeResult.Failure &&
                    submit.error !in setOf(
                        OperationError.STORAGE_FAILURE,
                        OperationError.RECOVERY_REQUIRED,
                        OperationError.QUARANTINED,
                    )
                ) {
                    quarantine(recordId)
                    return AdmissionResult.Failure(submit.error)
                }
            } finally {
                command.opaqueRecord.fill(0)
            }
        }
    }

    private suspend fun execute(
        recordId: String,
        command: ActivationCommand,
    ): StoragePayloads =
        when (command.kind) {
            ActivationCommandKind.SNAPSHOT -> StoragePayloads(
                active = reopenIfPresent(recordId, SecureDataClass.ACTIVATION_ACTIVE),
                lastKnownGood = reopenIfPresent(
                    recordId,
                    SecureDataClass.ACTIVATION_LAST_KNOWN_GOOD,
                ),
            )
            ActivationCommandKind.STAGE_CANDIDATE -> {
                blobs.stage(
                    recordId,
                    SecureDataClass.ACTIVATION_STAGED,
                    command.opaqueRecord,
                )
                catalog.upsert(entity(recordId, TransactionState.STAGED))
                StoragePayloads()
            }
            ActivationCommandKind.REOPEN_CANDIDATE -> {
                val reopened = blobs.reopen(recordId, SecureDataClass.ACTIVATION_STAGED)
                catalog.upsert(entity(recordId, TransactionState.REOPENED))
                StoragePayloads(reopened = reopened)
            }
            ActivationCommandKind.MARK_ACTIVATION -> {
                catalog.upsert(entity(recordId, TransactionState.MARKED))
                StoragePayloads()
            }
            ActivationCommandKind.COMMIT_MARKED -> {
                val staged = blobs.reopen(recordId, SecureDataClass.ACTIVATION_STAGED)
                try {
                    blobs.stage(recordId, SecureDataClass.ACTIVATION_ACTIVE, staged)
                } finally {
                    staged.fill(0)
                }
                catalog.upsert(entity(recordId, TransactionState.COMMITTED))
                StoragePayloads()
            }
            ActivationCommandKind.FINALIZE_ACTIVATION -> {
                catalog.upsert(entity(recordId, TransactionState.COMMITTED))
                blobs.delete(recordId, SecureDataClass.ACTIVATION_STAGED)
                StoragePayloads()
            }
            ActivationCommandKind.RECOVER -> {
                clearActivationBlobs(recordId)
                catalog.upsert(entity(recordId, TransactionState.RECOVERY_REQUIRED))
                StoragePayloads()
            }
            ActivationCommandKind.QUARANTINE -> {
                quarantine(recordId)
                StoragePayloads()
            }
            ActivationCommandKind.COMPLETE -> error("complete is not a storage command")
        }

    private suspend fun admissionConflict(verified: VerifiedPreviewHandle): AdmissionConflict {
        val superseded = mutableListOf<ProfileCatalogEntity>()
        for (row in catalog.listAll()) {
            if (row.transactionState != TransactionState.FINALIZED.name ||
                row.health == CatalogHealth.QUARANTINED.name
            ) {
                continue
            }
            val encodedPreview = runCatching {
                blobs.reopen(row.localRecordId, SecureDataClass.PROFILE_PREVIEW)
            }.getOrNull() ?: continue
            val preview = try {
                runCatching {
                    ProfilePreviewCodec.decode(encodedPreview).first
                }.getOrNull() ?: continue
            } finally {
                encodedPreview.fill(0)
            }
            if (preview.contentFingerprint == verified.preview.contentFingerprint) {
                return AdmissionConflict(OperationError.DUPLICATE)
            }
            if (preview.lineageFingerprint == verified.preview.lineageFingerprint) {
                if (preview.generation >= verified.preview.generation) {
                    return AdmissionConflict(OperationError.POLICY_REJECTED)
                }
                superseded += row
            }
        }
        return AdmissionConflict(superseded = superseded)
    }

    private suspend fun resumeRestore(): RestoreResult {
        val encoded = try {
            blobs.reopen(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH)
        } catch (_: KeyInvalidatedException) {
            return RestoreResult.Failure(OperationError.KEY_INVALIDATED)
        } catch (_: Throwable) {
            return RestoreResult.Failure(OperationError.STORAGE_FAILURE)
        }
        val records = try {
            BackupPayloadCodec.decode(encoded)
        } catch (_: Throwable) {
            rollbackPendingRestore()
            return RestoreResult.Failure(OperationError.INVALID_INPUT)
        } finally {
            encoded.fill(0)
        }
        try {
            for (record in records) {
                val resolved = when (val result = resolveVerified(record.verifyRequest, null)) {
                    is NativeResult.Failure -> {
                        rollbackPendingRestore()
                        return RestoreResult.Failure(result.error)
                    }
                    is NativeResult.Success -> result.value
                }
                val verified = resolved.verified
                val preview = verified.preview
                nativeCore.releaseVerified(verified)
                when (
                    val result = admitInternal(
                        verifyRequest = record.verifyRequest,
                        expectedPreview = preview,
                        finalHealth = CatalogHealth.RESTORE_PENDING,
                        publishSuperseded = false,
                        recipientKeyLocalId = resolved.recipientKeyLocalId,
                    )
                ) {
                    is AdmissionResult.Success -> Unit
                    is AdmissionResult.Failure -> {
                        if (result.error != OperationError.DUPLICATE) {
                            rollbackPendingRestore()
                            return RestoreResult.Failure(result.error)
                        }
                    }
                }
            }
            val pending = catalog.listAll()
                .filter { it.health == CatalogHealth.RESTORE_PENDING.name }
            val existing = catalog.listAll()
                .filter { it.health == CatalogHealth.AVAILABLE.name }
            val superseded = mutableSetOf<String>()
            for (pendingRow in pending) {
                val pendingEncoded =
                    blobs.reopen(pendingRow.localRecordId, SecureDataClass.PROFILE_PREVIEW)
                val pendingPreview = try {
                    ProfilePreviewCodec.decode(pendingEncoded).first
                } finally {
                    pendingEncoded.fill(0)
                }
                for (existingRow in existing) {
                    val existingEncoded =
                        blobs.reopen(existingRow.localRecordId, SecureDataClass.PROFILE_PREVIEW)
                    val existingPreview = try {
                        ProfilePreviewCodec.decode(existingEncoded).first
                    } finally {
                        existingEncoded.fill(0)
                    }
                    if (
                        pendingPreview.lineageFingerprint == existingPreview.lineageFingerprint &&
                        pendingPreview.generation > existingPreview.generation
                    ) {
                        superseded += existingRow.localRecordId
                    }
                }
            }
            catalog.publishRestore(
                restoredRecordIds = pending.map { it.localRecordId },
                supersededRecordIds = superseded.toList(),
            )
            blobs.delete(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH)
            return RestoreResult.Success(pending.size)
        } catch (_: KeyInvalidatedException) {
            return RestoreResult.Failure(OperationError.KEY_INVALIDATED)
        } catch (_: Throwable) {
            rollbackPendingRestore()
            return RestoreResult.Failure(OperationError.STORAGE_FAILURE)
        } finally {
            records.forEach { it.verifyRequest.fill(0) }
        }
    }

    private data class ResolvedVerified(
        val verified: VerifiedPreviewHandle,
        val recipientKeyLocalId: String?,
    )

    private fun resolveVerified(
        verifyRequest: ByteArray,
        preferredRecipientKeyLocalId: String?,
    ): NativeResult<ResolvedVerified> {
        if (preferredRecipientKeyLocalId == null) {
            when (val public = nativeCore.verifyPreview(verifyRequest)) {
                is NativeResult.Success -> return NativeResult.Success(ResolvedVerified(public.value, null))
                is NativeResult.Failure -> Unit
            }
        }
        val candidates = if (preferredRecipientKeyLocalId != null) {
            listOf(recipientKeys?.credentials(preferredRecipientKeyLocalId)
                ?: return NativeResult.Failure(OperationError.KEY_INVALIDATED))
        } else {
            recipientKeys?.credentialCandidates().orEmpty()
        }
        var finalError = OperationError.TRUST_REJECTED
        try {
            for (candidate in candidates) {
                when (
                    val result = nativeCore.verifyPreviewWithRecipient(
                        verifyRequest,
                        candidate.publicRequest,
                        candidate.privateBundle,
                    )
                ) {
                    is NativeResult.Success -> return NativeResult.Success(
                        ResolvedVerified(result.value, candidate.localRecordId),
                    )
                    is NativeResult.Failure -> finalError = result.error
                }
            }
        } finally {
            candidates.forEach(RecipientCredentialLease::close)
        }
        return NativeResult.Failure(finalError)
    }

    private suspend fun rollbackPendingRestore() {
        var cleanupFailed = false
        catalog.listAll()
            .filter { it.health == CatalogHealth.RESTORE_PENDING.name }
            .forEach { row ->
                try {
                    SecureDataClass.entries.forEach { dataClass ->
                        blobs.delete(row.localRecordId, dataClass)
                    }
                    catalog.delete(row.localRecordId)
                } catch (_: Throwable) {
                    cleanupFailed = true
                    runCatching {
                        catalog.upsert(row.copy(health = CatalogHealth.QUARANTINED.name))
                    }
                }
            }
        if (!cleanupFailed) {
            runCatching {
                blobs.delete(RESTORE_RECORD_ID, SecureDataClass.RESTORE_BATCH)
            }
        }
    }

    private fun reopenIfPresent(
        recordId: String,
        dataClass: SecureDataClass,
    ): ByteArray =
        if (blobs.exists(recordId, dataClass)) {
            blobs.reopen(recordId, dataClass)
        } else {
            byteArrayOf()
        }

    private fun clearActivationBlobs(recordId: String) {
        listOf(
            SecureDataClass.ACTIVATION_STAGED,
            SecureDataClass.ACTIVATION_ACTIVE,
            SecureDataClass.ACTIVATION_LAST_KNOWN_GOOD,
        ).forEach { dataClass ->
            blobs.delete(recordId, dataClass)
        }
    }

    private suspend fun quarantine(recordId: String) {
        catalog.upsert(
            entity(
                recordId,
                TransactionState.QUARANTINED,
                CatalogHealth.QUARANTINED,
            ),
        )
    }

    private suspend fun cleanupFailedPreparation(recordId: String) {
        runCatching {
            blobs.delete(recordId, SecureDataClass.IMPORT_REQUEST)
        }
        runCatching {
            catalog.delete(recordId)
        }
    }

    private fun entity(
        recordId: String,
        state: TransactionState,
        health: CatalogHealth = CatalogHealth.AVAILABLE,
    ): ProfileCatalogEntity =
        ProfileCatalogEntity(
            localRecordId = recordId,
            transactionState = state.name,
            envelopeVersion = 1,
            keyGeneration = 1,
            health = health.name,
        )

    private fun newRecordId(): String {
        val bytes = ByteArray(16).also(random::nextBytes)
        return try {
            bytes[6] = (bytes[6].toInt() and 0x0f or 0x40).toByte()
            bytes[8] = (bytes[8].toInt() and 0x3f or 0x80).toByte()
            val hex = bytes.joinToString("") { "%02x".format(it) }
            "${hex.take(8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-" +
                "${hex.substring(16, 20)}-${hex.substring(20)}"
        } finally {
            bytes.fill(0)
        }
    }

    private data class StoragePayloads(
        val active: ByteArray = byteArrayOf(),
        val lastKnownGood: ByteArray = byteArrayOf(),
        val reopened: ByteArray = byteArrayOf(),
    ) {
        fun destroy() {
            active.fill(0)
            lastKnownGood.fill(0)
            reopened.fill(0)
        }
    }

    private data class AdmissionConflict(
        val error: OperationError? = null,
        val superseded: List<ProfileCatalogEntity> = emptyList(),
    )
}

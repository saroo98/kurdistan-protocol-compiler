// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.DeploymentDisplayEntry
import org.kurdistanvpn.data.secure.DeploymentDisplayMetadata
import org.kurdistanvpn.domain.*

internal interface ProductEnrollmentForeground {
    fun requestEnrollmentDestination(id: CatalogId, destination: EnrollmentExport, bytes: ByteArray): Boolean
}

internal class ProductProfileRepository(
    private val facade: () -> ProtectedStateApplicationFacade?,
    private val imports: ProductImportOperations,
    private val applySettings: suspend ((ProductSettings) -> ProductSettings) -> DomainResult<Unit>,
    private val backups: ProductBackupOperations,
    private val exportDestination: suspend (ByteArray) -> Boolean,
    private val firstUse: () -> Boolean,
    private val prepareEnrollment: suspend () -> Boolean,
    private val enrollmentDestination: suspend (CatalogId, EnrollmentExport, ByteArray) -> Boolean,
) : ProfileRepository {
    private val profiles = MutableStateFlow<List<ProfileProjection>>(emptyList())
    override fun observeProfiles(): StateFlow<List<ProfileProjection>> = profiles.asStateFlow()

    private fun owner() = checkNotNull(facade()) { "PROTECTED_STATE_UNAVAILABLE" }

    override suspend fun readEnrollment(): DomainResult<EnrollmentUiState> = read {
        if (facade() == null && firstUse()) return@read EnrollmentUiState.NoEnrollmentKey
        val keys = checkNotNull(owner().enrollmentSummaries())
        val summaries = keys.map { EnrollmentKeySummary(it.localRecordId, it.requestFingerprint,
            it.createdAtEpochSeconds, it.expiresAtEpochSeconds, it.boundProfileCount) }
        when {
            keys.isEmpty() -> EnrollmentUiState.NoEnrollmentKey
            keys.any { it.status == org.kurdistanvpn.data.secure.ClientKeyStatus.PROFILE_VERIFIED } -> EnrollmentUiState.ProfileVerified(summaries)
            keys.any { it.status == org.kurdistanvpn.data.secure.ClientKeyStatus.AWAITING_PROFILE } -> EnrollmentUiState.AwaitingProfile(summaries)
            else -> EnrollmentUiState.RequestReady(summaries)
        }
    }
    override suspend fun createEnrollment(validitySeconds: Int): DomainResult<Unit> = withContext(Dispatchers.IO) {
        if (!prepareEnrollment()) return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
        enrollmentResult(owner().createEnrollment(validitySeconds, System.currentTimeMillis() / 1000))
    }
    override suspend fun deleteEnrollment(id: CatalogId): DomainResult<Unit> = withContext(Dispatchers.IO) {
        enrollmentResult(owner().deleteEnrollment(id.value))
    }
    override suspend fun markEnrollmentExported(id: CatalogId): DomainResult<Unit> = withContext(Dispatchers.IO) {
        enrollmentResult(owner().markEnrollmentExported(id.value))
    }
    override suspend fun exportEnrollment(id: CatalogId, destination: EnrollmentExport): DomainResult<Unit> = withContext(Dispatchers.IO) {
        val bytes = owner().enrollmentRequest(id.value) ?: return@withContext rejected(ProductFailureCode.INVALID_INPUT)
        var accepted = false
        try {
            accepted = enrollmentDestination(id, destination, bytes)
            if (!accepted) rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            else if (destination == EnrollmentExport.QR) markEnrollmentExported(id)
            else DomainResult.Success(Unit)
        } finally { if (!accepted) bytes.fill(0) }
    }
    private fun enrollmentResult(result: ProtectedStateApplicationFacade.CommandResult<*>): DomainResult<Unit> = when (result) {
        is ProtectedStateApplicationFacade.CommandResult.Committed -> DomainResult.Success(Unit)
        is ProtectedStateApplicationFacade.CommandResult.Rejected -> rejected(result.error.failureCode())
        else -> rejected(ProductFailureCode.STORAGE_DEGRADED)
    }
    private fun projection(summary: ProfileSummary, stored: ProtectedStateApplicationFacade.ProductStorageReadProjection): ProfileProjection {
        val cached = stored.profile?.profile
        check(cached == null || cached.id.value == summary.localRecordId && cached.generation == summary.generation &&
            cached.expiresAtEpochSeconds == summary.expiresAtEpochSeconds)
        return ProfileProjection(CatalogId(summary.localRecordId), cached?.alias ?: SafeAlias("Profile"),
            summary.generation, summary.expiresAtEpochSeconds,
            if (summary.trust in setOf(ProfileTrust.VERIFIED_PRODUCTION, ProfileTrust.VERIFIED_NONPRODUCTION))
                ProjectionStatus.VERIFIED else ProjectionStatus.UNAVAILABLE)
    }

    override suspend fun listProfiles(): DomainResult<List<ProfileProjection>> = read {
        val owner = owner()
        val snapshot = checkNotNull(owner.readProjection())
        val values = snapshot.profiles.map { summary ->
            val stored = checkNotNull(owner.readProductStorage(summary.localRecordId))
            check(stored.revision == snapshot.revision)
            projection(summary, stored)
        }
        check(owner.readProjection()?.revision == snapshot.revision)
        profiles.value = values
        values
    }

    override suspend fun detail(profileId: CatalogId): DomainResult<ProfileDetail> = read {
        val owner = owner()
        val snapshot = checkNotNull(owner.readProjection())
        val summary = snapshot.profiles.singleOrNull { it.localRecordId == profileId.value }
            ?: throw MissingProfile()
        val stored = checkNotNull(owner.readProductStorage(profileId.value))
        check(stored.revision == snapshot.revision)
        val display = stored.deploymentDisplay?.entries?.singleOrNull { it.profileId == profileId }
        ProfileDetail(projection(summary, stored), stored.profile?.deployment,
            profileId.value in snapshot.settings.profiles.favoriteLocalRecordIds, display?.priority ?: 0,
            stored.profileTrustRevision)
    }

    override suspend fun preview(source: ImportSource, stagedInputId: CatalogId): DomainResult<ProfileImportPreview> = withContext(Dispatchers.IO) {
        when (val result = imports.prepareStaged(stagedInputId, source)) {
            is NativeResult.Success -> DomainResult.Success(ProfileImportPreview(result.value.id, result.value.display))
            is NativeResult.Failure -> rejected(result.error.failureCode())
        }
    }

    override suspend fun admit(previewId: CatalogId): DomainResult<ProfileProjection> = withContext(Dispatchers.IO) {
        try {
            when (val result = imports.confirm(previewId)) {
                is NativeResult.Failure -> rejected(result.error.failureCode())
                is NativeResult.Success -> {
                    when (val current = detail(result.value)) {
                        is DomainResult.Success -> { listProfiles(); DomainResult.Success(current.value.profile) }
                        is DomainResult.Rejected -> current
                    }
                }
            }
        } finally { imports.cancel(previewId) }
    }

    override suspend fun cancelImport(previewId: CatalogId): DomainResult<Unit> = read { imports.cancel(previewId) }

    override suspend fun activate(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<ProfileProjection> = withContext(Dispatchers.IO) {
        val owner = facade() ?: return@withContext rejected(ProductFailureCode.STORAGE_LOCKED)
        val snapshot = owner.readProjection() ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
        val stored = owner.readProductStorage(profileId.value) ?: return@withContext rejected(ProductFailureCode.PROFILE_UNTRUSTED)
        if (stored.revision != snapshot.revision || stored.profileTrustRevision != expectedTrustRevision)
            return@withContext rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        if (snapshot.settings.profiles.activeLocalRecordId != profileId.value) {
            val changed = applySettings { settings ->
                check(owner.readProductStorage(profileId.value)?.profileTrustRevision == expectedTrustRevision)
                settings.copy(profiles = settings.profiles.copy(activeLocalRecordId = profileId.value))
            }
            if (changed is DomainResult.Rejected) return@withContext changed
        }
        when (val fresh = detail(profileId)) {
            is DomainResult.Success -> DomainResult.Success(fresh.value.profile)
            is DomainResult.Rejected -> fresh
        }
    }

    override suspend fun setFavorite(profileId: CatalogId, favorite: Boolean): DomainResult<Unit> {
        if (detail(profileId) !is DomainResult.Success) return rejected(ProductFailureCode.PROFILE_UNTRUSTED)
        return applySettings { current ->
            val next = current.profiles.favoriteLocalRecordIds.toMutableSet()
            if (favorite) next.add(profileId.value) else next.remove(profileId.value)
            current.copy(profiles = current.profiles.copy(favoriteLocalRecordIds = next))
        }
    }

    override suspend fun setPriority(profileId: CatalogId, priority: Int): DomainResult<Unit> = withContext(Dispatchers.IO) {
        if (priority !in 0..1023) return@withContext rejected(ProductFailureCode.INVALID_INPUT)
        val current = detail(profileId)
        if (current !is DomainResult.Success) return@withContext current as DomainResult.Rejected
        val owner = owner()
        val stored = owner.readProductStorage(profileId.value) ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
        val entries = stored.deploymentDisplay?.entries.orEmpty()
        val old = entries.singleOrNull { it.profileId == profileId }
        val replacement = old?.copy(priority = priority) ?: DeploymentDisplayEntry(profileId,
            current.value.profile.alias, priority, false, UpdateCategory.NOT_CHECKED)
        if (owner.setDeploymentDisplay(stored.revision, DeploymentDisplayMetadata(entries.filterNot { it.profileId == profileId } + replacement))
            is ProtectedStateApplicationFacade.CommandResult.Committed) DomainResult.Success(Unit)
        else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
    }

    override suspend fun delete(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit> = withContext(Dispatchers.IO) {
        val owner = facade() ?: return@withContext rejected(ProductFailureCode.STORAGE_LOCKED)
        val stored = owner.readProductStorage(profileId.value) ?: return@withContext rejected(ProductFailureCode.PROFILE_UNTRUSTED)
        if (stored.profileTrustRevision != expectedTrustRevision) return@withContext rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        if (owner.deleteProfile(profileId.value, stored.revision) is ProtectedStateApplicationFacade.CommandResult.Committed) {
            listProfiles(); DomainResult.Success(Unit)
        } else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
    }

    // No quarantine-only native/broker command is admitted. Do not silently replace revocation with deletion.
    override suspend fun revokeLocalTrust(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit> =
        rejected(ProductFailureCode.PROFILE_INCOMPATIBLE)
    override suspend fun previewSelectiveExport(profileIds: Set<CatalogId>): DomainResult<PendingProductOperation> = withContext(Dispatchers.IO) {
        when (val result = backups.previewExport(profileIds)) {
            is NativeResult.Success -> DomainResult.Success(PendingProductOperation(result.value.id,
                OperationPreview(OperationKind.BACKUP, result.value.profileCount)))
            is NativeResult.Failure -> rejected(result.error.failureCode())
        }
    }
    override suspend fun exportSelective(operationId: CatalogId): DomainResult<Unit> = withContext(Dispatchers.IO) {
        when (val result = backups.confirmExport(operationId)) {
            is NativeResult.Failure -> rejected(result.error.failureCode())
            is NativeResult.Success -> {
                var accepted = false
                try {
                    accepted = exportDestination(result.value)
                    if (accepted) DomainResult.Success(Unit) else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                } finally { if (!accepted) result.value.fill(0) }
            }
        }
    }
    override suspend fun redactedSummary(profileId: CatalogId) = detail(profileId)

    private class MissingProfile : IllegalArgumentException()
    private suspend fun <T> read(action: () -> T): DomainResult<T> = withContext(Dispatchers.IO) {
        try { DomainResult.Success(action()) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: MissingProfile) { rejected(ProductFailureCode.PROFILE_UNTRUSTED) }
        catch (_: Exception) { rejected(ProductFailureCode.STORAGE_DEGRADED) }
    }
    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
    private fun OperationError.failureCode() = when (this) {
        OperationError.INVALID_INPUT -> ProductFailureCode.INVALID_INPUT
        OperationError.TRUST_REJECTED -> ProductFailureCode.PROFILE_UNTRUSTED
        OperationError.CANCELLED -> ProductFailureCode.OPERATION_INTERRUPTED
        OperationError.RECOVERY_REQUIRED, OperationError.STORAGE_FAILURE -> ProductFailureCode.STORAGE_DEGRADED
        else -> ProductFailureCode.PROFILE_INCOMPATIBLE
    }
}

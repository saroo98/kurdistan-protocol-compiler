// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.profiles

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class ProfilesViewModelTest {
    @Test fun leavingReviewRetiresApprovalButAllowsAFreshReview() = runBlocking {
        val repository = Repository()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val vm = ProfilesViewModel(repository, SavedStateHandle(), scope)
            vm.review(repository.profile.id).join()
            vm.cancelReview().join()
            vm.deleteReviewed(repository.profile.id).join()
            assertEquals(0, repository.deleted)
            assertEquals(ProductFailureCode.OPERATION_INTERRUPTED, vm.failure.value)
            vm.review(repository.profile.id).join()
            vm.deleteReviewed(repository.profile.id).join()
            assertEquals(1, repository.deleted)
        } finally { scope.cancel() }
    }

    private class Repository : ProfileRepository {
        override suspend fun readEnrollment(): DomainResult<EnrollmentUiState> = error("Not requested")
        override suspend fun createEnrollment(validitySeconds: Int): DomainResult<Unit> = error("Not requested")
        override suspend fun exportEnrollment(id: CatalogId, destination: EnrollmentExport): DomainResult<Unit> = error("Not requested")
        override suspend fun markEnrollmentExported(id: CatalogId): DomainResult<Unit> = error("Not requested")
        override suspend fun deleteEnrollment(id: CatalogId): DomainResult<Unit> = error("Not requested")
        val id = CatalogId("reviewed-import")
        val profile = ProfileProjection(CatalogId("profile-a"), SafeAlias("Profile"), 1u, 100, ProjectionStatus.VERIFIED)
        var admits = 0
        var cancels = 0
        var rejectPreview = false
        var deleted = 0
        override fun observeProfiles() = flowOf(listOf(profile))
        override suspend fun listProfiles() = DomainResult.Success(listOf(profile))
        override suspend fun detail(profileId: CatalogId) = DomainResult.Success(ProfileDetail(profile, null, false, 0, 7))
        override suspend fun preview(source: ImportSource, stagedInputId: CatalogId): DomainResult<ProfileImportPreview> =
            if (rejectPreview) DomainResult.Rejected(ProductFailure(ProductFailureCode.PROFILE_UNTRUSTED))
            else DomainResult.Success(ProfileImportPreview(id, RedactedProfilePreview("signed", "production", "content", "lineage", 1u, 100, false)))
        override suspend fun admit(previewId: CatalogId): DomainResult<ProfileProjection> {
            assertEquals(id, previewId); admits++; return DomainResult.Success(profile)
        }
        override suspend fun cancelImport(previewId: CatalogId): DomainResult<Unit> {
            assertEquals(id, previewId); cancels++; return DomainResult.Success(Unit)
        }
        override suspend fun activate(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<ProfileProjection> = error("Not requested")
        override suspend fun setFavorite(profileId: CatalogId, favorite: Boolean): DomainResult<Unit> = error("Not requested")
        override suspend fun setPriority(profileId: CatalogId, priority: Int): DomainResult<Unit> = error("Not requested")
        override suspend fun delete(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit> {
            assertEquals(profile.id, profileId); assertEquals(7L, expectedTrustRevision)
            deleted++; return DomainResult.Success(Unit)
        }
        override suspend fun revokeLocalTrust(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit> = error("Not requested")
        override suspend fun previewSelectiveExport(profileIds: Set<CatalogId>): DomainResult<PendingProductOperation> = error("Not requested")
        override suspend fun exportSelective(operationId: CatalogId): DomainResult<Unit> = error("Not requested")
        override suspend fun redactedSummary(profileId: CatalogId) = detail(profileId)
    }

    @Test fun failedReplacementAndCancellationCannotConfirmEarlierImport() = runBlocking {
        val repository = Repository()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val saved = SavedStateHandle()
        try {
            val vm = ProfilesViewModel(repository, saved, scope)
            vm.preview(ImportSource.FILE, CatalogId("input-one")).join()
            assertTrue(vm.importState.value is AppState.ImportPreview)
            assertEquals(setOf("importPreviewId", "importSource"), saved.keys())
            repository.rejectPreview = true
            vm.preview(ImportSource.FILE, CatalogId("input-two")).join()
            vm.confirmImport().join()
            assertEquals(0, repository.admits)
            assertEquals(1, repository.cancels)
            repository.rejectPreview = false
            vm.preview(ImportSource.FILE, CatalogId("input-three")).join()
            vm.cancelImport().join(); vm.confirmImport().join()
            assertEquals(0, repository.admits)
            vm.preview(ImportSource.FILE, CatalogId("input-four")).join()
            vm.confirmImport().join(); vm.confirmImport().join()
            assertEquals(1, repository.admits)
            assertTrue(saved.keys().isEmpty())
        } finally { scope.cancel() }
    }

    @Test fun deletionConsumesOnlyTheReviewedProfileAndNeverRestoresConsent() = runBlocking {
        val repository = Repository()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val vm = ProfilesViewModel(repository, SavedStateHandle(), scope)
            vm.deleteReviewed(repository.profile.id).join()
            assertEquals(0, repository.deleted)
            vm.review(repository.profile.id).join()
            vm.deleteReviewed(CatalogId("different-profile")).join()
            assertEquals(0, repository.deleted)
            vm.deleteReviewed(repository.profile.id).join()
            assertEquals(0, repository.deleted)
            vm.review(repository.profile.id).join()
            vm.deleteReviewed(repository.profile.id).join()
            vm.deleteReviewed(repository.profile.id).join()
            assertEquals(1, repository.deleted)
        } finally { scope.cancel() }
    }
}

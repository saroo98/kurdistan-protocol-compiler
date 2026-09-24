// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ProfileProjection
import org.kurdistanvpn.core.model.DeploymentProjection
import org.kurdistanvpn.core.model.OperationPreview
import org.kurdistanvpn.core.model.EnrollmentUiState

interface ProfileRepository {
    suspend fun readEnrollment(): DomainResult<EnrollmentUiState>
    suspend fun createEnrollment(validitySeconds: Int): DomainResult<Unit>
    suspend fun exportEnrollment(id: CatalogId, destination: EnrollmentExport): DomainResult<Unit>
    suspend fun markEnrollmentExported(id: CatalogId): DomainResult<Unit>
    suspend fun deleteEnrollment(id: CatalogId): DomainResult<Unit>
    fun observeProfiles(): Flow<List<ProfileProjection>>
    suspend fun listProfiles(): DomainResult<List<ProfileProjection>>
    suspend fun detail(profileId: CatalogId): DomainResult<ProfileDetail>
    /** Staging identity names an adapter-owned bounded input, never a path, URI or native handle. */
    suspend fun preview(source: ImportSource, stagedInputId: CatalogId): DomainResult<ProfileImportPreview>
    suspend fun admit(previewId: CatalogId): DomainResult<ProfileProjection>
    suspend fun cancelImport(previewId: CatalogId): DomainResult<Unit>
    suspend fun activate(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<ProfileProjection>
    suspend fun setFavorite(profileId: CatalogId, favorite: Boolean): DomainResult<Unit>
    /** Priority is 0..1023; adapters reject invalid values before persistence. */
    suspend fun setPriority(profileId: CatalogId, priority: Int): DomainResult<Unit>
    suspend fun delete(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit>
    suspend fun revokeLocalTrust(profileId: CatalogId, expectedTrustRevision: Long): DomainResult<Unit>
    /** At most 1024 IDs; encrypted export only, explicit protected preview and local destination. */
    suspend fun previewSelectiveExport(profileIds: Set<CatalogId>): DomainResult<PendingProductOperation>
    suspend fun exportSelective(operationId: CatalogId): DomainResult<Unit>
    suspend fun redactedSummary(profileId: CatalogId): DomainResult<ProfileDetail>
}

enum class EnrollmentExport { FILE, QR }

data class ProfileDetail(val profile: ProfileProjection, val deployment: DeploymentProjection?,
    val favorite: Boolean, val priority: Int, val trustRevision: Long?)
data class ProfileImportPreview(val id: CatalogId, val preview: RedactedProfilePreview)
/** Local transaction identity, not retained authority. Execution must revalidate preview and scope. */
data class PendingProductOperation(val id: CatalogId, val preview: OperationPreview)

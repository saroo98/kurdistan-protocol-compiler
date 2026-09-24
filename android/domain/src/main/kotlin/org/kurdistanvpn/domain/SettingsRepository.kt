// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.domain

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.*

data class SettingsEffectiveValues(val mtu: Int?, val reconnectMaximum: Int?) {
    init { require(mtu == null || mtu in 1280..1500); require(reconnectMaximum == null || reconnectMaximum in 0..10) }
}
data class SettingsRevision(val revision: Long, val settings: ProductSettings, val effective: SettingsEffectiveValues? = null)
data class SettingsDraft(val id: CatalogId, val basedOn: SettingsRevision)
data class ResumableSettingsDraft(val draft: SettingsDraft, val requested: ProductSettings)

interface SettingsRepository {
    fun observeAppliedRevision(): Flow<SettingsRevision>
    suspend fun appliedRevision(): DomainResult<SettingsRevision>
    suspend fun openDraft(): DomainResult<SettingsDraft>
    suspend fun saveDraft(draftId: CatalogId, requested: ProductSettings): DomainResult<Unit>
    suspend fun resumeDraft(draftId: CatalogId): DomainResult<ResumableSettingsDraft>
    suspend fun validate(draftId: CatalogId, requested: ProductSettings): DomainResult<OperationPreview>
    /** Compare-and-apply. Revalidate then reconnect once; failure restores the prior applied revision. */
    suspend fun apply(draftId: CatalogId, expectedAppliedRevision: Long, requested: ProductSettings): DomainResult<SettingsRevision>
    suspend fun cancel(draftId: CatalogId): DomainResult<Unit>
}

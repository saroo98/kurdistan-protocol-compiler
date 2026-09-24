// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.*
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

/** Stable feature binding. Reset/migration replaces the delegate, never the screen's repository. */
internal class ProductSettingsRepository(
    private val current: () -> SettingsRepository?,
    private val owners: StateFlow<SettingsRepository?>,
    private val applyAppearance: suspend (SettingsRepository, Long, ProductSettings) -> DomainResult<Unit>,
    private val prepareExplicitEdit: suspend () -> Boolean,
) : SettingsRepository {
    @OptIn(ExperimentalCoroutinesApi::class)
    override fun observeAppliedRevision(): Flow<SettingsRevision> = flow {
        current()
        emitAll(owners.flatMapLatest { it?.observeAppliedRevision() ?: emptyFlow() })
    }
    override suspend fun appliedRevision(): DomainResult<SettingsRevision> = current()?.appliedRevision() ?: unavailable()
    override suspend fun openDraft(): DomainResult<SettingsDraft> {
        if (current() == null && !prepareExplicitEdit()) return unavailable()
        return current()?.openDraft() ?: unavailable()
    }
    override suspend fun saveDraft(draftId: CatalogId, requested: ProductSettings): DomainResult<Unit> =
        current()?.saveDraft(draftId, requested) ?: unavailable()
    override suspend fun resumeDraft(draftId: CatalogId): DomainResult<ResumableSettingsDraft> =
        current()?.resumeDraft(draftId) ?: unavailable()
    override suspend fun validate(draftId: CatalogId, requested: ProductSettings): DomainResult<OperationPreview> =
        current()?.validate(draftId, requested) ?: unavailable()
    override suspend fun apply(draftId: CatalogId, expectedAppliedRevision: Long, requested: ProductSettings): DomainResult<SettingsRevision> {
        val owner = current() ?: return unavailable()
        val applied = when (val read = owner.appliedRevision()) {
            is DomainResult.Rejected -> return read
            is DomainResult.Success -> read.value
        }
        if (applied.revision == expectedAppliedRevision && applied.settings.copy(theme = requested.theme,
                highContrast = requested.highContrast, reducedMotion = requested.reducedMotion) == requested) {
            when (val valid = owner.validate(draftId, requested)) {
                is DomainResult.Rejected -> return valid
                is DomainResult.Success -> Unit
            }
            when (val result = applyAppearance(owner, expectedAppliedRevision, requested)) {
                is DomainResult.Rejected -> return result
                is DomainResult.Success -> return owner.appliedRevision()
            }
        }
        return owner.apply(draftId, expectedAppliedRevision, requested)
    }
    override suspend fun cancel(draftId: CatalogId): DomainResult<Unit> = current()?.cancel(draftId) ?: unavailable()
    private fun unavailable() = DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED))
}

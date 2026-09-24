// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class ProductSettingsRepositoryTest {
    private class Owner(val revision: Long) : SettingsRepository {
        val id = CatalogId("draft-$revision")
        var value = SettingsRevision(revision, ProductSettings())
        override fun observeAppliedRevision() = flowOf(value)
        override suspend fun appliedRevision() = DomainResult.Success(value)
        override suspend fun openDraft() = DomainResult.Success(SettingsDraft(id, value))
        override suspend fun saveDraft(draftId: CatalogId, requested: ProductSettings) = error("not used")
        override suspend fun resumeDraft(draftId: CatalogId): DomainResult<ResumableSettingsDraft> =
            if (draftId == id) DomainResult.Success(ResumableSettingsDraft(SettingsDraft(id, value), value.settings))
            else DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
        override suspend fun validate(draftId: CatalogId, requested: ProductSettings): DomainResult<OperationPreview> =
            if (draftId == id) DomainResult.Success(OperationPreview(OperationKind.SETTINGS_CHANGE, 1))
            else DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
        override suspend fun apply(draftId: CatalogId, expectedAppliedRevision: Long, requested: ProductSettings) = error("not used")
        override suspend fun cancel(draftId: CatalogId) = error("not used")
    }

    @Test fun sameRepositoryReloadsNewOwnerAndDoesNotRestoreAnOldOwnersDraft() = runBlocking {
        val owners = MutableStateFlow<SettingsRepository?>(Owner(2))
        val repository = ProductSettingsRepository({ owners.value }, owners, { _, _, _ -> error("not used") }) { false }
        val old = (repository.openDraft() as DomainResult.Success).value.id
        owners.value = Owner(4)
        assertEquals(4L, (repository.appliedRevision() as DomainResult.Success).value.revision)
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED)), repository.resumeDraft(old))
        owners.value = null
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED)), repository.appliedRevision())
    }

    @Test fun appearanceOnlyApplyUsesPresentationWriterWithoutRuntimeTransaction() = runBlocking {
        val owner = Owner(2)
        val owners = MutableStateFlow<SettingsRepository?>(owner)
        val repository = ProductSettingsRepository({ owner }, owners, { _, revision, settings ->
            check(revision == 2L)
            owner.value = SettingsRevision(revision, settings)
            DomainResult.Success(Unit)
        }) { false }
        val requested = owner.value.settings.copy(theme = ThemePreference.DARK)
        assertEquals(DomainResult.Success(SettingsRevision(2, requested)), repository.apply(owner.id, 2, requested))
        assertEquals(DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED)),
            repository.apply(CatalogId("foreign-draft"), 2, requested))
    }
}

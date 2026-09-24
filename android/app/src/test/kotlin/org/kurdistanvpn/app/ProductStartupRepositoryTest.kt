// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade

class ProductStartupRepositoryTest {
    @Test fun unprovedCleanupPreventsHealthyStartupAndPublishesRecoveryReason() = runBlocking {
        val projection = ProtectedStateApplicationFacade.ReadProjection(2, ProductSettings(), emptyList(), CatalogHealth.AVAILABLE)
        val recovery = org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.Required(
            org.kurdistanvpn.core.model.ProtectedRecoveryReason.CLEANUP_UNPROVEN)
        val repository = DefaultProductStartupRepository({ ProtectedStartupRead.Ready(projection) },
            { NativeResult.Success(compatibility) }, { recovery })
        repository.refresh()
        assertSame(AppState.DegradedStorage, repository.observeStartup().first())
        assertEquals(recovery, repository.presentation.value.recovery)
        assertEquals(ProductSettings(), repository.presentation.value.settings)
        assertNotNull(repository.presentation.value.compatibility)
    }
    private val compatibility = NativeCompatibility("kurd-android-bridge-v1", "kurd-go-core-phase9-v1",
        "profile", "strategy", "relay", "diagnostic", 1, 1024, 1, 1024, 1024, 1)

    @Test fun unavailableStorageNeverQueriesCoreOrInventsProjection() = runBlocking {
        for (failure in ProductCompositionRoot.StorageFailure.entries) {
            val unavailable = ProtectedStartupRead.Unavailable(failure)
            val repository = DefaultProductStartupRepository({ unavailable }, { error("must not query core") })
            repository.refresh()
            assertEquals(unavailable.presentation, repository.observeStartup().first())
            assertNull(repository.snapshot.compatibility)
        }
    }

    @Test fun existingEmptyStoreStaysReadOnlyAndCoreFailureIsNotMigration() = runBlocking {
        val projection = ProtectedStateApplicationFacade.ReadProjection(1, ProductSettings(), emptyList(), CatalogHealth.AVAILABLE)
        var reads = 0
        var coreResult: NativeResult<NativeCompatibility> = NativeResult.Success(compatibility)
        val repository = DefaultProductStartupRepository({ reads++; ProtectedStartupRead.Ready(projection) }, { coreResult })
        repository.refresh()
        assertSame(AppState.NoProfiles, repository.observeStartup().first())
        assertEquals(1, reads)
        assertSame(projection, (repository.snapshot.protectedRead as ProtectedStartupRead.Ready).projection)
        coreResult = NativeResult.Failure(OperationError.INTERNAL_FAILURE)
        repository.refresh()
        assertSame(AppState.CoreUnavailable, repository.observeStartup().first())
        coreResult = NativeResult.Success(compatibility.copy(bridgeVersion = "unsupported"))
        repository.refresh()
        assertSame(AppState.CoreIncompatible, repository.observeStartup().first())
    }
}

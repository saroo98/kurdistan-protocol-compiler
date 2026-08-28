// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.nio.file.Files
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProtectedRecoveryReason
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.junit.Assert.*
import org.junit.Test

class FirstUseStartupTest {
    @Test fun missingProjectionCollectionDoesNotThrowOrFabricateSettingsOrCreateStorage() = runBlocking {
        val parent = Files.createTempDirectory("startup-read-").toFile().canonicalFile
        val missing = java.io.File(parent, "protected-state")
        var reads = 0
        val settings = SettingsCoordinator {
            reads++
            assertFalse(missing.exists())
            null
        }
        assertTrue(settings.settings.toList().isEmpty())
        assertEquals(1, reads)
        assertFalse(missing.exists())
        assertEquals(emptyList<String>(), parent.listFiles()!!.map { it.name })
    }

    @Test fun cancellationFromProjectionReadIsNotAnOrdinaryUiResult() {
        val cancellation = CancellationException("synthetic cancellation")
        val settings = SettingsCoordinator { throw cancellation }
        assertSame(cancellation, assertThrows(CancellationException::class.java) {
            runBlocking { settings.settings.toList() }
        })
    }

    @Test fun unavailableStatesRemainDistinctAndNeverReadOrInitializeAStore() = runBlocking {
        val cases = listOf(
            Triple(ProtectedStateApplicationFacade.OpenResult.Missing, AppState.FirstLaunch, null),
            Triple(ProtectedStateApplicationFacade.OpenResult.Locked, AppState.LockedStorage, null),
            Triple(ProtectedStateApplicationFacade.OpenResult.KeyInvalidated, AppState.KeyInvalidated, ProtectedRecoveryReason.INCONSISTENT),
            Triple(ProtectedStateApplicationFacade.OpenResult.MigrationRequired, AppState.MigrationRequired, null),
            Triple(ProtectedStateApplicationFacade.OpenResult.Unproven, AppState.DegradedStorage, ProtectedRecoveryReason.MUTATION_UNPROVEN),
        )
        for ((opened, state, reason) in cases) {
            val failure = Phase9CompositionRoot.classifyStorageOpen(opened)
            val result = readStartupProjection(failure) { error("Unavailable state must not read a projection") }
            assertTrue(result is ProtectedStartupRead.Unavailable)
            result as ProtectedStartupRead.Unavailable
            assertSame(state, result.presentation)
            assertEquals(reason, result.recoveryReason)
        }
    }

    @Test fun inconsistentReadCannotMasqueradeAsFirstUseOrMutationSuccess() = runBlocking {
        val result = readStartupProjection(null) { null } as ProtectedStartupRead.Unavailable
        assertSame(AppState.DegradedStorage, result.presentation)
        assertEquals(ProtectedRecoveryReason.INCONSISTENT, result.recoveryReason)
    }

    @Test fun unexpectedReadFailureHasAnExplicitFatalOutcomeWithoutFabricatedSettings() = runBlocking {
        val result = readStartupProjection(null) { throw IllegalStateException("synthetic unexpected failure") }
        assertSame(ProtectedStartupRead.UnexpectedFailure, result)
        assertTrue(SettingsCoordinator { throw IllegalStateException("synthetic failure") }.settings.toList().isEmpty())
    }

    @Test fun availableSettingsComeOnlyFromTheActualAuthenticatedProjection() = runBlocking {
        val settings = Phase9Settings(highContrast = true)
        val projection = ProtectedStateApplicationFacade.ReadProjection(2L, settings, emptyList(), CatalogHealth.AVAILABLE)
        var reads = 0
        val result = readStartupProjection(null) { reads++; projection } as ProtectedStartupRead.Ready
        assertSame(projection, result.projection)
        assertSame(settings, result.projection.settings)
        assertEquals(1, reads)
    }
}

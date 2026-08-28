// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.nio.file.Files
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProtectedRecoveryReason
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.junit.Assert.*
import org.junit.Test

class FirstUseStartupTest {
    @Test fun storageFailureInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertDirectCallbackContract(
            listOf(null) + Phase9CompositionRoot.StorageFailure.entries,
            { callback -> recoveryCoordinator(storageFailure = callback) },
            RecoveryCoordinator::storageFailure,
        )
    }

    @Test fun presentationRecoveryRequiredInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertDirectCallbackContract(
            listOf(null, false, true),
            { callback -> recoveryCoordinator(presentationRecoveryRequired = callback) },
            RecoveryCoordinator::presentationRecoveryRequired,
        )
    }

    @Test fun recoverPresentationInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertSuspendingCallbackContract(
            listOf(ProtectedStateApplicationFacade.CommandResult.Committed(Unit),
                ProtectedStateApplicationFacade.CommandResult.Busy),
            { callback -> recoveryCoordinator(recoverPresentation = callback) },
            RecoveryCoordinator::recoverPresentation,
        )
    }

    @Test fun resetProfilesInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertSuspendingCallbackContract(
            listOf(false, true),
            { callback -> recoveryCoordinator(resetProfiles = callback) },
            RecoveryCoordinator::resetProfiles,
        )
    }

    @Test fun resetRoutingInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertSuspendingCallbackContract(
            listOf(false, true),
            { callback -> recoveryCoordinator(resetRouting = callback) },
            RecoveryCoordinator::resetRouting,
        )
    }

    @Test fun resetDiagnosticsInvokesItsCallbackExactlyOnceWithoutChangingItsOutcome() {
        assertSuspendingCallbackContract(
            listOf(false, true),
            { callback -> recoveryCoordinator(resetDiagnostics = callback) },
            RecoveryCoordinator::resetDiagnostics,
        )
    }

    @Test fun realRecoveryAndSettingsCompositionReachesFirstLaunchWithoutProtectedStateSideEffects() = runBlocking {
        val parent = Files.createTempDirectory("composed-first-use-").toFile().canonicalFile
        var failureReads = 0
        var projectionOrStorageAccesses = 0
        var recoveryWrites = 0
        var diagnosticWrites = 0
        val recovery = recoveryCoordinator(
            storageFailure = { failureReads++; Phase9CompositionRoot.StorageFailure.FIRST_USE },
            recoverPresentation = { recoveryWrites++; error("First use cannot recover presentation") },
            resetProfiles = { recoveryWrites++; error("First use cannot reset profiles or keys") },
            resetRouting = { recoveryWrites++; error("First use cannot reset routing") },
            resetDiagnostics = { diagnosticWrites++; error("First use cannot persist diagnostics") },
        )
        // The real façade boundary must not be entered: it is the only supplied route
        // to a projection, protected storage, keys, or persistent diagnostics.
        val settings = SettingsCoordinator {
            projectionOrStorageAccesses++
            error("First use cannot obtain a protected-state façade")
        }

        val outcomes = settings.startup { recovery.storageFailure() }.toList()

        assertEquals(1, outcomes.size)
        val unavailable = outcomes.single() as ProtectedStartupRead.Unavailable
        assertSame(Phase9CompositionRoot.StorageFailure.FIRST_USE, unavailable.failure)
        assertSame(AppState.FirstLaunch, unavailable.presentation)
        assertNull(unavailable.recoveryReason)
        assertFalse(outcomes.any { it is ProtectedStartupRead.Ready })
        assertEquals(1, failureReads)
        assertEquals(0, projectionOrStorageAccesses)
        assertEquals(0, recoveryWrites)
        assertEquals(0, diagnosticWrites)
        assertEquals(emptyList<String>(), parent.listFiles()!!.map { it.name })
    }

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

    private fun recoveryCoordinator(
        storageFailure: () -> Phase9CompositionRoot.StorageFailure? = { error("Unexpected storage read") },
        presentationRecoveryRequired: () -> Boolean? = { error("Unexpected recovery-state read") },
        recoverPresentation: suspend () -> ProtectedStateApplicationFacade.CommandResult<Unit> = { error("Unexpected recovery") },
        resetProfiles: suspend () -> Boolean = { error("Unexpected profile reset") },
        resetRouting: suspend () -> Boolean = { error("Unexpected routing reset") },
        resetDiagnostics: suspend () -> Boolean = { error("Unexpected diagnostic reset") },
    ) = RecoveryCoordinator(storageFailure, presentationRecoveryRequired, recoverPresentation,
        resetProfiles, resetRouting, resetDiagnostics)

    private fun <T> assertDirectCallbackContract(
        results: List<T>,
        create: (() -> T) -> RecoveryCoordinator,
        invoke: (RecoveryCoordinator) -> T,
    ) {
        for (expected in results) {
            var calls = 0
            val actual = invoke(create { calls++; expected })
            assertSame("The exact callback result must be returned", expected, actual)
            assertEquals("The supplied callback must run exactly once", 1, calls)
        }
        for (expected in listOf(IllegalStateException("synthetic callback failure"),
            CancellationException("synthetic callback cancellation"))) {
            var calls = 0
            val actual = assertThrows(RuntimeException::class.java) {
                invoke(create { calls++; throw expected })
            }
            assertSame("The callback exception must not be wrapped or swallowed", expected, actual)
            assertEquals(1, calls)
        }
    }

    private fun <T> assertSuspendingCallbackContract(
        results: List<T>,
        create: (suspend () -> T) -> RecoveryCoordinator,
        invoke: suspend (RecoveryCoordinator) -> T,
    ) = runBlocking {
        for (expected in results) {
            var calls = 0
            val actual = invoke(create { calls++; expected })
            assertSame("The exact callback result must be returned", expected, actual)
            assertEquals("The supplied callback must run exactly once", 1, calls)
        }
        for (expected in listOf(IllegalStateException("synthetic callback failure"),
            CancellationException("synthetic callback cancellation"))) {
            var calls = 0
            val actual = try {
                invoke(create { calls++; throw expected })
                fail("The callback exception must propagate")
                null
            } catch (failure: RuntimeException) {
                failure
            }
            assertSame("The callback exception must not be wrapped or swallowed", expected, actual)
            assertEquals(1, calls)
        }

        val entered = CompletableDeferred<Unit>()
        val cancellation = CancellationException("synthetic suspended cancellation")
        var calls = 0
        var completions = 0
        var returned = false
        var callbackCancellation: CancellationException? = null
        var observedCancellation: CancellationException? = null
        val operation = launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                invoke(create {
                    calls++
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } catch (cancelled: CancellationException) {
                        callbackCancellation = cancelled
                        throw cancelled
                    } finally {
                        completions++
                    }
                })
                returned = true
            } catch (cancelled: CancellationException) {
                observedCancellation = cancelled
                throw cancelled
            }
        }
        assertTrue("The supplied callback must reach suspension", entered.isCompleted)
        assertEquals(1, calls)
        operation.cancel(cancellation)
        operation.join()
        assertTrue(operation.isCancelled)
        assertFalse("Cancellation cannot become an ordinary result", returned)
        val callbackObserved = callbackCancellation
        val wrapperObserved = observedCancellation
        assertNotNull("The callback must observe cancellation", callbackObserved)
        assertNotNull("Cancellation must propagate through the wrapper", wrapperObserved)
        callbackObserved!!
        wrapperObserved!!
        assertSame(CancellationException::class.java, callbackObserved.javaClass)
        assertSame(CancellationException::class.java, wrapperObserved.javaClass)
        assertEquals(cancellation.message, callbackObserved.message)
        assertEquals(cancellation.message, wrapperObserved.message)
        if (wrapperObserved !== callbackObserved) {
            val connected = generateSequence(wrapperObserved.cause) { it.cause }
                .take(16)
                .any { it === callbackObserved }
            assertTrue("A recovered cancellation copy must remain cause-connected to the callback exception", connected)
        }
        assertEquals("Suspended callback cleanup must run exactly once", 1, completions)
        assertEquals(1, calls)
    }
}

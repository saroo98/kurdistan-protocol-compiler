// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.feature.settingsrecovery

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class SettingsViewModelTest {
    @Test fun unavailableReadClearsCachedSettingsWithoutClaimingAMutationFailed() = runBlocking {
        val repository = Repository()
        val scope = scope()
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), maintenance, scope)
            assertNotNull(vm.appliedSettings.value)
            repository.readFailure = true
            vm.refreshApplied().join()
            assertNull(vm.appliedSettings.value)
            assertNull(vm.changeFailure.value)
            assertEquals(0, repository.commits)
        } finally { scope.cancel() }
    }
    private val maintenance = object : NodeMaintenanceRepository {
        override fun observeUpdate(deploymentId: CatalogId) = flowOf(OperationState.Idle)
        override suspend fun scheduleSignedUpdate(deploymentId: CatalogId, preferences: UpdatePreferences) = error("not requested")
        override suspend fun checkSignedUpdate(deploymentId: CatalogId) = error("not requested")
        override suspend fun cancelSignedUpdate(deploymentId: CatalogId) = error("not requested")
        override suspend fun probe(profileId: CatalogId, request: ProbePreferences): DomainResult<ProbeSample> {
            check(profileId == CatalogId("profile-one"))
            return DomainResult.Success(ProbeSample(10, 12, 0, 0, ProbeStability.UNKNOWN, null))
        }
        override suspend fun cancelProbe(profileId: CatalogId) = DomainResult.Success(Unit)
        override fun observeProbeHistory(profileId: CatalogId) = flowOf(ProbeHistory(emptyList(), 10))
    }

    @Test fun probeUsesAppliedSelectionAndPublishesActualResult() = runBlocking {
        val repository = Repository()
        repository.applied = SettingsRevision(4, ProductSettings(profiles = ProfilePreferences("profile-one")))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), maintenance, scope)
            vm.runProbe().join()
            assertEquals(ProbeExecutionState.Succeeded(12), vm.probeState.value)
        } finally { scope.cancel() }
    }
    private class Repository : SettingsRepository {
        val id = CatalogId("4d76ee20-21c1-4d69-b21a-d34cf038caab")
        var applied = SettingsRevision(4, ProductSettings())
        var saved = applied.settings
        var writes = 0
        var commits = 0
        var gate: CompletableDeferred<Unit>? = null
        var resumeFailure = false
        var cancelFailure = false
        var readFailure = false
        override fun observeAppliedRevision() = flowOf(applied)
        override suspend fun appliedRevision(): DomainResult<SettingsRevision> =
            if (readFailure) DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_LOCKED))
            else DomainResult.Success(applied)
        override suspend fun openDraft() = DomainResult.Success(SettingsDraft(id, applied))
        override suspend fun saveDraft(draftId: CatalogId, requested: ProductSettings): DomainResult<Unit> {
            check(draftId == id); writes++; gate?.await(); saved = requested
            return DomainResult.Success(Unit)
        }
        override suspend fun resumeDraft(draftId: CatalogId): DomainResult<ResumableSettingsDraft> =
            if (resumeFailure) DomainResult.Rejected(ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
            else DomainResult.Success(ResumableSettingsDraft(SettingsDraft(id, applied), saved))
        override suspend fun validate(draftId: CatalogId, requested: ProductSettings) =
            DomainResult.Success(OperationPreview(OperationKind.SETTINGS_CHANGE, 1))
        override suspend fun apply(draftId: CatalogId, expectedAppliedRevision: Long, requested: ProductSettings): DomainResult<SettingsRevision> {
            check(expectedAppliedRevision == applied.revision); commits++
            return DomainResult.Success(SettingsRevision(5, requested).also { applied = it })
        }
        override suspend fun cancel(draftId: CatalogId): DomainResult<Unit> =
            if (cancelFailure) DomainResult.Rejected(ProductFailure(ProductFailureCode.STORAGE_DEGRADED))
            else DomainResult.Success(Unit)
    }
    private fun scope() = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)

    @Test fun draftApplyPublishesCommittedSettingsAndReportsSchedulingFailure() = runBlocking {
        val repository = Repository()
        repository.applied = SettingsRevision(4, ProductSettings(profiles = ProfilePreferences("profile-one")))
        val scheduler = object : NodeMaintenanceRepository by maintenance {
            override suspend fun scheduleSignedUpdate(deploymentId: CatalogId, preferences: UpdatePreferences): DomainResult<Unit> {
                check(deploymentId == CatalogId("profile-one") && preferences.automatic)
                return DomainResult.Rejected(ProductFailure(ProductFailureCode.INTERNAL_FAILURE))
            }
        }
        val scope = scope()
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), scheduler, scope)
            vm.open().join()
            vm.saveDraft(repository.applied.settings.copy(updates = UpdatePreferences(automatic = true))).join()
            vm.apply().join()
            assertTrue(checkNotNull(vm.appliedSettings.value).updates.automatic)
            assertEquals(ProductFailureCode.INTERNAL_FAILURE, vm.state.value.failure)
            assertNull(vm.state.value.draft)
        } finally { scope.cancel() }
    }

    @Test fun immediateChangePublishesCommittedSettingsAndReportsCleanupFailure() = runBlocking {
        val repository = Repository(); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), maintenance, scope)
            vm.change { it.copy(highContrast = true) }.join()
            assertTrue(checkNotNull(vm.appliedSettings.value).highContrast)
            repository.cancelFailure = true
            vm.change { it.copy(reducedMotion = true) }.join()
            assertEquals(ProductFailureCode.STORAGE_DEGRADED, vm.changeFailure.value)
        } finally { scope.cancel() }
    }

    @Test fun savedIsPublishedOnlyAfterDurableWriteAndOnlyIdIsRetained() = runBlocking {
        val repository = Repository(); val handle = SavedStateHandle(); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, handle, maintenance, scope)
            vm.open().join()
            repository.gate = CompletableDeferred()
            val job = vm.saveDraft(repository.saved)
            assertEquals(SettingsEditorPhase.SAVING, vm.state.value.phase)
            assertEquals(setOf("draftId"), handle.keys())
            assertEquals(repository.id.value, handle.get<String>("draftId"))
            assertEquals(0, repository.commits)
            repository.gate!!.complete(Unit); job.join()
            assertEquals(SettingsEditorPhase.SAVED, vm.state.value.phase)
            val restored = SettingsViewModel(repository, handle, maintenance, scope)
            restored.open().join()
            assertEquals(repository.saved, restored.state.value.requested)
            assertEquals(0, repository.commits)
            restored.apply().join()
            assertEquals(1, repository.commits)
            assertTrue(handle.keys().isEmpty())
        } finally { scope.cancel() }
    }

    @Test fun missingSavedParentIsInterruptedAndNeverCreatesOrAppliesAnotherDraft() = runBlocking {
        val repository = Repository().apply { resumeFailure = true }
        val handle = SavedStateHandle(mapOf("draftId" to repository.id.value)); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, handle, maintenance, scope)
            vm.open().join(); vm.apply().join()
            assertEquals(ProductFailureCode.OPERATION_INTERRUPTED, vm.state.value.failure)
            assertEquals(0, repository.commits)
            assertEquals(0, repository.writes)
        } finally { scope.cancel() }
    }

    @Test fun cancelledWriteDoesNotPublishSaved() = runBlocking {
        val repository = Repository(); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), maintenance, scope)
            vm.open().join(); repository.gate = CompletableDeferred()
            val writing = vm.saveDraft(repository.saved)
            writing.cancelAndJoin()
            assertEquals(SettingsEditorPhase.FAILED, vm.state.value.phase)
            assertEquals(ProductFailureCode.OPERATION_INTERRUPTED, vm.state.value.failure)
            assertEquals(0, repository.commits)
        } finally { scope.cancel() }
    }

    @Test fun failedCleanupAfterApplyIsNotPresentedAsUnqualifiedSuccess() = runBlocking {
        val repository = Repository(); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, SavedStateHandle(), maintenance, scope)
            vm.open().join(); repository.cancelFailure = true
            vm.apply().join()
            assertEquals(1, repository.commits)
            assertEquals(SettingsEditorPhase.FAILED, vm.state.value.phase)
            assertEquals(ProductFailureCode.STORAGE_DEGRADED, vm.state.value.failure)
            assertEquals(repository.applied, vm.state.value.applied)
        } finally { scope.cancel() }
    }

    @Test fun rapidEditsPersistInOrderAndCancelRetiresPendingWrites() = runBlocking {
        val repository = Repository(); val handle = SavedStateHandle(); val scope = scope()
        try {
            val vm = SettingsViewModel(repository, handle, maintenance, scope)
            vm.open().join(); repository.gate = CompletableDeferred()
            val first = vm.saveDraft(repository.saved.copy(highContrast = true))
            val latest = repository.saved.copy(reducedMotion = true)
            val second = vm.saveDraft(latest)
            repository.gate!!.complete(Unit)
            first.join(); second.join()
            assertEquals(2, repository.writes)
            assertEquals(latest, repository.saved)
            repository.gate = CompletableDeferred()
            val pending = vm.saveDraft(latest.copy(highContrast = true))
            vm.cancel().join()
            assertTrue(pending.isCompleted)
            assertTrue(handle.keys().isEmpty())
            assertEquals(SettingsEditorPhase.IDLE, vm.state.value.phase)
            assertEquals(0, repository.commits)
        } finally { scope.cancel() }
    }
}

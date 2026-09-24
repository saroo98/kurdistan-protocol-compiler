// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.diagnosticsabout

import androidx.lifecycle.SavedStateHandle
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.flowOf
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class DiagnosticsViewModelTest {
    private class Repository : DiagnosticsRepository {
        val id = CatalogId("diagnostic-preview")
        var exports = 0
        var cancels = 0
        override fun observeEvents() = flowOf(emptyList<DiagnosticEvent>())
        override fun observeExport() = flowOf<DiagnosticWorkflowState>(DiagnosticWorkflowState.Idle)
        override suspend fun setPreferences(preferences: DiagnosticPreferences) = DomainResult.Success(Unit)
        override suspend fun clear() = DomainResult.Success(Unit)
        override suspend fun previewSafeSupportExport() = DomainResult.Success(
            DiagnosticExportPreview(id, DiagnosticWorkflowState.Preview(1, "2", "30")))
        override suspend fun exportSafeSupport(operationId: CatalogId): DomainResult<Unit> {
            assertEquals(id, operationId); exports++; return DomainResult.Success(Unit)
        }
        override suspend fun cancelExport(operationId: CatalogId): DomainResult<Unit> {
            assertEquals(id, operationId); cancels++; return DomainResult.Success(Unit)
        }
    }
    @Test fun onlyOpaquePreviewIdIsSavedAndConfirmationIsNeverReplayed() = runBlocking {
        val repository = Repository()
        val saved = SavedStateHandle()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        try {
            val vm = DiagnosticsViewModel(repository, saved, scope)
            vm.confirm().join()
            assertEquals(0, repository.exports)
            vm.prepare().join()
            assertEquals(setOf("previewId"), saved.keys())
            assertEquals(repository.id.value, saved.get<String>("previewId"))
            vm.confirm().join(); vm.confirm().join()
            assertEquals(1, repository.exports)
            assertTrue(saved.keys().isEmpty())
            vm.prepare().join(); vm.cancel().join()
            assertEquals(1, repository.cancels)
            assertEquals(1, repository.exports)
        } finally { scope.cancel() }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class ProductDiagnosticsRepositoryTest {
    @Test fun onlyTheOutstandingDestinationCanCompleteAnExportOnce() = runBlocking {
        val native = ProductDiagnosticOperationsTest.NativeFixture()
        var destinationId: CatalogId? = null
        val repository = ProductDiagnosticsRepository(ProductDiagnosticOperations(native.core),
            { emptyList() }, { true }, { 0 }, { DiagnosticPreferences() },
            { DomainResult.Success(Unit) }, { id, _ -> destinationId = id; true })
        val preview = (repository.previewSafeSupportExport() as DomainResult.Success).value
        assertTrue(repository.exportSafeSupport(preview.id) is DomainResult.Success)
        assertEquals(preview.id, destinationId)
        assertEquals(DiagnosticWorkflowState.Working, repository.observeExport().value)
        repository.destinationFinished(CatalogId("foreign"), null)
        assertEquals(DiagnosticWorkflowState.Working, repository.observeExport().value)
        assertTrue(repository.previewSafeSupportExport() is DomainResult.Rejected)
        repository.destinationFinished(preview.id, OperationError.CANCELLED)
        assertEquals(DiagnosticWorkflowState.Idle, repository.observeExport().value)
        repository.destinationFinished(preview.id, null)
        assertEquals(DiagnosticWorkflowState.Idle, repository.observeExport().value)
    }

    @Test fun protectedReadsDoNotBlockTheCallingUiThread() = runBlocking {
        val caller = Thread.currentThread()
        val native = ProductDiagnosticOperationsTest.NativeFixture()
        var readThread: Thread? = null
        val repository = ProductDiagnosticsRepository(ProductDiagnosticOperations(native.core),
            { readThread = Thread.currentThread(); emptyList() }, { true }, { 0 },
            { DiagnosticPreferences() }, { DomainResult.Success(Unit) }, { _, _ -> false })
        repository.refresh()
        assertNotSame(caller, readThread)
        readThread = null
        assertTrue(repository.previewSafeSupportExport() is DomainResult.Success)
        assertNotSame(caller, readThread)
    }

    @Test fun cancelledOrStaleExportCannotBuildAndRejectedDestinationWipesBytes() = runBlocking {
        val native = ProductDiagnosticOperationsTest.NativeFixture()
        var launches = 0
        val repository = ProductDiagnosticsRepository(ProductDiagnosticOperations(native.core), { emptyList() }, { true },
            { 0 }, { DiagnosticPreferences() }, { DomainResult.Success(Unit) }, { _, _ -> launches++; false })
        val cancelled = (repository.previewSafeSupportExport() as DomainResult.Success).value
        val nextPreview = native.preview.clone()
        assertTrue(repository.cancelExport(cancelled.id) is DomainResult.Success)
        assertTrue(repository.exportSafeSupport(cancelled.id) is DomainResult.Rejected)
        assertEquals(0, native.builds)
        native.preview = nextPreview
        val current = (repository.previewSafeSupportExport() as DomainResult.Success).value
        assertTrue(repository.exportSafeSupport(current.id) is DomainResult.Rejected)
        assertEquals(1, launches)
        assertArrayEquals(ByteArray(2), native.output)
        assertTrue(repository.exportSafeSupport(current.id) is DomainResult.Rejected)
        assertEquals(1, launches)
    }

    @Test fun failedStorageReadIsACategoricalRejectionNotAnEmptySuccessfulExport() = runBlocking {
        val native = ProductDiagnosticOperationsTest.NativeFixture()
        val repository = ProductDiagnosticsRepository(ProductDiagnosticOperations(native.core), { error("Unreadable") }, { false },
            { 0 }, { DiagnosticPreferences() }, { DomainResult.Success(Unit) }, { _, _ -> error("Must not launch") })
        assertTrue(repository.previewSafeSupportExport() is DomainResult.Rejected)
        assertEquals(0, native.prepares)
        assertTrue(repository.clear() is DomainResult.Rejected)
    }

    @Test fun failedReplacementPreviewRetiresTheEarlierConfirmation() = runBlocking {
        val native = ProductDiagnosticOperationsTest.NativeFixture()
        var unreadable = false
        val repository = ProductDiagnosticsRepository(ProductDiagnosticOperations(native.core),
            { check(!unreadable); emptyList() }, { true }, { 0 }, { DiagnosticPreferences() },
            { DomainResult.Success(Unit) }, { _, _ -> true })
        val first = (repository.previewSafeSupportExport() as DomainResult.Success).value
        unreadable = true
        assertTrue(repository.previewSafeSupportExport() is DomainResult.Rejected)
        assertTrue(repository.exportSafeSupport(first.id) is DomainResult.Rejected)
        assertEquals(0, native.builds)
        assertEquals(1, native.releases)
    }
}

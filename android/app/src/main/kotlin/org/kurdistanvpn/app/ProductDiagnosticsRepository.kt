// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.domain.*

internal interface ProductDiagnosticForeground {
    /** Takes ownership of the bounded bytes only when a local destination request is accepted. */
    fun requestDiagnosticDestination(operationId: CatalogId, bytes: ByteArray): Boolean
}

internal class ProductDiagnosticsRepository(
    private val operations: ProductDiagnosticOperations,
    private val read: () -> List<DiagnosticEvent>,
    private val write: suspend (List<DiagnosticEvent>) -> Boolean,
    private val profileCount: () -> Int,
    private val preferences: () -> DiagnosticPreferences,
    private val applyPreferences: suspend (DiagnosticPreferences) -> DomainResult<Unit>,
    private val destination: suspend (CatalogId, ByteArray) -> Boolean,
) : DiagnosticsRepository {
    private val events = MutableStateFlow<List<DiagnosticEvent>>(emptyList())
    private val export = MutableStateFlow<DiagnosticWorkflowState>(DiagnosticWorkflowState.Idle)
    private val mutex = Mutex()
    private var pending: CatalogId? = null
    private val destinationMonitor = Any()
    private var exporting: CatalogId? = null
    override fun observeEvents(): StateFlow<List<DiagnosticEvent>> = events.asStateFlow()
    override fun observeExport(): StateFlow<DiagnosticWorkflowState> = export.asStateFlow()

    fun destinationFinished(operationId: CatalogId, error: OperationError?) {
        synchronized(destinationMonitor) {
            if (exporting != operationId) return
            exporting = null
            export.value = when (error) {
                null -> DiagnosticWorkflowState.Completed
                OperationError.CANCELLED -> DiagnosticWorkflowState.Idle
                else -> DiagnosticWorkflowState.Failed(error)
            }
        }
    }

    suspend fun resetPresentation(): Boolean = onStorageDispatcher {
        synchronized(destinationMonitor) { exporting = null }
        val result = operations.cancel(pending)
        pending = null
        events.value = emptyList()
        export.value = if (result is NativeResult.Success) DiagnosticWorkflowState.Idle
            else DiagnosticWorkflowState.Failed(OperationError.RECOVERY_REQUIRED)
        result is NativeResult.Success
    }

    suspend fun refresh() = onStorageDispatcher {
        events.value = retainDiagnosticEvents(read(), preferences().retention)
    }

    suspend fun record(level: DiagnosticLogLevel, component: DiagnosticComponent, category: String) = onStorageDispatcher {
        val policy = preferences()
        if (!shouldRecord(level, policy.level)) return@onStorageDispatcher
        val current = events.value
        val event = DiagnosticEvent(Math.addExact(current.maxOfOrNull { it.sequence } ?: 0, 1), level,
            component, category, System.currentTimeMillis() / 60_000)
        val next = retainDiagnosticEvents(current + event, policy.retention).takeLast(200)
        check(write(next)) { "DIAGNOSTICS_WRITE_REJECTED" }
        events.value = next
    }

    override suspend fun setPreferences(preferences: DiagnosticPreferences): DomainResult<Unit> = applyPreferences(preferences)
    override suspend fun clear(): DomainResult<Unit> = onStorageDispatcher {
        val committed = try { write(emptyList()) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { false }
        if (!committed) return@onStorageDispatcher rejected(ProductFailureCode.STORAGE_DEGRADED)
        events.value = emptyList()
        DomainResult.Success(Unit)
    }

    override suspend fun previewSafeSupportExport(): DomainResult<DiagnosticExportPreview> = onStorageDispatcher {
        if (synchronized(destinationMonitor) { exporting != null })
            return@onStorageDispatcher rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        export.value = DiagnosticWorkflowState.Working
        val retired = operations.cancel(pending)
        pending = null
        if (retired is NativeResult.Failure) {
            export.value = DiagnosticWorkflowState.Failed(retired.error)
            return@onStorageDispatcher rejected(retired.error.toProductFailure())
        }
        val request = try { ProductExportWire.diagnosticRequest(profileCount(), read()) }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) {
            export.value = DiagnosticWorkflowState.Failed(OperationError.STORAGE_FAILURE)
            return@onStorageDispatcher rejected(ProductFailureCode.STORAGE_DEGRADED)
        }
        val result = try { operations.prepare(request) } finally { request.fill(0) }
        when (result) {
            is NativeResult.Failure -> {
                export.value = DiagnosticWorkflowState.Failed(result.error)
                rejected(result.error.toProductFailure())
            }
            is NativeResult.Success -> {
                pending = result.value.id
                export.value = result.value.display
                DomainResult.Success(DiagnosticExportPreview(result.value.id, result.value.display))
            }
        }
    }

    override suspend fun exportSafeSupport(operationId: CatalogId): DomainResult<Unit> = onStorageDispatcher {
        if (pending != operationId) return@onStorageDispatcher rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        pending = null
        export.value = DiagnosticWorkflowState.Working
        when (val result = operations.confirm(operationId)) {
            is NativeResult.Failure -> {
                export.value = DiagnosticWorkflowState.Failed(result.error)
                rejected(result.error.toProductFailure())
            }
            is NativeResult.Success -> {
                var handedOff = false
                synchronized(destinationMonitor) { exporting = operationId }
                try {
                    handedOff = destination(operationId, result.value)
                    if (handedOff) DomainResult.Success(Unit) else {
                        export.value = DiagnosticWorkflowState.Failed(OperationError.CANCELLED)
                        rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                    }
                } finally {
                    if (!handedOff) {
                        result.value.fill(0)
                        destinationFinished(operationId, OperationError.CANCELLED)
                    }
                }
            }
        }
    }

    override suspend fun cancelExport(operationId: CatalogId): DomainResult<Unit> = onStorageDispatcher {
        if (pending != operationId) return@onStorageDispatcher rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        pending = null
        when (val result = operations.cancel(operationId)) {
            is NativeResult.Failure -> {
                export.value = DiagnosticWorkflowState.Failed(result.error)
                rejected(result.error.toProductFailure())
            }
            is NativeResult.Success -> { export.value = DiagnosticWorkflowState.Idle; DomainResult.Success(Unit) }
        }
    }

    private suspend fun <T> onStorageDispatcher(action: suspend () -> T): T =
        withContext(Dispatchers.IO) { mutex.withLock { action() } }

    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
    private fun OperationError.toProductFailure() = when (this) {
        OperationError.CANCELLED -> ProductFailureCode.OPERATION_INTERRUPTED
        OperationError.RECOVERY_REQUIRED -> ProductFailureCode.STORAGE_DEGRADED
        OperationError.INVALID_INPUT -> ProductFailureCode.INVALID_INPUT
        else -> ProductFailureCode.INTERNAL_FAILURE
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.diagnosticsabout

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class DiagnosticsViewModel(private val repository: DiagnosticsRepository, private val saved: SavedStateHandle,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)) : ViewModel(scope) {
    val events = repository.observeEvents().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    private val mutableFailure = MutableStateFlow<ProductFailureCode?>(null)
    val failure = mutableFailure.asStateFlow()
    val state = combine(repository.observeExport(), failure) { observed, failed ->
        if (failed == null) observed else DiagnosticWorkflowState.Failed(when (failed) {
            ProductFailureCode.INVALID_INPUT -> OperationError.INVALID_INPUT
            ProductFailureCode.OPERATION_INTERRUPTED, ProductFailureCode.CANCELLED -> OperationError.CANCELLED
            ProductFailureCode.STORAGE_DEGRADED, ProductFailureCode.STORAGE_LOCKED -> OperationError.STORAGE_FAILURE
            else -> OperationError.INTERNAL_FAILURE
        })
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DiagnosticWorkflowState.Idle)
    private val operation = Mutex()

    fun prepare() = command {
        saved.remove<String>("previewId")
        when (val result = repository.previewSafeSupportExport()) {
            is DomainResult.Success -> saved["previewId"] = result.value.id.value
            is DomainResult.Rejected -> mutableFailure.value = result.failure.code
        }
    }
    fun confirm() = command {
        val id = saved.remove<String>("previewId")?.let(::CatalogId)
            ?: return@command fail(ProductFailureCode.OPERATION_INTERRUPTED)
        handle(repository.exportSafeSupport(id))
    }
    fun cancel() = command {
        val id = saved.remove<String>("previewId")?.let(::CatalogId) ?: return@command
        handle(repository.cancelExport(id))
    }
    fun clear() = command { handle(repository.clear()) }
    fun setPreferences(value: DiagnosticPreferences) = command { handle(repository.setPreferences(value)) }
    private fun handle(result: DomainResult<Unit>) { if (result is DomainResult.Rejected) fail(result.failure.code) }
    private fun fail(code: ProductFailureCode) { mutableFailure.value = code }
    private fun command(action: suspend () -> Unit) = viewModelScope.launch {
        operation.withLock {
            mutableFailure.value = null
            try { action() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { fail(ProductFailureCode.INTERNAL_FAILURE) }
        }
    }
}

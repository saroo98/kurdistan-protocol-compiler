// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.onboarding

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class OnboardingViewModel(private val repository: ProfileRepository, private val saved: SavedStateHandle,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)) : ViewModel(scope) {
    private val mutableState = MutableStateFlow<EnrollmentUiState>(EnrollmentUiState.NoEnrollmentKey)
    val state = mutableState.asStateFlow()
    private val operation = Mutex()

    fun refresh() = command { refreshState() }
    fun createEnrollment(validitySeconds: Int = 24 * 60 * 60) = command {
        mutableState.value = EnrollmentUiState.Working
        handle(repository.createEnrollment(validitySeconds))
    }
    fun export(id: CatalogId, destination: EnrollmentExport) = command {
        saved["selectedEnrollment"] = id.value
        handle(repository.exportEnrollment(id, destination))
    }
    fun markExported(id: CatalogId) = command { handle(repository.markEnrollmentExported(id)) }
    fun delete(id: CatalogId) = command { handle(repository.deleteEnrollment(id)) }

    private suspend fun handle(result: DomainResult<Unit>) {
        when (result) {
            is DomainResult.Success -> refreshState()
            is DomainResult.Rejected -> failed(result.failure.code)
        }
    }
    private suspend fun refreshState() {
        when (val result = repository.readEnrollment()) {
            is DomainResult.Success -> mutableState.value = result.value
            is DomainResult.Rejected -> failed(result.failure.code)
        }
    }
    private fun failed(code: ProductFailureCode) {
        mutableState.value = when (code) {
            ProductFailureCode.STORAGE_KEY_INVALIDATED -> EnrollmentUiState.KeyInvalidated
            ProductFailureCode.STORAGE_LOCKED, ProductFailureCode.STORAGE_DEGRADED -> EnrollmentUiState.RecoveryRequired
            else -> EnrollmentUiState.Failed(if (code == ProductFailureCode.OPERATION_INTERRUPTED) OperationError.CANCELLED else OperationError.INTERNAL_FAILURE)
        }
    }
    private fun command(action: suspend () -> Unit) = viewModelScope.launch {
        operation.withLock {
            try { action() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { failed(ProductFailureCode.STORAGE_DEGRADED) }
        }
    }
}

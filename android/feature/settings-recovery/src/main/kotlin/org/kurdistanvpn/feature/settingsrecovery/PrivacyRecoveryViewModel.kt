// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.settingsrecovery

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

/** A saved identity can retire an interrupted operation, never recreate consent. */
class PrivacyRecoveryViewModel(
    private val repository: PrivacyRecoveryRepository,
    private val saved: SavedStateHandle,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) : ViewModel(scope) {
    private val mutableState = MutableStateFlow<OperationState>(OperationState.Idle)
    val state = mutableState.asStateFlow()
    private val mutex = Mutex()
    private var pending: PendingProductOperation? = null
    private var apply: (suspend (CatalogId) -> DomainResult<Unit>)? = null
    private var resetScope: ResetScope? = null
    private val mutableBackup = MutableStateFlow<BackupWorkflowState>(BackupWorkflowState.Idle)
    val backupState = mutableBackup.asStateFlow()

    init {
        viewModelScope.launch { repository.observeBackup().collect { mutableBackup.value = it } }
        viewModelScope.launch { repository.observeOperation().collect { mutableState.value = it } }
        saved.remove<String>("privacyOperationId")?.let { value ->
            runOperation(OperationKind.RESET) {
                repository.cancel(CatalogId(value))
                mutableState.value = failed(OperationKind.RESET, ProductFailureCode.OPERATION_INTERRUPTED)
            }
        }
    }

    fun previewReset(scope: ResetScope) = preview(OperationKind.RESET, { repository.previewReset(scope) }, repository::reset, scope)
    fun previewBackup(ids: Set<CatalogId>) = preview(OperationKind.BACKUP, { repository.previewBackup(ids) }, repository::backup)
    fun previewRestore(id: CatalogId) = preview(OperationKind.RESTORE, { repository.previewRestore(id) }, repository::restore)
    fun previewTransfer(profile: CatalogId, recipient: CatalogId) =
        preview(OperationKind.BACKUP, { repository.previewTransfer(profile, recipient) }, repository::transfer)

    private fun preview(kind: OperationKind, read: suspend () -> DomainResult<PendingProductOperation>,
        confirm: suspend (CatalogId) -> DomainResult<Unit>, scope: ResetScope? = null): Job = runOperation(kind) {
        val old = takePending()
        if (old != null) when (val cancelled = repository.cancel(old.id)) {
            is DomainResult.Rejected -> { mutableState.value = OperationState.Failed(kind, cancelled.failure); return@runOperation }
            is DomainResult.Success -> Unit
        }
        mutableState.value = OperationState.Loading(kind)
        when (val result = read()) {
            is DomainResult.Rejected -> mutableState.value = OperationState.Failed(kind, result.failure)
            is DomainResult.Success -> {
                pending = result.value
                apply = confirm
                resetScope = scope
                saved["privacyOperationId"] = result.value.id.value
                mutableState.value = OperationState.AwaitingConfirmation(result.value.preview)
            }
        }
    }

    fun confirmBackup() = confirm(OperationKind.BACKUP)
    fun confirmRestore() = confirm(OperationKind.RESTORE)
    fun confirmReset(scope: ResetScope) = confirm(OperationKind.RESET, scope)
    private fun confirm(expectedKind: OperationKind, expectedScope: ResetScope? = null): Job = runOperation(expectedKind) {
        val action = apply
        val matches = pending?.preview?.kind == expectedKind && resetScope == expectedScope
        val current = takePending() ?: return@runOperation
        if (!matches) {
            repository.cancel(current.id)
            mutableState.value = failed(expectedKind, ProductFailureCode.OPERATION_INTERRUPTED)
            return@runOperation
        }
        if (action == null) return@runOperation
        val kind = current.preview.kind
        mutableState.value = OperationState.Applying(OperationProgress(kind, 0, maxOf(1, current.preview.itemCount)))
        when (val result = action(current.id)) {
            is DomainResult.Rejected -> mutableState.value =
                repository.observeOperation().first().takeIf { it is OperationState.PartiallyApplied }
                    ?: OperationState.Failed(kind, result.failure)
            is DomainResult.Success -> mutableState.value = repository.observeOperation().first()
        }
    }

    fun beginBackupInput() = replaceBackupInput(BackupWorkflowState.Working)
    fun backupInputFailed(error: OperationError) = replaceBackupInput(BackupWorkflowState.Failed(error))
    private fun replaceBackupInput(next: BackupWorkflowState): Job = runOperation(OperationKind.RESTORE) {
        val old = takePending()
        if (old != null && repository.cancel(old.id) is DomainResult.Rejected) {
            mutableBackup.value = BackupWorkflowState.Failed(OperationError.RECOVERY_REQUIRED)
            return@runOperation
        }
        mutableBackup.value = next
    }
    fun dismissFailure() { if (state.value is OperationState.Failed || state.value is OperationState.PartiallyApplied) mutableState.value = OperationState.Idle }

    fun cancel(): Job = runOperation(pending?.preview?.kind ?: OperationKind.RESET) {
        val current = takePending() ?: return@runOperation
        mutableState.value = when (val result = repository.cancel(current.id)) {
            is DomainResult.Rejected -> OperationState.Failed(current.preview.kind, result.failure)
            is DomainResult.Success -> OperationState.Cancelled(current.preview.kind)
        }
    }

    fun cancelReset(): Job = runOperation(OperationKind.RESET) {
        if (pending?.preview?.kind != OperationKind.RESET) return@runOperation
        val current = takePending() ?: return@runOperation
        when (val result = repository.cancel(current.id)) {
            is DomainResult.Success -> mutableState.value = OperationState.Cancelled(OperationKind.RESET)
            is DomainResult.Rejected -> mutableState.value = OperationState.Failed(OperationKind.RESET, result.failure)
        }
    }

    fun migrateLegacy(): Job = runOperation(OperationKind.SETTINGS_CHANGE) {
        when (val result = repository.migrateLegacyProtectedState()) {
            is DomainResult.Rejected -> mutableState.value = OperationState.Failed(OperationKind.SETTINGS_CHANGE, result.failure)
            is DomainResult.Success -> mutableState.value = result.value
        }
    }

    fun recover(): Job = runOperation(OperationKind.RESET) {
        when (val result = repository.recoverProtectedState()) {
            is DomainResult.Rejected -> mutableState.value = OperationState.Failed(OperationKind.RESET, result.failure)
            is DomainResult.Success -> mutableState.value = result.value
        }
    }

    private fun takePending(): PendingProductOperation? = pending.also {
        pending = null; apply = null; resetScope = null; saved.remove<String>("privacyOperationId")
    }

    private fun runOperation(kind: OperationKind, block: suspend () -> Unit): Job = viewModelScope.launch {
        mutex.withLock {
            try { block() }
            catch (cancelled: CancellationException) {
                val current = takePending()
                if (current != null) withContext(NonCancellable) { repository.cancel(current.id) }
                throw cancelled
            } catch (_: Exception) {
                val current = takePending()
                if (current != null) withContext(NonCancellable) { repository.cancel(current.id) }
                mutableState.value = failed(kind, ProductFailureCode.STORAGE_DEGRADED)
            }
        }
    }

    private fun failed(kind: OperationKind, code: ProductFailureCode) = OperationState.Failed(kind, ProductFailure(code))
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.feature.settingsrecovery

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

enum class SettingsEditorPhase { IDLE, LOADING, EDITING, SAVING, SAVED, APPLYING, APPLIED, FAILED }

data class SettingsEditorState(
    val phase: SettingsEditorPhase = SettingsEditorPhase.IDLE,
    val draft: SettingsDraft? = null,
    val requested: ProductSettings? = null,
    val applied: SettingsRevision? = null,
    val failure: ProductFailureCode? = null,
)

/** Protected values are reloaded from their owner; only the draft ID survives process loss. */
class SettingsViewModel(
    private val repository: SettingsRepository,
    private val savedState: SavedStateHandle,
    private val maintenance: NodeMaintenanceRepository,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) : ViewModel(scope) {
    private val mutableState = MutableStateFlow(SettingsEditorState())
    val state = mutableState.asStateFlow()
    private val operation = Mutex()
    private val pendingSaves = linkedSetOf<Job>()
    private val mutableProbe = MutableStateFlow<ProbeExecutionState>(ProbeExecutionState.Idle)
    val probeState = mutableProbe.asStateFlow()
    private var probeJob: Job? = null
    private val mutableAppliedSettings = MutableStateFlow<ProductSettings?>(null)
    val appliedSettings = mutableAppliedSettings.asStateFlow()
    private val mutableChangeFailure = MutableStateFlow<ProductFailureCode?>(null)
    val changeFailure = mutableChangeFailure.asStateFlow()

    init {
        viewModelScope.launch {
            try { repository.observeAppliedRevision().collect { mutableAppliedSettings.value = it.settings } }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableAppliedSettings.value = null }
        }
    }

    fun clearChangeFailure() { mutableChangeFailure.value = null }
    fun refreshApplied(): Job = viewModelScope.launch {
        when (val result = repository.appliedRevision()) {
            is DomainResult.Success -> mutableAppliedSettings.value = result.value.settings
            // Startup/recovery owns unavailable storage. A read is not a failed settings change.
            is DomainResult.Rejected -> mutableAppliedSettings.value = null
        }
    }

    /** Immediate controls still use a fresh durable draft and the one compare-and-apply owner. */
    fun change(transform: (ProductSettings) -> ProductSettings): Job = viewModelScope.launch {
        operation.withLock {
            mutableChangeFailure.value = null
            if (state.value.draft != null) {
                mutableChangeFailure.value = ProductFailureCode.OPERATION_ALREADY_ACTIVE
                return@withLock
            }
            var draft: SettingsDraft? = null
            try {
                draft = when (val opened = repository.openDraft()) {
                    is DomainResult.Rejected -> { mutableChangeFailure.value = opened.failure.code; return@withLock }
                    is DomainResult.Success -> opened.value
                }
                when (val applied = repository.apply(draft.id, draft.basedOn.revision, transform(draft.basedOn.settings))) {
                    is DomainResult.Rejected -> mutableChangeFailure.value = applied.failure.code
                    is DomainResult.Success -> {
                        mutableAppliedSettings.value = applied.value.settings
                        if (applied.value.settings.updates != draft.basedOn.settings.updates)
                            applied.value.settings.profiles.activeLocalRecordId?.let { id ->
                                val scheduled = maintenance.scheduleSignedUpdate(CatalogId(id), applied.value.settings.updates)
                                if (scheduled is DomainResult.Rejected) mutableChangeFailure.value = scheduled.failure.code
                            }
                    }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: IllegalArgumentException) { mutableChangeFailure.value = ProductFailureCode.INVALID_INPUT }
            catch (_: Exception) { mutableChangeFailure.value = ProductFailureCode.INTERNAL_FAILURE }
            finally {
                draft?.let { value ->
                    when (val cleanup = withContext(NonCancellable) { repository.cancel(value.id) }) {
                        is DomainResult.Rejected -> mutableChangeFailure.value = cleanup.failure.code
                        is DomainResult.Success -> Unit
                    }
                }
            }
        }
    }

    fun runProbe(): Job {
        probeJob?.takeIf { it.isActive }?.let { return it }
        return viewModelScope.launch {
            var profile: CatalogId? = null
            mutableProbe.value = ProbeExecutionState.Running
            try {
                val applied = when (val current = repository.appliedRevision()) {
                    is DomainResult.Rejected -> return@launch probeFailed(current.failure.code)
                    is DomainResult.Success -> current.value.settings
                }
                profile = applied.profiles.activeLocalRecordId?.let(::CatalogId)
                    ?: return@launch probeFailed(ProductFailureCode.INVALID_INPUT)
                when (val result = maintenance.probe(profile, applied.probes)) {
                    is DomainResult.Rejected -> probeFailed(result.failure.code)
                    is DomainResult.Success -> result.value.failure?.let(::probeFailed)
                        ?: run { mutableProbe.value = ProbeExecutionState.Succeeded(result.value.latencyMillis.toLong()) }
                }
            } catch (cancelled: CancellationException) {
                profile?.let { withContext(NonCancellable) { maintenance.cancelProbe(it) } }
                probeFailed(ProductFailureCode.CANCELLED)
                throw cancelled
            } catch (_: Exception) { probeFailed(ProductFailureCode.INTERNAL_FAILURE) }
        }.also { probeJob = it }
    }

    fun cancelProbe() { probeJob?.cancel() }

    private fun probeFailed(code: ProductFailureCode) {
        mutableProbe.value = ProbeExecutionState.Failed(when (code) {
            ProductFailureCode.INVALID_INPUT -> OperationError.INVALID_INPUT
            ProductFailureCode.CANCELLED, ProductFailureCode.OPERATION_INTERRUPTED -> OperationError.CANCELLED
            ProductFailureCode.NETWORK_UNAVAILABLE -> OperationError.NETWORK_LOST
            ProductFailureCode.NODE_UNREACHABLE -> OperationError.ENDPOINT_UNAVAILABLE
            ProductFailureCode.STORAGE_DEGRADED, ProductFailureCode.STORAGE_LOCKED,
            ProductFailureCode.STORAGE_KEY_INVALIDATED -> OperationError.STORAGE_FAILURE
            ProductFailureCode.INTERNAL_FAILURE -> OperationError.INTERNAL_FAILURE
            else -> OperationError.AUTHORITY_UNAVAILABLE
        })
    }

    fun open(): Job = runOperation {
        if (state.value.draft != null) return@runOperation
        mutableState.value = SettingsEditorState(phase = SettingsEditorPhase.LOADING)
        val id = savedState.get<String>("draftId")
        if (id != null) {
            when (val restored = repository.resumeDraft(CatalogId(id))) {
                is DomainResult.Success -> mutableState.value = SettingsEditorState(
                    SettingsEditorPhase.SAVED, restored.value.draft, restored.value.requested,
                    restored.value.draft.basedOn)
                is DomainResult.Rejected -> fail(restored.failure.code)
            }
        } else when (val opened = repository.openDraft()) {
            is DomainResult.Success -> {
                savedState["draftId"] = opened.value.id.value
                mutableState.value = SettingsEditorState(SettingsEditorPhase.EDITING, opened.value,
                    opened.value.basedOn.settings, opened.value.basedOn)
            }
            is DomainResult.Rejected -> fail(opened.failure.code)
        }
    }

    fun saveDraft(requested: ProductSettings): Job {
        val job = runOperation(start = CoroutineStart.LAZY) {
            val draft = state.value.draft ?: return@runOperation fail(ProductFailureCode.OPERATION_INTERRUPTED)
            mutableState.value = state.value.copy(phase = SettingsEditorPhase.SAVING, requested = requested, failure = null)
            when (val result = repository.saveDraft(draft.id, requested)) {
                is DomainResult.Success -> mutableState.value = state.value.copy(phase = SettingsEditorPhase.SAVED)
                is DomainResult.Rejected -> fail(result.failure.code)
            }
        }
        synchronized(pendingSaves) { pendingSaves.add(job) }
        job.invokeOnCompletion { synchronized(pendingSaves) { pendingSaves.remove(job) } }
        job.start()
        return job
    }

    fun apply(): Job = runOperation {
        val current = state.value
        val draft = current.draft ?: return@runOperation fail(ProductFailureCode.OPERATION_INTERRUPTED)
        val requested = current.requested ?: return@runOperation fail(ProductFailureCode.OPERATION_INTERRUPTED)
        mutableState.value = current.copy(phase = SettingsEditorPhase.APPLYING, failure = null)
        try {
            when (val result = repository.apply(draft.id, draft.basedOn.revision, requested)) {
                is DomainResult.Success -> {
                    mutableAppliedSettings.value = result.value.settings
                    mutableState.value = SettingsEditorState(
                        phase = SettingsEditorPhase.APPLIED, applied = result.value)
                    if (result.value.settings.updates != draft.basedOn.settings.updates)
                        result.value.settings.profiles.activeLocalRecordId?.let { id ->
                            when (val scheduled = maintenance.scheduleSignedUpdate(CatalogId(id), result.value.settings.updates)) {
                                is DomainResult.Rejected -> fail(scheduled.failure.code)
                                is DomainResult.Success -> Unit
                            }
                        }
                }
                is DomainResult.Rejected -> fail(result.failure.code)
            }
        } finally {
            // Apply may have consumed its confirmation even when publication failed. Never replay it.
            savedState.remove<String>("draftId")
            mutableState.value = state.value.copy(draft = null, requested = null)
            when (val cleanup = withContext(NonCancellable) { repository.cancel(draft.id) }) {
                is DomainResult.Rejected -> fail(cleanup.failure.code)
                is DomainResult.Success -> Unit
            }
        }
    }

    fun cancel(): Job {
        synchronized(pendingSaves) { pendingSaves.toList() }.forEach { it.cancel() }
        return runOperation {
            val id = state.value.draft?.id ?: savedState.get<String>("draftId")?.let(::CatalogId)
            if (id != null) when (val result = repository.cancel(id)) {
                is DomainResult.Rejected -> return@runOperation fail(result.failure.code)
                is DomainResult.Success -> Unit
            }
            savedState.remove<String>("draftId")
            mutableState.value = SettingsEditorState(applied = state.value.applied)
        }
    }

    private fun runOperation(start: CoroutineStart = CoroutineStart.DEFAULT, action: suspend () -> Unit): Job = viewModelScope.launch(start = start) {
        operation.withLock {
            try { action() }
            catch (cancelled: CancellationException) { fail(ProductFailureCode.OPERATION_INTERRUPTED); throw cancelled }
            catch (_: IllegalArgumentException) { fail(ProductFailureCode.INVALID_INPUT) }
            catch (_: Exception) { fail(ProductFailureCode.INTERNAL_FAILURE) }
        }
    }

    private fun fail(code: ProductFailureCode) {
        mutableState.value = state.value.copy(phase = SettingsEditorPhase.FAILED, failure = code)
    }
}

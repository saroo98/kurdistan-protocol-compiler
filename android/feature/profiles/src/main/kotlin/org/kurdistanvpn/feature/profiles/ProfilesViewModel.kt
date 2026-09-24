// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.profiles

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class ProfilesViewModel(private val repository: ProfileRepository, private val saved: SavedStateHandle,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)) : ViewModel(scope) {
    val profiles = repository.observeProfiles().stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    private val mutableImport = MutableStateFlow<AppState?>(null)
    val importState = mutableImport.asStateFlow()
    private val mutableFailure = MutableStateFlow<ProductFailureCode?>(null)
    val failure = mutableFailure.asStateFlow()
    private val operation = Mutex()
    private var reviewed: Pair<CatalogId, Long>? = null

    init {
        // An ID restored into a new ViewModel is not a restored native preview or user consent.
        if (saved.remove<String>("importPreviewId") != null) mutableImport.value = AppState.ImportRejected(OperationError.CANCELLED)
        saved.remove<String>("importSource")
    }

    fun preview(source: ImportSource, stagedInputId: CatalogId) = command {
        if (!retirePreview()) return@command
        mutableImport.value = AppState.Importing(source)
        when (val result = repository.preview(source, stagedInputId)) {
            is DomainResult.Success -> {
                saved["importPreviewId"] = result.value.id.value
                saved["importSource"] = source.name
                mutableImport.value = AppState.ImportPreview(result.value.preview)
            }
            is DomainResult.Rejected -> reject(result.failure.code)
        }
    }

    fun confirmImport() = command {
        val id = saved.remove<String>("importPreviewId")?.let(::CatalogId) ?: return@command
        val source = saved.remove<String>("importSource")?.let { value -> ImportSource.entries.find { it.name == value } }
            ?: ImportSource.FILE
        mutableImport.value = AppState.Importing(source)
        when (val result = repository.admit(id)) {
            is DomainResult.Success -> { mutableImport.value = null; repository.listProfiles() }
            is DomainResult.Rejected -> reject(result.failure.code)
        }
    }

    fun cancelImport() = command { if (retirePreview()) mutableImport.value = null }
    fun rejectImport(error: OperationError = OperationError.INVALID_INPUT) = command {
        if (retirePreview()) mutableImport.value = AppState.ImportRejected(error)
    }
    fun refresh() = command { handle(repository.listProfiles()) }
    fun dismissFailure() { mutableFailure.value = null }
    fun cancelReview() = command { reviewed = null }
    fun review(id: CatalogId) = command {
        reviewed = null
        when (val result = repository.detail(id)) {
            is DomainResult.Success -> {
                val revision = result.value.trustRevision
                if (revision != null && result.value.profile.id == id) reviewed = id to revision
                else mutableFailure.value = ProductFailureCode.PROFILE_UNTRUSTED
            }
            is DomainResult.Rejected -> handle(result)
        }
    }
    fun deleteReviewed(id: CatalogId) = command {
        val revision = consumeReview(id) ?: return@command
        handle(repository.delete(id, revision))
    }
    fun activateReviewed(id: CatalogId) = command {
        val revision = consumeReview(id) ?: return@command
        handle(repository.activate(id, revision))
    }
    fun setFavorite(id: CatalogId, favorite: Boolean) = command { handle(repository.setFavorite(id, favorite)) }
    fun setPriority(id: CatalogId, priority: Int) = command { handle(repository.setPriority(id, priority)) }

    private suspend fun retirePreview(): Boolean {
        val id = saved.remove<String>("importPreviewId")?.let(::CatalogId)
        saved.remove<String>("importSource")
        if (id == null) return true
        val result = repository.cancelImport(id)
        if (result is DomainResult.Rejected) { reject(result.failure.code); return false }
        return true
    }
    private fun handle(result: DomainResult<*>) { if (result is DomainResult.Rejected) mutableFailure.value = result.failure.code }
    private fun consumeReview(id: CatalogId): Long? {
        val value = reviewed
        reviewed = null
        if (value?.first == id) return value.second
        mutableFailure.value = ProductFailureCode.OPERATION_INTERRUPTED
        return null
    }
    private fun reject(code: ProductFailureCode) {
        mutableFailure.value = code
        mutableImport.value = AppState.ImportRejected(when (code) {
            ProductFailureCode.PROFILE_UNTRUSTED -> OperationError.TRUST_REJECTED
            ProductFailureCode.INVALID_INPUT -> OperationError.INVALID_INPUT
            ProductFailureCode.SIZE_LIMIT -> OperationError.SIZE_LIMIT
            ProductFailureCode.STORAGE_LOCKED, ProductFailureCode.STORAGE_DEGRADED -> OperationError.RECOVERY_REQUIRED
            ProductFailureCode.OPERATION_INTERRUPTED, ProductFailureCode.CANCELLED -> OperationError.CANCELLED
            else -> OperationError.INTERNAL_FAILURE
        })
    }
    private fun command(action: suspend () -> Unit) = viewModelScope.launch {
        operation.withLock {
            mutableFailure.value = null
            try { action() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { reject(ProductFailureCode.INTERNAL_FAILURE) }
        }
    }
}

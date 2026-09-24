// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

/** Display state is never saved. Every new owner observes the actual session again. */
class ConnectionViewModel(private val repository: ConnectionRepository,
    scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate),
) : ViewModel(scope) {
    val state = repository.observeState().catch {
        if (it is CancellationException) throw it
        emit(ConnectionState.SafeMode(SafeModeSummary(SafeModeReason.INCONSISTENT_STATE)))
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000),
        ConnectionState.Recovering(RecoveryProgress(RecoveryReason.PROCESS_RECREATION)))
    private val mutableFailure = MutableStateFlow<ProductFailure?>(null)
    val failure = mutableFailure.asStateFlow()
    fun dismissFailure() { mutableFailure.value = null }
    fun connect(id: CatalogId, revision: Long) = command { repository.connect(id, revision) }
    fun disconnect() = command { repository.disconnect() }
    fun recoverInternet() = command { repository.recoverInternet() }
    fun pause(durationMillis: Long = 0) = command { repository.pause(durationMillis) }
    fun resume() = command { repository.resume() }
    fun reconnect() = command { repository.reconnect() }
    private fun command(action: suspend () -> DomainResult<ConnectionCommandResult>) = viewModelScope.launch {
        mutableFailure.value = null
        try { mutableFailure.value = (action() as? DomainResult.Rejected)?.failure }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { mutableFailure.value = ProductFailure(ProductFailureCode.INTERNAL_FAILURE) }
    }
}

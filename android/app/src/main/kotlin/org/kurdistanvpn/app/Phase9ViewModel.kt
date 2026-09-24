// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.kurdistanvpn.core.model.*


class ProductRootViewModel(
    private val root: ProductCompositionRoot,
) : ViewModel() {
    private val mutableState = MutableStateFlow<AppState>(AppState.Booting)
    val state: StateFlow<AppState> = mutableState.asStateFlow()
    private val mutableSettings = MutableStateFlow(ProductSettings())
    val settings: StateFlow<ProductSettings> = mutableSettings.asStateFlow()
    private val mutableCompatibility = MutableStateFlow<CompatibilitySummary?>(null)
    val compatibility: StateFlow<CompatibilitySummary?> = mutableCompatibility.asStateFlow()
    private val mutableProtectedRecovery =
        MutableStateFlow<ProtectedRecoveryPresentation>(ProtectedRecoveryPresentation.NotRequired)
    val protectedRecovery: StateFlow<ProtectedRecoveryPresentation> =
        mutableProtectedRecovery.asStateFlow()
    internal val foregroundLaunch = ForegroundLaunchAdmission()


    init { refresh() }

    fun clearError() { refresh() }

    fun refresh(): Job = viewModelScope.launch {
        mutableState.value = AppState.CompatibilityCheck
        try {
            root.startupRepository.refresh()
            val presentation = root.startupRepository.presentation.value
            mutableSettings.value = presentation.settings
            mutableCompatibility.value = presentation.compatibility
            mutableProtectedRecovery.value = presentation.recovery
            mutableState.value = presentation.state
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) {
            mutableState.value = AppState.FatalRecovery
            mutableProtectedRecovery.value = ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.INCONSISTENT)
        }
    }


    class Factory(
        private val root: ProductCompositionRoot,
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(ProductRootViewModel::class.java))
            return ProductRootViewModel(root) as T
        }
    }
}



internal fun shouldRecord(event: DiagnosticLogLevel, configured: DiagnosticLogLevel): Boolean = when (configured) {
    DiagnosticLogLevel.NONE -> false
    DiagnosticLogLevel.ERROR -> event == DiagnosticLogLevel.ERROR
    DiagnosticLogLevel.WARNING -> event == DiagnosticLogLevel.ERROR || event == DiagnosticLogLevel.WARNING
    DiagnosticLogLevel.INFO -> event != DiagnosticLogLevel.DEBUG && event != DiagnosticLogLevel.NONE
    DiagnosticLogLevel.DEBUG -> event != DiagnosticLogLevel.NONE
}

internal fun retainDiagnosticEvents(
    events: List<DiagnosticEvent>,
    retention: DiagnosticRetention,
    nowMinutes: Long = System.currentTimeMillis() / 60_000,
): List<DiagnosticEvent> {
    val durationMinutes = when (retention) {
        DiagnosticRetention.ONE_HOUR -> 60
        DiagnosticRetention.SIX_HOURS -> 6 * 60
        DiagnosticRetention.ONE_DAY -> 24 * 60
        DiagnosticRetention.SEVEN_DAYS -> 7 * 24 * 60
    }
    val earliest = (nowMinutes - durationMinutes).coerceAtLeast(0)
    return events.filter { it.coarseEpochMinutes >= earliest }.takeLast(200)
}

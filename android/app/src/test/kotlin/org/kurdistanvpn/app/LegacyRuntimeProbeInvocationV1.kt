// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.CompatibilitySummary
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.EnrollmentKeySummary
import org.kurdistanvpn.core.model.EnrollmentUiState
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.ProductSettings
import org.kurdistanvpn.core.model.ThemePreference
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProbeExecutionState
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticLogLevel
import org.kurdistanvpn.core.model.DiagnosticRetention
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.model.ResetScope
import org.kurdistanvpn.core.model.ProtectedRecoveryAction
import org.kurdistanvpn.core.model.ProtectedRecoveryPresentation
import org.kurdistanvpn.core.model.ProtectedRecoveryReason
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.NativeProbeResult
import org.kurdistanvpn.data.secure.AdmissionResult
import org.kurdistanvpn.data.secure.ClientKeyRestoreResult
import org.kurdistanvpn.data.secure.ClientKeyResult
import org.kurdistanvpn.data.secure.ClientKeyStatus
import org.kurdistanvpn.data.secure.RestoreResult
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStatePreviewBackupPolicy
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig

// Historical probe cancellation characterization; production uses NodeMaintenanceRepository.
internal class RuntimeProbeInvocationV1(
    private val scope: CoroutineScope,
    private val run: (ProbePreferences) -> NativeProductResult<NativeProbeResult>,
    private val publish: (ProbeExecutionState) -> Unit,
) {
    private val inFlight = java.util.concurrent.atomic.AtomicBoolean(false)
    private val currentRequest = java.util.concurrent.atomic.AtomicReference<Any?>()

    @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class, kotlinx.coroutines.DelicateCoroutinesApi::class)
    fun start(preferences: ProbePreferences): Job? {
        if (!inFlight.compareAndSet(false, true)) return null
        val request = Any()
        currentRequest.set(request)
        try {
            publish(ProbeExecutionState.Running)
            // ATOMIC enters the finally block even if the scope was already cancelled.
            return scope.launch(Dispatchers.Default, start = CoroutineStart.ATOMIC) {
                try {
                    val context = currentCoroutineContext()
                    if (!context.isActive) return@launch
                    val result = try { run(preferences) }
                    catch (cancelled: CancellationException) { throw cancelled }
                    catch (_: Exception) {
                        NativeProductResult.Failure(org.kurdistanvpn.core.model.ProductFailureCode.INTERNAL_FAILURE)
                    }
                    if (context.isActive && currentRequest.get() === request) {
                        publish(legacyProbeStateV1(result))
                    }
                } finally {
                    // Synchronous native work has returned. UI cancellation alone never frees this slot.
                    currentRequest.compareAndSet(request, null)
                    inFlight.set(false)
                }
            }
        } catch (failure: Throwable) {
            currentRequest.compareAndSet(request, null)
            inFlight.set(false)
            throw failure
        }
    }
}

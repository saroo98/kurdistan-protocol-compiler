// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.AppState
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeCompatibility
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.domain.DomainResult
import org.kurdistanvpn.domain.ProductStartupRepository

internal data class ProductStartupSnapshot(
    val protectedRead: ProtectedStartupRead,
    val compatibility: NativeResult<NativeCompatibility>?,
)

internal data class StartupPresentation(
    val state: AppState = AppState.Booting,
    val settings: ProductSettings = ProductSettings(),
    val compatibility: CompatibilitySummary? = null,
    val recovery: ProtectedRecoveryPresentation = ProtectedRecoveryPresentation.NotRequired,
)

/** Only read capabilities are injected. No path here can provision or repair storage. */
internal class DefaultProductStartupRepository(
    private val read: suspend () -> ProtectedStartupRead,
    private val queryCompatibility: () -> NativeResult<NativeCompatibility>,
    private val readRecovery: suspend () -> ProtectedRecoveryPresentation = { ProtectedRecoveryPresentation.NotRequired },
) : ProductStartupRepository {
    private val lock = Mutex()
    private val state = MutableStateFlow<AppState>(AppState.Booting)
    private val mutablePresentation = MutableStateFlow(StartupPresentation())
    val presentation = mutablePresentation.asStateFlow()
    @Volatile var snapshot = ProductStartupSnapshot(ProtectedStartupRead.UnexpectedFailure, null)
        private set

    override fun observeStartup() = state.asStateFlow()

    override suspend fun refresh(): DomainResult<Unit> = lock.withLock {
        val next = withContext(Dispatchers.IO) {
            val storage = read()
            val compatibility = if (storage is ProtectedStartupRead.Ready) {
                readCoreCompatibility(queryCompatibility)
            } else null
            ProductStartupSnapshot(storage, compatibility)
        }
        currentCoroutineContext().ensureActive()
        var appState = when (val storage = next.protectedRead) {
            is ProtectedStartupRead.Unavailable -> storage.presentation
            ProtectedStartupRead.UnexpectedFailure -> AppState.FatalRecovery
            is ProtectedStartupRead.Ready -> coreStartupFailure(checkNotNull(next.compatibility)) ?: when (storage.projection.health) {
                CatalogHealth.KEY_INVALIDATED -> AppState.KeyInvalidated
                CatalogHealth.QUARANTINED -> AppState.Quarantined
                CatalogHealth.DEGRADED, CatalogHealth.RESTORE_PENDING, CatalogHealth.SUPERSEDED -> AppState.DegradedStorage
                CatalogHealth.AVAILABLE -> if (storage.projection.profiles.isEmpty()) AppState.NoProfiles
                    else AppState.Ready(storage.projection.profiles)
            }
        }
        val recovery = when (val storage = next.protectedRead) {
            is ProtectedStartupRead.Unavailable -> storage.recoveryReason?.let { ProtectedRecoveryPresentation.Required(it) }
                ?: ProtectedRecoveryPresentation.NotRequired
            ProtectedStartupRead.UnexpectedFailure -> ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.INCONSISTENT)
            is ProtectedStartupRead.Ready -> when (appState) {
                AppState.Quarantined -> ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.QUARANTINED)
                AppState.DegradedStorage, AppState.KeyInvalidated -> ProtectedRecoveryPresentation.Required(ProtectedRecoveryReason.INCONSISTENT)
                AppState.NoProfiles, is AppState.Ready -> withContext(Dispatchers.IO) { readRecovery() }
                else -> ProtectedRecoveryPresentation.NotRequired
            }
        }
        if ((appState == AppState.NoProfiles || appState is AppState.Ready) &&
            recovery is ProtectedRecoveryPresentation.Required && recovery.reason in setOf(
                ProtectedRecoveryReason.CLEANUP_UNPROVEN, ProtectedRecoveryReason.MUTATION_UNPROVEN,
                ProtectedRecoveryReason.INCONSISTENT)) appState = AppState.DegradedStorage
        val settings = (next.protectedRead as? ProtectedStartupRead.Ready)?.projection?.let { projection ->
            projection.settings.copy(profiles = org.kurdistanvpn.data.protectedstate.ProtectedStatePreviewBackupPolicy.projectProfiles(
                projection.settings.profiles, projection.profiles.map { it.localRecordId }))
        } ?: ProductSettings()
        val compatibility = (next.compatibility as? NativeResult.Success)?.value?.let {
            CompatibilitySummary(it.goCoreVersion, it.profileSchema, it.strategyRegistry, it.relaySchema, it.diagnosticSchema, it.cryptoSuite)
        }
        currentCoroutineContext().ensureActive()
        snapshot = next
        mutablePresentation.value = StartupPresentation(appState, settings, compatibility, recovery)
        state.value = appState
        // Success acknowledges the read, not readiness. Availability comes only from observeStartup.
        DomainResult.Success(Unit)
    }
}

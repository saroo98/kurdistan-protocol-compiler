// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlinx.coroutines.flow.Flow
import org.kurdistanvpn.core.model.ConnectionPreferences
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticPreferences
import org.kurdistanvpn.core.model.ExpertPreferences
import org.kurdistanvpn.core.model.Phase9Settings
import org.kurdistanvpn.core.model.ProbePreferences
import org.kurdistanvpn.core.model.ProfileSummary
import org.kurdistanvpn.core.model.RoutingPreferences
import org.kurdistanvpn.core.model.TunnelPreferences
import org.kurdistanvpn.core.model.UpdatePreferences
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.secure.EncryptedDiagnosticEventStore
import org.kurdistanvpn.data.secure.ProfileAdmissionJournal
import org.kurdistanvpn.data.secure.RuntimeAuthorityResult
import org.kurdistanvpn.data.secure.SecureRoutingPolicyStore
import org.kurdistanvpn.data.settings.Phase9SettingsStore

internal class ProfileAdmissionCoordinator(
    val nativeCore: KurdNativeCore,
    private val journal: () -> ProfileAdmissionJournal?,
) {
    fun journalOrNull(): ProfileAdmissionJournal? = journal()
}

internal class RuntimeSessionCoordinator(
    private val nativeCore: KurdNativeCore,
    private val journal: () -> ProfileAdmissionJournal?,
) {
    suspend fun openAuthority(localRecordId: String): RuntimeAuthorityResult? =
        journal()?.openRuntimeAuthority(localRecordId)

    fun probe(payload: ByteArray) = nativeCore.phase11RoundTrip(payload)
}

internal interface RoutingPolicyRepository {
    fun available(): Boolean
    fun load(): Set<String>
    fun save(packages: Set<String>)
    fun clear()
}

internal class EncryptedRoutingPolicyRepository(
    private val store: () -> SecureRoutingPolicyStore?,
) : RoutingPolicyRepository {
    override fun available(): Boolean = store() != null

    override fun load(): Set<String> = store()?.loadPackages().orEmpty()

    override fun save(packages: Set<String>) {
        checkNotNull(store()) { "ROUTING_STORAGE_UNAVAILABLE" }.savePackages(packages)
    }

    override fun clear() {
        store()?.clear()
    }
}

internal class SettingsCoordinator(
    private val store: Phase9SettingsStore,
    val routing: RoutingPolicyRepository,
) {
    val settings: Flow<Phase9Settings> = store.settings

    suspend fun setConnection(value: ConnectionPreferences) = store.setConnection(value)
    suspend fun setTunnel(value: TunnelPreferences) = store.setTunnel(value)
    suspend fun setRouting(value: RoutingPreferences) = store.setRouting(value)
    suspend fun setUpdates(value: UpdatePreferences) = store.setUpdates(value)
    suspend fun setProbes(value: ProbePreferences) = store.setProbes(value)
    suspend fun setDiagnostics(value: DiagnosticPreferences) = store.setDiagnostics(value)
    suspend fun setExpert(value: ExpertPreferences) = store.setExpert(value)
    suspend fun setTheme(value: org.kurdistanvpn.core.model.ThemePreference) = store.setTheme(value)
    suspend fun setHighContrast(value: Boolean) = store.setHighContrast(value)
    suspend fun setReducedMotion(value: Boolean) = store.setReducedMotion(value)
    suspend fun setProfiles(value: org.kurdistanvpn.core.model.ProfilePreferences) = store.setProfiles(value)
    suspend fun clearLegacyRoutingPackages() = store.clearLegacyRoutingPackages()
    suspend fun resetAll() = store.resetAll()
    suspend fun resetSettings() = store.resetSettings()
    suspend fun resetProfiles() = store.resetProfiles()
    suspend fun resetRouting() = store.resetRouting()
    suspend fun resetDiagnostics() = store.resetDiagnostics()
}

internal class DiagnosticsCoordinator(
    private val store: () -> EncryptedDiagnosticEventStore?,
) {
    fun load(): List<DiagnosticEvent> = store()?.load().orEmpty()
    fun save(events: List<DiagnosticEvent>) = checkNotNull(store()) {
        "DIAGNOSTIC_STORAGE_UNAVAILABLE"
    }.save(events)
    fun clear() = store()?.clear()
}

internal class RecoveryCoordinator(
    private val storageFailure: () -> Phase9CompositionRoot.StorageFailure?,
    private val resetProtectedState: suspend () -> Boolean,
    private val resetProfiles: suspend () -> Boolean,
    private val resetRouting: suspend () -> Boolean,
    private val resetDiagnostics: suspend () -> Boolean,
) {
    fun storageFailure(): Phase9CompositionRoot.StorageFailure? = storageFailure.invoke()
    suspend fun resetProtectedState(): Boolean = resetProtectedState.invoke()
    suspend fun resetProfiles(): Boolean = resetProfiles.invoke()
    suspend fun resetRouting(): Boolean = resetRouting.invoke()
    suspend fun resetDiagnostics(): Boolean = resetDiagnostics.invoke()
}

internal class ProviderProjectionRepository {
    fun activeProfile(profiles: List<ProfileSummary>, activeRecordId: String?): ProfileSummary? =
        profiles.firstOrNull { it.localRecordId == activeRecordId } ?: profiles.firstOrNull()
}

internal data class Phase13Coordinators(
    val profiles: ProfileAdmissionCoordinator,
    val runtime: RuntimeSessionCoordinator,
    val settings: SettingsCoordinator,
    val diagnostics: DiagnosticsCoordinator,
    val recovery: RecoveryCoordinator,
    val providers: ProviderProjectionRepository,
) {
    companion object {
        fun create(root: Phase9CompositionRoot): Phase13Coordinators {
            val routing = EncryptedRoutingPolicyRepository { root.sensitiveRoutingStore }
            return Phase13Coordinators(
                profiles = ProfileAdmissionCoordinator(root.nativeCore) { root.admissionJournal },
                runtime = RuntimeSessionCoordinator(root.nativeCore) { root.admissionJournal },
                settings = SettingsCoordinator(root.settingsStore, routing),
                diagnostics = DiagnosticsCoordinator { root.diagnosticEventStore },
                recovery = RecoveryCoordinator(
                    storageFailure = { root.storageFailure },
                    resetProtectedState = root::resetProtectedState,
                    resetProfiles = {
                        root.admissionJournal?.resetAll() ?: false
                    },
                    resetRouting = {
                        root.sensitiveRoutingStore?.let { store ->
                            runCatching { store.clear() }.isSuccess
                        } ?: false
                    },
                    resetDiagnostics = {
                        root.diagnosticEventStore?.let { store ->
                            runCatching { store.clear() }.isSuccess
                        } ?: false
                    },
                ),
                providers = ProviderProjectionRepository(),
            )
        }
    }
}

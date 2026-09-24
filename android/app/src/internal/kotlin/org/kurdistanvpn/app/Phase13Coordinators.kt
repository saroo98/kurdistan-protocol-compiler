// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.NativeProbeResult
import org.kurdistanvpn.runtime.android.RuntimeSelectedProbeV1
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.ClientKeySummary

// Historical internal harness adapters. Not included in release builds.
internal data class ProfileReadProjection(val profiles: List<ProfileSummary>, val health: CatalogHealth)

/** App adapter over the closed typed façade. No journal, key store, DAO, or writer escapes. */
internal class ProfileAdmissionCoordinator(
    val nativeCore: KurdNativeCore,
    private val facade: () -> ProtectedStateApplicationFacade?,
) {
    suspend fun readProfileProjection(): ProfileReadProjection {
        val projection = checkNotNull(facade()?.readProjection()) { "PROTECTED_STATE_UNAVAILABLE" }
        return ProfileReadProjection(projection.profiles, projection.health)
    }
    fun enrollmentKeys(): List<ClientKeySummary> = facade()?.enrollmentSummaries().orEmpty()
    fun enrollmentRequest(id: String): ByteArray? = facade()?.enrollmentRequest(id)
    suspend fun createEnrollment(validitySeconds: Int, now: Long): ProtectedStateApplicationFacade.CommandResult<ClientKeySummary> =
        facade()?.createEnrollment(validitySeconds, now) ?: ProtectedStateApplicationFacade.CommandResult.Busy
    suspend fun deleteEnrollmentKey(id: String): ProtectedStateApplicationFacade.CommandResult<Unit> =
        facade()?.deleteEnrollment(id) ?: ProtectedStateApplicationFacade.CommandResult.Busy
    suspend fun markEnrollmentRequestExported(id: String): ProtectedStateApplicationFacade.CommandResult<Unit> =
        facade()?.markEnrollmentExported(id) ?: ProtectedStateApplicationFacade.CommandResult.Busy
    suspend fun deleteProfile(id: String): ProtectedStateApplicationFacade.CommandResult<Unit> =
        facade()?.deleteProfile(id) ?: ProtectedStateApplicationFacade.CommandResult.Busy
}

internal interface RoutingPolicyRepository {
    fun available(): Boolean
    fun load(): Set<String>
    suspend fun save(packages: Set<String>)
    suspend fun clear()
}

internal class ProtectedRoutingPolicyRepository(private val facade: () -> ProtectedStateApplicationFacade?) : RoutingPolicyRepository {
    override fun available(): Boolean = facade()?.readProjection() != null
    override fun load(): Set<String> = facade()?.readProjection()?.settings?.routing?.packages.orEmpty()
    override suspend fun save(packages: Set<String>) {
        check(facade()?.replaceRouting(packages) == true) { "ROUTING_MUTATION_REJECTED" }
    }
    override suspend fun clear() = save(emptySet())
}

internal class SettingsCoordinator(private val facade: () -> ProtectedStateApplicationFacade?) {
    val routing: RoutingPolicyRepository = ProtectedRoutingPolicyRepository(facade)
    fun startup(failure: () -> ProductCompositionRoot.StorageFailure?): Flow<ProtectedStartupRead> = flow {
        emit(readStartupProjection(failure()) { facade()?.readProjection() })
    }
    // Existing non-startup consumers receive only authenticated settings. Missing
    // state emits nothing, rather than throwing or inventing a valid projection.
    val settings: Flow<ProductSettings> = flow {
        startup { null }.collect { result ->
            if (result is ProtectedStartupRead.Ready) emit(result.projection.settings)
        }
    }
    private suspend fun replace(
        residuePolicy: org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy = org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.PRESERVE,
        transform: (ProductSettings) -> ProductSettings,
    ) {
        val current = checkNotNull(facade()?.readProjection()) { "PROTECTED_STATE_UNAVAILABLE" }
        check(facade()?.replaceSettings(current.revision, transform(current.settings), residuePolicy) is ProtectedStateApplicationFacade.CommandResult.Committed)
    }
    suspend fun setConnection(value: ConnectionPreferences) = replace { it.copy(connection = value) }
    suspend fun setTunnel(value: TunnelPreferences) = replace { it.copy(tunnel = value) }
    suspend fun setRouting(value: RoutingPreferences) = replace { it.copy(routing = value) }
    suspend fun setUpdates(value: UpdatePreferences) = replace { it.copy(updates = value) }
    suspend fun setProbes(value: ProbePreferences) = replace { it.copy(probes = value) }
    suspend fun setDiagnostics(value: DiagnosticPreferences) = replace { it.copy(diagnostics = value) }
    suspend fun setExpert(value: ExpertPreferences) = replace { it.copy(expert = value) }
    suspend fun setTheme(value: ThemePreference) = replace { it.copy(theme = value) }
    suspend fun setHighContrast(value: Boolean) = replace { it.copy(highContrast = value) }
    suspend fun setReducedMotion(value: Boolean) = replace { it.copy(reducedMotion = value) }
    suspend fun setProfiles(value: ProfilePreferences) = replace { it.copy(profiles = value) }
    suspend fun resetSettings() = replace(org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.DISCARD) { old -> ProductSettings().copy(routing = old.routing, diagnostics = old.diagnostics, profiles = old.profiles) }
    suspend fun resetProfiles() = replace { old -> old.copy(profiles = ProductSettings().profiles) }
    suspend fun resetRouting() = replace { old -> old.copy(routing = ProductSettings().routing) }
    suspend fun resetDiagnostics() = replace { old -> old.copy(diagnostics = ProductSettings().diagnostics) }
    suspend fun resetAll() = replace(org.kurdistanvpn.data.settings.LegacySettingsResiduePolicy.DISCARD) { ProductSettings() }
}

internal class DiagnosticsCoordinator(private val facade: () -> ProtectedStateApplicationFacade?) {
    fun load(): List<DiagnosticEvent> = facade()?.diagnostics().orEmpty()
    suspend fun save(events: List<DiagnosticEvent>) {
        check(facade()?.replaceDiagnostics(events) is ProtectedStateApplicationFacade.CommandResult.Committed)
    }
    suspend fun clear() = save(emptyList())
}

internal class RuntimeSessionCoordinator(private val selectedProbe: RuntimeSelectedProbeV1? = null) {
    fun probe(preferences: ProbePreferences): NativeProductResult<NativeProbeResult> =
        selectedProbe?.runSelected(preferences)
            ?: NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
}

internal class RecoveryCoordinator(
    private val storageFailureCallback: () -> ProductCompositionRoot.StorageFailure?,
    private val presentationRecoveryRequiredCallback: () -> Boolean?,
    private val recoverPresentationCallback: suspend () -> ProtectedStateApplicationFacade.CommandResult<Unit>,
    private val resetProfilesCallback: suspend () -> Boolean,
    private val resetRoutingCallback: suspend () -> Boolean,
    private val resetDiagnosticsCallback: suspend () -> Boolean,
) {
    fun storageFailure(): ProductCompositionRoot.StorageFailure? = storageFailureCallback.invoke()
    fun presentationRecoveryRequired(): Boolean? = presentationRecoveryRequiredCallback.invoke()
    suspend fun recoverPresentation(): ProtectedStateApplicationFacade.CommandResult<Unit> = recoverPresentationCallback.invoke()
    suspend fun resetProfiles(): Boolean = resetProfilesCallback.invoke()
    suspend fun resetRouting(): Boolean = resetRoutingCallback.invoke()
    suspend fun resetDiagnostics(): Boolean = resetDiagnosticsCallback.invoke()
}

internal class ProviderProjectionRepository {
    fun activeProfile(profiles: List<ProfileSummary>, activeRecordId: String?): ProfileSummary? =
        profiles.firstOrNull { it.localRecordId == activeRecordId } ?: profiles.firstOrNull()
}

internal data class Phase13Coordinators(
    val profiles: ProfileAdmissionCoordinator,
    val settings: SettingsCoordinator,
    val diagnostics: DiagnosticsCoordinator,
    val runtime: RuntimeSessionCoordinator,
    val recovery: RecoveryCoordinator,
    val providers: ProviderProjectionRepository,
) {
    companion object {
        fun create(root: ProductCompositionRoot): Phase13Coordinators {
            val facade = root::protectedStateFacade
            val routing = ProtectedRoutingPolicyRepository(facade)
            val settings = SettingsCoordinator(facade)
            return Phase13Coordinators(
                profiles = ProfileAdmissionCoordinator(root.nativeCore, facade),
                settings = settings,
                diagnostics = DiagnosticsCoordinator(facade),
                runtime = RuntimeSessionCoordinator(),
                recovery = RecoveryCoordinator(
                    storageFailureCallback = { root.storageFailure },
                    presentationRecoveryRequiredCallback = {
                        facade()?.presentationRecoveryRequired() ?: false
                    },
                    recoverPresentationCallback = {
                        facade()?.recoverPresentationConfirmed()
                            ?: ProtectedStateApplicationFacade.CommandResult.Busy
                    },
                    resetProfilesCallback = {
                        val ids = facade()?.readProjection()?.profiles?.map { it.localRecordId }?.toSet().orEmpty()
                        facade()?.resetProfiles(ids) is ProtectedStateApplicationFacade.CommandResult.Committed
                    },
                    resetRoutingCallback = { runCatching { routing.clear() }.isSuccess },
                    resetDiagnosticsCallback = { runCatching { facade()?.replaceDiagnostics(emptyList()) is ProtectedStateApplicationFacade.CommandResult.Committed }.getOrDefault(false) },
                ),
                providers = ProviderProjectionRepository(),
            )
        }
    }
}

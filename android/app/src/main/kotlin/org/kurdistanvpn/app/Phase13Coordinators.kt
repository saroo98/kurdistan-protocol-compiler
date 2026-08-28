// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.ClientKeySummary

internal data class ProfileReadProjection(val profiles: List<ProfileSummary>, val health: CatalogHealth)

/** Availability is presentation, never a default projection or permission to initialize storage. */
internal sealed interface ProtectedStartupRead {
    data class Ready(val projection: ProtectedStateApplicationFacade.ReadProjection) : ProtectedStartupRead
    data class Unavailable(val failure: Phase9CompositionRoot.StorageFailure) : ProtectedStartupRead {
        val presentation: AppState get() = when (failure) {
            Phase9CompositionRoot.StorageFailure.FIRST_USE -> AppState.FirstLaunch
            Phase9CompositionRoot.StorageFailure.LOCKED -> AppState.LockedStorage
            Phase9CompositionRoot.StorageFailure.KEY_INVALIDATED -> AppState.KeyInvalidated
            Phase9CompositionRoot.StorageFailure.MIGRATION_REQUIRED -> AppState.MigrationRequired
            Phase9CompositionRoot.StorageFailure.DEGRADED,
            Phase9CompositionRoot.StorageFailure.MUTATION_UNPROVEN -> AppState.DegradedStorage
        }
        val recoveryReason: ProtectedRecoveryReason? get() = when (failure) {
            Phase9CompositionRoot.StorageFailure.MUTATION_UNPROVEN -> ProtectedRecoveryReason.MUTATION_UNPROVEN
            Phase9CompositionRoot.StorageFailure.DEGRADED,
            Phase9CompositionRoot.StorageFailure.KEY_INVALIDATED -> ProtectedRecoveryReason.INCONSISTENT
            else -> null
        }
    }
    data object UnexpectedFailure : ProtectedStartupRead
}

/** Read-only adapter. Cancellation propagates; unexpected exceptions have a distinct fatal result. */
internal suspend fun readStartupProjection(
    failure: Phase9CompositionRoot.StorageFailure?,
    read: () -> ProtectedStateApplicationFacade.ReadProjection?,
): ProtectedStartupRead {
    currentCoroutineContext().ensureActive()
    if (failure != null) return ProtectedStartupRead.Unavailable(failure)
    return try {
        val projection = read()
        currentCoroutineContext().ensureActive()
        if (projection == null) ProtectedStartupRead.Unavailable(Phase9CompositionRoot.StorageFailure.DEGRADED)
        else ProtectedStartupRead.Ready(projection)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        ProtectedStartupRead.UnexpectedFailure
    }
}

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
    fun startup(failure: () -> Phase9CompositionRoot.StorageFailure?): Flow<ProtectedStartupRead> = flow {
        emit(readStartupProjection(failure()) { facade()?.readProjection() })
    }
    // Existing non-startup consumers receive only authenticated settings. Missing
    // state emits nothing, rather than throwing or inventing a valid projection.
    val settings: Flow<Phase9Settings> = flow {
        startup { null }.collect { result ->
            if (result is ProtectedStartupRead.Ready) emit(result.projection.settings)
        }
    }
    private suspend fun replace(transform: (Phase9Settings) -> Phase9Settings) {
        val current = checkNotNull(facade()?.readProjection()) { "PROTECTED_STATE_UNAVAILABLE" }
        check(facade()?.replaceSettings(current.revision, transform(current.settings)) is ProtectedStateApplicationFacade.CommandResult.Committed)
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
    suspend fun resetSettings() = replace { old -> Phase9Settings().copy(routing = old.routing, diagnostics = old.diagnostics, profiles = old.profiles) }
    suspend fun resetProfiles() = replace { old -> old.copy(profiles = Phase9Settings().profiles) }
    suspend fun resetRouting() = replace { old -> old.copy(routing = Phase9Settings().routing) }
    suspend fun resetDiagnostics() = replace { old -> old.copy(diagnostics = Phase9Settings().diagnostics) }
    suspend fun resetAll() = replace { Phase9Settings() }
}

internal class DiagnosticsCoordinator(private val facade: () -> ProtectedStateApplicationFacade?) {
    fun load(): List<DiagnosticEvent> = facade()?.diagnostics().orEmpty()
    suspend fun save(events: List<DiagnosticEvent>) {
        check(facade()?.replaceDiagnostics(events) is ProtectedStateApplicationFacade.CommandResult.Committed)
    }
    suspend fun clear() = save(emptyList())
}

internal class RuntimeSessionCoordinator(private val nativeCore: KurdNativeCore) {
    fun probe(payload: ByteArray) = nativeCore.phase11RoundTrip(payload)
}

internal class RecoveryCoordinator(
    private val storageFailure: () -> Phase9CompositionRoot.StorageFailure?,
    private val presentationRecoveryRequired: () -> Boolean?,
    private val recoverPresentation: suspend () -> ProtectedStateApplicationFacade.CommandResult<Unit>,
    private val resetProfiles: suspend () -> Boolean,
    private val resetRouting: suspend () -> Boolean,
    private val resetDiagnostics: suspend () -> Boolean,
) {
    fun storageFailure(): Phase9CompositionRoot.StorageFailure? = storageFailure()
    fun presentationRecoveryRequired(): Boolean? = presentationRecoveryRequired()
    suspend fun recoverPresentation(): ProtectedStateApplicationFacade.CommandResult<Unit> = recoverPresentation()
    suspend fun resetProfiles(): Boolean = resetProfiles()
    suspend fun resetRouting(): Boolean = resetRouting()
    suspend fun resetDiagnostics(): Boolean = resetDiagnostics()
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
        fun create(root: Phase9CompositionRoot): Phase13Coordinators {
            val facade = root::protectedStateFacade
            val routing = ProtectedRoutingPolicyRepository(facade)
            val settings = SettingsCoordinator(facade)
            return Phase13Coordinators(
                profiles = ProfileAdmissionCoordinator(root.nativeCore, facade),
                settings = settings,
                diagnostics = DiagnosticsCoordinator(facade),
                runtime = RuntimeSessionCoordinator(root.nativeCore),
                recovery = RecoveryCoordinator(
                    storageFailure = { root.storageFailure },
                    presentationRecoveryRequired = {
                        facade()?.presentationRecoveryRequired() ?: false
                    },
                    recoverPresentation = {
                        facade()?.recoverPresentationConfirmed()
                            ?: ProtectedStateApplicationFacade.CommandResult.Busy
                    },
                    resetProfiles = {
                        val ids = facade()?.readProjection()?.profiles?.map { it.localRecordId }?.toSet().orEmpty()
                        facade()?.resetProfiles(ids) is ProtectedStateApplicationFacade.CommandResult.Committed
                    },
                    resetRouting = { runCatching { routing.clear() }.isSuccess },
                    resetDiagnostics = { runCatching { facade()?.replaceDiagnostics(emptyList()) is ProtectedStateApplicationFacade.CommandResult.Committed }.getOrDefault(false) },
                ),
                providers = ProviderProjectionRepository(),
            )
        }
    }
}

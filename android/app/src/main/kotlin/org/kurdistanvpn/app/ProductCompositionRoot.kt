// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.Context
import android.net.VpnService
import android.os.SystemClock
import android.os.UserManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first
import org.kurdistanvpn.core.model.RuntimeAvailability
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.DurableFilePrimitives
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.protectedstate.ProtectedStateProcessOwner
import org.kurdistanvpn.data.protectedstate.ProtectedAuthorityEnvironment
import org.kurdistanvpn.runtime.api.VpnRuntimeConfig
import org.kurdistanvpn.runtime.api.UnavailableRuntime

/**
 * Default-process composition owns the only interactive protected-state façade. It deliberately
 * exposes neither legacy stores nor a writable adapter. Opening existing state is no-create;
 * provisioning has a separate explicit-user command and never runs during Application startup.
 */
class ProductCompositionRoot private constructor(
    private val context: Context,
    val nativeCore: KurdNativeCore,
    private val primitives: DurableFilePrimitives,
    private val processOwner: ProtectedStateProcessOwner,
    private var facade: ProtectedStateApplicationFacade?,
    initialStorageFailure: StorageFailure?,
    runtimePolicy: kotlinx.coroutines.flow.Flow<org.kurdistanvpn.domain.SystemPolicyState>,
    private val settingsRuntime: () -> org.kurdistanvpn.data.settings.SettingsRuntimePort,
) : AutoCloseable {
    private var foregroundActions = java.lang.ref.WeakReference<org.kurdistanvpn.platform.system.ForegroundSystemActions>(null)
    internal val systemPolicy = org.kurdistanvpn.platform.system.AndroidSystemPolicyRepository(context, runtimePolicy) {
        foregroundActions.get()
    }
    internal fun attachSystemActions(actions: org.kurdistanvpn.platform.system.ForegroundSystemActions) {
        foregroundActions = java.lang.ref.WeakReference(actions)
        systemPolicy.refreshPlatformState()
    }
    internal fun detachSystemActions(actions: org.kurdistanvpn.platform.system.ForegroundSystemActions) {
        if (foregroundActions.get() === actions) foregroundActions.clear()
        if (privacyBinding.isInitialized()) privacyBinding.value.backgrounded()
        systemPolicy.refreshPlatformState()
    }
    val runtime: UnavailableRuntime = UnavailableRuntime(RuntimeAvailability.NOT_ADMITTED)
    internal val diagnosticOperations = ProductDiagnosticOperations(nativeCore)
    internal val backupOperations = ProductBackupOperations(nativeCore, ::protectedStateFacade, SystemClock::elapsedRealtime)
    internal val importOperations = ProductImportOperations({ request ->
        protectedStateFacade()?.previewExternalImport(request, { false }, SystemClock::elapsedRealtime)
            ?: org.kurdistanvpn.data.protectedstate.ProtectedExternalPreviewResult.Rejected(
                org.kurdistanvpn.data.protectedstate.ProtectedReadFailure.STATE_UNPROVEN)
    }, { confirmed ->
        when (val result = protectedStateFacade()?.confirmImport(confirmed)) {
            is ProtectedStateApplicationFacade.CommandResult.Committed -> org.kurdistanvpn.core.nativeapi.NativeResult.Success(org.kurdistanvpn.core.model.CatalogId(result.value))
            is ProtectedStateApplicationFacade.CommandResult.Rejected -> org.kurdistanvpn.core.nativeapi.NativeResult.Failure(result.error)
            else -> org.kurdistanvpn.core.nativeapi.NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        }
    })
    @Volatile var storageFailure: StorageFailure? = initialStorageFailure
        private set

    enum class StorageFailure { FIRST_USE, LOCKED, KEY_INVALIDATED, MIGRATION_REQUIRED, DEGRADED, MUTATION_UNPROVEN }
    internal val durableFilePrimitives: DurableFilePrimitives get() = primitives

    internal val startupRepository by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        DefaultProductStartupRepository(
            { readStartupProjection(storageFailure) { protectedStateFacade()?.readProjection() } },
            nativeCore::compatibility,
            {
                if (importOperations.cleanupUnproven) org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.Required(
                    org.kurdistanvpn.core.model.ProtectedRecoveryReason.CLEANUP_UNPROVEN)
                else if (profileRepository.readEnrollment() !is org.kurdistanvpn.domain.DomainResult.Success)
                    org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.Required(org.kurdistanvpn.core.model.ProtectedRecoveryReason.INCONSISTENT)
                else {
                    diagnosticsRepository.refresh()
                    when (protectedStateFacade()?.presentationRecoveryRequired()) {
                        true -> org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.Required(
                            org.kurdistanvpn.core.model.ProtectedRecoveryReason.RECOVERY_REQUIRED,
                            org.kurdistanvpn.core.model.ProtectedRecoveryAction.RECOVER_PRESENTATION)
                        false -> org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.NotRequired
                        null -> org.kurdistanvpn.core.model.ProtectedRecoveryPresentation.Required(
                            org.kurdistanvpn.core.model.ProtectedRecoveryReason.MUTATION_UNPROVEN)
                    }
                }
            },
        )
    }

    internal val connectionRepository: org.kurdistanvpn.domain.ConnectionRepository by lazy {
        val app = context as KurdistanApplication
        ProductConnectionRepository(app.runtimeSnapshots, ::readConnectionCurrent,
            { System.currentTimeMillis() / 1000 }, { id, revision ->
                withContext(Dispatchers.Main.immediate) {
                    (foregroundActions.get() as? ProductConnectionForeground)?.beginConnection(id, revision) == true
                }
            }, { app.runtimeController.stop() }, { app.runtimeController.recoverInternet() }, ::setConnectionPaused)
    }

    internal val diagnosticsRepository: ProductDiagnosticsRepository by lazy {
        ProductDiagnosticsRepository(diagnosticOperations,
            { checkNotNull(protectedStateFacade()?.diagnostics()) },
            { protectedStateFacade()?.replaceDiagnostics(it) is ProtectedStateApplicationFacade.CommandResult.Committed },
            { checkNotNull(protectedStateFacade()?.readProjection()).profiles.size },
            { checkNotNull(protectedStateFacade()?.readProjection()).settings.diagnostics },
            { value -> applySettingsChange { it.copy(diagnostics = value) } },
            { id, bytes -> withContext(Dispatchers.Main.immediate) {
                (foregroundActions.get() as? ProductDiagnosticForeground)?.requestDiagnosticDestination(id, bytes) == true
            } })
    }

    @Volatile private var maintenanceController: VpnRuntimeController? = null
    private val maintenanceBinding = lazy {
        ProductNodeMaintenanceRepository(::protectedStateFacade,
            { id, request -> withMaintenanceController { it.runSelectedProbe(id, request) } },
            { id -> withMaintenanceController { it.checkSignedUpdate(id) } },
            { maintenanceController?.cancelSelectedProbe() ?: true },
            ProductUpdateScheduler(context)::schedule)
    }
    internal val nodeMaintenanceRepository: ProductNodeMaintenanceRepository get() = maintenanceBinding.value

    private suspend fun <T> withMaintenanceController(action: suspend (VpnRuntimeController) -> T): T {
        val owner = (context as KurdistanApplication).runtimeController
        owner.retainSettingsOwner()
        maintenanceController = owner
        try {
            kotlinx.coroutines.withTimeout(10_000) { owner.controlReady.first { it } }
            return action(owner)
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            withContext(kotlinx.coroutines.NonCancellable) { owner.cancelSelectedProbe() }
            throw cancelled
        } finally { maintenanceController = null; owner.releaseSettingsOwner() }
    }

    private val privacyBinding = lazy {
        ProductPrivacyRecoveryRepository(::protectedStateFacade, ::applySettingsChange, backupOperations,
            diagnosticsRepository, systemPolicy, { action, allowed -> withContext(Dispatchers.Main.immediate) {
                (foregroundActions.get() as? ProductPrivacyForeground)?.authenticatePrivacy(action, allowed) == true
            } }, { id, bytes -> withContext(Dispatchers.Main.immediate) {
                (foregroundActions.get() as? ProductBackupForeground)?.requestBackupDestination(bytes, id) == true
            } }, {
                resetProtectedStateConfirmed().also { result ->
                    if (result is ProtectedStateApplicationFacade.CommandResult.Committed) {
                        importOperations.close()
                        backupOperations.close()
                        check(diagnosticsRepository.resetPresentation())
                    }
                }
            }, ::migrateLegacyProtectedStateForExplicitUserAction)
    }
    internal val privacyRepository: ProductPrivacyRecoveryRepository get() = privacyBinding.value

    internal val profileRepository: ProductProfileRepository by lazy {
        ProductProfileRepository(::protectedStateFacade, importOperations, ::applySettingsChange, backupOperations, { bytes ->
            withContext(Dispatchers.Main.immediate) {
                (foregroundActions.get() as? ProductBackupForeground)?.requestBackupDestination(bytes) == true
            }
        }, { storageFailure == StorageFailure.FIRST_USE }, {
            if (protectedStateFacade() == null && storageFailure == StorageFailure.FIRST_USE)
                initializeProtectedStateForExplicitUserAction()
            else protectedStateFacade() != null && storageFailure == null
        }, { id, destination, bytes -> withContext(Dispatchers.Main.immediate) {
            (foregroundActions.get() as? ProductEnrollmentForeground)?.requestEnrollmentDestination(id, destination, bytes) == true
        } })
    }

    internal suspend fun applySettingsChange(transform: (org.kurdistanvpn.core.model.ProductSettings) -> org.kurdistanvpn.core.model.ProductSettings):
        org.kurdistanvpn.domain.DomainResult<Unit> = withContext(Dispatchers.IO) {
        fun rejected() = org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(
            org.kurdistanvpn.core.model.ProductFailureCode.STORAGE_DEGRADED))
        val repository = settingsRepository() ?: return@withContext rejected()
        val draft = when (val opened = repository.openDraft()) {
            is org.kurdistanvpn.domain.DomainResult.Success -> opened.value
            is org.kurdistanvpn.domain.DomainResult.Rejected -> return@withContext opened
        }
        var result: org.kurdistanvpn.domain.DomainResult<Unit>
        var cleanupFailure: org.kurdistanvpn.domain.DomainResult.Rejected? = null
        try {
            result = when (val applied = repository.apply(draft.id, draft.basedOn.revision, transform(draft.basedOn.settings))) {
                is org.kurdistanvpn.domain.DomainResult.Success -> org.kurdistanvpn.domain.DomainResult.Success(Unit)
                is org.kurdistanvpn.domain.DomainResult.Rejected -> applied
            }
        } finally {
            val cleanup = withContext(kotlinx.coroutines.NonCancellable) { repository.cancel(draft.id) }
            if (cleanup is org.kurdistanvpn.domain.DomainResult.Rejected) cleanupFailure = cleanup
        }
        cleanupFailure ?: result
    }

    internal suspend fun readConnectionCurrent(): ProductConnectionCurrent = withContext(Dispatchers.IO) {
        val projection = protectedStateFacade()?.readProjection()
        val health = when {
            storageFailure == StorageFailure.LOCKED -> org.kurdistanvpn.core.model.StorageHealth.LOCKED
            storageFailure == StorageFailure.KEY_INVALIDATED -> org.kurdistanvpn.core.model.StorageHealth.KEY_INVALIDATED
            projection?.health == org.kurdistanvpn.data.metadata.CatalogHealth.AVAILABLE -> org.kurdistanvpn.core.model.StorageHealth.AVAILABLE
            else -> org.kurdistanvpn.core.model.StorageHealth.DEGRADED
        }
        val selected = projection?.profiles?.singleOrNull { it.localRecordId == projection.settings.profiles.activeLocalRecordId }
        val profile = selected?.let {
            org.kurdistanvpn.core.model.ProfileProjection(org.kurdistanvpn.core.model.CatalogId(it.localRecordId),
                org.kurdistanvpn.core.model.SafeAlias("Profile"), it.generation, it.expiresAtEpochSeconds,
                // The read-only profile adapter classifies the audience separately from signature validity.
                // Runtime admission still enforces production audience and all execution policy.
                if (it.trust in setOf(org.kurdistanvpn.core.model.ProfileTrust.VERIFIED_PRODUCTION,
                        org.kurdistanvpn.core.model.ProfileTrust.VERIFIED_NONPRODUCTION))
                    org.kurdistanvpn.core.model.ProjectionStatus.VERIFIED else org.kurdistanvpn.core.model.ProjectionStatus.UNAVAILABLE)
        }
        val packageRevision = org.kurdistanvpn.runtime.android.currentRuntimePackageRevision(context)
        ProductConnectionCurrent(profile, packageRevision?.let { projection?.runtimeProfile?.withPackageRevision(it) }, health)
    }

    private suspend fun setConnectionPaused(durationMillis: Long?): org.kurdistanvpn.domain.DomainResult<Unit> = withContext(Dispatchers.IO) {
        val current = protectedStateFacade()
            ?: return@withContext org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(org.kurdistanvpn.core.model.ProductFailureCode.STORAGE_LOCKED))
        val controller = (context as KurdistanApplication).runtimeController
        val port = (context as KurdistanApplication).settingsRuntimePort
        fun rejected(code: org.kurdistanvpn.core.model.ProductFailureCode) = org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(code))
        try {
            kotlinx.coroutines.withTimeout(10_000) { controller.controlReady.first { it } }
            val status = controller.querySettingsStatus()
            if (durationMillis != null && (status.alwaysOn != false || status.lockdown != false))
                return@withContext rejected(org.kurdistanvpn.core.model.ProductFailureCode.ROUTE_POLICY_REJECTED)
            when (val stopped = port.prepare()) {
                is org.kurdistanvpn.data.settings.SettingsPortResult.Rejected -> return@withContext rejected(stopped.code)
                else -> Unit
            }
            val projection = current.readProjection() ?: return@withContext rejected(org.kurdistanvpn.core.model.ProductFailureCode.STORAGE_DEGRADED)
            val revision = current.settingsRepository()?.appliedRevision() as? org.kurdistanvpn.domain.DomainResult.Success
                ?: return@withContext rejected(org.kurdistanvpn.core.model.ProductFailureCode.STORAGE_DEGRADED)
            val timer = if (durationMillis != null) org.kurdistanvpn.data.secure.StoredPauseState(System.currentTimeMillis(),
                SystemClock.elapsedRealtime(), android.provider.Settings.Global.getInt(context.contentResolver,
                    android.provider.Settings.Global.BOOT_COUNT), durationMillis) else null
            when (current.applyPause(projection.revision, revision.value.revision, timer)) {
                is ProtectedStateApplicationFacade.CommandResult.Committed -> org.kurdistanvpn.domain.DomainResult.Success(Unit)
                else -> rejected(org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED)
            }
        } finally { withContext(kotlinx.coroutines.NonCancellable) { port.finish() } }
    }

    internal suspend fun expireForegroundPause(wallMillis: Long, elapsedMillis: Long, bootCount: Int) = withContext(Dispatchers.IO) {
        val current = protectedStateFacade() ?: return@withContext
        val projection = current.readProductStorage() ?: return@withContext
        val timer = projection.pause ?: return@withContext
        if (!timer.expired(wallMillis, elapsedMillis, bootCount)) return@withContext
        val applied = current.settingsRepository()?.appliedRevision()
            as? org.kurdistanvpn.domain.DomainResult.Success ?: return@withContext
        // Exact journal comparison rejects a replaced timer; expiry never starts or schedules a connection.
        current.applyPause(projection.revision, applied.value.revision, null)
        settingsRepository().appliedRevision()
        Unit
    }

    /** The typed boundary only. It never returns a journal, KEK, DAO, writer, or authority. */
    @Synchronized fun protectedStateFacade(): ProtectedStateApplicationFacade? = facade

    private var settingsOwner: ProtectedStateApplicationFacade? = null
    private val settingsOwners = kotlinx.coroutines.flow.MutableStateFlow<org.kurdistanvpn.domain.SettingsRepository?>(null)
    private val stableSettings by lazy {
        ProductSettingsRepository(::currentSettingsDelegate, settingsOwners, ::applyAppearance) {
            storageFailure == StorageFailure.FIRST_USE && initializeProtectedStateForExplicitUserAction()
        }
    }
    fun settingsRepository(): org.kurdistanvpn.domain.SettingsRepository = stableSettings
    @Synchronized private fun currentSettingsDelegate(): org.kurdistanvpn.domain.SettingsRepository? {
        val current = facade
        if (settingsOwner !== current) {
            settingsOwners.value = current?.settingsRepository(settingsRuntime())
            settingsOwner = current
        }
        return settingsOwners.value
    }
    @Synchronized fun settingsRepository(runtime: org.kurdistanvpn.data.settings.SettingsRuntimePort): org.kurdistanvpn.domain.SettingsRepository? =
        facade?.settingsRepository(runtime)

    private suspend fun applyAppearance(expectedOwner: org.kurdistanvpn.domain.SettingsRepository, expectedRevision: Long,
        requested: org.kurdistanvpn.core.model.ProductSettings): org.kurdistanvpn.domain.DomainResult<Unit> = withContext(Dispatchers.IO) {
        fun rejected() = org.kurdistanvpn.domain.DomainResult.Rejected(org.kurdistanvpn.core.model.ProductFailure(
            org.kurdistanvpn.core.model.ProductFailureCode.OPERATION_INTERRUPTED))
        val owner = synchronized(this@ProductCompositionRoot) {
            facade.takeIf { currentSettingsDelegate() === expectedOwner }
        } ?: return@withContext rejected()
        val applied = expectedOwner.appliedRevision() as? org.kurdistanvpn.domain.DomainResult.Success
            ?: return@withContext rejected()
        val projection = owner.readProjection() ?: return@withContext rejected()
        if (applied.value.revision != expectedRevision || projection.settings.copy(theme = requested.theme,
                highContrast = requested.highContrast, reducedMotion = requested.reducedMotion) != requested)
            return@withContext rejected()
        if (owner.replaceSettings(projection.revision, requested) is ProtectedStateApplicationFacade.CommandResult.Committed)
            org.kurdistanvpn.domain.DomainResult.Success(Unit) else rejected()
    }

    /**
     * Explicit destructive reset. A committed result means the authenticated reset manifest
     * rolled forward and the facade has relinquished every owned directory; it does not
     * provision replacement state.
     */
    suspend fun resetProtectedStateConfirmed(
        recoverPending: Boolean = false,
    ): ProtectedStateApplicationFacade.CommandResult<Unit> = withContext(Dispatchers.IO) {
        val current = synchronized(this@ProductCompositionRoot) { facade }
            ?: return@withContext ProtectedStateApplicationFacade.CommandResult.Busy
        val result = current.resetProtectedStateConfirmed(recoverPending)
        synchronized(this@ProductCompositionRoot) {
            if (result is ProtectedStateApplicationFacade.CommandResult.Committed && facade === current) {
                facade = null
                currentSettingsDelegate()
                storageFailure = StorageFailure.FIRST_USE
            }
        }
        result
    }

    /** Complete committed capture, not the legacy UI's partial transport configuration. */
    suspend fun validateProductionManualStart(profileId: org.kurdistanvpn.core.model.CatalogId,
        expectedSettingsRevision: Long): OperationError? = withContext(Dispatchers.IO) {
        val current = protectedStateFacade() ?: return@withContext OperationError.RECOVERY_REQUIRED
        val environment = object : ProtectedAuthorityEnvironment {
            override fun isUserUnlocked() = context.getSystemService(UserManager::class.java).isUserUnlocked
            override fun isConsentPrepared() = VpnService.prepare(context) == null
            override fun isCancelled() = false
            override fun elapsedRealtimeMillis() = SystemClock.elapsedRealtime()
        }
        try {
            when (val result = current.reconstructProductionCapture(environment)) {
                is org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult.Ready -> result.capture.use {
                    if (it.presentation.profileId == profileId.value &&
                        it.presentation.settingsRevision == expectedSettingsRevision) null else OperationError.POLICY_REJECTED
                }
                is org.kurdistanvpn.data.protectedstate.ProductionCaptureReadResult.Rejected ->
                    result.error ?: OperationError.POLICY_REJECTED
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
        catch (_: Exception) { OperationError.RECOVERY_REQUIRED }
    }

    /** Called only after an explicit first-use interaction. Existing/partial state is never overwritten. */
    suspend fun initializeProtectedStateForExplicitUserAction(): Boolean = withContext(Dispatchers.IO) {
        synchronized(this@ProductCompositionRoot) {
            if (facade != null) return@withContext true
            when (val opened = ProtectedStateApplicationFacade.initializeForExplicitInteraction(
                context, primitives, nativeCore, processOwner,
            )) {
                is ProtectedStateApplicationFacade.OpenResult.Ready -> {
                    facade = opened.facade
                    currentSettingsDelegate()
                    storageFailure = null
                    true
                }
                is ProtectedStateApplicationFacade.OpenResult.KeyInvalidated -> {
                    storageFailure = StorageFailure.KEY_INVALIDATED
                    false
                }
                else -> {
                    storageFailure = classifyStorageOpen(opened)
                    false
                }
            }
        }
    }

    /** Explicit one-way legacy adoption. No startup, preview, or readonly path may invoke it. */
    suspend fun migrateLegacyProtectedStateForExplicitUserAction(): Boolean = withContext(Dispatchers.IO) {
        synchronized(this@ProductCompositionRoot) {
            if (facade != null) return@withContext false
            when (val opened = ProtectedStateApplicationFacade.migrateLegacyForExplicitInteraction(
                context, primitives, nativeCore, processOwner,
            )) {
                is ProtectedStateApplicationFacade.OpenResult.Ready -> {
                    facade = opened.facade
                    currentSettingsDelegate()
                    storageFailure = null
                    true
                }
                ProtectedStateApplicationFacade.OpenResult.KeyInvalidated -> {
                    storageFailure = StorageFailure.KEY_INVALIDATED
                    false
                }
                ProtectedStateApplicationFacade.OpenResult.MigrationRequired -> {
                    storageFailure = StorageFailure.MIGRATION_REQUIRED
                    false
                }
                else -> {
                    storageFailure = classifyStorageOpen(opened)
                    false
                }
            }
        }
    }

    /** Explicit product storage actions only. Ordinary open/read paths never invoke these. */
    suspend fun migrateProductProjectionConfirmed(expectedRevision: Long): ProtectedStateApplicationFacade.CommandResult<Unit> {
        val current = protectedStateFacade() ?: return ProtectedStateApplicationFacade.CommandResult.Busy
        val result = current.migrateProductProjectionConfirmed(expectedRevision)
        recordProductStorageResult(current, result)
        return result
    }

    suspend fun recoverProductSchemaConfirmed(rollback: Boolean = false): ProtectedStateApplicationFacade.CommandResult<Unit> {
        val current = protectedStateFacade() ?: return ProtectedStateApplicationFacade.CommandResult.Busy
        val result = current.recoverProductSchemaConfirmed(rollback)
        recordProductStorageResult(current, result)
        return result
    }

    suspend fun recoverProductOperationConfirmed(rollback: Boolean = false): ProtectedStateApplicationFacade.CommandResult<Unit> {
        val current = protectedStateFacade() ?: return ProtectedStateApplicationFacade.CommandResult.Busy
        val result = current.recoverProductOperationConfirmed(rollback)
        recordProductStorageResult(current, result)
        return result
    }

    @Synchronized private fun recordProductStorageResult(current: ProtectedStateApplicationFacade,
        result: ProtectedStateApplicationFacade.CommandResult<Unit>) {
        if (facade !== current) return
        storageFailure = when (result) {
            is ProtectedStateApplicationFacade.CommandResult.Committed -> null
            is ProtectedStateApplicationFacade.CommandResult.Unproven -> StorageFailure.MUTATION_UNPROVEN
            is ProtectedStateApplicationFacade.CommandResult.Busy -> storageFailure
            is ProtectedStateApplicationFacade.CommandResult.Rejected -> when (result.error) {
                OperationError.KEY_INVALIDATED -> StorageFailure.KEY_INVALIDATED
                else -> StorageFailure.DEGRADED
            }
        }
    }

    override fun close() {
        val closing = synchronized(this) { facade.also { facade = null; currentSettingsDelegate() } }
        var failure: Throwable? = null
        foregroundActions.clear()
        for (owner in listOfNotNull(if (maintenanceBinding.isInitialized()) maintenanceBinding.value else null,
                importOperations, backupOperations, diagnosticOperations, closing, processOwner)) {
            try { owner.close() } catch (error: Throwable) {
                if (failure == null) failure = error else checkNotNull(failure).addSuppressed(error)
            }
        }
        failure?.let { throw it }
    }

    companion object {
        internal fun classifyStorageOpen(opened: ProtectedStateApplicationFacade.OpenResult): StorageFailure? = when (opened) {
            is ProtectedStateApplicationFacade.OpenResult.Ready -> null
            ProtectedStateApplicationFacade.OpenResult.Missing -> StorageFailure.FIRST_USE
            ProtectedStateApplicationFacade.OpenResult.Locked -> StorageFailure.LOCKED
            ProtectedStateApplicationFacade.OpenResult.KeyInvalidated -> StorageFailure.KEY_INVALIDATED
            ProtectedStateApplicationFacade.OpenResult.MigrationRequired -> StorageFailure.MIGRATION_REQUIRED
            ProtectedStateApplicationFacade.OpenResult.Unproven -> StorageFailure.MUTATION_UNPROVEN
        }

        fun create(context: Context, processOwner: ProtectedStateProcessOwner,
            runtimePolicy: kotlinx.coroutines.flow.Flow<org.kurdistanvpn.domain.SystemPolicyState> =
                kotlinx.coroutines.flow.flowOf(org.kurdistanvpn.domain.SystemPolicyState(null, null, null)),
            settingsRuntime: () -> org.kurdistanvpn.data.settings.SettingsRuntimePort = {
                (context as KurdistanApplication).settingsRuntimePort
            },
        ): ProductCompositionRoot {
            check(context.applicationContext === context)
            val native = NativeBridge()
            val primitives = native.durableFiles()
            val opened = ProtectedStateApplicationFacade.openForInteractiveMutation(
                context, primitives, native, processOwner,
            )
            val facade = (opened as? ProtectedStateApplicationFacade.OpenResult.Ready)?.facade
            val failure = classifyStorageOpen(opened)
            return ProductCompositionRoot(context, native, primitives, processOwner, facade, failure, runtimePolicy, settingsRuntime)
        }
    }
}

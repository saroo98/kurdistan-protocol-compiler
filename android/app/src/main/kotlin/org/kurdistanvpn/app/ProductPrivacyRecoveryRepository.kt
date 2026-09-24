// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import java.util.UUID
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.core.model.SensitiveAction as PrivacyAction

internal interface ProductPrivacyForeground {
    suspend fun authenticatePrivacy(action: PrivacyAction, allowed: Set<AllowedAuthenticator>): Boolean
}

/** One confirmation owner. Native handles, passwords and reset snapshots stay in the app graph. */
internal class ProductPrivacyRecoveryRepository(
    private val facade: () -> ProtectedStateApplicationFacade?,
    private val applySettings: suspend ((ProductSettings) -> ProductSettings) -> DomainResult<Unit>,
    private val backups: ProductBackupOperations,
    private val diagnostics: ProductDiagnosticsRepository,
    private val system: SystemPolicyRepository,
    private val authenticate: suspend (PrivacyAction, Set<AllowedAuthenticator>) -> Boolean,
    private val destination: suspend (CatalogId, ByteArray) -> Boolean,
    private val resetAll: suspend () -> ProtectedStateApplicationFacade.CommandResult<Unit>,
    private val migrateLegacy: suspend () -> Boolean,
) : PrivacyRecoveryRepository {
    private val lock = MutableStateFlow(AppLockState.UNAVAILABLE)
    private val policy = MutableStateFlow<PrivacyPreferences?>(null)
    private val operation = MutableStateFlow<OperationState>(OperationState.Idle)
    private val backupState = MutableStateFlow<BackupWorkflowState>(BackupWorkflowState.Idle)
    private var exporting: Pair<CatalogId, Int>? = null
    private val mutex = Mutex()
    private data class Pending(val id: CatalogId, val preview: OperationPreview,
        val run: suspend () -> DomainResult<Int>, val cancel: suspend () -> DomainResult<Unit>)
    private var pending: Pending? = null
    private var authenticatedPolicy: PrivacyPreferences? = null

    fun backgrounded() { authenticatedPolicy = null; lock.value = if (policy.value?.appLockEnabled == false) AppLockState.UNLOCKED else AppLockState.LOCKED }
    override fun observeAppLock(): Flow<AppLockState> = flow { refreshPolicy(); emitAll(lock) }
    override fun observePrivacy(): Flow<PrivacySummary> = flow {
        refreshPolicy()
        emitAll(combine(policy.filterNotNull(), system.observeClipboard(), system.observeScreenshotPolicy(), ::PrivacySummary))
    }
    override fun observeOperation(): StateFlow<OperationState> = operation.asStateFlow()
    override fun observeBackup(): StateFlow<BackupWorkflowState> = backupState.asStateFlow()

    @Synchronized fun backupDestinationFinished(id: CatalogId, error: OperationError?) {
        val current = exporting?.takeIf { it.first == id } ?: return
        exporting = null
        if (error == null) {
            backupState.value = BackupWorkflowState.Exported
            operation.value = OperationState.Succeeded(OperationResult(OperationKind.BACKUP, current.second))
        } else {
            backupState.value = if (error == OperationError.CANCELLED) BackupWorkflowState.Idle else BackupWorkflowState.Failed(error)
            operation.value = if (error == OperationError.CANCELLED) OperationState.Cancelled(OperationKind.BACKUP)
                else OperationState.Failed(OperationKind.BACKUP, ProductFailure(error.failureCode()))
        }
    }

    private suspend fun refreshPolicy(): PrivacyPreferences? = withContext(Dispatchers.IO) {
        val current = facade()?.readProjection()?.settings?.privacy
        policy.value = current
        lock.value = when {
            current == null -> AppLockState.UNAVAILABLE
            !current.appLockEnabled || current == authenticatedPolicy -> AppLockState.UNLOCKED
            else -> AppLockState.LOCKED
        }
        current
    }

    override suspend fun unlock(action: PrivacyAction): DomainResult<UnlockResult> {
        // Emergency cleanup must work even when every protected read fails.
        if (action == PrivacyAction.DISCONNECT || action == PrivacyAction.RECOVER_INTERNET)
            return DomainResult.Success(UnlockResult.NOT_REQUIRED)
        return safe {
            val current = refreshPolicy() ?: return@safe rejected(ProductFailureCode.STORAGE_LOCKED)
            if (!current.requiresUnlock(action)) return@safe DomainResult.Success(UnlockResult.NOT_REQUIRED)
            if (!authenticate(action, current.allowedAuthenticators)) return@safe rejected(ProductFailureCode.CANCELLED)
            // Authentication cannot authorize a policy changed while the system prompt was open.
            if (refreshPolicy() != current) return@safe rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            authenticatedPolicy = current; lock.value = AppLockState.UNLOCKED
            DomainResult.Success(UnlockResult.AUTHORIZED)
        }
    }

    override suspend fun setAppLock(preferences: PrivacyPreferences): DomainResult<Unit> = applyPrivacy(preferences)
    override suspend fun applyPrivacy(preferences: PrivacyPreferences): DomainResult<Unit> = safe {
        val current = refreshPolicy() ?: return@safe rejected(ProductFailureCode.STORAGE_LOCKED)
        if (current.appLockEnabled || preferences.appLockEnabled) {
            // Enabling must prove the new policy is usable. Disabling must satisfy the old policy.
            val allowed = if (current.appLockEnabled) current.allowedAuthenticators else preferences.allowedAuthenticators
            if (!authenticate(PrivacyAction.APP_ENTRY, allowed)) return@safe rejected(ProductFailureCode.CANCELLED)
        }
        val result = applySettings { old ->
            check(old.privacy == current) { "PRIVACY_POLICY_CHANGED" }
            old.copy(privacy = preferences)
        }
        authenticatedPolicy = null
        refreshPolicy()
        result
    }

    override suspend fun previewBackup(profileIds: Set<CatalogId>) = preview(OperationKind.BACKUP) {
        when (val result = backups.previewExport(profileIds)) {
            is NativeResult.Failure -> rejected(result.error.failureCode())
            is NativeResult.Success -> {
                val id = result.value.id
                DomainResult.Success(Pending(id, OperationPreview(OperationKind.BACKUP, result.value.profileCount), {
                    when (val exported = backups.confirmExport(id)) {
                        is NativeResult.Failure -> rejected(exported.error.failureCode())
                        is NativeResult.Success -> {
                            var accepted = false
                            try {
                                synchronized(this@ProductPrivacyRecoveryRepository) { exporting = id to result.value.profileCount }
                                accepted = destination(id, exported.value)
                                if (accepted) DomainResult.Success(result.value.profileCount)
                                else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                            } finally { if (!accepted) {
                                exported.value.fill(0)
                                backupDestinationFinished(id, OperationError.CANCELLED)
                            } }
                        }
                    }
                }, { backups.cancelExport(id); DomainResult.Success(Unit) }))
            }
        }
    }
    override suspend fun backup(operationId: CatalogId) = confirm(operationId, OperationKind.BACKUP)

    override suspend fun previewRestore(stagedInputId: CatalogId) = preview(OperationKind.RESTORE) {
        when (val result = backups.review(stagedInputId)) {
            is NativeResult.Failure -> rejected(result.error.failureCode())
            is NativeResult.Success -> {
                backupState.value = result.value.display
                DomainResult.Success(Pending(stagedInputId,
                OperationPreview(OperationKind.RESTORE, result.value.display.recordCount), {
                    when (val restored = backups.restore(stagedInputId)) {
                        is NativeResult.Success -> DomainResult.Success(restored.value)
                        is NativeResult.Failure -> rejected(restored.error.failureCode())
                    }
                }, { when (val cancelled = backups.cancel(stagedInputId)) {
                    is NativeResult.Success -> DomainResult.Success(Unit)
                    is NativeResult.Failure -> rejected(cancelled.error.failureCode())
                } }))
            }
        }
    }
    override suspend fun restore(operationId: CatalogId) = confirm(operationId, OperationKind.RESTORE)

    // The existing native API exports encrypted backups, not a recipient-transfer artifact.
    // Do not silently export plaintext or reinterpret a backup as a recipient-bound transfer.
    override suspend fun previewTransfer(profileId: CatalogId, stagedRecipientId: CatalogId): DomainResult<PendingProductOperation> =
        preview(OperationKind.BACKUP) { rejected(ProductFailureCode.PROFILE_INCOMPATIBLE) }
    override suspend fun transfer(operationId: CatalogId): DomainResult<Unit> = rejected(ProductFailureCode.PROFILE_INCOMPATIBLE)

    override suspend fun previewReset(scope: ResetScope) = preview(OperationKind.RESET) {
        if (scope.unavailableReason != null) return@preview rejected(ProductFailureCode.PROFILE_INCOMPATIBLE)
        val owner = facade() ?: return@preview rejected(ProductFailureCode.STORAGE_LOCKED)
        val snapshot = owner.readProjection() ?: return@preview rejected(ProductFailureCode.STORAGE_DEGRADED)
        val ids = snapshot.profiles.map { it.localRecordId }.toSet()
        val id = CatalogId(UUID.randomUUID().toString())
        val count = when (scope) {
            ResetScope.PROFILES_AND_TRUST -> ids.size
            ResetScope.DIAGNOSTICS -> 2 // Settings reset and categorical event erasure have distinct owners.
            else -> 1
        }
        DomainResult.Success(Pending(id, OperationPreview(OperationKind.RESET, count), {
            if (facade() !== owner || owner.readProjection()?.revision != snapshot.revision)
                return@Pending rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            when (scope) {
                ResetScope.PROFILES_AND_TRUST -> if (ids.isEmpty()) DomainResult.Success(0)
                    else command(owner.resetProfiles(ids, snapshot.revision), count)
                ResetScope.PENDING_CREDENTIALS -> when (val reset = owner.resetPendingCredentialsConfirmed(snapshot.revision)) {
                    is ProtectedStateApplicationFacade.CommandResult.Committed -> DomainResult.Success(reset.value)
                    else -> rejected(ProductFailureCode.STORAGE_DEGRADED)
                }
                ResetScope.EVERYTHING -> command(resetAll(), count)
                ResetScope.SETTINGS, ResetScope.ROUTING, ResetScope.DIAGNOSTICS -> {
                    val result = applySettings { current ->
                        check(current == snapshot.settings) { "RESET_SETTINGS_CHANGED" }
                        when (scope) {
                            ResetScope.SETTINGS -> ProductSettings().copy(routing = current.routing,
                                diagnostics = current.diagnostics, profiles = current.profiles)
                            ResetScope.ROUTING -> current.copy(routing = ProductSettings().routing)
                            else -> current.copy(diagnostics = ProductSettings().diagnostics)
                        }
                    }
                    if (result is DomainResult.Rejected) result
                    else if (scope == ResetScope.DIAGNOSTICS) when (val cleared = diagnostics.clear()) {
                        is DomainResult.Rejected -> {
                            operation.value = OperationState.PartiallyApplied(PartialOperationResult(OperationKind.RESET, 1, 1))
                            cleared
                        }
                        is DomainResult.Success -> DomainResult.Success(count)
                    } else DomainResult.Success(count)
                }
                ResetScope.LOCAL_CREDENTIALS -> rejected(ProductFailureCode.PROFILE_INCOMPATIBLE)
            }
        }, { DomainResult.Success(Unit) }))
    }
    override suspend fun reset(operationId: CatalogId) = confirm(operationId, OperationKind.RESET)

    override suspend fun recoverProtectedState(): DomainResult<OperationState> = safe {
        val owner = facade() ?: return@safe rejected(ProductFailureCode.STORAGE_LOCKED)
        when (val result = command(owner.recoverPresentationConfirmed(), 1)) {
            is DomainResult.Rejected -> result
            is DomainResult.Success -> DomainResult.Success(OperationState.Succeeded(OperationResult(OperationKind.RESET, 1)).also { operation.value = it })
        }
    }

    override suspend fun migrateLegacyProtectedState(): DomainResult<OperationState> = safe {
        if (migrateLegacy()) DomainResult.Success(OperationState.Succeeded(OperationResult(OperationKind.SETTINGS_CHANGE, 1)).also { operation.value = it })
        else rejected(ProductFailureCode.MIGRATION_REQUIRED)
    }

    private suspend fun preview(kind: OperationKind, prepare: suspend () -> DomainResult<Pending>): DomainResult<PendingProductOperation> =
        safe { mutex.withLock {
            if (synchronized(this@ProductPrivacyRecoveryRepository) { exporting != null })
                return@withLock rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
            val prior = pending; pending = null
            if (prior != null) when (val retired = prior.cancel()) {
                is DomainResult.Rejected -> {
                    operation.value = OperationState.Failed(kind, retired.failure)
                    return@withLock retired
                }
                is DomainResult.Success -> Unit
            }
            operation.value = OperationState.Loading(kind)
            when (val result = prepare()) {
                is DomainResult.Rejected -> {
                    operation.value = OperationState.Failed(kind, result.failure)
                    if (kind == OperationKind.BACKUP || kind == OperationKind.RESTORE) backupState.value = BackupWorkflowState.Failed(OperationError.RECOVERY_REQUIRED)
                    result
                }
                is DomainResult.Success -> {
                    pending = result.value
                    operation.value = OperationState.AwaitingConfirmation(result.value.preview)
                    DomainResult.Success(PendingProductOperation(result.value.id, result.value.preview))
                }
            }
        } }

    private suspend fun confirm(id: CatalogId, kind: OperationKind): DomainResult<Unit> = safe { mutex.withLock {
        val current = pending?.takeIf { it.id == id && it.preview.kind == kind }
            ?: return@withLock rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        pending = null
        var cleanup: DomainResult<Unit> = DomainResult.Success(Unit)
        val outcome: DomainResult<Int> = try {
            when (val unlocked = unlock(if (kind == OperationKind.RESET) PrivacyAction.RESET else PrivacyAction.EXPORT)) {
                is DomainResult.Rejected -> unlocked
                is DomainResult.Success -> {
                    operation.value = OperationState.Applying(OperationProgress(kind, 0, maxOf(1, current.preview.itemCount)))
                    if (kind == OperationKind.BACKUP || kind == OperationKind.RESTORE) backupState.value = BackupWorkflowState.Working
                    current.run()
                }
            }
        } catch (cancelled: CancellationException) {
            operation.value = OperationState.Failed(kind, ProductFailure(ProductFailureCode.OPERATION_INTERRUPTED))
            throw cancelled
        } catch (_: Exception) { rejected(ProductFailureCode.STORAGE_DEGRADED) }
        finally { cleanup = withContext(NonCancellable) { safe { current.cancel() } } }
        val result = (cleanup as? DomainResult.Rejected) ?: outcome
        when (result) {
            is DomainResult.Rejected -> {
                if (operation.value !is OperationState.PartiallyApplied) operation.value = OperationState.Failed(kind, result.failure)
                if (kind == OperationKind.BACKUP || kind == OperationKind.RESTORE) backupState.value = BackupWorkflowState.Failed(OperationError.RECOVERY_REQUIRED)
                result
            }
            is DomainResult.Success -> {
                // Opening a destination is not proof that its bytes were written.
                if (kind != OperationKind.BACKUP) {
                    operation.value = OperationState.Succeeded(OperationResult(kind, result.value))
                    if (kind == OperationKind.RESTORE) backupState.value = BackupWorkflowState.Completed(result.value)
                }
                DomainResult.Success(Unit)
            }
        }
    } }

    override suspend fun cancel(operationId: CatalogId): DomainResult<Unit> = safe { mutex.withLock {
        val current = pending?.takeIf { it.id == operationId }
            ?: return@withLock rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        pending = null
        current.cancel().also { result ->
            if (current.preview.kind == OperationKind.BACKUP || current.preview.kind == OperationKind.RESTORE)
                backupState.value = if (result is DomainResult.Success) BackupWorkflowState.Idle else BackupWorkflowState.Failed(OperationError.RECOVERY_REQUIRED)
            operation.value = when (result) {
            is DomainResult.Success -> OperationState.Cancelled(current.preview.kind)
            is DomainResult.Rejected -> OperationState.Failed(current.preview.kind, result.failure)
        } }
    } }

    private fun command(result: ProtectedStateApplicationFacade.CommandResult<*>, count: Int): DomainResult<Int> =
        if (result is ProtectedStateApplicationFacade.CommandResult.Committed) DomainResult.Success(count)
        else rejected(ProductFailureCode.STORAGE_DEGRADED)
    private suspend fun <T> safe(action: suspend () -> DomainResult<T>): DomainResult<T> = withContext(Dispatchers.IO) {
        try { action() }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { rejected(ProductFailureCode.STORAGE_DEGRADED) }
    }
    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
    private fun OperationError.failureCode() = when (this) {
        OperationError.INVALID_INPUT -> ProductFailureCode.INVALID_INPUT
        OperationError.CANCELLED -> ProductFailureCode.OPERATION_INTERRUPTED
        OperationError.TRUST_REJECTED -> ProductFailureCode.PROFILE_UNTRUSTED
        else -> ProductFailureCode.STORAGE_DEGRADED
    }
}

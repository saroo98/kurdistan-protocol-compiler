// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import android.content.Context
import android.net.VpnService
import android.os.SystemClock
import android.os.UserManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
class Phase9CompositionRoot private constructor(
    private val context: Context,
    val nativeCore: KurdNativeCore,
    private val primitives: DurableFilePrimitives,
    private val processOwner: ProtectedStateProcessOwner,
    private var facade: ProtectedStateApplicationFacade?,
    initialStorageFailure: StorageFailure?,
) : AutoCloseable {
    val runtime: UnavailableRuntime = UnavailableRuntime(RuntimeAvailability.PHASE_9_NO_RUNTIME)
    @Volatile var storageFailure: StorageFailure? = initialStorageFailure
        private set

    enum class StorageFailure { FIRST_USE, LOCKED, KEY_INVALIDATED, MIGRATION_REQUIRED, DEGRADED, MUTATION_UNPROVEN }

    /** The typed boundary only. It never returns a journal, KEK, DAO, writer, or authority. */
    @Synchronized fun protectedStateFacade(): ProtectedStateApplicationFacade? = facade

    /**
     * Explicit destructive reset. A committed result means the authenticated reset manifest
     * rolled forward and the facade has relinquished every owned directory; it does not
     * provision replacement state.
     */
    suspend fun resetProtectedStateConfirmed(
        recoverPending: Boolean = false,
    ): ProtectedStateApplicationFacade.CommandResult<Unit> = withContext(Dispatchers.IO) {
        val current = synchronized(this@Phase9CompositionRoot) { facade }
            ?: return@withContext ProtectedStateApplicationFacade.CommandResult.Busy
        val result = current.resetProtectedStateConfirmed(recoverPending)
        synchronized(this@Phase9CompositionRoot) {
            if (result is ProtectedStateApplicationFacade.CommandResult.Committed && facade === current) {
                facade = null
                storageFailure = StorageFailure.FIRST_USE
            }
        }
        result
    }

    /** Canonical post-consent validation. It reconstructs and closes fresh authority internally. */
    fun validateManualStart(config: VpnRuntimeConfig): OperationError? {
        val current = synchronized(this) { facade } ?: return OperationError.RECOVERY_REQUIRED
        val environment = object : ProtectedAuthorityEnvironment {
            override fun isUserUnlocked(): Boolean = context.getSystemService(UserManager::class.java).isUserUnlocked
            override fun isConsentPrepared(): Boolean = VpnService.prepare(context) == null
            override fun isCancelled(): Boolean = false
            override fun elapsedRealtimeMillis(): Long = SystemClock.elapsedRealtime()
        }
        return current.validateManualStart(config, environment)
    }

    /** Called only after an explicit first-use interaction. Existing/partial state is never overwritten. */
    suspend fun initializeProtectedStateForExplicitUserAction(): Boolean = withContext(Dispatchers.IO) {
        synchronized(this@Phase9CompositionRoot) {
            if (facade != null) return@withContext true
            when (val opened = ProtectedStateApplicationFacade.initializeForExplicitInteraction(
                context, primitives, nativeCore, processOwner,
            )) {
                is ProtectedStateApplicationFacade.OpenResult.Ready -> {
                    facade = opened.facade
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
        synchronized(this@Phase9CompositionRoot) {
            if (facade != null) return@withContext false
            when (val opened = ProtectedStateApplicationFacade.migrateLegacyForExplicitInteraction(
                context, primitives, nativeCore, processOwner,
            )) {
                is ProtectedStateApplicationFacade.OpenResult.Ready -> {
                    facade = opened.facade
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

    override fun close() {
        val closing = synchronized(this) { facade.also { facade = null } }
        var failure: Throwable? = null
        try { closing?.close() } catch (error: Throwable) { failure = error }
        try { processOwner.close() } catch (error: Throwable) {
            if (failure == null) failure = error else checkNotNull(failure).addSuppressed(error)
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

        fun create(context: Context, processOwner: ProtectedStateProcessOwner): Phase9CompositionRoot {
            check(context.applicationContext === context)
            val native = NativeBridge()
            val primitives = native.durableFiles()
            val opened = ProtectedStateApplicationFacade.openForInteractiveMutation(
                context, primitives, native, processOwner,
            )
            val facade = (opened as? ProtectedStateApplicationFacade.OpenResult.Ready)?.facade
            val failure = classifyStorageOpen(opened)
            return Phase9CompositionRoot(context, native, primitives, processOwner, facade, failure)
        }
    }
}

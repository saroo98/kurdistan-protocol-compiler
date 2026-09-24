// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.UUID
import org.kurdistanvpn.core.model.BackupWorkflowState
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.BackupPreviewHandle
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ProtectedBackupEnumeration
import org.kurdistanvpn.data.protectedstate.PendingProtectedBackup
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.BackupPayloadCodec

internal data class BackupOperationPreview(val id: CatalogId, val display: BackupWorkflowState.RestorePreview)
internal data class BackupExportPreview(val id: CatalogId, val profileCount: Int)
internal interface ProductBackupForeground {
    fun requestBackupDestination(bytes: ByteArray, operationId: CatalogId? = null): Boolean
}

/** Blocking native work is called on the existing worker dispatcher. No handle leaves this owner. */
internal class ProductBackupOperations(
    private val core: KurdNativeCore,
    private val facade: () -> ProtectedStateApplicationFacade?,
    private val elapsedMillis: () -> Long,
) : AutoCloseable {
    private var pending: Pair<CatalogId, BackupPreviewHandle>? = null
    private var cleanupUnproven = false
    private var stagedExport: Pair<Set<CatalogId>, ByteArray>? = null
    private data class Export(val id: CatalogId, val plan: PendingProtectedBackup, val password: ByteArray)
    private var pendingExport: Export? = null

    /** Only the foreground adapter supplies the password, after the user's authentication. */
    @Synchronized fun stageExportPassword(ids: Set<CatalogId>, password: ByteArray) {
        clearExport()
        if (cleanupUnproven || ids.size > 1024 || password.size !in 1..1024) {
            password.fill(0)
            return
        }
        stagedExport = ids.toSet() to password
    }

    @Synchronized fun previewExport(ids: Set<CatalogId>): NativeResult<BackupExportPreview> {
        val staged = stagedExport
        stagedExport = null
        if (staged == null) return NativeResult.Failure(OperationError.CANCELLED)
        var retained = false
        try {
            if (cleanupUnproven) return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
            if (ids != staged.first) return NativeResult.Failure(OperationError.INVALID_INPUT)
            val owner = facade() ?: return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
            val profiles = owner.readProjection()?.profiles?.map { CatalogId(it.localRecordId) }?.toSet()
                ?: return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
            if (!profiles.containsAll(ids)) return NativeResult.Failure(OperationError.INVALID_INPUT)
            // The admitted backup format supports one selected profile or the complete inventory.
            if (ids.size > 1 && ids != profiles) return NativeResult.Failure(OperationError.AUTHORITY_UNAVAILABLE)
            val selected = ids.singleOrNull()?.value
            return when (val result = owner.enumerateBackup(selected, { false }, elapsedMillis)) {
                is ProtectedBackupEnumeration.Rejected -> NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
                is ProtectedBackupEnumeration.Ready -> {
                    val id = CatalogId(UUID.randomUUID().toString())
                    pendingExport = Export(id, result.plan, staged.second)
                    retained = true
                    NativeResult.Success(BackupExportPreview(id, result.plan.profileCount))
                }
            }
        } finally { if (!retained) staged.second.fill(0) }
    }

    @Synchronized fun confirmExport(id: CatalogId): NativeResult<ByteArray> {
        val current = pendingExport?.takeIf { it.id == id } ?: return NativeResult.Failure(OperationError.CANCELLED)
        pendingExport = null
        return try { current.plan.use { it.confirmEncryptedExport(current.password) } }
        finally { current.password.fill(0) }
    }

    @Synchronized fun cancelExport(id: CatalogId?) {
        if (id == null || pendingExport?.id == id) clearExport()
    }

    private fun clearExport() {
        stagedExport?.second?.fill(0)
        stagedExport = null
        val previous = pendingExport
        pendingExport = null
        try { previous?.plan?.close() }
        finally { previous?.password?.fill(0) }
    }

    fun create(localId: String?, password: ByteArray): NativeResult<ByteArray> = try {
        when (val plan = facade()?.enumerateBackup(localId, { false }, elapsedMillis)) {
            is ProtectedBackupEnumeration.Ready -> plan.plan.use { it.confirmEncryptedExport(password) }
            else -> NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        }
    } finally { password.fill(0) }

    @Synchronized fun open(bytes: ByteArray, password: ByteArray): NativeResult<BackupOperationPreview> = try {
        cancel(pending?.first)
        if (cleanupUnproven) NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        else when (val result = core.openBackup(bytes, password)) {
            is NativeResult.Failure -> result
            is NativeResult.Success -> {
                val decoded = try { ProductExportWire.backupPreview(result.value.previewBytes) }
                catch (_: IllegalArgumentException) {
                    release(result.value)
                    return NativeResult.Failure(if (cleanupUnproven) OperationError.RECOVERY_REQUIRED else OperationError.INVALID_INPUT)
                }
                val id = CatalogId(UUID.randomUUID().toString())
                pending = id to result.value
                NativeResult.Success(BackupOperationPreview(id, BackupWorkflowState.RestorePreview(decoded.first, decoded.second)))
            }
        }
    } finally { bytes.fill(0); password.fill(0) }

    @Synchronized fun review(id: CatalogId): NativeResult<BackupOperationPreview> {
        val current = pending?.takeIf { it.first == id }
            ?: return NativeResult.Failure(OperationError.CANCELLED)
        if (cleanupUnproven) return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        val display = ProductExportWire.backupPreview(current.second.previewBytes)
        return NativeResult.Success(BackupOperationPreview(id, BackupWorkflowState.RestorePreview(display.first, display.second)))
    }

    suspend fun restore(id: CatalogId): NativeResult<Int> {
        val result = synchronized(this) {
            val current = pending?.takeIf { it.first == id } ?: return NativeResult.Failure(OperationError.CANCELLED)
            pending = null
            try { core.restoreBackup(current.second) } finally { release(current.second) }
        }
        if (result is NativeResult.Failure) return result
        val bytes = (result as NativeResult.Success).value
        val records = try {
            if (cleanupUnproven) return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
            try { BackupPayloadCodec.decodePayload(bytes) }
            catch (_: IllegalArgumentException) { return NativeResult.Failure(OperationError.INVALID_INPUT) }
        } finally { bytes.fill(0) }
        val restored = try {
            val encoded = BackupPayloadCodec.encode(records)
            try { facade()?.restoreConfirmedBackup(encoded) } finally { encoded.fill(0) }
        } finally {
            records.clientKeys.forEach { it.destroy() }
            records.profiles.forEach { it.verifyRequest.fill(0) }
        }
        return when (restored) {
            is ProtectedStateApplicationFacade.CommandResult.Committed -> NativeResult.Success(restored.value)
            is ProtectedStateApplicationFacade.CommandResult.Rejected -> NativeResult.Failure(restored.error)
            else -> NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        }
    }

    @Synchronized fun cancel(id: CatalogId?): NativeResult<Unit> {
        val current = pending
        if (current != null && current.first == id) {
            pending = null
            release(current.second)
        }
        return if (cleanupUnproven) NativeResult.Failure(OperationError.RECOVERY_REQUIRED) else NativeResult.Success(Unit)
    }

    private fun release(handle: BackupPreviewHandle) {
        try {
            if (core.releaseBackup(handle) is NativeResult.Failure) cleanupUnproven = true
        } catch (_: Exception) {
            cleanupUnproven = true
        } finally { handle.previewBytes.fill(0) }
    }

    @Synchronized override fun close() {
        clearExport()
        check(cancel(pending?.first) is NativeResult.Success) { "BACKUP_CLEANUP_UNPROVEN" }
    }
}

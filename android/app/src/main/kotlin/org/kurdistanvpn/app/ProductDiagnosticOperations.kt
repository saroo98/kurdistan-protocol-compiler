// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.UUID
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.DiagnosticWorkflowState
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.nativeapi.DiagnosticPreviewHandle
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeResult

internal data class DiagnosticOperationPreview(val id: CatalogId, val display: DiagnosticWorkflowState.Preview)

/** Native preview parent stays at the repository boundary; UI holds only a redacted display and ID. */
internal class ProductDiagnosticOperations(private val core: KurdNativeCore) : AutoCloseable {
    private var pending: Pair<CatalogId, DiagnosticPreviewHandle>? = null
    private var cleanupUnproven = false

    @Synchronized fun prepare(request: ByteArray): NativeResult<DiagnosticOperationPreview> {
        val cancelled = cancel(pending?.first)
        if (cancelled is NativeResult.Failure || cleanupUnproven) return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        return when (val result = core.prepareDiagnostic(request)) {
            is NativeResult.Failure -> result
            is NativeResult.Success -> {
                val decoded = try { ProductExportWire.diagnosticPreview(result.value.previewBytes) }
                catch (_: IllegalArgumentException) {
                    release(result.value)
                    return NativeResult.Failure(if (cleanupUnproven) OperationError.RECOVERY_REQUIRED else OperationError.INVALID_INPUT)
                } catch (_: IllegalStateException) {
                    release(result.value)
                    return NativeResult.Failure(if (cleanupUnproven) OperationError.RECOVERY_REQUIRED else OperationError.INVALID_INPUT)
                }
                val id = CatalogId(UUID.randomUUID().toString())
                pending = id to result.value
                NativeResult.Success(DiagnosticOperationPreview(id,
                    DiagnosticWorkflowState.Preview(decoded.first, decoded.second, decoded.third)))
            }
        }
    }

    @Synchronized fun confirm(id: CatalogId): NativeResult<ByteArray> {
        val current = pending?.takeIf { it.first == id } ?: return NativeResult.Failure(OperationError.CANCELLED)
        pending = null
        val result = try { core.confirmAndBuildDiagnostic(current.second) }
        finally { release(current.second) }
        if (cleanupUnproven) {
            if (result is NativeResult.Success) result.value.fill(0)
            return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
        }
        return result
    }

    @Synchronized fun cancel(id: CatalogId?): NativeResult<Unit> {
        val current = pending
        if (current != null && current.first == id) {
            pending = null
            release(current.second)
        }
        return if (cleanupUnproven) NativeResult.Failure(OperationError.RECOVERY_REQUIRED) else NativeResult.Success(Unit)
    }

    private fun release(handle: DiagnosticPreviewHandle) {
        try {
            if (core.releaseDiagnostic(handle) is NativeResult.Failure) cleanupUnproven = true
        } catch (_: Exception) {
            cleanupUnproven = true
        } finally { handle.previewBytes.fill(0) }
    }

    @Synchronized override fun close() {
        check(cancel(pending?.first) is NativeResult.Success) { "DIAGNOSTIC_CLEANUP_UNPROVEN" }
    }
}

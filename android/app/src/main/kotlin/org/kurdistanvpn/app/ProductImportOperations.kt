// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.UUID
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ImportSource
import org.kurdistanvpn.core.model.OperationError
import org.kurdistanvpn.core.model.RedactedProfilePreview
import org.kurdistanvpn.core.nativeapi.NativeResult
import org.kurdistanvpn.data.protectedstate.ConfirmedProtectedImport
import org.kurdistanvpn.data.protectedstate.PendingProtectedImport
import org.kurdistanvpn.data.protectedstate.ProtectedExternalPreviewResult
import org.kurdistanvpn.data.protectedstate.ProtectedReadFailure
import org.kurdistanvpn.platform.importing.ArtifactClass
import org.kurdistanvpn.platform.importing.ImportCandidate
import org.kurdistanvpn.platform.importing.VerifyRequestEncoder

internal data class ImportOperationPreview(val id: CatalogId, val source: ImportSource, val display: RedactedProfilePreview)

internal class ProductImportOperations(
    private val preview: (ByteArray) -> ProtectedExternalPreviewResult,
    private val commit: suspend (ConfirmedProtectedImport) -> NativeResult<CatalogId>,
) : AutoCloseable {
    private var pending: Pair<CatalogId, PendingProtectedImport>? = null
    private var staged: Triple<CatalogId, ImportSource, ImportCandidate>? = null
    var cleanupUnproven = false
        private set

    /** Activity ingress transfers bounded input ownership; features receive only this opaque ID. */
    @Synchronized fun stage(candidate: ImportCandidate, source: ImportSource): NativeResult<CatalogId> {
        staged?.third?.parts?.forEach { it.fill(0) }
        staged = null
        val failure = if (cleanupUnproven) OperationError.RECOVERY_REQUIRED else try {
            VerifyRequestEncoder.encodedSize(candidate)
            null
        } catch (_: IllegalArgumentException) { OperationError.INVALID_INPUT }
        if (failure != null) {
            candidate.parts.forEach { it.fill(0) }
            return NativeResult.Failure(failure)
        }
        val id = CatalogId(UUID.randomUUID().toString())
        staged = Triple(id, source, candidate)
        return NativeResult.Success(id)
    }

    @Synchronized fun prepareStaged(id: CatalogId, source: ImportSource): NativeResult<ImportOperationPreview> {
        val current = staged?.takeIf { it.first == id && it.second == source }
            ?: return NativeResult.Failure(OperationError.CANCELLED)
        staged = null
        return prepare(current.third, source)
    }

    @Synchronized fun prepare(candidate: ImportCandidate, source: ImportSource): NativeResult<ImportOperationPreview> {
        try {
            cancel(pending?.first)
            if (cleanupUnproven) return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
            for (artifactClass in ArtifactClass.entries) {
                val request = try { VerifyRequestEncoder.encode(candidate.copy(artifactClass = artifactClass)) }
                catch (_: IllegalArgumentException) { return NativeResult.Failure(OperationError.INVALID_INPUT) }
                val result = try { preview(request) } finally { request.fill(0) }
                when (result) {
                    is ProtectedExternalPreviewResult.Rejected -> {
                        if (result.category == ProtectedReadFailure.CLEANUP_UNPROVEN) {
                            cleanupUnproven = true
                            return NativeResult.Failure(OperationError.RECOVERY_REQUIRED)
                        }
                    }
                    is ProtectedExternalPreviewResult.Ready -> {
                        try {
                            val id = CatalogId(UUID.randomUUID().toString())
                            val display = ImportOperationPreview(id, source, result.preview.display)
                            pending = id to result.preview
                            return NativeResult.Success(display)
                        } catch (failure: Throwable) { result.preview.close(); throw failure }
                    }
                }
            }
            return NativeResult.Failure(OperationError.TRUST_REJECTED)
        } finally { candidate.parts.forEach { it.fill(0) } }
    }

    suspend fun confirm(id: CatalogId): NativeResult<CatalogId> {
        val current = synchronized(this) {
            val value = pending?.takeIf { it.first == id } ?: return NativeResult.Failure(OperationError.CANCELLED)
            pending = null
            value.second
        }
        return current.use { parent -> parent.confirm().use { commit(it) } }
    }

    @Synchronized fun cancel(id: CatalogId?) {
        val current = pending?.takeIf { it.first == id } ?: return
        pending = null
        current.second.close()
    }

    @Synchronized override fun close() {
        staged?.third?.parts?.forEach { it.fill(0) }
        staged = null
        cancel(pending?.first)
    }
}

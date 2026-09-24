// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.UUID
import org.kurdistanvpn.core.model.CatalogId

internal enum class ExportDocumentKind { BACKUP, DIAGNOSTIC, ENROLLMENT }

internal class ExportDocument(
    val kind: ExportDocumentKind,
    val bytes: ByteArray,
    val enrollmentLocalId: String?,
) : AutoCloseable {
    override fun close() { bytes.fill(0) }
}

/** Owns one already bounded export, never persisted. Activity recreation retains only its IDs. */
internal class ProductExportDestination(private val effects: ProductActivityEffects) {
    private var request: ActivityEffectRequest? = null
    private var document: ExportDocument? = null

    fun stage(kind: ExportDocumentKind, bytes: ByteArray, localId: String?, resumed: Boolean,
        operationId: CatalogId? = null): ActivityEffectRequest? {
        val next = ActivityEffectRequest(CatalogId(UUID.randomUUID().toString()),
            operationId ?: CatalogId(UUID.randomUUID().toString()), ActivityEffectKind.EXPORT_DESTINATION)
        if (!resumed || request != null || !effects.offer(next)) {
            bytes.fill(0)
            return null
        }
        if (!effects.claim(next.id, resumed)) {
            effects.cancel(next.id)
            bytes.fill(0)
            return null
        }
        document = ExportDocument(kind, bytes, localId)
        request = next
        return next
    }

    fun take(id: CatalogId, operationId: CatalogId): ExportDocument? {
        val current = request ?: return null
        if (current.id != id || current.operationId != operationId) return null
        val value = document
        document = null
        request = null
        if (effects.complete(id, operationId, value != null) != EffectCompletion.COMPLETED) {
            value?.close()
            return null
        }
        return value
    }

    fun cancel(id: CatalogId) {
        if (request?.id != id) return
        effects.cancel(id)
        document?.close()
        document = null
        request = null
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.kurdistanvpn.core.model.CatalogId

internal enum class ActivityEffectKind {
    FILE_IMPORT, BACKUP_IMPORT, EXPORT_DESTINATION, VPN_CONSENT,
    NOTIFICATION_PERMISSION, CAMERA_PERMISSION, SENSITIVE_AUTHENTICATION, SYSTEM_SETTINGS, SCREENSHOT_POLICY,
}

internal data class ActivityEffectRequest(
    val id: CatalogId,
    val operationId: CatalogId,
    val kind: ActivityEffectKind,
)

internal enum class EffectCompletion { COMPLETED, INTERRUPTED }

/** Main-thread, process-local claim owner. Saved IDs are correlation, never authorization. */
internal class ProductActivityEffects {
    private enum class Phase { PENDING, LAUNCHED }
    private var current: ActivityEffectRequest? = null
    private var phase: Phase? = null

    fun offer(request: ActivityEffectRequest): Boolean {
        if (current != null) return false
        current = request
        phase = Phase.PENDING
        return true
    }

    fun claim(id: CatalogId, resumed: Boolean): Boolean {
        if (!resumed || current?.id != id || phase != Phase.PENDING) return false
        phase = Phase.LAUNCHED
        return true
    }

    fun complete(id: CatalogId, operationId: CatalogId, operationCurrent: Boolean): EffectCompletion {
        val request = current ?: return EffectCompletion.INTERRUPTED
        if (request.id != id || request.operationId != operationId || phase != Phase.LAUNCHED) {
            return EffectCompletion.INTERRUPTED
        }
        cancel(id)
        return if (operationCurrent) EffectCompletion.COMPLETED else EffectCompletion.INTERRUPTED
    }

    fun cancel(id: CatalogId) {
        if (current?.id != id) return
        current = null
        phase = null
    }
}

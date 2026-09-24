// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*

/** One bounded probe borrows its service-owned capability. Cancellation never cancels the tunnel. */
internal class RuntimeControlProbe(private val selected: (CatalogId) -> RuntimeSelectedProbeV1?) {
    private class Call(val id: String, val peer: Any) { var cancelled = false }
    private val monitor = Any()
    private var running: Call? = null

    fun run(id: String, profileId: CatalogId, preferences: ProbePreferences, peer: Any): NativeProductResult<NativeProbeResult> {
        val call = synchronized(monitor) {
            if (running != null) return NativeProductResult.Failure(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
            Call(id, peer).also { running = it }
        }
        try {
            val result = try {
                selected(profileId)?.runSelected(preferences)
                    ?: NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
            } catch (_: Exception) { NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            return synchronized(monitor) {
                if (call.cancelled) NativeProductResult.Failure(ProductFailureCode.CANCELLED) else result
            }
        } finally { synchronized(monitor) { if (running === call) running = null } }
    }

    fun cancel(id: String?, peer: Any): Boolean = synchronized(monitor) {
        val call = running ?: return false
        if (call.peer != peer || id != null && call.id != id) return false
        call.cancelled = true
        true
    }
}

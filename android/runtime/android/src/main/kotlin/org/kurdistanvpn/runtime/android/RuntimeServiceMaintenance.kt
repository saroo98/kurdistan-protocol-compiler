// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import android.net.VpnService
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.runtime.api.RuntimeAuthorityTrigger

/** Bounded service-owned borrow. It neither creates a second tunnel nor owns application storage. */
internal class RuntimeServiceMaintenance(
    private val service: VpnService,
    private val activeOwner: () -> RuntimeProductionPlatformOwner?,
    private val idle: () -> Boolean,
    private val live: () -> Boolean,
) {
    private class Call(val id: String, val peer: Any) {
        var cancelled = false
        var parent: ProductionNativeMaintenance? = null
        var standalone: RuntimeProductionPlatformOwner? = null
    }
    private val monitor = Any()
    private var pending: Call? = null

    fun cancel(id: String?, peer: Any): Boolean {
        val parent = synchronized(monitor) {
            val call = pending ?: return false
            if (call.peer != peer || id != null && call.id != id) return false
            call.cancelled = true
            call.parent
        }
        return parent == null || parent.cancel() is NativeProductResult.Success
    }

    /** Lifecycle cancellation is nonblocking. The service's existing cleanup worker retires the owner. */
    fun markCancelled(): RuntimeProductionPlatformOwner? = synchronized(monitor) {
        pending?.let { it.cancelled = true; it.standalone }
    }

    fun <T> run(id: String, profile: CatalogId, peer: Any,
        operation: (ProductionNativeMaintenance) -> NativeProductResult<T>): NativeProductResult<T> {
        val call = synchronized(monitor) {
            if (pending != null) return NativeProductResult.Failure(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
            Call(id, peer).also { pending = it }
        }
        var associated: RuntimeProductionPlatformOwner? = null
        var cleanupSucceeded = true
        var result: NativeProductResult<T> = NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
        try {
            check(live() && !synchronized(monitor) { call.cancelled })
            if (VpnService.prepare(service) != null) return NativeProductResult.Failure(ProductFailureCode.VPN_CONSENT_REQUIRED)
            fun open(owner: RuntimeProductionPlatformOwner) {
                check(owner.capturedProfileId() == profile.value)
                when (val opened = owner.openMaintenanceSession()) {
                    is NativeProductResult.Failure -> result = opened
                    is NativeProductResult.Success -> synchronized(monitor) { call.parent = opened.value }
                }
            }
            val active = activeOwner()
            if (active != null) {
                if (active.capturedProfileId() != profile.value)
                    return NativeProductResult.Failure(ProductFailureCode.PROFILE_INCOMPATIBLE)
                associated = active
                active.acquireAssociatedMaintenance(::open)
            } else {
                if (!idle()) return NativeProductResult.Failure(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
                RuntimeProductionPlatformOwner.acquireIfIdle(service, RuntimeAuthorityTrigger.MANUAL, 2,
                    onAdmitted = { owner -> synchronized(monitor) { call.standalone = owner } }, setup = ::open)
            }
            val parent = synchronized(monitor) { call.parent }
            if (parent != null) {
                result = if (!live() || synchronized(monitor) { call.cancelled })
                    NativeProductResult.Failure(ProductFailureCode.CANCELLED) else operation(parent)
            }
        } catch (_: Exception) { result = NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED) }
        finally {
            try {
                associated?.retireAssociatedMaintenance()
                call.standalone?.let { check(it.stop(RuntimeStopReason.CANCEL) == RuntimeStartDecision.Idle) }
            } catch (_: Exception) {
                cleanupSucceeded = false
                try { associated?.stop(RuntimeStopReason.CANCEL) } catch (_: Exception) { }
            } finally {
                synchronized(monitor) {
                    result = finishRuntimeMaintenance(result, call.cancelled, cleanupSucceeded)
                    if (pending === call) pending = null
                }
            }
        }
        return result
    }
}

/** Cleanup uncertainty takes precedence over a simultaneous cancellation. */
internal fun <T> finishRuntimeMaintenance(result: NativeProductResult<T>, cancelled: Boolean,
    cleanupSucceeded: Boolean): NativeProductResult<T> {
    if (cleanupSucceeded && !cancelled) return result
    (result as? NativeProductResult.Success)?.value.let { if (it is RuntimeVerifiedUpdate) it.close() }
    return NativeProductResult.Failure(if (cleanupSucceeded) ProductFailureCode.CANCELLED
        else ProductFailureCode.STORAGE_DEGRADED)
}

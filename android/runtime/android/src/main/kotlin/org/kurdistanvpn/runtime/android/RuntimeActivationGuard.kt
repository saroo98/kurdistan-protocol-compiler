// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable

enum class RuntimeCleanupState { CLEANUP_REQUIRED, UNPROVEN, CLEAN }
enum class RuntimeResourceKind { AUTHORITY_DESCRIPTOR, NATIVE_SESSION, SOCKET, TUN, NOTIFICATION, HEALTH_MONITOR }

/** Constructed without acquiring external resources. The guard registers this owner before
 * prepare runs. Every partial acquisition is retained by this object until close; prepare
 * must not transfer ownership elsewhere. No readiness or cleanup Boolean is accepted. */
abstract class RuntimeActivationResource : Closeable {
    private val ownership = Any()
    private var claimant: Any? = null
    private var terminal = false
    private var closing = false
    private var unproven = false
    protected abstract fun acquire()
    protected abstract fun release()
    internal fun claim(owner: Any): Boolean = synchronized(ownership) {
        if (claimant != null || terminal) false else { claimant = owner; true }
    }
    internal fun prepareOwned(owner: Any) {
        synchronized(ownership) { check(claimant === owner && !terminal) }
        acquire()
    }
    internal fun closeIfUnclaimed() {
        val accepted = synchronized(ownership) {
            if (claimant != null || terminal) false else { terminal = true; closing = true; true }
        }
        if (accepted) releaseOnce()
    }
    final override fun close() {
        val accepted = synchronized(ownership) {
            check(!closing && !unproven) { "ACTIVATION_RESOURCE_CLEANUP_UNPROVEN" }
            if (terminal) false else { terminal = true; closing = true; true }
        }
        if (accepted) releaseOnce()
    }
    private fun releaseOnce() {
        var clean = false
        try { release(); clean = true }
        finally { synchronized(ownership) { closing = false; unproven = !clean } }
    }
}

/** Created before acquisition. Ownership is recorded from actual resources, never callback flags. */
class RuntimeActivationGuard internal constructor(private val monitor: Any) : Closeable {
    constructor() : this(Any())
    private class Owner(val kind: RuntimeResourceKind, val resource: Closeable, val next: Owner?) {
        private var result = RuntimeCleanupState.CLEANUP_REQUIRED
        private var closingStarted = false
        private var preparationStarted = false
        private var preparing = false
        private var prepared = false
        private var closeRequested = false
        fun prepare() {
            synchronized(this) {
                check(!preparationStarted && !closingStarted && !closeRequested)
                preparationStarted = true; preparing = true
            }
            try {
                (resource as RuntimeActivationResource).prepareOwned(this)
                synchronized(this) { prepared = true }
            } finally {
                val closeNow = synchronized(this) { preparing = false; closeRequested }
                if (closeNow) closeOnce()
            }
        }
        fun isPrepared() = synchronized(this) { prepared && !preparing && !closeRequested && !closingStarted }
        fun state() = synchronized(this) { result }
        fun closeOnce(): RuntimeCleanupState {
            synchronized(this) {
                closeRequested = true
                if (preparing || closingStarted) return result
                closingStarted = true
            }
            // Mark before invoking close: EINTR, exceptions and reentrancy never retry a raw FD.
            // Do not hold an owner lock across user/platform cleanup callbacks.
            val closed = try { resource.close(); RuntimeCleanupState.CLEAN } catch (_: Throwable) { RuntimeCleanupState.UNPROVEN }
            return synchronized(this) { result = closed; closed }
        }
    }
    // One allocation precedes publication; publishing the head cannot leave two mutable
    // registries inconsistent. Cancellation traverses the immutable chain without a snapshot.
    private var head: Owner? = null
    private var cancelled = false
    private var active = false
    private var acquiring = 0
    private var closing = 0
    private var unproven = false
    private var cleanupInvoked = false

    fun <T : Closeable> own(kind: RuntimeResourceKind, resource: T): T? {
        var late: Owner? = null
        var conflictingRole = false
        try {
            synchronized(monitor) {
                val existing = findOwner(resource)
                if (existing != null) {
                    if (existing.kind != kind) { cancelled = true; active = false; conflictingRole = true }
                    else return if (cancelled) null else resource
                } else {
                    val owner = Owner(kind, resource, head)
                    if (resource is RuntimeActivationResource && !resource.claim(owner)) {
                        conflictingRole = true; cancelled = true; active = false
                    } else {
                        head = owner
                        if (cancelled) { closing++; late = owner }
                    }
                }
            }
        } catch (_: Throwable) {
            // A failed node allocation has not published this incoming owner. Close it once,
            // drain the known chain, and preserve uncertainty even if those closes succeed.
            synchronized(monitor) { cancelled = true; active = false; unproven = true }
            try {
                if (resource is RuntimeActivationResource) resource.closeIfUnclaimed() else resource.close()
            } catch (_: Throwable) { }
            cancel()
            return null
        }
        if (conflictingRole) { cancel(); return null }
        if (late != null) {
            val result = checkNotNull(late).closeOnce()
            synchronized(monitor) { closing--; if (result == RuntimeCleanupState.UNPROVEN) unproven = true }
            return null
        }
        return resource
    }

    fun acquire(acquisition: (RuntimeActivationGuard) -> Unit): Boolean {
        synchronized(monitor) { if (cancelled) return false; acquiring++ }
        var succeeded = false
        try { acquisition(this); succeeded = true } catch (_: Throwable) { cancel() }
        finally { synchronized(monitor) { acquiring-- } }
        return synchronized(monitor) { succeeded && !cancelled && !unproven }
    }

    fun activate(lease: RuntimeRevisionLeaseClient, checks: () -> RuntimeActivationChecks,
        notification: RuntimeActivationResource, healthMonitor: RuntimeActivationResource, publish: () -> Unit): Boolean {
        // Register both unacquired owners before the first fallible preparation step.
        val notificationOwner = own(RuntimeResourceKind.NOTIFICATION, notification)
        val healthOwner = own(RuntimeResourceKind.HEALTH_MONITOR, healthMonitor)
        if (notificationOwner == null || healthOwner == null) { lease.close(); return false }
        val setup = acquire { scope ->
            scope.prepareOwned(notification)
            scope.prepareOwned(healthMonitor)
        }
        if (!setup) { lease.close(); return false }
        val published = synchronized(monitor) {
            if (cancelled || unproven || acquiring != 0 || active ||
                !hasKind(RuntimeResourceKind.NATIVE_SESSION) || !hasKind(RuntimeResourceKind.TUN) ||
                findOwner(notification)?.isPrepared() != true || findOwner(healthMonitor)?.isPrepared() != true) false
            else try {
                if (!lease.authorizePublication(checks())) false
                else { publish(); active = !cancelled && !unproven; active }
            } catch (_: Throwable) { false }
        }
        if (!published) { lease.close(); cancel() }
        return published
    }

    /** Optional display delivery is serialized with invalidation and cannot escape
     * into the activation transaction. Required foreground promotion happens before
     * this barrier with a truthful CONNECTING label, never an early ACTIVE claim. */
    internal fun publishOptionalActiveStatus(deliver: () -> Unit): Boolean = synchronized(monitor) {
        if (!active || cancelled || unproven) false
        else try { deliver(); true } catch (_: Throwable) { false }
    }

    /** Native/TUN setup may require these owners before final publication. The same
     * guard owns them from before acquisition; activate never reacquires a ready owner. */
    internal fun prepareActivationResource(kind: RuntimeResourceKind, resource: RuntimeActivationResource) {
        require(kind == RuntimeResourceKind.NOTIFICATION || kind == RuntimeResourceKind.HEALTH_MONITOR)
        check(own(kind, resource) === resource) { "ACTIVATION_RESOURCE_REJECTED" }
        check(acquire { prepareOwned(resource) }) { "ACTIVATION_RESOURCE_PREPARATION_FAILED" }
    }

    /** Serial cancellation has no foreign callbacks. The caller must still drain owned cleanup. */
    internal fun markCancellation() = synchronized(monitor) { cancelled = true; active = false }

    fun cancel(): RuntimeCleanupState {
        var cursor = synchronized(monitor) {
            cancelled = true; active = false; cleanupInvoked = true; closing++
            head
        }
        var uncertain = false
        try {
            while (cursor != null) {
                val owner = cursor
                try { if (owner.closeOnce() == RuntimeCleanupState.UNPROVEN) uncertain = true }
                catch (_: Throwable) { uncertain = true }
                cursor = owner.next
            }
        } finally { synchronized(monitor) { closing--; unproven = unproven || uncertain } }
        return cleanupState()
    }
    fun cleanupState(): RuntimeCleanupState = synchronized(monitor) { when {
        unproven || hasOwnerState(RuntimeCleanupState.UNPROVEN) -> RuntimeCleanupState.UNPROVEN
        !cancelled || !cleanupInvoked || acquiring != 0 || closing != 0 ||
            hasOwnerState(RuntimeCleanupState.CLEANUP_REQUIRED) -> RuntimeCleanupState.CLEANUP_REQUIRED
        else -> RuntimeCleanupState.CLEAN
    } }
    private fun prepareOwned(resource: RuntimeActivationResource) {
        val owner = synchronized(monitor) { check(!cancelled && !unproven); checkNotNull(findOwner(resource)) }
        if (!owner.isPrepared()) owner.prepare()
    }
    private fun findOwner(resource: Closeable): Owner? {
        var cursor = head
        while (cursor != null) { if (cursor.resource === resource) return cursor; cursor = cursor.next }
        return null
    }
    private fun hasKind(kind: RuntimeResourceKind): Boolean {
        var cursor = head
        while (cursor != null) { if (cursor.kind == kind) return true; cursor = cursor.next }
        return false
    }
    private fun hasOwnerState(state: RuntimeCleanupState): Boolean {
        var cursor = head
        while (cursor != null) { if (cursor.state() == state) return true; cursor = cursor.next }
        return false
    }
    fun isActive(): Boolean = synchronized(monitor) { active && !cancelled && !unproven }
    override fun close() { cancel() }
}

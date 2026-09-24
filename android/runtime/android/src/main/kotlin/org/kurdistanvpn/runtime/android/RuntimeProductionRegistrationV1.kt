// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

/** Private-module signal boundary. IDs are the native owner's pre-reserved identities. */
internal interface RuntimeProductionRevisionSignalsV1 {
    fun fence(owner: Long, signal: Long): Int
    fun invalidate(owner: Long, signal: Long): Int
}

/** Exactly one production and one associated-maintenance subscriber on one authenticated arm. */
internal class RuntimeProductionRegistrationV1(
    private val signals: RuntimeProductionRevisionSignalsV1,
) : AutoCloseable {
    private class Subscriber {
        var owner = 0L
        var signal = 0L
        var used = false
    }
    private val monitor = Any()
    private val production = Subscriber()
    private val maintenance = Subscriber()
    private var terminal = false
    private var handling = false
    private var finished = false
    private var unproven = false

    fun register(kind: Int, owner: Long, signal: Long): Boolean = synchronized(monitor) {
        if (terminal || owner == 0L || signal == 0L) return false
        val selected = when (kind) { 1 -> production; 2 -> maintenance; else -> return false }
        if (selected.used || production.owner == owner || maintenance.owner == owner) return false
        selected.used = true
        selected.owner = owner
        selected.signal = signal
        true
    }

    fun isCurrent(kind: Int, owner: Long, signal: Long): Boolean = synchronized(monitor) {
        val selected = when (kind) { 1 -> production; 2 -> maintenance; else -> return false }
        !terminal && !unproven && owner != 0L && selected.owner == owner && selected.signal == signal
    }

    /** Called only by the exact native registration-close callback after its retirement. */
    fun retire(kind: Int, owner: Long, signal: Long): Boolean = synchronized(monitor) {
        if (handling) { unproven = true; return false }
        val selected = when (kind) { 1 -> production; 2 -> maintenance; else -> return false }
        if (owner == 0L || signal == 0L || selected.owner != owner || selected.signal != signal) return false
        selected.owner = 0
        selected.signal = 0
        true
    }

    fun isRetired(): Boolean = synchronized(monitor) {
        !handling && !unproven && production.owner == 0L && maintenance.owner == 0L
    }

    /** Service owner calls only after complete native-parent retirement, not merely revision close. */
    fun rearmMaintenanceAfterRetirement(): Boolean = synchronized(monitor) {
        if (terminal || handling || unproven || production.owner == 0L ||
            maintenance.owner != 0L || maintenance.signal != 0L) return false
        maintenance.used = false
        true
    }

    fun invalidate(): Boolean {
        synchronized(monitor) {
            if (handling) { unproven = true; return false }
            if (finished) return !unproven
            terminal = true
            handling = true
        }
        // Terminal prevents slot mutation. No monitor covers JNI, either sink, or its output drain.
        var clean = true
        fun attempt(subscriber: Subscriber, fence: Boolean) {
            if (subscriber.owner == 0L) return
            try {
                val result = if (fence) signals.fence(subscriber.owner, subscriber.signal)
                    else signals.invalidate(subscriber.owner, subscriber.signal)
                if (result != 0) clean = false
            } catch (_: Throwable) { clean = false }
        }
        attempt(production, true)
        attempt(maintenance, true)
        attempt(production, false)
        attempt(maintenance, false)
        return synchronized(monitor) {
            if (!clean) unproven = true
            handling = false
            finished = true
            !unproven
        }
    }

    /** Publication's caller must unwind before joined invalidation can run. */
    fun fencePendingPublication(): Boolean {
        synchronized(monitor) {
            if (handling || unproven || finished) return false
            terminal = true
            handling = true
        }
        var clean = true
        for (subscriber in listOf(production, maintenance)) if (subscriber.owner != 0L) {
            try { if (signals.fence(subscriber.owner, subscriber.signal) != 0) clean = false }
            catch (_: Throwable) { clean = false }
        }
        return synchronized(monitor) {
            if (!clean) unproven = true
            handling = false
            !unproven
        }
    }

    override fun close() {
        synchronized(monitor) {
            if (handling) {
                unproven = true
                throw RuntimeAuthorityCleanupUnprovenException()
            }
        }
        if (!invalidate()) throw RuntimeAuthorityCleanupUnprovenException()
    }
}

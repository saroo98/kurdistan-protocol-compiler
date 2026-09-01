// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

/**
 * Default-process admission shared by the broker and authority provider. This is
 * cooperative serialization, not a security boundary against same-UID code.
 * A resource owner must be an idempotent cleanup guard, never a raw descriptor.
 * Only that guard may retry its unfinished children after a failed close.
 */
internal class ActiveSessionMutationPolicy(private val acquireQuiescence: (() -> AutoCloseable?)? = null,
    private val monotonicMillis: () -> Long) {
    private val monitor = Any()
    private val owners = linkedMapOf<OwnedSession, Entry>()
    private val usedIdentities = hashSetOf<String>()
    private val cleanupFailures = mutableListOf<CleanupFailure>()
    private var draining = false
    private var writer: WriteLease? = null
    private var exhausted = false

    internal enum class CleanupFailure { OWNER_CLEANUP_UNPROVEN }

    internal interface OwnedSession : AutoCloseable
    internal interface FinalLease : AutoCloseable { fun validate(currentRevision: Long): Boolean }
    internal interface MutationLease : AutoCloseable { fun requireCurrent() }
    internal interface MutationReservation : MutationLease { fun retirePriorOwners() }

    private class Entry(val resourceOwner: AutoCloseable, val revision: Long) {
        var retired = false
        var clean = false
        var closing = false
        var finalLeaseIssued = false
        var finalLease: Lease? = null

        fun retire() {
            retired = true
            finalLease?.terminal = true
        }
    }

    private inner class SessionHandle : OwnedSession {
        override fun close() {
            val entry = synchronized(monitor) {
                owners[this]?.also { it.retire() }
            } ?: return
            cleanOwned(entry)
        }
    }

    private inner class Lease(
        private val session: OwnedSession,
        private val entry: Entry,
        private val revision: Long,
        private val deadline: Long,
    ) : FinalLease {
        var terminal = false

        override fun validate(currentRevision: Long): Boolean = synchronized(monitor) {
            val now = nowOrInvalid()
            val valid = !terminal && !exhausted && !draining && writer == null &&
                owners[session] === entry && !entry.retired && !entry.clean &&
                currentRevision == revision && entry.revision == revision &&
                now >= 0 && now < deadline
            if (!valid) terminal = true
            valid
        }

        override fun close() { synchronized(monitor) { terminal = true } }

        /** The final activation barrier excludes a writer until cancellation or deadline. */
        fun blocksMutation(now: Long): Boolean {
            if (terminal) return false
            if (now >= deadline) {
                terminal = true
                return false
            }
            return true
        }
    }

    private enum class WriteState { RESERVED, RETIRING, RETIRED, CLOSED }

    private inner class WriteLease(private val quiescence: AutoCloseable?) : MutationReservation {
        var state = WriteState.RESERVED

        override fun retirePriorOwners() {
            val pending = synchronized(monitor) {
                check(writer === this && state == WriteState.RESERVED && !draining && !exhausted)
                state = WriteState.RETIRING
                draining = true
                owners.values.forEach { it.retire() }
                owners.values.toList()
            }
            // Never hold the policy monitor across Binder/native owner cleanup.
            try { pending.forEach(::cleanOwned) }
            finally {
                synchronized(monitor) {
                    draining = false
                    if (state == WriteState.CLOSED) {
                        if (writer === this) writer = null
                    } else {
                        state = if (!exhausted && owners.values.all { it.clean }) WriteState.RETIRED
                            else WriteState.RESERVED
                    }
                }
            }
            requireCurrent()
        }

        override fun requireCurrent() {
            synchronized(monitor) {
                check(writer === this && state == WriteState.RETIRED && !draining && !exhausted &&
                    owners.values.all { it.clean }) { "SESSION_CLEANUP_UNPROVEN" }
            }
        }

        override fun close() {
            val release = synchronized(monitor) {
                if (state == WriteState.CLOSED) return
                state = WriteState.CLOSED
                quiescence
            }
            var clean = true
            try { release?.close() } catch (_: Throwable) { clean = false }
            synchronized(monitor) {
                // A reentrant/concurrent close must not release admission while cleanup runs;
                // failed remote quiescence release is terminal, never a raw Binder retry.
                if (!clean) exhausted = true
                if (clean && !draining && writer === this) writer = null
            }
            if (!clean) throw IllegalStateException("QUIESCENCE_RELEASE_UNPROVEN")
        }
    }

    /** Takes ownership even if admission is refused. Failed cleanup remains owned. */
    fun register(epoch: String, generation: Long, revision: Long, owner: AutoCloseable): OwnedSession? {
        val handle = SessionHandle()
        val entry: Entry
        val admitted: Boolean
        synchronized(monitor) {
            entry = Entry(owner, revision)
            owners[handle] = entry
            val valid = epoch.length == 32 && epoch.all { it in '0'..'9' || it in 'a'..'f' } &&
                epoch.any { it != '0' } && generation > 0 && revision > 0 && revision % 2L == 0L
            val identity = "$epoch:$generation"
            admitted = valid && !exhausted && !draining && writer == null &&
                owners.values.none { it !== entry && it.retired && !it.clean } &&
                usedIdentities.size < MAX_IDENTITIES && usedIdentities.add(identity)
            if (!admitted) entry.retire()
        }
        if (!admitted) { cleanOwned(entry); return null }
        return handle
    }

    fun acquireFinalLease(session: OwnedSession, revision: Long, deadline: Long): FinalLease? =
        synchronized(monitor) {
            val entry = owners[session] ?: return null
            val now = nowOrInvalid()
            if (exhausted || draining || writer != null || entry.retired ||
                entry.clean || entry.finalLeaseIssued || revision != entry.revision ||
                now < 0 || deadline <= now || deadline - now > MAX_LEASE_MILLIS) return null
            entry.finalLeaseIssued = true
            Lease(session, entry, revision, deadline).also { entry.finalLease = it }
        }

    /**
     * Excludes registration and final leases without retiring or closing an existing owner.
     * The broker invokes retirement only from the journal's verified DIRTY/intent callback.
     * Reservation itself is not permission to change product state: requireCurrent fails
     * until the policy has independently retired and cleaned every owned session.
     */
    fun reserveMutation(): MutationReservation? {
        // Do not issue another remote admission request after an owned quiescence release is
        // uncertain.  A late Binder operation may still hold the VPN-process lease.
        if (synchronized(monitor) { exhausted }) return null
        val quiescence = try { acquireQuiescence?.invoke() }
        catch (_: Throwable) {
            synchronized(monitor) { exhausted = true }
            return null
        }
        if (acquireQuiescence != null && quiescence == null) return null
        val admitted = synchronized(monitor) {
            val now = nowOrInvalid()
            if (now < 0 || draining || writer != null || exhausted ||
                owners.values.any { it.finalLease?.blocksMutation(now) == true }) null
            else WriteLease(quiescence).also { writer = it }
        }
        if (admitted != null) return admitted
        if (quiescence != null) try { quiescence.close() } catch (_: Throwable) {
            synchronized(monitor) { exhausted = true }
        }
        return null
    }

    /** Low-level retirement helper; the durable mutation broker uses reserveMutation instead. */
    fun beginMutation(): MutationLease? {
        val reservation = reserveMutation() ?: return null
        return try {
            reservation.retirePriorOwners()
            reservation
        } catch (_: IllegalStateException) {
            reservation.close()
            null
        }
    }

    fun failures(): List<CleanupFailure> = synchronized(monitor) { cleanupFailures.toList() }

    private fun cleanOwned(entry: Entry) {
        synchronized(monitor) {
            if (entry.clean || entry.closing) return
            entry.closing = true
        }
        var succeeded = false
        try { entry.resourceOwner.close(); succeeded = true } catch (_: Throwable) {
            // Never retain an exception message, which can contain private state.
            synchronized(monitor) {
                if (cleanupFailures.size < MAX_FAILURES) cleanupFailures += CleanupFailure.OWNER_CLEANUP_UNPROVEN
                else exhausted = true
            }
        } finally {
            synchronized(monitor) {
                entry.clean = succeeded; entry.closing = false
                if (succeeded) owners.entries.removeAll { it.value === entry }
            }
        }
    }

    private fun nowOrInvalid(): Long = try { monotonicMillis() } catch (_: Throwable) { -1 }

    private companion object {
        const val MAX_IDENTITIES = 4096
        const val MAX_FAILURES = 4096
        const val MAX_LEASE_MILLIS = 2000L
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.io.Closeable
import java.io.OutputStream
import java.util.UUID
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.*

/** The Application's default-process owner supplies this facade. No stores are opened here. */
interface RuntimeAuthorityReissueBackend {
    /** Must perform read-only checks, including fresh external expiry/revocation/key/consent checks.
     * Locked state must be determined before any credential-protected lookup. */
    fun observe(start: RuntimeReissueStart): RuntimeAuthorityProviderState?
    /** Internally owns and wipes every partial acquisition if this method throws. */
    fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial?
    /** Acquisition and active registration are serialized by the broker's revision owner. */
    fun acquireRevisionLease(request: RuntimeAuthorityRequest): RuntimeProviderRevisionLease?
}
data class RuntimeAuthorityProviderState(val unlocked: Boolean, val vpnPrepared: Boolean, val automaticEnabled: Boolean,
    val revision: Long, val signedRetryBudget: Int)
interface RuntimeReissueMaterial : Closeable {
    val revision: Long
    val signedRetryBudget: Int
    val payloadLength: Int
    fun writeTo(output: OutputStream)
}
interface RuntimeProviderRevisionLease : Closeable {
    val revision: Long
    fun isCurrent(): Boolean
    /** Installed before PRE_ACTIVE returns, while the revision lease remains held. */
    fun registerActive(onInvalidated: () -> Unit): Closeable
}

/** One instance belongs to the immutable Application composition root, not Service lifetime.
 * Binder validates OS caller metadata; the same-UID split is not a security sandbox. */
class RuntimeAuthorityReissueIpcAdapter internal constructor(private val uid: Long, val providerEpoch: String,
    private val backend: RuntimeAuthorityReissueBackend, private val now: () -> Long,
    private val ids: () -> String = { UUID.randomUUID().toString().replace("-", "") }) {
    private enum class Cleanup { CLEAN, PENDING, UNPROVEN }
    private class Owned(val value: Closeable) {
        private var started = false
        private var done = false
        private var good = false
        fun closeOnce(): Cleanup {
            synchronized(this) { if (started) return if (!done) Cleanup.PENDING else if (good) Cleanup.CLEAN else Cleanup.UNPROVEN; started = true }
            val result = try { value.close(); true } catch (_: Throwable) { false }
            return synchronized(this) { good = result; done = true; if (result) Cleanup.CLEAN else Cleanup.UNPROVEN }
        }
    }
    private class Peer(val epoch: String, val pid: Int, var token: Any, var invalidated: () -> Unit,
        val admission: RuntimeAuthorityReissueAdmission) {
        var retired = false
        var highWater = 0L
        val usedRequests = mutableSetOf<String>()
    }
    private enum class Stage { PREPARING, FULL_AUTHORITY, PRE_TUN, PRE_ACTIVE, WAIT_COMPLETE, ACTIVE, CANCELLED }
    private class Arm(val peer: Peer, val start: RuntimeReissueStart) {
        var stage = Stage.PREPARING
        var busy = true
        var offer: RuntimeAuthorityOffer? = null
        var material: RuntimeReissueMaterial? = null
        var materialOwner: Owned? = null
        var lease: RuntimeProviderRevisionLease? = null
        var leaseOwner: Owned? = null
        var registrationOwner: Owned? = null
        var leaseReleased = false
        val owned = mutableListOf<Owned>()
        var notified = false
    }
    private val monitor = Any()
    private val peers = mutableMapOf<String, Peer>()
    private var bound: Peer? = null
    private var arm: Arm? = null
    private var unproven = false
    private var completedFullAuthorities = 0
    init { require(uid in 0..0xffff_fffeL && RuntimeAuthorityLimits.validId(providerEpoch)) }

    fun bind(consumerEpoch: String, callerUid: Long, callerPid: Int, token: Any, onInvalidated: () -> Unit): Boolean = synchronized(monitor) {
        if (unproven || callerUid != uid || callerPid <= 0 || !RuntimeAuthorityLimits.validId(consumerEpoch) || consumerEpoch == providerEpoch) return false
        if (arm != null && bound?.token !== token) return false
        val existing = peers[consumerEpoch]
        if (existing != null && (existing.retired || existing.pid != callerPid)) return false
        val peer = existing ?: run {
            if (peers.size >= 256) return false
            Peer(consumerEpoch, callerPid, token, onInvalidated,
                RuntimeAuthorityReissueAdmission(uid, consumerEpoch, providerEpoch)).also { peers[consumerEpoch] = it }
        }
        peer.token = token; peer.invalidated = onInvalidated; bound = peer
        true
    }

    fun offer(start: RuntimeReissueStart, callerUid: Long, callerPid: Int, token: Any): RuntimeAuthorityOffer? {
        val active = synchronized(monitor) {
            val peer = peer(callerUid, callerPid, token) ?: return null
            if (arm != null || !start.isLiveAt(now()) || start.consumerEpoch != peer.epoch ||
                start.generation <= peer.highWater || start.requestId in peer.usedRequests || peer.usedRequests.size >= 4096) return null
            peer.highWater = start.generation; peer.usedRequests += start.requestId
            Arm(peer, start).also { arm = it }
        }
        var material: RuntimeReissueMaterial? = null
        var adopted = false
        return try {
            val state = backend.observe(start) ?: error("state unavailable")
            require(valid(state, start))
            material = backend.prepare(start) ?: error("authority unavailable")
            val candidate = RuntimeAuthorityOffer(start, providerEpoch, material.revision, material.signedRetryBudget,
                material.payloadLength, ids(), ids())
            require(candidate.revision == state.revision && candidate.signedRetryBudget == state.signedRetryBudget)
            synchronized(monitor) {
                check(live(active))
                val owner = Owned(material)
                active.material = material; active.materialOwner = owner; active.owned += owner; adopted = true
                active.offer = candidate; active.stage = Stage.FULL_AUTHORITY; active.busy = false
                candidate
            }
        } catch (failure: Throwable) {
            if (failure is RuntimeAuthorityCleanupUnprovenException) poison()
            cancelArm(active, false)
            null
        }
        finally {
            if (!adopted && material != null && Owned(material).closeOnce() == Cleanup.UNPROVEN) poison()
            if (!adopted) { synchronized(monitor) { active.busy = false }; cancelArm(active, false) }
        }
    }

    /** Synchronous worker operation. Both transferred pipe owners are adopted even on rejection. */
    fun respond(requestId: String, purpose: RuntimeAuthorityPurpose, descriptorId: String, callerUid: Long, callerPid: Int, token: Any,
        capability: RuntimeReissueReadPipe, output: RuntimeReissueWritePipe): Boolean {
        var outputSucceeded = false
        val capOwner = Owned(capability)
        val frameOwner = Owned(Closeable { if (outputSucceeded) output.close() else output.abort() })
        var active: Arm? = null
        var key: ByteArray? = null; var payload: ByteArray? = null; var frame: ByteArray? = null
        var success = false
        try {
            active = synchronized(monitor) {
                val current = arm ?: error("unarmed")
                check(current.start.requestId == requestId && peer(callerUid, callerPid, token) === current.peer && live(current) && !current.busy)
                current.busy = true; current.owned += capOwner; current.owned += frameOwner
                current
            }
            check(active.stage.name == purpose.name)
            val offer = checkNotNull(active.offer)
            val inputIdentity = capability.identity.also { it.requirePipe(uid, 0) }
            val outputIdentity = output.identity.also { it.requirePipe(uid, 1) }
            require(inputIdentity.device != outputIdentity.device || inputIdentity.inode != outputIdentity.inode)
            val size = RuntimeAuthorityFrameCodec.encodedLength(if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) offer.payloadLength else 0)
            val request = offer.request(purpose, outputIdentity.descriptor(descriptorId, size))
            val state = backend.observe(active.start) ?: error("state unavailable")
            require(valid(state, active.start) && state.revision == offer.revision && state.signedRetryBudget == offer.signedRetryBudget)
            val environment = RuntimeAdmissionEnvironment(uid, state.unlocked, state.vpnPrepared, state.automaticEnabled,
                state.revision, now(), state.signedRetryBudget, offer.capabilityChannelId, offer.frameChannelId)
            val admission = if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) active.peer.admission.admit(request, environment)
                else active.peer.admission.checkLease(request, environment)
            check(admission == RuntimeReissueAdmission.Allowed)
            key = RuntimeReissuePipeIo.readExact(capability, 32) { synchronized(monitor) { live(active) } }
            check(capOwner.closeOnce() == Cleanup.CLEAN)
            if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) {
                val collector = BoundedPayload(offer.payloadLength)
                try { checkNotNull(active.material).writeTo(collector); payload = collector.takeExact() }
                finally { collector.close() }
                check(checkNotNull(active.materialOwner).closeOnce() == Cleanup.CLEAN)
            } else payload = byteArrayOf()
            if (purpose == RuntimeAuthorityPurpose.PRE_TUN) {
                val lease = backend.acquireRevisionLease(request) ?: error("lease unavailable")
                val leaseOwner = Owned(lease)
                if (!adopt(active, leaseOwner)) error("cancelled lease")
                active.lease = lease; active.leaseOwner = leaseOwner
                require(lease.revision == offer.revision && lease.isCurrent())
            }
            if (purpose == RuntimeAuthorityPurpose.PRE_ACTIVE) {
                val lease = checkNotNull(active.lease)
                require(lease.revision == offer.revision && lease.isCurrent())
                val registration = Owned(lease.registerActive { cancelArm(active, true, propagateUnproven = true) })
                check(adopt(active, registration))
                active.registrationOwner = registration
            }
            check(synchronized(monitor) { live(active) })
            RuntimeAuthorityFrameCodec.sealer(key, request).use { frame = it.seal(payload) ?: error("frame rejected") }
            key = null
            RuntimeReissuePipeIo.writeExact(output, checkNotNull(frame)) { synchronized(monitor) { live(active) } }
            synchronized(monitor) {
                check(live(active)); active.stage = when (purpose) {
                    RuntimeAuthorityPurpose.FULL_AUTHORITY -> Stage.PRE_TUN
                    RuntimeAuthorityPurpose.PRE_TUN -> Stage.PRE_ACTIVE
                    RuntimeAuthorityPurpose.PRE_ACTIVE -> Stage.WAIT_COMPLETE
                }
                if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY && completedFullAuthorities < MAX_COMPLETED_FULL_AUTHORITIES)
                    completedFullAuthorities++
                outputSucceeded = true
            }
            check(frameOwner.closeOnce() == Cleanup.CLEAN)
            synchronized(monitor) { check(live(active)); active.busy = false }
            success = true
            return true
        } catch (_: Throwable) { active?.let { cancelArm(it, false) }; return false }
        finally {
            key?.fill(0); payload?.fill(0); frame?.fill(0)
            val capClean = capOwner.closeOnce(); val frameClean = frameOwner.closeOnce()
            if (capClean == Cleanup.UNPROVEN || frameClean == Cleanup.UNPROVEN) { poison(); active?.let { cancelArm(it, true) } }
            if (!success) active?.let { synchronized(monitor) { it.busy = false }; cancelArm(it, false) }
        }
    }

    fun responseReady(requestId: String, purpose: RuntimeAuthorityPurpose, callerUid: Long, callerPid: Int, token: Any): Boolean = synchronized(monitor) {
        val a = arm ?: return false
        if (peer(callerUid, callerPid, token) !== a.peer || a.start.requestId != requestId || !live(a) || a.busy) return false
        a.stage == when (purpose) { RuntimeAuthorityPurpose.FULL_AUTHORITY -> Stage.PRE_TUN
            RuntimeAuthorityPurpose.PRE_TUN -> Stage.PRE_ACTIVE; RuntimeAuthorityPurpose.PRE_ACTIVE -> Stage.WAIT_COMPLETE }
    }
    /** 0 rejected, 1 completed and clean, 2 admitted response still finishing. Never a PASS claim. */
    fun responseStatus(requestId: String, purpose: RuntimeAuthorityPurpose, callerUid: Long, callerPid: Int, token: Any): Int = synchronized(monitor) {
        val a = arm ?: return 0
        if (peer(callerUid, callerPid, token) !== a.peer || a.start.requestId != requestId || !live(a)) return 0
        val completed = when (purpose) { RuntimeAuthorityPurpose.FULL_AUTHORITY -> Stage.PRE_TUN
            RuntimeAuthorityPurpose.PRE_TUN -> Stage.PRE_ACTIVE; RuntimeAuthorityPurpose.PRE_ACTIVE -> Stage.WAIT_COMPLETE }
        when { a.busy && (a.stage.name == purpose.name || a.stage == completed) -> 2
            !a.busy && a.stage == completed -> 1
            else -> 0 }
    }
    fun expectedDeadline(requestId: String, callerUid: Long, callerPid: Int, token: Any): Long? = synchronized(monitor) {
        arm?.takeIf { it.start.requestId == requestId && peer(callerUid, callerPid, token) === it.peer && live(it) && !it.busy }
            ?.start?.deadlineElapsedMillis
    }

    fun complete(requestId: String, callerUid: Long, callerPid: Int, token: Any): Boolean {
        val a = synchronized(monitor) {
            val current = arm ?: return false
            if (peer(callerUid, callerPid, token) !== current.peer || current.start.requestId != requestId ||
                !live(current) || current.busy || current.stage != Stage.WAIT_COMPLETE) return false
            current.busy = true; current
        }
        val held = try {
            val lease = checkNotNull(a.lease)
            checkNotNull(a.leaseOwner)
            checkNotNull(a.registrationOwner)
            lease.isCurrent() && !a.leaseReleased
        } catch (_: Throwable) { false }
        if (!held) { synchronized(monitor) { a.busy = false }; cancelArm(a, true); return false }
        val completed = synchronized(monitor) {
            a.busy = false
            if (live(a)) { a.stage = Stage.ACTIVE; true } else false
        }
        if (!completed) cancelArm(a, false)
        return completed
    }

    /** Post-publication cleanup is retry-safe: a successful release stays acknowledged. */
    fun releaseLease(requestId: String, callerUid: Long, callerPid: Int, token: Any): Boolean {
        val a = synchronized(monitor) {
            val current = arm ?: return false
            if (peer(callerUid, callerPid, token) !== current.peer || current.start.requestId != requestId ||
                current.busy || current.stage != Stage.ACTIVE) return false
            if (current.leaseReleased) return true
            current.busy = true; current
        }
        val clean = try {
            checkNotNull(a.lease).isCurrent() && checkNotNull(a.leaseOwner).closeOnce() == Cleanup.CLEAN
        } catch (_: Throwable) { false }
        if (!clean) { synchronized(monitor) { a.busy = false }; cancelArm(a, true); return false }
        return synchronized(monitor) {
            a.busy = false
            if (live(a) && a.stage == Stage.ACTIVE) {
                a.leaseReleased = true
                true
            } else false
        }.also { if (!it) cancelArm(a, false) }
    }

    fun cancel(requestId: String, callerUid: Long, callerPid: Int, token: Any) {
        val a = synchronized(monitor) { arm?.takeIf { peer(callerUid, callerPid, token) === it.peer && it.start.requestId == requestId } }
        a?.let { cancelArm(it, false) }
    }
    fun cancellationStatus(requestId: String, callerUid: Long, callerPid: Int, token: Any): Int = synchronized(monitor) {
        val p = peer(callerUid, callerPid, token) ?: return 0
        if (requestId !in p.usedRequests) return 0
        val a = arm
        if (a == null || a.start.requestId != requestId) 1 else if (a.stage == Stage.CANCELLED) 2 else 0
    }
    /** A negative admission also consumes an as-yet-undelivered start. This is live-process
     * replay state, never persistent authority or a historical tombstone. */
    fun cancelStart(start: RuntimeReissueStart, callerUid: Long, callerPid: Int, token: Any): Int {
        synchronized(monitor) {
            val p = peer(callerUid, callerPid, token) ?: return 0
            if (start.consumerEpoch != p.epoch) return 0
            if (start.requestId !in p.usedRequests) {
                if (start.generation <= p.highWater || p.usedRequests.size >= 4096) return 0
                p.highWater = start.generation; p.usedRequests += start.requestId
            }
            arm?.takeIf { it.start.requestId == start.requestId }?.let { if (it.start != start) return 0 }
        }
        cancel(start.requestId, callerUid, callerPid, token)
        return cancellationStatus(start.requestId, callerUid, callerPid, token)
    }
    fun peerDied(token: Any) {
        val a = synchronized(monitor) {
            val p = bound?.takeIf { it.token === token } ?: return
            p.retired = true; p.admission.close(); arm?.takeIf { it.peer === p }
        }
        a?.let { cancelArm(it, true) }
    }
    /** Service recreation is not process death. Retain process-epoch replay admission. */
    fun connectionClosed(token: Any) {
        val a = synchronized(monitor) { arm?.takeIf { it.peer.token === token } }
        a?.let { cancelArm(it, true) }
    }
    fun expire() {
        val a = synchronized(monitor) {
            arm?.takeIf { !it.busy && (it.stage != Stage.ACTIVE && !it.start.isLiveAt(now()) ||
                it.stage == Stage.ACTIVE && !it.leaseReleased) }
        } ?: return
        val expired = if (a.stage == Stage.ACTIVE) {
            try { !checkNotNull(a.lease).isCurrent() } catch (_: Throwable) { true }
        } else true
        if (expired) cancelArm(a, true)
    }
    fun cleanupUnproven() = synchronized(monitor) { unproven }
    /** Bounded process-lifetime observability for the installed retry harness, never authority. */
    fun completedFullAuthorityCount(): Int = synchronized(monitor) { completedFullAuthorities }
    fun transportCleanupFailed() {
        val a = synchronized(monitor) { unproven = true; arm }
        a?.let { cancelArm(it, true) }
    }
    private fun peer(callerUid: Long, callerPid: Int, token: Any): Peer? =
        bound?.takeIf { !unproven && !it.retired && callerUid == uid && callerPid == it.pid && it.token === token }
    private fun live(a: Arm) = !unproven && arm === a && !a.peer.retired && a.stage != Stage.CANCELLED &&
        (a.stage == Stage.ACTIVE || a.start.isLiveAt(now()))
    private fun valid(s: RuntimeAuthorityProviderState, start: RuntimeReissueStart) =
        s.unlocked && s.vpnPrepared && RuntimeAuthorityLimits.validRevision(s.revision) &&
        s.signedRetryBudget in 0..RuntimeAuthorityLimits.MAX_RETRIES && start.retryAttempt <= s.signedRetryBudget &&
        (start.trigger != RuntimeAuthorityTrigger.AUTOMATIC || s.automaticEnabled) && start.isLiveAt(now())
    private fun adopt(a: Arm, owner: Owned): Boolean {
        synchronized(monitor) { if (live(a)) { a.owned += owner; return true } }
        if (owner.closeOnce() == Cleanup.UNPROVEN) poison()
        return false
    }
    private fun poison() { synchronized(monitor) { unproven = true } }
    private fun cancelArm(a: Arm, notify: Boolean, propagateUnproven: Boolean = false) {
        val resources: List<Owned>
        val callback: (() -> Unit)?
        synchronized(monitor) {
            a.stage = Stage.CANCELLED; a.peer.admission.cancel(a.start.requestId)
            resources = a.owned.asReversed().toList()
            callback = if (notify && !a.notified) { a.notified = true; a.peer.invalidated } else null
        }
        var allClean = true
        resources.forEach { when (it.closeOnce()) {
            Cleanup.UNPROVEN -> { poison(); allClean = false }
            Cleanup.PENDING -> allClean = false
            Cleanup.CLEAN -> Unit
        } }
        synchronized(monitor) { if (arm === a && !a.busy && allClean) arm = null }
        val callbackClean = try {
            callback?.invoke()
            true
        } catch (_: Throwable) {
            poison()
            false
        }
        // RuntimeRegistrationOwner marks the shared revision clean only when its callback
        // returns. Preserve this categorical failure through that callback: otherwise a failed
        // peer invalidation or re-entrant registration close would permit a broker mutation.
        if (!allClean || !callbackClean) {
            poison()
            if (propagateUnproven) throw RuntimeAuthorityCleanupUnprovenException()
        }
    }
    private class BoundedPayload(private val expected: Int) : OutputStream() {
        private var bytes: ByteArray? = ByteArray(expected)
        private var offset = 0
        override fun write(value: Int) { check(offset < expected); checkNotNull(bytes)[offset++] = value.toByte() }
        override fun write(source: ByteArray, at: Int, count: Int) {
            val snapshot = source.copyOf()
            try {
                require(at >= 0 && count >= 0 && at <= snapshot.size - count && count <= expected - offset)
                snapshot.copyInto(checkNotNull(bytes), offset, at, at + count); offset += count
            } finally { snapshot.fill(0) }
        }
        fun takeExact(): ByteArray { check(offset == expected); return checkNotNull(bytes).also { bytes = null } }
        override fun close() { bytes?.fill(0); bytes = null }
    }

    private companion object { const val MAX_COMPLETED_FULL_AUTHORITIES = 4096 }
}

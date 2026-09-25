// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.io.Closeable
import java.io.OutputStream
import java.util.UUID
import org.kurdistanvpn.runtime.api.*
import org.kurdistanvpn.runtime.android.*

/** Peer fenced publication, but its native caller has not yet returned and retired. */
internal class RuntimeAuthorityPeerCleanupPendingException : RuntimeException()

/** The Application's default-process owner supplies this facade. No stores are opened here. */
interface RuntimeAuthorityReissueBackend {
    /** Must perform read-only checks, including fresh external expiry/revocation/key/consent checks.
     * Locked state must be determined before any credential-protected lookup. */
    fun observe(start: RuntimeReissueStart): RuntimeAuthorityProviderState?
    /** Call-local fixed rejection scalars, never authorization or payload. */
    fun observe(start: RuntimeReissueStart, rejection: LongArray): RuntimeAuthorityProviderState? = observe(start)
    /** Internally owns and wipes every partial acquisition if this method throws. */
    fun prepare(start: RuntimeReissueStart): RuntimeReissueMaterial?
    /** Acquisition and active registration are serialized by the broker's revision owner. */
    fun acquireRevisionLease(request: RuntimeAuthorityRequest): RuntimeProviderRevisionLease?
}
data class RuntimeAuthorityProviderState(val unlocked: Boolean, val vpnPrepared: Boolean, val automaticEnabled: Boolean,
    val revision: Long, val signedRetryBudget: Int)
interface RuntimeReissueMaterial : Closeable {
    val presentation: RuntimeProfilePresentation? get() = null
    val revision: Long
    val signedRetryBudget: Int
    val payloadLength: Int
    fun writeTo(output: OutputStream)
}
interface RuntimeProviderRevisionLease : Closeable {
    val revision: Long
    /** Exact immutable deadline supplied to the protected lease, never a receipt-time estimate. */
    val publicationDeadlineElapsedMillis: Long? get() = null
    fun isCurrent(): Boolean
    /** Only immediately after this response's fresh backend observation and admission. */
    fun isCurrentAfterFreshObservation(): Boolean = isCurrent()
    /** Installed before PRE_ACTIVE returns, while the revision lease remains held. */
    fun registerActive(onInvalidated: () -> Unit): Closeable = registerActive(onInvalidated) { }
    /** Local bounded completion publication only, never IPC, cleanup, or follow-up work. */
    fun registerActive(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable
    /** Same PRE_ACTIVE response's fresh observation/admission; COMPLETE still revalidates before publication. */
    fun registerActiveAfterFreshObservation(onInvalidated: () -> Unit, onRetired: (Boolean) -> Unit): Closeable =
        registerActive(onInvalidated, onRetired)
}

interface RuntimeProviderRegisteredRevisionLease : RuntimeProviderRevisionLease {
    fun isRegisteredCurrent(observationDeadlineElapsedMillis: Long): Boolean
}

/** One instance belongs to the immutable Application composition root, not Service lifetime.
 * Binder validates OS caller metadata; the same-UID split is not a security sandbox. */
class RuntimeAuthorityReissueIpcAdapter internal constructor(private val uid: Long, val providerEpoch: String,
    private val backend: RuntimeAuthorityReissueBackend, private val now: () -> Long,
    private val productionBackend: RuntimeAuthorityReissueBackend? = null,
    private val ids: () -> String = { UUID.randomUUID().toString().replace("-", "") }) {
    private enum class Cleanup { CLEAN, PENDING, UNPROVEN }
    private class Owned(val value: Closeable) {
        private var started = false
        private var done = false
        private var good = false
        fun isClean(): Boolean = synchronized(this) { done && good }
        fun closeOnce(): Cleanup {
            synchronized(this) { if (started) return if (!done) Cleanup.PENDING else if (good) Cleanup.CLEAN else Cleanup.UNPROVEN; started = true }
            val result = try { value.close(); true } catch (_: Throwable) { false }
            return synchronized(this) { good = result; done = true; if (result) Cleanup.CLEAN else Cleanup.UNPROVEN }
        }
    }
    private class Peer(val epoch: String, val pid: Int, var token: Any, var invalidated: () -> Unit, val protocol: Int,
        val admission: RuntimeAuthorityReissueAdmission) {
        var retired = false
        var highWater = 0L
        val usedRequests = mutableSetOf<String>()
    }
    private enum class Stage { PREPARING, FULL_AUTHORITY, PRE_TUN, PRE_ACTIVE, WAIT_COMPLETE, ACTIVE, CANCELLED }
    private enum class Completion { OPEN, RUNNING, PENDING, CLEAN, UNPROVEN }
    private class Arm(val peer: Peer, val start: RuntimeReissueStart) {
        val registeredDiagnostic = LongArray(3)
        val publicationDiagnostic = LongArray(16) { -1 }
        var stage = Stage.PREPARING
        var busy = true
        var offer: RuntimeAuthorityOffer? = null
        var material: RuntimeReissueMaterial? = null
        var materialOwner: Owned? = null
        var lease: RuntimeProviderRevisionLease? = null
        var leaseReturnedAt = -1L
        var leaseOwner: Owned? = null
        var registrationOwner: Owned? = null
        var registrationAcquiring = false
        var registrationRetirement = Completion.OPEN
        var leaseReleased = false
        val owned = mutableListOf<Owned>()
        var notification = Completion.OPEN
    }
    private val monitor = Any()
    private val peers = mutableMapOf<String, Peer>()
    private var bound: Peer? = null
    private var arm: Arm? = null
    private var unproven = false
    private var completedFullAuthorities = 0
    private var responseDiagnostic = LongArray(7) { -1 }
    private var observationDiagnostic = LongArray(3) { -1 }
    private var registeredDiagnostic = LongArray(3)
    private var publicationDiagnostic: LongArray? = null
    init { require(uid in 0..0xffff_fffeL && RuntimeAuthorityLimits.validId(providerEpoch)) }

    fun bind(consumerEpoch: String, callerUid: Long, callerPid: Int, token: Any, onInvalidated: () -> Unit): Boolean =
        bindProtocol(consumerEpoch, callerUid, callerPid, token, 2, onInvalidated)

    fun bindProduction(consumerEpoch: String, callerUid: Long, callerPid: Int, token: Any, onInvalidated: () -> Unit): Boolean =
        bindProtocol(consumerEpoch, callerUid, callerPid, token, 3, onInvalidated)

    fun acceptsProtocol(callerUid: Long, callerPid: Int, token: Any, protocol: Int): Boolean = synchronized(monitor) {
        peer(callerUid, callerPid, token)?.protocol == protocol
    }

    private fun bindProtocol(consumerEpoch: String, callerUid: Long, callerPid: Int, token: Any,
        protocol: Int, onInvalidated: () -> Unit): Boolean = synchronized(monitor) {
        if (unproven || callerUid != uid || callerPid <= 0 || !RuntimeAuthorityLimits.validId(consumerEpoch) || consumerEpoch == providerEpoch) return false
        if (protocol == 3 && productionBackend == null) return false
        if (peers.values.any { it.token === token && it.protocol != protocol }) return false
        if (arm != null && bound?.token !== token) return false
        val existing = peers[consumerEpoch]
        if (existing != null && (existing.retired || existing.pid != callerPid || existing.protocol != protocol)) return false
        val peer = existing ?: run {
            if (peers.size >= 256) return false
            Peer(consumerEpoch, callerPid, token, onInvalidated, protocol,
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
            Arm(peer, start).also { arm = it; registeredDiagnostic = it.registeredDiagnostic; publicationDiagnostic = it.publicationDiagnostic }
        }
        var material: RuntimeReissueMaterial? = null
        var adopted = false
        return try {
            val selectedBackend = backend(active)
            val state = selectedBackend.observe(start) ?: error("state unavailable")
            require(valid(state, start))
            material = selectedBackend.prepare(start) ?: error("authority unavailable")
            if (active.peer.protocol == 3) require(material.payloadLength in 37..RuntimeCaptureCodecV1.MAX_BYTES)
            val candidate = RuntimeAuthorityOffer(start, providerEpoch, material.revision, material.signedRetryBudget,
                material.payloadLength, ids(), ids(), material.presentation)
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
        val diagnostic = LongArray(7) { -1 }.apply { this[4] = 0 }
        val observation = LongArray(3) { -1 }
        synchronized(monitor) { responseDiagnostic = diagnostic; observationDiagnostic = observation }
        var diagnosticStage = 1L
        try {
            active = synchronized(monitor) {
                val current = arm ?: error("unarmed")
                check(current.start.requestId == requestId && peer(callerUid, callerPid, token) === current.peer && live(current) && !current.busy)
                current.busy = true; current.owned += capOwner; current.owned += frameOwner
                current
            }
            diagnosticStage = 2
            check(active.stage.name == purpose.name)
            val offer = checkNotNull(active.offer)
            val inputIdentity = capability.identity.also { it.requirePipe(uid, 0) }
            val outputIdentity = output.identity.also { it.requirePipe(uid, 1) }
            require(inputIdentity.device != outputIdentity.device || inputIdentity.inode != outputIdentity.inode)
            val payloadLength = if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) offer.payloadLength else 0
            val size = if (active.peer.protocol == 3) RuntimeProductionAuthorityFrameCodecV1.encodedLength(payloadLength)
                else RuntimeAuthorityFrameCodec.encodedLength(payloadLength)
            val request = offer.request(purpose, outputIdentity.descriptor(descriptorId, size))
            val selectedBackend = backend(active)
            diagnosticStage = 3
            val state = selectedBackend.observe(active.start, observation) ?: error("state unavailable")
            diagnosticStage = 4
            require(valid(state, active.start) && state.revision == offer.revision && state.signedRetryBudget == offer.signedRetryBudget)
            val environment = RuntimeAdmissionEnvironment(uid, state.unlocked, state.vpnPrepared, state.automaticEnabled,
                state.revision, now(), state.signedRetryBudget, offer.capabilityChannelId, offer.frameChannelId)
            diagnosticStage = 5
            val admission = if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) active.peer.admission.admit(request, environment)
                else active.peer.admission.checkLease(request, environment)
            check(admission == RuntimeReissueAdmission.Allowed)
            diagnosticStage = 6
            key = RuntimeReissuePipeIo.readExact(capability, 32) { synchronized(monitor) { live(active) } }
            diagnosticStage = 7
            check(capOwner.closeOnce() == Cleanup.CLEAN)
            if (purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) {
                diagnosticStage = 8
                val collector = BoundedPayload(offer.payloadLength)
                try { checkNotNull(active.material).writeTo(collector); payload = collector.takeExact() }
                finally { collector.close() }
                diagnosticStage = 9
                check(checkNotNull(active.materialOwner).closeOnce() == Cleanup.CLEAN)
            } else payload = byteArrayOf()
            if (purpose == RuntimeAuthorityPurpose.PRE_TUN) {
                diagnosticStage = 10
                val lease = selectedBackend.acquireRevisionLease(request) ?: error("lease unavailable")
                active.leaseReturnedAt = try { now() } catch (_: Throwable) { -1 }
                val leaseOwner = Owned(lease)
                if (!adopt(active, leaseOwner)) error("cancelled lease")
                active.lease = lease; active.leaseOwner = leaseOwner
                require(lease.revision == offer.revision && lease.isCurrentAfterFreshObservation())
            }
            if (purpose == RuntimeAuthorityPurpose.PRE_ACTIVE) {
                diagnosticStage = 11
                val lease = checkNotNull(active.lease)
                require(lease.revision == offer.revision && lease.isCurrentAfterFreshObservation())
                synchronized(monitor) { check(live(active)); active.registrationAcquiring = true }
                try {
                    val register: (() -> Unit, (Boolean) -> Unit) -> Closeable =
                        if (active.peer.protocol == 3) lease::registerActiveAfterFreshObservation else lease::registerActive
                    val registration = Owned(register(
                        { cancelArm(active, true, propagateUnproven = true) },
                        { clean -> synchronized(monitor) {
                            if (active.registrationRetirement != Completion.UNPROVEN)
                                active.registrationRetirement = if (clean) Completion.CLEAN else Completion.UNPROVEN
                            if (!clean) unproven = true
                            clearRetiredArm(active)
                        } }))
                    synchronized(monitor) { active.registrationOwner = registration }
                } catch (failure: Throwable) {
                    if (!isDefiniteRegistrationNotStarted(lease, failure)) {
                        synchronized(monitor) { active.registrationRetirement = Completion.UNPROVEN; unproven = true }
                    }
                    throw failure
                } finally {
                    synchronized(monitor) { active.registrationAcquiring = false }
                }
                check(synchronized(monitor) { live(active) })
            }
            check(synchronized(monitor) { live(active) })
            diagnosticStage = 12
            if (active.peer.protocol == 3) {
                RuntimeProductionAuthorityFrameCodecV1.sealer(key, RuntimeProductionAuthorityRequestV1(request)).use {
                    frame = it.seal(payload) ?: error("production frame rejected")
                }
            } else RuntimeAuthorityFrameCodec.sealer(key, request).use { frame = it.seal(payload) ?: error("frame rejected") }
            key = null
            diagnosticStage = 13
            RuntimeReissuePipeIo.writeExact(output, checkNotNull(frame)) { synchronized(monitor) { live(active) } }
            diagnosticStage = 14
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
            diagnosticStage = 15
            check(frameOwner.closeOnce() == Cleanup.CLEAN)
            diagnosticStage = 16
            synchronized(monitor) { check(live(active)); active.busy = false }
            success = true
            diagnosticStage = 17
            return true
        } catch (failure: Throwable) {
            recordResponseFailure(diagnostic, diagnosticStage, failure, active?.leaseReturnedAt ?: -1)
            active?.let { cancelArm(it, false) }; return false
        }
        finally {
            key?.fill(0); payload?.fill(0); frame?.fill(0)
            val capClean = capOwner.closeOnce(); val frameClean = frameOwner.closeOnce()
            if (capClean == Cleanup.UNPROVEN || frameClean == Cleanup.UNPROVEN) { poison(); active?.let { cancelArm(it, true) } }
            if (!success) active?.let { synchronized(monitor) { it.busy = false }; cancelArm(it, false) }
            synchronized(monitor) {
                diagnostic[0] = diagnosticStage
                if (success) diagnostic[1] = 0
                diagnostic[4] = 1
            }
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

    fun complete(requestId: String, callerUid: Long, callerPid: Int, token: Any): Boolean =
        completeHeld(requestId, callerUid, callerPid, token, false) != null

    fun completeProduction(requestId: String, callerUid: Long, callerPid: Int, token: Any): Long? =
        completeHeld(requestId, callerUid, callerPid, token, true)

    private fun completeHeld(requestId: String, callerUid: Long, callerPid: Int, token: Any, production: Boolean): Long? {
        val a = synchronized(monitor) {
            val current = arm ?: return null
            if (peer(callerUid, callerPid, token) !== current.peer || current.start.requestId != requestId ||
                !live(current) || current.busy || current.stage != Stage.WAIT_COMPLETE || (production && current.peer.protocol != 3)) {
                recordPublication(current, 0, 2, 1); return null
            }
            current.busy = true; current
        }
        var phase = 3
        var predicate = -1L
        var deadline = 0L
        val held = try {
            val lease = checkNotNull(a.lease)
            checkNotNull(a.leaseOwner)
            checkNotNull(a.registrationOwner)
            if (production) {
                deadline = checkNotNull(lease.publicationDeadlineElapsedMillis)
                require(deadline > 0 && deadline <= a.start.deadlineElapsedMillis)
            }
            phase = 4
            val current = lease.isCurrent()
            predicate = if (current) 1 else 0
            current && run { phase = 5; !a.leaseReleased }
        } catch (failure: Throwable) { recordPublication(a, 0, phase, 2, predicate, failure = failure); false }
        if (!held) recordPublication(a, 0, phase, 1, predicate)
        if (!held) { synchronized(monitor) { a.busy = false }; cancelArm(a, true); return null }
        val completed = synchronized(monitor) {
            a.busy = false
            if (live(a)) { a.stage = Stage.ACTIVE; true } else false
        }
        recordPublication(a, 0, if (completed) 7 else 6, if (completed) 0 else 1, predicate, completed = if (completed) 1 else 0)
        if (!completed) cancelArm(a, false)
        return if (completed) deadline else null
    }

    /** Post-publication cleanup is retry-safe: a successful release stays acknowledged. */
    fun releaseLease(requestId: String, callerUid: Long, callerPid: Int, token: Any): Boolean {
        val a = synchronized(monitor) {
            val current = arm ?: return false
            if (peer(callerUid, callerPid, token) !== current.peer || current.start.requestId != requestId ||
                current.busy || current.stage != Stage.ACTIVE) {
                recordPublication(current, 8, 2, 1); return false
            }
            if (current.leaseReleased) {
                recordPublication(current, 8, 3, 0, completed = 1); return true
            }
            current.busy = true; current
        }
        var phase = 4
        var predicate = -1L
        var closeState = -1L
        val clean = try {
            val current = checkNotNull(a.lease).isCurrent()
            predicate = if (current) 1 else 0
            current && run {
                phase = 5
                val closed = checkNotNull(a.leaseOwner).closeOnce()
                closeState = when (closed) { Cleanup.CLEAN -> 0L; Cleanup.PENDING -> 1L; Cleanup.UNPROVEN -> 2L }
                closed == Cleanup.CLEAN
            }
        } catch (failure: Throwable) { recordPublication(a, 8, phase, 2, predicate, closeState, failure = failure); false }
        if (!clean) recordPublication(a, 8, phase, 1, predicate, closeState)
        if (!clean) {
            synchronized(monitor) { a.busy = false }; cancelArm(a, true); return false
        }
        return synchronized(monitor) {
            a.busy = false
            if (live(a) && a.stage == Stage.ACTIVE) {
                a.leaseReleased = true
                true
            } else false
        }.also {
            recordPublication(a, 8, if (it) 7 else 6, if (it) 0 else 1, predicate, closeState, if (it) 1 else 0)
            if (!it) cancelArm(a, false)
        }
    }

    /** 2 means only the lease closed; the fenced peer still owes native retirement. */
    fun releaseProductionLease(requestId: String, callerUid: Long, callerPid: Int, token: Any): Int {
        if (releaseLease(requestId, callerUid, callerPid, token)) return 1
        return synchronized(monitor) {
            val a = arm ?: return@synchronized 0
            if (!unproven && peer(callerUid, callerPid, token) === a.peer && a.peer.protocol == 3 &&
                a.start.requestId == requestId && a.stage == Stage.CANCELLED &&
                a.notification == Completion.PENDING && a.leaseOwner?.isClean() == true &&
                a.owned.all { it.isClean() }) 2 else 0
        }
    }

    /** FULL was authenticated, but native preparation precedes the one final lease. */
    fun prepublicationCurrent(expected: RuntimeProductionAuthorityOfferV1, deadline: Long,
        callerUid: Long, callerPid: Int, token: Any): Boolean {
        fun deadlineLive(): Boolean = RuntimeProductionReissueWireV1.validObservationDeadline(now(), deadline)
        fun exact(a: Arm): Boolean = live(a) && a.start.isLiveAt(now()) && deadlineLive() &&
            peer(callerUid, callerPid, token) === a.peer && a.peer.protocol == 3 && a.offer?.sameAuthority(expected.offer) == true &&
            a.stage == Stage.PRE_TUN && a.lease == null && a.leaseOwner == null &&
            a.registrationOwner == null && !a.registrationAcquiring && !a.leaseReleased
        val a = synchronized(monitor) {
            val selected = arm ?: return false
            if (selected.busy || !exact(selected)) return false
            selected.busy = true
            selected
        }
        var observed = false
        try {
            val state = checkNotNull(productionBackend).observe(a.start)
            observed = state != null && valid(state, a.start) && state.revision == expected.offer.revision &&
                state.signedRetryBudget == expected.offer.signedRetryBudget
        } catch (failure: Throwable) {
            if (failure is RuntimeAuthorityCleanupUnprovenException) poison()
        }
        val accepted = synchronized(monitor) { a.busy = false; observed && exact(a) }
        if (!accepted) cancelArm(a, true)
        return accepted
    }

    /** Same retained v3 arm, fresh observation only. Original OFFER time is identity, not renewal. */
    fun registeredCurrent(expected: RuntimeProductionAuthorityOfferV1, deadline: Long,
        callerUid: Long, callerPid: Int, token: Any): Boolean {
        fun liveDeadline(): Boolean {
            val current = now()
            return current >= 0 && deadline > current && deadline - current <= 60_000
        }
        val a = synchronized(monitor) {
            val current = arm ?: return false
            fun rejects(failed: Boolean, bit: Int): Boolean {
                if (failed) recordRegisteredFailure(current, 1, bit.toLong(), 0)
                return failed
            }
            if (rejects(!liveDeadline(), 1) || rejects(peer(callerUid, callerPid, token) !== current.peer, 2) ||
                rejects(current.peer.protocol != 3, 4) || rejects(current.offer?.sameAuthority(expected.offer) != true, 8) || rejects(!live(current), 16) ||
                rejects(current.stage != Stage.ACTIVE, 32) || rejects(current.busy, 64) || rejects(!current.leaseReleased, 128) ||
                rejects(current.leaseOwner?.isClean() != true, 256) || rejects(current.registrationRetirement != Completion.OPEN, 512) ||
                rejects(current.registrationOwner == null, 1024) || rejects(current.registrationAcquiring, 2048)) return false
            current.busy = true
            current
        }
        var observed = false
        try {
            observed = (a.lease as? RuntimeProviderRegisteredRevisionLease)?.isRegisteredCurrent(deadline) == true
            if (!observed) recordRegisteredFailure(a, 2, 0, 0)
        } catch (failure: Throwable) {
            if (failure is RuntimeAuthorityCleanupUnprovenException) poison()
            val category = when (failure) {
                is RuntimeAuthorityCleanupUnprovenException -> 1L
                is java.util.concurrent.CancellationException -> 2L
                is IllegalArgumentException -> 3L
                is IllegalStateException -> 4L
                is java.io.IOException -> 5L
                else -> 6L
            }
            recordRegisteredFailure(a, 3, 0, category)
            observed = false
        }
        val accepted = synchronized(monitor) {
            a.busy = false
            fun accepts(value: Boolean, bit: Int): Boolean {
                if (!value) recordRegisteredFailure(a, 4, bit.toLong(), 0)
                return value
            }
            observed && accepts(liveDeadline(), 1) && accepts(live(a), 2) && accepts(peer(callerUid, callerPid, token) === a.peer, 4) &&
                accepts(a.offer?.sameAuthority(expected.offer) == true, 8) && accepts(a.stage == Stage.ACTIVE, 16) && accepts(a.leaseReleased, 32) &&
                accepts(a.registrationRetirement == Completion.OPEN, 64)
        }
        if (!accepted) cancelArm(a, true)
        return accepted
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
    fun cancelStart(start: RuntimeReissueStart, callerUid: Long, callerPid: Int, token: Any, retired: Boolean = false): Int {
        synchronized(monitor) {
            val p = peer(callerUid, callerPid, token) ?: return 0
            if (start.consumerEpoch != p.epoch) return 0
            if (start.requestId !in p.usedRequests) {
                if (start.generation <= p.highWater || p.usedRequests.size >= 4096) return 0
                p.highWater = start.generation; p.usedRequests += start.requestId
            }
            arm?.takeIf { it.start.requestId == start.requestId }?.let {
                if (it.start != start) return 0
                if (retired && p.protocol == 3 && it.stage == Stage.CANCELLED && it.notification == Completion.PENDING)
                    it.notification = Completion.CLEAN
            }
        }
        cancel(start.requestId, callerUid, callerPid, token)
        return cancellationStatus(start.requestId, callerUid, callerPid, token)
    }
    fun peerDied(token: Any) {
        val a = synchronized(monitor) {
            val p = bound?.takeIf { it.token === token } ?: return
            p.retired = true; p.admission.close(); arm?.takeIf { it.peer === p }?.also {
                if (it.notification == Completion.PENDING) it.notification = Completion.CLEAN
            }
        }
        // Binder death already proves the peer cannot retain runtime resources.
        // Retire local ownership, but do not demand an IPC acknowledgement from it.
        a?.let { cancelArm(it, false) }
    }
    /** Service recreation is not process death. Retain process-epoch replay admission. */
    fun connectionClosed(token: Any) {
        val a = synchronized(monitor) { arm?.takeIf { it.peer.token === token } }
        a?.let { cancelArm(it, true) }
    }
    fun expire() {
        val candidate = synchronized(monitor) {
            arm?.takeIf { !it.busy && (it.stage != Stage.ACTIVE && !it.start.isLiveAt(now()) ||
                it.stage == Stage.ACTIVE && !it.leaseReleased) }?.let { ExpiryCandidate(it, it.stage, it.lease) }
        } ?: return
        val a = candidate.arm
        val expired = if (candidate.stage == Stage.ACTIVE) {
            try {
                val lease = checkNotNull(candidate.lease)
                if (a.peer.protocol == 3) {
                    // The timer only retires expired publication. Reconstructing authority
                    // here competes with the mandatory fresh COMPLETE and RELEASE checks.
                    val deadline = lease.publicationDeadlineElapsedMillis
                    val current = now()
                    deadline == null || deadline <= 0 || current < 0 || current >= deadline
                } else !lease.isCurrent()
            } catch (_: Throwable) { true }
        } else true
        if (expired) cancelArm(a, true, expiry = candidate)
    }
    fun cleanupUnproven() = synchronized(monitor) { unproven }
    /** Bounded process-lifetime observability for the installed retry harness, never authority. */
    fun completedFullAuthorityCount(): Int = synchronized(monitor) { completedFullAuthorities }
    /** Fixed process-local observations only; never authority, payload or exception text. */
    internal fun responseDiagnosticSnapshot(page: Int = 0): LongArray = synchronized(monitor) {
        require(page in 0..2)
        if (page == 0) (responseDiagnostic + registeredDiagnostic).also { it[5] = if (unproven) 1 else 0 }
        else if (page == 2) responseDiagnostic + synchronized(observationDiagnostic) { observationDiagnostic.copyOf() }
        else LongArray(24) { -1 }.also { result ->
            result[0] = 1; result[1] = 1; result[2] = 0
            publicationDiagnostic?.let { values ->
                synchronized(values) { values.copyInto(result, 4) }
                result[2] = 1
            }
        }
    }
    private fun recordPublication(a: Arm, offset: Int, phase: Int, category: Int,
        predicate: Long = -1, state: Long = -1, completed: Long = 0, failure: Throwable? = null) {
        // No live/currentness/cleanup call is added for observation. Retain only scalars.
        runCatching {
            val observedAt = now()
            val age = if (a.leaseReturnedAt >= 0 && observedAt >= a.leaseReturnedAt && observedAt - a.leaseReturnedAt <= 60000)
                observedAt - a.leaseReturnedAt else -1
            synchronized(a.publicationDiagnostic) {
                val values = a.publicationDiagnostic
                if (values[offset + 1] > 0) return
                values[offset] = phase.toLong(); values[offset + 1] = category.toLong(); values[offset + 2] = age
                values[offset + 3] = predicate; values[offset + 4] = state; values[offset + 5] = completed
                values[offset + 6] = when (failure) {
                    null -> 0L
                    is java.util.concurrent.CancellationException -> 1L
                    is RuntimeAuthorityCleanupUnprovenException -> 2L
                    is IllegalArgumentException -> 3L
                    is IllegalStateException -> 4L
                    is java.io.IOException -> 5L
                    else -> 6L
                }
            }
        }
    }
    private fun recordRegisteredFailure(a: Arm, phase: Long, predicate: Long, category: Long) = synchronized(monitor) {
        if (a.registeredDiagnostic[0] == 0L) {
            a.registeredDiagnostic[0] = phase; a.registeredDiagnostic[1] = predicate; a.registeredDiagnostic[2] = category
        }
    }
    private fun recordResponseFailure(diagnostic: LongArray, stage: Long, failure: Throwable, leaseReturnedAt: Long) {
        val failedAt = try { now() } catch (_: Throwable) { -1 }
        val leaseAge = if (leaseReturnedAt >= 0 && failedAt >= leaseReturnedAt && failedAt - leaseReturnedAt <= 60_000)
            failedAt - leaseReturnedAt else -1
        var origin = failure
        repeat(4) { origin.cause?.let { origin = it } }
        val category = when (origin) {
            is java.util.concurrent.CancellationException -> 4L
            is IllegalArgumentException -> 1L
            is IllegalStateException -> 2L
            is java.io.IOException -> 3L
            else -> 5L
        }
        var code = -1L; var line = -1L
        for (frame in origin.stackTrace.take(32)) {
            code = when (frame.className.substringBefore('$') + "#" + frame.fileName) {
                "org.kurdistanvpn.app.RuntimeAuthorityReissueIpcAdapter#RuntimeAuthorityReissueIpcAdapter.kt" -> 1L
                "org.kurdistanvpn.app.DefaultProcessAuthorityBackend#KurdistanApplication.kt" -> 2L
                "org.kurdistanvpn.runtime.android.RuntimeReissuePipeIo#RuntimeAuthorityReissueClient.kt" -> 3L
                "org.kurdistanvpn.runtime.android.RuntimeAuthorityPipeOwner#RuntimeAuthorityReissueClient.kt" -> 4L
                "org.kurdistanvpn.runtime.android.RuntimeProductionAuthorityFrameCodecV1#RuntimeProductionAuthorityFrameCodecV1.kt" -> 5L
                "org.kurdistanvpn.runtime.api.RuntimeCaptureCodecV1#RuntimeProductionCapture.kt" -> 6L
                else -> continue
            }
            line = if (frame.lineNumber in 1..10_000) frame.lineNumber.toLong() else -1
            break
        }
        synchronized(monitor) {
            diagnostic[0] = stage; diagnostic[1] = category; diagnostic[2] = code; diagnostic[3] = line
            diagnostic[6] = leaseAge
        }
    }
    fun transportCleanupFailed() {
        val a = synchronized(monitor) { unproven = true; arm }
        a?.let { cancelArm(it, true) }
    }
    private fun peer(callerUid: Long, callerPid: Int, token: Any): Peer? =
        bound?.takeIf { !unproven && !it.retired && callerUid == uid && callerPid == it.pid && it.token === token }
    private fun backend(a: Arm): RuntimeAuthorityReissueBackend =
        if (a.peer.protocol == 3) checkNotNull(productionBackend) else backend
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
    /** Called only under monitor; the acknowledgement does no cleanup or external work. */
    private fun clearRetiredArm(a: Arm) {
        val registrationClean = a.registrationRetirement == Completion.CLEAN ||
            (a.registrationRetirement == Completion.OPEN && a.registrationOwner == null) ||
            a.registrationOwner?.isClean() == true
        if (arm === a && !unproven && a.stage == Stage.CANCELLED && !a.busy && !a.registrationAcquiring &&
            a.owned.all { it.isClean() } &&
            (a.notification == Completion.OPEN || a.notification == Completion.CLEAN) && registrationClean) arm = null
    }
    private data class ExpiryCandidate(val arm: Arm, val stage: Stage, val lease: RuntimeProviderRevisionLease?)
    private fun cancelArm(a: Arm, notify: Boolean, propagateUnproven: Boolean = false, expiry: ExpiryCandidate? = null) {
        val resources: List<Owned>
        val callback: (() -> Unit)?
        synchronized(monitor) {
            // Expiry observation runs outside the monitor. RELEASE may have completed
            // meanwhile; only the timer must revalidate ownership before cancelling.
            if (expiry != null && (arm !== a || a.busy || a.stage != expiry.stage ||
                    a.stage == Stage.ACTIVE && (a.leaseReleased || a.lease !== expiry.lease))) return
            a.stage = Stage.CANCELLED; a.peer.admission.cancel(a.start.requestId)
            resources = a.owned.asReversed().toList()
            callback = if (notify && a.notification == Completion.OPEN) {
                a.notification = Completion.RUNNING; a.peer.invalidated
            } else null
        }
        var allClean = true
        resources.forEach { when (it.closeOnce()) {
            Cleanup.UNPROVEN -> { poison(); allClean = false }
            Cleanup.PENDING -> allClean = false
            Cleanup.CLEAN -> Unit
        } }
        if (callback != null) {
            val completion = try { callback.invoke(); Completion.CLEAN }
                catch (_: RuntimeAuthorityPeerCleanupPendingException) {
                    if (a.peer.protocol == 3 && !a.leaseReleased) Completion.PENDING else Completion.UNPROVEN
                } catch (_: Throwable) { Completion.UNPROVEN }
            synchronized(monitor) {
                a.notification = completion
                if (completion == Completion.UNPROVEN) unproven = true
            }
        }
        // Only initial-publication retirement can be pending. It retains the
        // registration, so no new authority or mutation obtains a clean proof.
        if (allClean && !propagateUnproven && synchronized(monitor) { a.notification == Completion.PENDING && !unproven }) return
        val callbackClean = synchronized(monitor) {
            a.notification == Completion.OPEN || a.notification == Completion.CLEAN
        }
        // The invalidation callback must never close its containing registration. An
        // explicit lifecycle caller may do so only after ordinary and peer cleanup.
        if (!propagateUnproven && allClean && callbackClean) {
            val registration = synchronized(monitor) { if (a.registrationAcquiring) null else a.registrationOwner }
            if (registration != null && registration.closeOnce() != Cleanup.CLEAN) { allClean = false; poison() }
        }
        // RuntimeRegistrationOwner marks the shared revision clean only when its callback
        // returns. Preserve this categorical failure through that callback: otherwise a failed
        // peer invalidation or re-entrant registration close would permit a broker mutation.
        if (!allClean || !callbackClean || (propagateUnproven && synchronized(monitor) { unproven })) {
            poison()
            if (propagateUnproven) throw RuntimeAuthorityCleanupUnprovenException()
        }
        synchronized(monitor) { clearRetiredArm(a) }
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.util.UUID
import java.security.SecureRandom
import org.kurdistanvpn.runtime.api.*

data class RuntimeStartToken(val epoch: String, val requestId: String, val generation: Long,
    val trigger: RuntimeAuthorityTrigger, val retryAttempt: Int)
enum class RuntimeStopReason(val priority: Int) { CANCEL(1), STOP(2), RECOVER_INTERNET(3), REVOKE(4) }
enum class RuntimeStartFailure(val retryable: Boolean) {
    NETWORK_UNAVAILABLE(true), NETWORK_CHANGED(true), NETWORK_LOST(true), ENDPOINT_UNAVAILABLE(true),
    AUTHORITY_REJECTED(false), TLS_REJECTED(false), CONSENT_REVOKED(false), STATE_CORRUPT(false),
    CANCELLED(false), CLEANUP_UNPROVEN(false), INTERNAL_FAILURE(false), RETRY_EXHAUSTED(false), PAUSED(false),
    PROXY_BIND_FAILED(false), AUTHORITY_PROVIDER_LOST(true),
}
sealed interface RuntimeStartDecision {
    data class RequestAuthority(val token: RuntimeStartToken, val guard: RuntimeActivationGuard,
        val delayMillis: Long, val retryBudgetCeiling: Int?) : RuntimeStartDecision
    data class Ready(val token: RuntimeStartToken, val guard: RuntimeActivationGuard,
        val authority: RuntimeVerifiedAuthority, val leases: RuntimeRevisionLeaseClient) : RuntimeStartDecision
    data class Active(val token: RuntimeStartToken) : RuntimeStartDecision
    data class Coalesced(val token: RuntimeStartToken) : RuntimeStartDecision
    data class CleanupPending(val token: RuntimeStartToken, val state: RuntimeCleanupState) : RuntimeStartDecision
    data class Rejected(val failure: RuntimeStartFailure) : RuntimeStartDecision
    data object Stale : RuntimeStartDecision
    data object Idle : RuntimeStartDecision
}

/** Public callers install one nonreplaceable VPN-process coordinator. The internal constructor
 * is the module's deterministic composition boundary, not an alternative app installation path. */
class RuntimeStartCoordinator internal constructor(val epoch: String,
    private val retryRandom: () -> Double = SecureRandom()::nextDouble,
    private val requestIds: () -> String = { UUID.randomUUID().toString().replace("-", "") }) {
    private enum class Phase { AUTHORITY, ACQUIRING, ACTIVE, STOPPING }
    private data class Current(val token: RuntimeStartToken, val guard: RuntimeActivationGuard,
        var phase: Phase, var budget: Int?, val origin: RuntimeAuthorityTrigger,
        var terminalFailure: RuntimeStartFailure? = null, var stable: Boolean = false)
    private data class Next(val trigger: RuntimeAuthorityTrigger, val requestId: String?, val attempt: Int,
        val budget: Int?, val origin: RuntimeAuthorityTrigger, val delay: Long)
    private var generation = 0L
    private var current: Current? = null
    private var queued: Next? = null
    private var stopReason: RuntimeStopReason? = null
    private var suppressAutomatic = false
    private val usedIds = mutableSetOf<String>()
    private var mutationQuiescence: MutationQuiescenceLease? = null
    init { require(RuntimeAuthorityLimits.validId(epoch)) }

    /** Acquired only after every existing Attempt has retired with guard cleanup proven.
     * While held, no new Attempt can acquire a TUN or authority resources. */
    internal fun acquireMutationQuiescenceLease(): AutoCloseable? = synchronized(this) {
        if (current != null || mutationQuiescence != null) null
        else MutationQuiescenceLease().also { mutationQuiescence = it }
    }

    private inner class MutationQuiescenceLease : AutoCloseable {
        private var closed = false
        override fun close() = synchronized(this@RuntimeStartCoordinator) {
            if (!closed) {
                closed = true
                if (mutationQuiescence === this) mutationQuiescence = null
            }
        }
    }

    /** Non-disruptive admission for a sole service owner. Validation and acquisition
     * share the ordinary coordinator monitor; a refusal never mutates its queue. */
    fun beginIfIdle(trigger: RuntimeAuthorityTrigger, unlocked: Boolean, vpnPrepared: Boolean,
        manualRequestId: String? = null): RuntimeStartDecision = synchronized(this) {
        if (!unlocked || !vpnPrepared || trigger == RuntimeAuthorityTrigger.NETWORK_RETRY ||
            (manualRequestId != null && (trigger != RuntimeAuthorityTrigger.MANUAL || !RuntimeAuthorityLimits.validId(manualRequestId))))
            return RuntimeStartDecision.Rejected(RuntimeStartFailure.CONSENT_REVOKED)
        if (current != null || queued != null || mutationQuiescence != null)
            return RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN)
        if (trigger == RuntimeAuthorityTrigger.AUTOMATIC && suppressAutomatic)
            return RuntimeStartDecision.Rejected(RuntimeStartFailure.CANCELLED)
        start(Next(trigger, manualRequestId, 0, null, trigger, 0))
    }

    fun begin(trigger: RuntimeAuthorityTrigger, unlocked: Boolean, vpnPrepared: Boolean,
        manualRequestId: String? = null): RuntimeStartDecision {
        val retiring = synchronized(this) {
            if (!unlocked || !vpnPrepared || trigger == RuntimeAuthorityTrigger.NETWORK_RETRY ||
                (manualRequestId != null && (trigger != RuntimeAuthorityTrigger.MANUAL || !RuntimeAuthorityLimits.validId(manualRequestId))))
                return RuntimeStartDecision.Rejected(RuntimeStartFailure.CONSENT_REVOKED)
            if (mutationQuiescence != null)
                return RuntimeStartDecision.Rejected(RuntimeStartFailure.CLEANUP_UNPROVEN)
            if (trigger == RuntimeAuthorityTrigger.AUTOMATIC && suppressAutomatic)
                return RuntimeStartDecision.Rejected(RuntimeStartFailure.CANCELLED)
            val existing = current
            if (existing != null) {
                if (existing.phase == Phase.STOPPING) {
                    // A user start can replace a queued automatic retry, but cannot overtake
                    // cleanup or a stop/revoke that already won this retirement.
                    if (trigger == RuntimeAuthorityTrigger.MANUAL && stopReason == null && queued?.trigger != RuntimeAuthorityTrigger.MANUAL)
                        queued = Next(trigger, manualRequestId, 0, null, trigger, 0)
                    return RuntimeStartDecision.CleanupPending(existing.token, existing.guard.cleanupState())
                }
                if (trigger != RuntimeAuthorityTrigger.MANUAL || existing.token.trigger == RuntimeAuthorityTrigger.MANUAL)
                    return RuntimeStartDecision.Coalesced(existing.token)
                queued = Next(trigger, manualRequestId, 0, null, trigger, 0)
                existing.phase = Phase.STOPPING
                existing.guard.markCancellation()
                existing
            } else return start(Next(trigger, manualRequestId, 0, null, trigger, 0))
        }
        return retire(retiring)
    }

    fun acceptAuthority(token: RuntimeStartToken, authority: RuntimeVerifiedAuthority,
        nowElapsedMillis: Long): RuntimeStartDecision {
        val failure = synchronized(this) {
            val active = current
            if (active == null || active.token != token || active.phase != Phase.AUTHORITY) {
                authority.close()
                return RuntimeStartDecision.Stale
            }
            val request = authority.request
            if (request.consumerEpoch != epoch || request.requestId != token.requestId || request.generation != token.generation ||
                request.trigger != token.trigger || request.retryAttempt != token.retryAttempt ||
                request.purpose != RuntimeAuthorityPurpose.FULL_AUTHORITY || !request.isLiveAt(nowElapsedMillis) ||
                (active.budget != null && request.signedRetryBudget > active.budget!!)) {
                authority.close()
                RuntimeStartFailure.AUTHORITY_REJECTED
            } else if (active.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, authority) == null) RuntimeStartFailure.CANCELLED
            else {
                val leases = RuntimeRevisionLeaseClient(request)
                active.guard.own(RuntimeResourceKind.AUTHORITY_DESCRIPTOR, leases)
                active.budget = request.signedRetryBudget
                active.phase = Phase.ACQUIRING
                return RuntimeStartDecision.Ready(token, active.guard, authority, leases)
            }
        }
        return failed(token, failure)
    }

    /** Only the production platform owner calls this after native verification of its exact capture.
     * Records scheduling limits; it neither grants native authority nor publishes ACTIVE. */
    internal fun acceptProductionAuthority(token: RuntimeStartToken, effectiveRetryMaximum: Int): Boolean = synchronized(this) {
        val value = current ?: return false
        if (value.token != token || value.phase != Phase.AUTHORITY || !value.guard.isAcquisitionCurrent() ||
            effectiveRetryMaximum !in 0..5 || (value.budget != null && effectiveRetryMaximum > value.budget!!)) return false
        value.budget = effectiveRetryMaximum
        value.phase = Phase.ACQUIRING
        true
    }

    fun activationCompleted(token: RuntimeStartToken): RuntimeStartDecision {
        synchronized(this) {
            val active = current ?: return RuntimeStartDecision.Stale
            if (active.token != token || active.phase != Phase.ACQUIRING) return RuntimeStartDecision.Stale
            if (active.guard.isActive()) {
                active.phase = Phase.ACTIVE
                return RuntimeStartDecision.Active(token)
            }
        }
        return failed(token, RuntimeStartFailure.INTERNAL_FAILURE)
    }

    fun failed(token: RuntimeStartToken, failure: RuntimeStartFailure): RuntimeStartDecision {
        val active = synchronized(this) {
            val value = current ?: return RuntimeStartDecision.Stale
            if (value.token != token || value.phase == Phase.STOPPING) return RuntimeStartDecision.Stale
            val budget = value.budget ?: 0
            val used = if (value.stable) 0 else token.retryAttempt
            if (failure.retryable && used < budget) {
                val attempt = used + 1
                val sample = retryRandom()
                check(sample >= 0.0 && sample < 1.0)
                val delay = ((1000L shl (attempt - 1)).toDouble() * (0.8 + 0.4 * sample)).toLong().coerceAtMost(30_000)
                queued = Next(RuntimeAuthorityTrigger.NETWORK_RETRY, null, attempt, budget, value.origin,
                    delay)
                value.terminalFailure = null
            } else {
                queued = null
                suppressAutomatic = true
                value.terminalFailure = if (failure.retryable) RuntimeStartFailure.RETRY_EXHAUSTED else failure
            }
            value.phase = Phase.STOPPING
            value.guard.markCancellation()
            value
        }
        return retire(active)
    }

    fun stop(reason: RuntimeStopReason): RuntimeStartDecision = stopOwned(null, reason)

    internal fun recordStableSession(token: RuntimeStartToken, activeMillis: Long): Boolean = synchronized(this) {
        val value = current ?: return false
        if (value.token != token || value.phase != Phase.ACTIVE || !value.guard.isActive() || activeMillis < 60_000)
            return false
        value.stable = true
        true
    }

    /** A retained service owner cannot cancel a later generation. */
    fun stopIfCurrent(token: RuntimeStartToken, reason: RuntimeStopReason): RuntimeStartDecision = stopOwned(token, reason)

    private fun stopOwned(token: RuntimeStartToken?, reason: RuntimeStopReason): RuntimeStartDecision {
        val active = synchronized(this) {
            if (token != null && current?.token != token) return RuntimeStartDecision.Stale
            if (stopReason == null || reason.priority > stopReason!!.priority) stopReason = reason
            suppressAutomatic = true
            queued = null
            (current ?: return RuntimeStartDecision.Idle).also {
                it.terminalFailure = null
                it.phase = Phase.STOPPING
                it.guard.markCancellation()
                // Scoped production acquisition drains after its actual worker returns.
                // Cancellation and this observation share the guard's monitor, preventing
                // a new acquisition from starting between publication and deferral.
                if (token != null && it.guard.acquisitionInFlight())
                    return RuntimeStartDecision.CleanupPending(it.token, it.guard.cleanupState())
            }
        }
        return retire(active)
    }

    fun cleanupCompleted(token: RuntimeStartToken): RuntimeStartDecision {
        val active = synchronized(this) {
            val value = current ?: return RuntimeStartDecision.Stale
            if (value.token != token || value.phase != Phase.STOPPING) return RuntimeStartDecision.Stale
            value
        }
        return retire(active)
    }
    @Synchronized fun currentToken(): RuntimeStartToken? = current?.token
    internal fun ownsAdmission(admission: RuntimeStartDecision.RequestAuthority): Boolean = synchronized(this) {
        val value = current
        value != null && value.token == admission.token && value.guard === admission.guard &&
            value.phase == Phase.AUTHORITY && value.guard.isAcquisitionCurrent()
    }

    private fun retire(active: Current): RuntimeStartDecision {
        // STOPPING and cancellation are published together before cleanup. If publication
        // reentered stop, its outer monitor still belongs to this thread: defer foreign cleanup
        // until activate unwinds or cleanupCompleted drains it. No new start precedes CLEAN.
        if (Thread.holdsLock(this)) return RuntimeStartDecision.CleanupPending(active.token, active.guard.cleanupState())
        active.guard.cancel()
        return synchronized(this) {
            if (current !== active) RuntimeStartDecision.Stale else finishRetirement(active)
        }
    }
    private fun finishRetirement(active: Current): RuntimeStartDecision {
        val state = active.guard.cleanupState()
        if (state != RuntimeCleanupState.CLEAN) return RuntimeStartDecision.CleanupPending(active.token, state)
        current = null
        val next = queued
        queued = null
        return when {
            next != null -> start(next)
            active.terminalFailure != null -> RuntimeStartDecision.Rejected(active.terminalFailure!!)
            else -> RuntimeStartDecision.Idle
        }
    }
    private fun start(next: Next): RuntimeStartDecision {
        if (generation == Long.MAX_VALUE || usedIds.size >= 4096) return RuntimeStartDecision.Rejected(RuntimeStartFailure.INTERNAL_FAILURE)
        val id = try { next.requestId ?: requestIds() } catch (_: Throwable) { return RuntimeStartDecision.Rejected(RuntimeStartFailure.INTERNAL_FAILURE) }
        if (!RuntimeAuthorityLimits.validId(id) || !usedIds.add(id)) return RuntimeStartDecision.Rejected(RuntimeStartFailure.AUTHORITY_REJECTED)
        if (next.trigger == RuntimeAuthorityTrigger.MANUAL) { suppressAutomatic = false; stopReason = null }
        val token = RuntimeStartToken(epoch, id, ++generation, next.trigger, next.attempt)
        // Publication and stop share one monitor, avoiding coordinator/guard lock inversion.
        val owner = RuntimeActivationGuard(this) // Exists before any descriptor/key/native acquisition.
        current = Current(token, owner, Phase.AUTHORITY, next.budget, next.origin)
        return RuntimeStartDecision.RequestAuthority(token, owner, next.delay, next.budget)
    }

    companion object {
        private val processEpoch = UUID.randomUUID().toString().replace("-", "")
        private var installed: RuntimeStartCoordinator? = null
        fun processOwner(): RuntimeStartCoordinator = installOnce(processEpoch)
        @Synchronized fun installOnce(epoch: String): RuntimeStartCoordinator {
            val existing = installed
            if (existing != null) { check(existing.epoch == epoch) { "VPN process coordinator already installed" }; return existing }
            return RuntimeStartCoordinator(epoch).also { installed = it }
        }
    }
}

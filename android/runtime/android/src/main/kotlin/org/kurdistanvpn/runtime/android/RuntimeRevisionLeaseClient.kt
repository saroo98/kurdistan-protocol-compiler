// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import org.kurdistanvpn.runtime.api.*

/** epoch is the VPN/consumer epoch. providerEpoch is freshly observed by the bound provider
 * connection; provider/Binder death must also close this lease before any final activation. */
data class RuntimeActivationChecks(val epoch: String, val providerEpoch: String, val generation: Long, val revision: Long,
    val unlocked: Boolean, val vpnPrepared: Boolean, val cancelled: Boolean, val nowElapsedMillis: Long)

/** Full authority and both lease checks share an arm, but responses are one-use and ordered. */
class RuntimeRevisionLeaseClient(val request: RuntimeAuthorityRequest) : Closeable {
    private enum class Stage { WAIT_PRE_TUN, PRE_TUN_READY, WAIT_PRE_ACTIVE, PRE_ACTIVE_READY, TERMINAL }
    private var stage = Stage.WAIT_PRE_TUN
    private var finalDeadline: Long? = null
    init { require(request.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) }

    /** Start before PRE_TUN IPC. Android processes share elapsedRealtime: this earlier
     * consumer bound cannot outlive a provider lease acquired later for at most 2s. */
    @Synchronized fun beginFinalLease(nowElapsedMillis: Long): Boolean {
        if (stage != Stage.WAIT_PRE_TUN || finalDeadline != null || !request.isLiveAt(nowElapsedMillis) ||
            nowElapsedMillis > Long.MAX_VALUE - MAX_FINAL_LEASE_MILLIS) return fail()
        finalDeadline = minOf(request.deadlineElapsedMillis, nowElapsedMillis + MAX_FINAL_LEASE_MILLIS)
        return true
    }

    @Synchronized fun accept(verified: RuntimeVerifiedAuthority, checks: RuntimeActivationChecks): Boolean {
        val payload = verified.takePayload()
        return try {
            // A request whose entire remaining life is already <=2s is conservatively
            // bounded even without a separate earlier start call (including fixed vectors).
            if (finalDeadline == null && stage == Stage.WAIT_PRE_TUN &&
                request.isLiveAt(checks.nowElapsedMillis) &&
                request.deadlineElapsedMillis - checks.nowElapsedMillis <= MAX_FINAL_LEASE_MILLIS)
                finalDeadline = request.deadlineElapsedMillis
            val expected = when (stage) {
                Stage.WAIT_PRE_TUN -> RuntimeAuthorityPurpose.PRE_TUN
                Stage.WAIT_PRE_ACTIVE -> RuntimeAuthorityPurpose.PRE_ACTIVE
                else -> null
            }
            if (expected == null || payload == null || payload.isNotEmpty() || !request.sameArm(verified.request) ||
                verified.request.purpose != expected || !current(checks)) fail()
            else {
                stage = if (expected == RuntimeAuthorityPurpose.PRE_TUN) Stage.PRE_TUN_READY else Stage.PRE_ACTIVE_READY
                true
            }
        } finally { payload?.fill(0); verified.close() }
    }

    @Synchronized fun authorizeTun(checks: RuntimeActivationChecks): Boolean {
        if (stage != Stage.PRE_TUN_READY || !current(checks)) return fail()
        stage = Stage.WAIT_PRE_ACTIVE
        return true
    }
    @Synchronized fun authorizePublication(checks: RuntimeActivationChecks): Boolean {
        if (stage != Stage.PRE_ACTIVE_READY || !current(checks)) return fail()
        stage = Stage.TERMINAL
        return true
    }
    @Synchronized override fun close() { stage = Stage.TERMINAL }
    private fun current(c: RuntimeActivationChecks): Boolean = c.epoch == request.consumerEpoch && c.providerEpoch == request.providerEpoch &&
        c.generation == request.generation &&
        c.revision == request.revision && c.unlocked && c.vpnPrepared && !c.cancelled && request.isLiveAt(c.nowElapsedMillis) &&
        finalDeadline?.let { c.nowElapsedMillis < it } == true
    private fun fail(): Boolean { stage = Stage.TERMINAL; return false }
    private companion object { const val MAX_FINAL_LEASE_MILLIS = 2_000L }
}

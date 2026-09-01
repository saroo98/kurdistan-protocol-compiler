// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.io.Closeable
import org.kurdistanvpn.runtime.api.*

data class RuntimeAdmissionEnvironment(val callerUid: Long, val unlocked: Boolean, val vpnPrepared: Boolean,
    val automaticEnabled: Boolean, val currentRevision: Long, val nowElapsedMillis: Long, val authoritativeRetryBudget: Int,
    val observedCapabilityChannelId: String, val observedFrameChannelId: String)
sealed interface RuntimeReissueAdmission {
    data object Allowed : RuntimeReissueAdmission
    data class Rejected(val reason: RuntimeAdmissionFailure) : RuntimeReissueAdmission
}

/** The default-process owner composes one gate for an authenticated VPN-process epoch.
 * Observed channel IDs must come from its admitted pipe ownership, not untrusted Intent/Binder
 * scalar assertions. Android validates UID/Binder/process identity separately. Same UID is not
 * a sandbox. Generations are monotonic only within this bound consumer epoch. */
class RuntimeAuthorityReissueAdmission(private val applicationUid: Long, private val consumerEpoch: String,
    private val providerEpoch: String) : Closeable {
    private var closed = false
    private var highWaterGeneration = 0L
    private var armed: RuntimeAuthorityRequest? = null
    private var nextPurpose = RuntimeAuthorityPurpose.PRE_TUN
    private val usedIds = mutableSetOf<String>()
    private val usedChannels = mutableSetOf<String>()
    init {
        require(applicationUid in 0..0xffff_fffeL)
        require(RuntimeAuthorityLimits.validId(consumerEpoch) && RuntimeAuthorityLimits.validId(providerEpoch) && consumerEpoch != providerEpoch)
    }

    @Synchronized fun admit(request: RuntimeAuthorityRequest, environment: RuntimeAdmissionEnvironment): RuntimeReissueAdmission {
        validate(request, environment)?.let { return RuntimeReissueAdmission.Rejected(it) }
        if (request.purpose != RuntimeAuthorityPurpose.FULL_AUTHORITY) return reject(RuntimeAdmissionFailure.PURPOSE_REJECTED)
        if (request.generation <= highWaterGeneration || request.requestId in usedIds ||
            request.capabilityChannelId in usedChannels || request.frameChannelId in usedChannels) return reject(RuntimeAdmissionFailure.REPLAY)
        if (armed != null) return reject(RuntimeAdmissionFailure.BUSY)
        if (usedIds.size >= 4096) return reject(RuntimeAdmissionFailure.RESOURCE_LIMIT)
        highWaterGeneration = request.generation
        usedIds += request.requestId
        usedChannels += request.capabilityChannelId
        usedChannels += request.frameChannelId
        armed = request
        nextPurpose = RuntimeAuthorityPurpose.PRE_TUN
        return RuntimeReissueAdmission.Allowed
    }

    @Synchronized fun checkLease(request: RuntimeAuthorityRequest, environment: RuntimeAdmissionEnvironment): RuntimeReissueAdmission {
        val active = armed ?: return reject(RuntimeAdmissionFailure.CANCELLED)
        if (!active.sameArm(request) || request.purpose != nextPurpose) return reject(RuntimeAdmissionFailure.PURPOSE_REJECTED)
        validate(request, environment)?.let { armed = null; return reject(it) }
        if (nextPurpose == RuntimeAuthorityPurpose.PRE_TUN) nextPurpose = RuntimeAuthorityPurpose.PRE_ACTIVE else armed = null
        return RuntimeReissueAdmission.Allowed
    }

    @Synchronized fun cancel(requestId: String) { if (armed?.requestId == requestId) armed = null }
    @Synchronized override fun close() { closed = true; armed = null }

    private fun validate(request: RuntimeAuthorityRequest, e: RuntimeAdmissionEnvironment): RuntimeAdmissionFailure? = when {
        closed -> RuntimeAdmissionFailure.CANCELLED
        e.callerUid !in 0..0xffff_fffeL || e.callerUid != applicationUid -> RuntimeAdmissionFailure.WRONG_CALLER
        request.consumerEpoch != consumerEpoch || request.providerEpoch != providerEpoch -> RuntimeAdmissionFailure.WRONG_EPOCH
        !RuntimeAuthorityLimits.validId(e.observedCapabilityChannelId) || !RuntimeAuthorityLimits.validId(e.observedFrameChannelId) ||
            request.capabilityChannelId != e.observedCapabilityChannelId || request.frameChannelId != e.observedFrameChannelId -> RuntimeAdmissionFailure.INVALID_STATE
        !e.unlocked -> RuntimeAdmissionFailure.LOCKED
        !e.vpnPrepared -> RuntimeAdmissionFailure.CONSENT_REQUIRED
        !RuntimeAuthorityLimits.validRevision(e.currentRevision) || request.revision != e.currentRevision -> RuntimeAdmissionFailure.STALE_REVISION
        !request.isLiveAt(e.nowElapsedMillis) -> RuntimeAdmissionFailure.EXPIRED
        request.trigger == RuntimeAuthorityTrigger.AUTOMATIC && !e.automaticEnabled -> RuntimeAdmissionFailure.INVALID_STATE
        e.authoritativeRetryBudget !in 0..RuntimeAuthorityLimits.MAX_RETRIES || request.signedRetryBudget != e.authoritativeRetryBudget -> RuntimeAdmissionFailure.BUDGET_REJECTED
        else -> null
    }
    private fun reject(reason: RuntimeAdmissionFailure) = RuntimeReissueAdmission.Rejected(reason)
}

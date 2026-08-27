// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

object RuntimeAuthorityLimits {
    const val MAX_PAYLOAD_BYTES = 1_500_000 + 1_200_000 + 512 + 128 + 32 * 1024
    const val MAX_FRAME_BYTES = MAX_PAYLOAD_BYTES + 512
    const val MAX_LIFETIME_MILLIS = 60_000L
    const val MAX_RETRIES = 5
    fun validId(value: String): Boolean = value.length == 32 && value.all { it in '0'..'9' || it in 'a'..'f' } && value.any { it != '0' }
    fun validRevision(value: Long): Boolean = value > 0 && value and 1L == 0L
}

/** Observed by the trusted descriptor adapter, never derived from Intent extras. */
data class RuntimeDescriptorBinding(val id: String, val device: Long, val inode: Long,
    val ownerUid: Long, val mode: Long, val length: Long, val accessMode: Int) {
    init {
        require(RuntimeAuthorityLimits.validId(id) && device >= 0 && inode > 0)
        require(ownerUid in 0..0xffff_fffeL && length in 1..RuntimeAuthorityLimits.MAX_FRAME_BYTES.toLong())
        require(mode in 0..0xffffL && mode and 0xfffL == 384L)
        require(mode and 0xf000L == 0x1000L || mode and 0xf000L == 0x8000L)
        require(accessMode == 0)
    }
}

/** Consumer is the VPN process; provider is the default process. Epochs and channel/request IDs
 * are fresh 128-bit runtime values, not the independent 256-bit durable operation identity.
 * The two channel IDs name distinct capability and authenticated-frame pipes for this arm. */
data class RuntimeAuthorityRequest(val consumerEpoch: String, val providerEpoch: String,
    val requestId: String, val generation: Long,
    val purpose: RuntimeAuthorityPurpose, val trigger: RuntimeAuthorityTrigger, val revision: Long,
    val deadlineElapsedMillis: Long, val capabilityChannelId: String, val frameChannelId: String,
    val descriptor: RuntimeDescriptorBinding,
    val signedRetryBudget: Int, val retryAttempt: Int) {
    init {
        require(listOf(consumerEpoch, providerEpoch, requestId, capabilityChannelId, frameChannelId).all(RuntimeAuthorityLimits::validId))
        require(consumerEpoch != providerEpoch && capabilityChannelId != frameChannelId)
        require(generation > 0 && RuntimeAuthorityLimits.validRevision(revision) && deadlineElapsedMillis > 0)
        require(signedRetryBudget in 0..RuntimeAuthorityLimits.MAX_RETRIES && retryAttempt in 0..signedRetryBudget)
        require((trigger == RuntimeAuthorityTrigger.NETWORK_RETRY) == (retryAttempt > 0))
    }
    fun isLiveAt(nowElapsedMillis: Long): Boolean = nowElapsedMillis >= 0 && nowElapsedMillis < deadlineElapsedMillis &&
        deadlineElapsedMillis - nowElapsedMillis <= RuntimeAuthorityLimits.MAX_LIFETIME_MILLIS
    fun forPurpose(value: RuntimeAuthorityPurpose, frameDescriptor: RuntimeDescriptorBinding = descriptor): RuntimeAuthorityRequest =
        copy(purpose = value, descriptor = frameDescriptor)
    /** Per-response descriptor changes do not create a second armed operation. */
    fun sameArm(other: RuntimeAuthorityRequest): Boolean = copy(purpose = RuntimeAuthorityPurpose.FULL_AUTHORITY, descriptor = other.descriptor) ==
        other.forPurpose(RuntimeAuthorityPurpose.FULL_AUTHORITY)
}

enum class RuntimeAdmissionFailure {
    WRONG_CALLER, WRONG_EPOCH, INVALID_STATE, LOCKED, CONSENT_REQUIRED, STALE_REVISION,
    EXPIRED, REPLAY, BUSY, CANCELLED, BUDGET_REJECTED, RESOURCE_LIMIT, PURPOSE_REJECTED,
}

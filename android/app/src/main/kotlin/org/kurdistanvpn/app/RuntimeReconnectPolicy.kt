// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import kotlin.math.roundToLong
import kotlin.random.Random
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

internal class RuntimeReconnectPolicy(
    private val jitter: (Long) -> Long = { baseDelayMillis ->
        jitterReconnectDelay(baseDelayMillis, Random.nextDouble())
    },
) {
    var attempts: Int = 0
        private set

    fun nextDelayMillis(maxAttempts: Int, failure: String?): Long? {
        if (maxAttempts <= 0 || !isRetryableRuntimeFailure(failure) || attempts >= maxAttempts) {
            return null
        }
        val delay = RECONNECT_DELAYS_MILLIS.getOrElse(attempts) {
            RECONNECT_DELAYS_MILLIS.last()
        }
        attempts++
        return jitter(delay)
    }

    fun reset() {
        attempts = 0
    }
}

internal fun isRetryableRuntimeFailure(failure: String?): Boolean = failure in setOf(
    "NETWORK_CHANGED",
    "NETWORK_UNAVAILABLE",
    "LIVE_NETWORK_UNAVAILABLE",
    "LIVE_FALLBACK_EXHAUSTED",
)

internal fun isTerminalInitialRuntimeOutcome(snapshot: VpnRuntimeSnapshot): Boolean =
    when (snapshot.state) {
        VpnRuntimeState.ACTIVE_KURD_LIVE,
        VpnRuntimeState.REVOKED,
        VpnRuntimeState.IDLE,
        VpnRuntimeState.STOPPING,
        -> true
        VpnRuntimeState.FAILED,
        VpnRuntimeState.BLOCKED,
        -> !isRetryableRuntimeFailure(snapshot.failure)
        else -> false
    }

internal fun jitterReconnectDelay(baseDelayMillis: Long, sample: Double): Long {
    require(baseDelayMillis > 0L) { "base delay must be positive" }
    require(sample.isFinite() && sample in 0.0..1.0) { "sample must be within [0, 1]" }
    val factor = 0.8 + (sample * 0.4)
    return (baseDelayMillis * factor).roundToLong().coerceAtMost(MAX_RECONNECT_DELAY_MILLIS)
}

private val RECONNECT_DELAYS_MILLIS = longArrayOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L)
private const val MAX_RECONNECT_DELAY_MILLIS = 30_000L

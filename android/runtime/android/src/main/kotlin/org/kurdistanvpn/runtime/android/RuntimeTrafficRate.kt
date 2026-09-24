// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

/** Display-only one-second sampling. Each admitted attempt owns a new sampler. */
internal class RuntimeTrafficRate {
    private var previousTime = -1L
    private var sent = 0L
    private var received = 0L

    fun sample(now: Long, totalSent: Long, totalReceived: Long): Pair<Long, Long>? {
        require(now >= 0 && totalSent >= 0 && totalReceived >= 0)
        val elapsed = now - previousTime
        if (previousTime >= 0 && elapsed in 0..999) return null
        val result = if (previousTime >= 0 && elapsed >= 1000)
            ((totalSent - sent).coerceAtLeast(0).toDouble() * 1000 / elapsed).toLong() to
                ((totalReceived - received).coerceAtLeast(0).toDouble() * 1000 / elapsed).toLong()
        else null
        previousTime = now; sent = totalSent; received = totalReceived
        return result
    }
}

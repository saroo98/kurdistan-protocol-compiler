// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

/**
 * Authority handoff starts before a TUN exists and therefore remains fail-closed
 * while Android asynchronously creates and binds the private authority process. The
 * wider startup window accommodates slow and heavily loaded devices. Once the
 * private pipe is connected, its read deadline stays deliberately narrow.
 */
internal object RuntimeAuthorityTimeoutPolicy {
    const val BIND_MILLIS = 30_000L
    const val ARRIVAL_MILLIS = 35_000L
    const val PENDING_DESCRIPTOR_MILLIS = ARRIVAL_MILLIS
    const val PIPE_READ_SECONDS = 5L
    fun pipeDeadline(requestDeadline: Long, now: Long): Long {
        require(now >= 0 && requestDeadline > now)
        return minOf(requestDeadline, Math.addExact(now, PIPE_READ_SECONDS * 1_000))
    }
}

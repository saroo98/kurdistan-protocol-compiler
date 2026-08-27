// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.util.concurrent.atomic.AtomicReference
import org.kurdistanvpn.runtime.api.VpnRuntimeState

internal data class RuntimeTermination(
    val state: VpnRuntimeState,
    val failure: String?,
)

/** One runtime generation only. Delivery consumption never rearms a stopped or revoked generation. */
internal class PendingRuntimeTermination {
    private data class State(val winner: RuntimeTermination? = null, val pending: RuntimeTermination? = null)
    private val value = AtomicReference(State())

    fun request(state: VpnRuntimeState, failure: String?) {
        require(state in setOf(VpnRuntimeState.IDLE, VpnRuntimeState.BLOCKED, VpnRuntimeState.FAILED, VpnRuntimeState.REVOKED))
        require(failure == null || failure.matches(Regex("[A-Z][A-Z0-9_]{0,63}")))
        val requested = RuntimeTermination(state, failure)
        value.updateAndGet { current ->
            if (current.winner == null || requested.priority() > current.winner.priority()) State(requested, requested) else current
        }
    }

    fun peek(): RuntimeTermination? = value.get().pending

    fun terminalOutcome(): RuntimeTermination? = value.get().winner

    fun take(): RuntimeTermination? {
        while (true) {
            val current = value.get()
            if (current.pending == null) return null
            if (value.compareAndSet(current, current.copy(pending = null))) return current.pending
        }
    }
}

private fun RuntimeTermination.priority(): Int = when (state) {
    VpnRuntimeState.REVOKED -> 3
    VpnRuntimeState.IDLE -> 2
    else -> 1
}

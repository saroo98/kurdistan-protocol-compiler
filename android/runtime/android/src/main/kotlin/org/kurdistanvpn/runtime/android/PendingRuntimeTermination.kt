// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.util.concurrent.atomic.AtomicReference
import org.kurdistanvpn.runtime.api.VpnRuntimeState

internal data class RuntimeTermination(
    val state: VpnRuntimeState,
    val failure: String?,
)

internal class PendingRuntimeTermination {
    private val value = AtomicReference<RuntimeTermination?>()

    fun request(state: VpnRuntimeState, failure: String?) {
        val requested = RuntimeTermination(state, failure)
        value.updateAndGet { current ->
            if (current == null || requested.priority() > current.priority()) requested else current
        }
    }

    fun peek(): RuntimeTermination? = value.get()

    fun take(): RuntimeTermination? = value.getAndSet(null)
}

private fun RuntimeTermination.priority(): Int = when (state) {
    VpnRuntimeState.REVOKED -> 3
    VpnRuntimeState.IDLE -> 2
    else -> 1
}

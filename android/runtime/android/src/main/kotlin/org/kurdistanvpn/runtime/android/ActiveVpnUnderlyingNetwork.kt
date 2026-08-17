// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import android.net.Network
import java.util.concurrent.atomic.AtomicReference

/** Process-local view of the carrier selected by the live VPN service. */
object ActiveVpnUnderlyingNetwork {
    private val state = ProcessLocalReference<Network>()

    fun publish(network: Network?) = state.publish(network)

    fun current(): Network? = state.current()
}

internal class ProcessLocalReference<T : Any> {
    private val value = AtomicReference<T?>()

    fun publish(current: T?) {
        value.set(current)
    }

    fun current(): T? = value.get()
}

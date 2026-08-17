// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

private const val INTERNAL_QUALIFICATION_PACKAGE = "org.kurdistanvpn.app.internal"

internal fun internalQualificationSocketProtectionEnabled(
    packageName: String,
    debuggable: Boolean,
): Boolean = debuggable && packageName == INTERNAL_QUALIFICATION_PACKAGE

internal class ActiveVpnOwnerSocketProtectorRegistry {
    private data class Registration(
        val owner: Any,
        val protect: (Socket) -> Boolean,
    )

    private val active = AtomicReference<Registration?>()

    fun register(
        owner: Any,
        debuggable: Boolean,
        protect: (Socket) -> Boolean,
    ) {
        if (!debuggable) {
            unregister(owner)
            return
        }
        active.set(Registration(owner, protect))
    }

    fun unregister(owner: Any) {
        while (true) {
            val registration = active.get() ?: return
            if (registration.owner !== owner) return
            if (active.compareAndSet(registration, null)) return
        }
    }

    fun protect(socket: Socket): Boolean = runCatching {
        active.get()?.protect?.invoke(socket) == true
    }.getOrDefault(false)
}

/**
 * Same-process protection for owner-operated qualification sockets. The active
 * VPN service registers only in debuggable variants, and no endpoint or socket
 * metadata crosses an IPC boundary or survives service teardown.
 */
object ActiveVpnOwnerSocketProtector {
    private val registry = ActiveVpnOwnerSocketProtectorRegistry()

    @JvmStatic
    fun protect(socket: Socket): Boolean = registry.protect(socket)

    internal fun register(
        owner: Any,
        debuggable: Boolean,
        protect: (Socket) -> Boolean,
    ) = registry.register(owner, debuggable, protect)

    internal fun unregister(owner: Any) = registry.unregister(owner)
}

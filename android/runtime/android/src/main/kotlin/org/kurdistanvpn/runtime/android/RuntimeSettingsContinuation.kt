// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.util.UUID

/** One observer-owned lifecycle continuation, not profile or execution authority. */
internal class RuntimeSettingsContinuation(private val now: () -> Long) {
    private data class Pending(val owner: Any, val token: String, val created: Long,
        var resumes: Int = 0, var request: String? = null)
    private var pending: Pending? = null
    @Synchronized fun hasPending(): Boolean = live() != null
    @Synchronized fun prepare(owner: Any): String? {
        live()
        if (pending != null) return null
        return id().also { pending = Pending(owner, it, now()) }
    }
    @Synchronized fun matches(owner: Any, token: String): Boolean =
        live()?.let { it.owner == owner && it.token == token } == true
    @Synchronized fun resume(owner: Any, token: String): String? {
        val value = live() ?: return null
        if (value.owner != owner || value.token != token || value.resumes >= 2) return null
        value.resumes++
        return id().also { value.request = it }
    }
    @Synchronized fun ownsRequest(owner: Any, token: String, request: String?): Boolean =
        matches(owner, token) && pending?.request == request
    @Synchronized fun invalidate(owner: Any? = null) {
        if (owner == null || pending?.owner == owner) pending = null
    }
    private fun live(): Pending? {
        val value = pending ?: return null
        val elapsed = now() - value.created
        if (elapsed !in 0 until 120_000) { pending = null; return null }
        return value
    }
    private fun id() = UUID.randomUUID().toString().replace("-", "")
}

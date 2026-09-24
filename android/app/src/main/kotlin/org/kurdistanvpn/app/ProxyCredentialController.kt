// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Activity-owned only. Callbacks run on the UI thread; no saved state or immutable secret strings. */
internal class ProxyCredentialController(
    private val now: () -> Long,
    private val authorize: ((Boolean) -> Unit) -> Unit,
    private val read: ((ByteArray?) -> Unit) -> Unit,
    private val rotateRemote: ((Boolean) -> Unit) -> Unit,
    private val copyToClipboard: (CharArray) -> Unit,
    private val clearClipboard: () -> Unit,
) : AutoCloseable {
    private val displayed = MutableStateFlow<CharArray?>(null)
    val visible = displayed.asStateFlow()
    private val unavailable = MutableStateFlow(false)
    val isUnavailable = unavailable.asStateFlow()
    private var generation = 0L
    private var foreground = true
    private var closed = false
    private var expires = 0L

    fun reveal() {
        if (closed || !foreground) return
        clear()
        val ticket = generation
        authorizeOnce { accepted ->
            if (!accepted && current(ticket)) unavailable.value = true
            if (accepted && current(ticket)) read { bytes ->
                try {
                    if (bytes != null && current(ticket) && valid(bytes)) {
                        expires = Math.addExact(now(), 60_000)
                        displayed.value = CharArray(bytes.size) { bytes[it].toInt().toChar() }
                    } else if (current(ticket)) unavailable.value = true
                } finally { bytes?.fill(0) }
            }
        }
    }

    fun copy() {
        expire()
        if (closed || !foreground || displayed.value == null) return
        val ticket = generation
        authorizeOnce { accepted ->
            if (accepted && current(ticket)) read { bytes ->
                var characters: CharArray? = null
                try {
                    if (bytes != null && current(ticket) && valid(bytes)) {
                        characters = CharArray(bytes.size) { bytes[it].toInt().toChar() }
                        copyToClipboard(characters)
                    } else if (current(ticket)) unavailable.value = true
                } finally { characters?.fill('\u0000'); bytes?.fill(0) }
            }
        }
    }

    fun rotate() {
        if (closed || !foreground) return
        clear()
        val ticket = generation
        authorizeOnce { accepted ->
            if (!accepted && current(ticket)) unavailable.value = true
            if (accepted && current(ticket)) rotateRemote { success ->
                if (current(ticket)) unavailable.value = !success
            }
        }
    }

    fun expire() {
        if (displayed.value != null && (now() >= expires || now() < expires - 60_000)) clear()
    }
    fun foreground() { if (!closed) foreground = true }
    fun background(preserveAuthorization: Boolean = false) {
        foreground = false
        clearSecrets()
        if (!preserveAuthorization) generation++
    }
    fun clear() {
        generation++
        clearSecrets()
    }
    private fun clearSecrets() {
        val old = displayed.value
        displayed.value = null
        old?.fill('\u0000')
        expires = 0
        unavailable.value = false
        clearClipboard()
    }
    override fun close() { closed = true; background() }
    private fun authorizeOnce(result: (Boolean) -> Unit) {
        var consumed = false
        authorize { accepted ->
            if (!consumed) {
                consumed = true
                result(accepted)
            }
        }
    }
    private fun current(ticket: Long) = !closed && foreground && generation == ticket
    private fun valid(bytes: ByteArray) = bytes.size == 60 && bytes[16] == ':'.code.toByte() &&
        bytes.indices.all { it == 16 || bytes[it].toInt().let { c ->
            c in 65..90 || c in 97..122 || c in 48..57 || c == 45 || c == 95 } }
}

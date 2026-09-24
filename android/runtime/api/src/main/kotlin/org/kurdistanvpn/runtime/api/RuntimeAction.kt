// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.api

/** Explicit Android control codes, independent of enum order and the native protocol. */
enum class RuntimeAction(val wireCode: Int) {
    START(1), STOP(2), PAUSE(3), RESUME(4), RECONNECT(5), RECOVER_INTERNET(6),
    ROTATE_PROXY_CREDENTIALS(7), QUERY_STATUS(8), RESTART_PROXY(9);

    companion object {
        fun fromWire(code: Int): RuntimeAction? = entries.firstOrNull { it.wireCode == code }
    }
}

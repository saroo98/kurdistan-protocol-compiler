// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

internal enum class ProcessRole { MAIN, VPN, OTHER }

internal fun processRole(packageName: String, processName: String?): ProcessRole =
    when (processName) {
        packageName -> ProcessRole.MAIN
        "$packageName:vpn" -> ProcessRole.VPN
        else -> ProcessRole.OTHER
    }

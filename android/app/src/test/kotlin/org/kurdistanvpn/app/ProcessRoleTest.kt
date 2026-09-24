// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.assertEquals
import org.junit.Test

class ProcessRoleTest {
    @Test fun onlyExactDeclaredProcessesReceiveAProductGraph() {
        val name = "org.kurdistanvpn.app"
        assertEquals(ProcessRole.MAIN, processRole(name, name))
        assertEquals(ProcessRole.VPN, processRole(name, "$name:vpn"))
        for (unknown in listOf(null, "", "other:vpn", "$name:worker", "${name}suffix")) {
            assertEquals(ProcessRole.OTHER, processRole(name, unknown))
        }
    }
}

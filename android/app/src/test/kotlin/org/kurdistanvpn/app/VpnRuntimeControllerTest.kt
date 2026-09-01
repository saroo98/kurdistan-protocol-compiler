// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test

class VpnRuntimeControllerTest {
    @Test fun consumedConsentTicketCannotSurviveStopOrAnotherUserStart() {
        val gate = ManualStartAdmission()
        val first = gate.stage()
        assertEquals(first, gate.consume())
        assertTrue(gate.isCurrent(first))
        gate.cancel()
        assertFalse(gate.isCurrent(first))
        val second = gate.stage()
        assertEquals(second, gate.consume())
        val newest = gate.stage()
        assertFalse(gate.isCurrent(second))
        assertTrue(gate.isCurrent(newest))
        assertEquals(newest, gate.consume())
        assertNull(gate.consume())
    }

    @Test fun consentStageIsOneUseAndContainsNoAuthority() {
        val gate = ManualStartAdmission()
        assertNull(gate.consume())
        val token = gate.stage()
        assertEquals(token, gate.consume())
        assertNull(gate.consume())
    }
    @Test fun stopAndNewUserIntentDefeatPendingStart() {
        val gate = ManualStartAdmission()
        val old = gate.stage()
        gate.cancel()
        assertFalse(gate.isCurrent(old))
        assertNull(gate.consume())
        val fresh = gate.stage()
        assertNotEquals(old, fresh)
        assertFalse(gate.isCurrent(old))
        assertTrue(gate.isCurrent(fresh))
    }
    @Test fun closePermanentlyRejectsStageAndEveryDelayedCallback() {
        val gate = ManualStartAdmission()
        val old = gate.stage()
        gate.close()
        assertNull(gate.consume())
        assertFalse(gate.isCurrent(old))
        assertThrows(IllegalStateException::class.java) { gate.stage() }
    }
}

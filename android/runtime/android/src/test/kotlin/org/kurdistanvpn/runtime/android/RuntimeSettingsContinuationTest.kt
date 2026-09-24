// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test

class RuntimeSettingsContinuationTest {
    @Test fun onlyCurrentOwnerCanResumeTwiceAndUserStopPreemptsRollback() {
        var now = 10L
        val gate = RuntimeSettingsContinuation { now }
        val owner = Any()
        val token = checkNotNull(gate.prepare(owner))
        assertTrue(gate.hasPending())
        assertNull(gate.prepare(owner))
        assertNull(gate.resume(Any(), token))
        val first = checkNotNull(gate.resume(owner, token))
        val second = checkNotNull(gate.resume(owner, token))
        assertNotEquals(first, second)
        assertNull(gate.resume(owner, token))
        gate.invalidate()
        assertFalse(gate.hasPending())
        assertFalse(gate.matches(owner, token))
        assertNull(gate.resume(owner, token))
        val next = checkNotNull(gate.prepare(owner))
        now += 120_000
        assertNull(gate.resume(owner, next))
        assertFalse(gate.hasPending())
    }
    @Test fun observerLossAndClockReversalInvalidateOnlyTheMatchingOwner() {
        var now = 100L
        val gate = RuntimeSettingsContinuation { now }
        val owner = Any()
        val token = checkNotNull(gate.prepare(owner))
        gate.invalidate(Any())
        assertTrue(gate.matches(owner, token))
        gate.invalidate(owner)
        assertFalse(gate.matches(owner, token))
        val next = checkNotNull(gate.prepare(owner))
        now = 99
        assertFalse(gate.matches(owner, next))
    }
}

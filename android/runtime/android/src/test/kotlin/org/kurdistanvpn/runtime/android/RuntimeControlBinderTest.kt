// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.RuntimeStatusWire

class RuntimeControlBinderTest {
    @Test fun foreignUidAndMalformedTransactionNeverRegisterOrConsumeAction() {
        val gate = RuntimeControlAdmission(1000)
        val version = RuntimeStatusWire.VERSION
        assertFalse(gate.allowed(1001, 1, version, 1))
        assertFalse(gate.allowed(1000, 0, version, 1))
        assertFalse(gate.allowed(1000, 1, version + 1, 1))
        assertFalse(gate.allowed(1000, 1, version - 1, 1))
        assertFalse(gate.allowed(1000, 1, version, 8193))
        assertTrue(gate.allowed(1000, 1, version, 8192))
    }

    @Test fun eachProcessHasOneObserverAndAnIncreasingActionSequence() {
        val gate = RuntimeControlAdmission(1000)
        val first = Any(); val replacement = Any()
        assertTrue(gate.register(10, first))
        assertFalse(gate.register(10, replacement))
        assertTrue(gate.consume(10, first, 1))
        assertFalse(gate.consume(10, first, 1))
        assertFalse(gate.consume(10, replacement, 2))
        assertTrue(gate.consume(10, first, 2))
        gate.remove(10, replacement)
        assertFalse(gate.register(10, replacement))
        gate.remove(10, first)
        assertTrue(gate.register(10, replacement))
        assertFalse(gate.consume(10, first, 3))
        assertTrue(gate.consume(10, replacement, 1))
    }

    @Test fun observerCapacityIsBoundedAndCloseRejectsEveryFutureRequest() {
        val gate = RuntimeControlAdmission(1000)
        val tokens = List(5) { Any() }
        repeat(4) { assertTrue(gate.register(it + 1, tokens[it])) }
        assertFalse(gate.register(5, tokens[4]))
        gate.close()
        assertFalse(gate.register(1, Any()))
        assertFalse(gate.consume(1, tokens[0], 1))
        assertFalse(gate.allowed(1000, 1, RuntimeStatusWire.VERSION, 1))
    }

    @Test fun observerTokenCannotBeSharedAcrossProcessesOrRemovedByAnotherProcess() {
        val gate = RuntimeControlAdmission(1000)
        val token = Any()
        assertTrue(gate.register(10, token))
        assertFalse(gate.register(11, token))
        assertFalse(gate.remove(11, token))
        assertTrue(gate.consume(10, token, 1))
        assertTrue(gate.remove(10, token))
        assertTrue(gate.register(11, token))
    }
}

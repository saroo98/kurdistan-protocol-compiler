// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ActiveVpnUnderlyingNetworkTest {
    @Test
    fun processLocalReferencePublishesReplacesAndClearsTheCarrier() {
        val state = ProcessLocalReference<String>()
        assertNull(state.current())
        state.publish("first")
        assertEquals("first", state.current())
        state.publish("second")
        assertEquals("second", state.current())
        state.publish(null)
        assertNull(state.current())
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativejni.AndroidPlatformConformanceV1

/** Compile-only in unit6b4b. Execution requires the separately approved internal installed lane. */
class AndroidPlatformProducerIntegrationTest {
    @Test fun actualLoadedTableAndGateLayoutsArePresentAndUnownedCallsCannotAcquireAuthority() {
        val layout = LongArray(12)
        assertEquals(0, AndroidPlatformConformanceV1.copyLayout(layout))
        assertTrue(layout.all { it > 0 })
        assertEquals(layout[0], layout[3]) // One shared C64-slot backing, not two registries.
        assertEquals(25, AndroidPlatformConformanceV1.rejectUnownedCancellation())
    }
}

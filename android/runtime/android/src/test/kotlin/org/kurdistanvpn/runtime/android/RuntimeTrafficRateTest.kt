// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test

class RuntimeTrafficRateTest {
    @Test fun samplesElapsedTimeWithoutOverflowOrReusingAnotherSessionsCounters() {
        val rate = RuntimeTrafficRate()
        assertNull(rate.sample(1000, 10, 20))
        assertNull(rate.sample(1500, 510, 1020))
        assertEquals(1000L to 2000L, rate.sample(2000, 1010, 2020))
        assertEquals(0L to 0L, rate.sample(3000, 0, 0))
        assertEquals(Long.MAX_VALUE to Long.MAX_VALUE, rate.sample(4000, Long.MAX_VALUE, Long.MAX_VALUE))
        assertNull(rate.sample(3999, Long.MAX_VALUE, Long.MAX_VALUE))
    }
}

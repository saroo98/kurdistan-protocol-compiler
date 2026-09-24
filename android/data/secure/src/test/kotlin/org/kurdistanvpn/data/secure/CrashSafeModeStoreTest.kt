// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*

class CrashSafeModeStoreTest {
    @Test fun malformedCrashFlagsAndCountersFailClosed() {
        val bytes = StoredCrashSafeMode(0, false, 0, false).encode()
        checkMalformed(bytes, listOf({ putLong(it, 6, -1) }, { it[14] = 2 }, { it[15] = 11 }, { it[16] = 2 },
            { it[15] = 3 }, { it[16] = 1 })) { StoredCrashSafeMode.decode(it) }
    }
    @Test fun crashRoundTripAndExplicitTransitionsNeverMutateReads() {
        val value = StoredCrashSafeMode(7, false, 2, false)
        checkRecord(value.encode(), 29, 64) { StoredCrashSafeMode.decode(it).encode() }
        assertTrue(value.started(8).safeMode)
        assertEquals(10, StoredCrashSafeMode(7, false, 10, true).started(8).consecutiveUncleanStarts)
        assertEquals(0, value.cleanStopped().started(8).consecutiveUncleanStarts)
        assertEquals(2, value.consecutiveUncleanStarts)
        for (bad in listOf<() -> Any>({ StoredCrashSafeMode(-1, false, 0, false) }, { StoredCrashSafeMode(0, false, 11, true) },
            { StoredCrashSafeMode(0, false, 3, false) }, { StoredCrashSafeMode(0, false, 2, true) }))
            assertThrows(IllegalArgumentException::class.java) { bad() }
    }
    @Test fun crashWrapperContract() {
        val value = StoredCrashSafeMode(0, true, 0, false)
        checkStore("crash-safe-mode-current", SecureDataClass.CRASH_SAFE_MODE_STATE, value.encode(),
            { CrashSafeModeStore(it).save(value) }, { CrashSafeModeStore(it).load()?.encode() },
            { CrashSafeModeStore(it).delete() }, { CrashSafeModeStore.readOnly(it).save(value) },
            { CrashSafeModeStore.readOnly(it).delete() })
    }
}

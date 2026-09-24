// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test

class PauseStateStoreTest {
    @Test fun elapsedClockOwnsSameBootExpiryAndRebootUsesNonReversedWallClock() {
        val pause = StoredPauseState(100_000, 10_000, 3, 60_000)
        assertFalse(pause.expired(999_999, 69_999, 3))
        assertTrue(pause.expired(1, 70_000, 3))
        assertFalse(pause.expired(160_000, 9_999, 3))
        assertTrue(pause.expired(160_000, 100, 4))
        assertFalse(pause.expired(99_999, 100, 4))
        assertFalse(pause.expired(160_000, 100, -1))
        assertFalse(StoredPauseState(100_000, 10_000, 3, 0).expired(Long.MAX_VALUE, Long.MAX_VALUE, 4))
    }
    @Test fun boundedCanonicalPauseRecordRejectsTruncationAndTrailingBytes() {
        val pause = StoredPauseState(100_000, 10_000, 3, 60_000)
        val encoded = pause.encode()
        assertArrayEquals(encoded, StoredPauseState.decode(encoded).encode())
        for (size in 0 until encoded.size) assertThrows(IllegalArgumentException::class.java) {
            StoredPauseState.decode(encoded.copyOf(size))
        }
        assertThrows(IllegalArgumentException::class.java) { StoredPauseState.decode(encoded + 0) }
        assertThrows(IllegalArgumentException::class.java) { StoredPauseState(0, 0, 0, 86_400_001) }
    }
}

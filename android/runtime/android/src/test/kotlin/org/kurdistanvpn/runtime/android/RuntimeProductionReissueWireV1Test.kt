// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test

class RuntimeProductionReissueWireV1Test {
    @Test fun completionRepliesKeepLegacyBooleanAndStrictProductionDeadlineLayouts() {
        fun encoded(production: Boolean, status: Int, deadline: Long): java.nio.ByteBuffer {
            val bytes = java.nio.ByteBuffer.allocate(32)
            RuntimeProductionReissueWireV1.writeCompletionReply(production, status, deadline,
                { bytes.putInt(it) }, { bytes.putLong(it) })
            bytes.flip()
            return bytes
        }
        for (status in 0..1) {
            val legacy = encoded(false, status, 0)
            assertEquals(4, legacy.remaining()); assertEquals(status, legacy.int); assertFalse(legacy.hasRemaining())
        }
        val accepted = encoded(true, 1, 3500)
        assertEquals(12, accepted.remaining())
        assertEquals(3500L, RuntimeProductionReissueWireV1.readCompletionReply(12, accepted.int, accepted.long, 60000))
        val rejected = encoded(true, 0, 0)
        assertNull(RuntimeProductionReissueWireV1.readCompletionReply(12, rejected.int, rejected.long, 60000))
        for (bytes in listOf(0, 4, 8, 11, 13, 16)) assertThrows(IllegalArgumentException::class.java) {
            RuntimeProductionReissueWireV1.readCompletionReply(bytes, 1, 3500, 60000)
        }
        for ((status, deadline) in listOf(-1 to 0L, 2 to 0L, 0 to 1L, 1 to 0L, 1 to -1L, 1 to 60001L)) {
            assertThrows(IllegalArgumentException::class.java) {
                RuntimeProductionReissueWireV1.readCompletionReply(12, status, deadline, 60000)
            }
        }
    }
    @Test fun onlyTheTenSuccessorOpcodesSelectTheVersionThreeParser() {
        val accepted = (0..200).filter { RuntimeProductionReissueWireV1.acceptsOpcode(it) }
        assertEquals(listOf(101, 102, 103, 104, 105, 106, 107, 108, 109, 110), accepted)
        assertFalse(RuntimeProductionReissueWireV1.acceptsOpcode(Int.MIN_VALUE))
        assertFalse(RuntimeProductionReissueWireV1.acceptsOpcode(Int.MAX_VALUE))
    }

    @Test fun freshObservationDeadlineDoesNotRenewAnOldStart() {
        assertTrue(RuntimeProductionReissueWireV1.validObservationDeadline(100, 60100))
        assertFalse(RuntimeProductionReissueWireV1.validObservationDeadline(100, 60101))
        assertFalse(RuntimeProductionReissueWireV1.validObservationDeadline(100, 100))
        assertFalse(RuntimeProductionReissueWireV1.validObservationDeadline(-1, 100))
        assertFalse(RuntimeProductionReissueWireV1.validObservationDeadline(Long.MAX_VALUE, Long.MIN_VALUE))
        assertTrue(RuntimeProductionReissueWireV1.validObservationDeadline(Long.MAX_VALUE - 1, Long.MAX_VALUE))
    }
}

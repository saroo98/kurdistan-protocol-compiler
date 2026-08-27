// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeAuthorityTimeoutPolicyTest {
    @Test fun pipeDeadlineNeverExtendsTheAuthenticatedRequestOrPermitsInvalidClockValues() {
        assertEquals(5_100L, RuntimeAuthorityTimeoutPolicy.pipeDeadline(60_000, 100))
        assertEquals(101L, RuntimeAuthorityTimeoutPolicy.pipeDeadline(101, 100))
        assertEquals(5_100L, RuntimeAuthorityTimeoutPolicy.pipeDeadline(5_100, 100))
        for ((deadline, now) in listOf(100L to 100L, 99L to 100L, 100L to -1L, 0L to 0L)) {
            org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
                RuntimeAuthorityTimeoutPolicy.pipeDeadline(deadline, now)
            }
        }
        org.junit.Assert.assertThrows(ArithmeticException::class.java) {
            RuntimeAuthorityTimeoutPolicy.pipeDeadline(Long.MAX_VALUE, Long.MAX_VALUE - 1)
        }
    }

    @Test
    fun asynchronousServiceStartupHasABoundedSlowDeviceWindow() {
        assertTrue(RuntimeAuthorityTimeoutPolicy.BIND_MILLIS >= 30_000L)
        assertTrue(
            RuntimeAuthorityTimeoutPolicy.ARRIVAL_MILLIS >=
                RuntimeAuthorityTimeoutPolicy.BIND_MILLIS +
                RuntimeAuthorityTimeoutPolicy.PIPE_READ_SECONDS * 1_000L,
        )
        assertEquals(
            RuntimeAuthorityTimeoutPolicy.ARRIVAL_MILLIS,
            RuntimeAuthorityTimeoutPolicy.PENDING_DESCRIPTOR_MILLIS,
        )
    }

    @Test
    fun establishedPipeReadRetainsTheNarrowTimeout() {
        assertEquals(5L, RuntimeAuthorityTimeoutPolicy.PIPE_READ_SECONDS)
        assertTrue(
            RuntimeAuthorityTimeoutPolicy.PIPE_READ_SECONDS * 1_000L <
                RuntimeAuthorityTimeoutPolicy.BIND_MILLIS,
        )
    }
}

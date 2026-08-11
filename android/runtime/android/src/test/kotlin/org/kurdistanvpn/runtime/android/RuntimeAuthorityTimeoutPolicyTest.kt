// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RuntimeAuthorityTimeoutPolicyTest {
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

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class VpnRuntimeContractTest {
    @Test
    fun defaultSnapshotIsTruthfullyIdleAndUnprotected() {
        val snapshot = VpnRuntimeSnapshot()

        assertEquals(VpnRuntimeState.IDLE, snapshot.state)
        assertEquals(0, snapshot.packetsRead)
        assertEquals(0, snapshot.packetsWritten)
        assertFalse(snapshot.alwaysOn)
        assertFalse(snapshot.lockdown)
    }

    @Test
    fun inputEofIsReportedAsUnexpected() {
        val loop = TunPacketLoop(
            ByteArrayInputStream(byteArrayOf()),
            ByteArrayOutputStream(),
            kurdRoundTrip = { it.copyOf() },
            onPacketCount = { _, _, _ -> },
        )

        assertEquals(TunPacketLoop.ExitReason.INPUT_EOF, loop.run())
    }

    @Test
    fun inputFailureIsReportedAsUnexpected() {
        val input = object : InputStream() {
            override fun read(): Int = throw IOException("test input failure")
        }
        val loop = TunPacketLoop(
            input,
            ByteArrayOutputStream(),
            kurdRoundTrip = { it.copyOf() },
            onPacketCount = { _, _, _ -> },
        )

        assertEquals(TunPacketLoop.ExitReason.INPUT_FAILURE, loop.run())
    }

    @Test
    fun explicitCloseIsNotReportedAsFailure() {
        val loop = TunPacketLoop(
            ByteArrayInputStream(byteArrayOf()),
            ByteArrayOutputStream(),
            kurdRoundTrip = { it.copyOf() },
            onPacketCount = { _, _, _ -> },
        )

        loop.close()

        assertEquals(TunPacketLoop.ExitReason.STOP_REQUESTED, loop.run())
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.kurdistanvpn.runtime.api.VpnRuntimeSnapshot
import org.kurdistanvpn.runtime.api.VpnRuntimeState

class VpnRuntimeContractTest {
    @Test fun onlyPreciselyMarkedPrivateCommandsAreManualAndExtrasNeverSupplyAuthority() {
        val id = "1".repeat(32)
        val valid = mapOf<String, Any?>(RuntimeServiceCommand.MARKER_KEY to RuntimeServiceCommand.MARKER_VERSION,
            RuntimeServiceCommand.REQUEST_KEY to id)
        assertEquals(RuntimeServiceCommand.Manual(id), RuntimeServiceCommand.fromScalars(RuntimeServiceCommand.ACTION_START, valid))
        assertEquals(RuntimeServiceCommand.Stop, RuntimeServiceCommand.fromScalars(RuntimeServiceCommand.ACTION_STOP,
            mapOf(RuntimeServiceCommand.MARKER_KEY to RuntimeServiceCommand.MARKER_VERSION)))
        for (action in listOf(null, "android.net.VpnService", "synthetic.lifecycle"))
            assertEquals(RuntimeServiceCommand.AutomaticTrigger, RuntimeServiceCommand.fromScalars(action, emptyMap()))
        val invalid = listOf(valid + ("authority" to byteArrayOf(1)), valid + (RuntimeServiceCommand.MARKER_KEY to "2"),
            valid - RuntimeServiceCommand.MARKER_KEY, valid + (RuntimeServiceCommand.REQUEST_KEY to 42))
        for (extras in invalid) org.junit.Assert.assertTrue(
            RuntimeServiceCommand.fromScalars(RuntimeServiceCommand.ACTION_START, extras) is RuntimeServiceCommand.Rejected)
    }

    @Test
    fun defaultSnapshotIsTruthfullyIdleAndUnprotected() {
        val snapshot = VpnRuntimeSnapshot()

        assertEquals(VpnRuntimeState.IDLE, snapshot.state)
        assertEquals(0, snapshot.packetsRead)
        assertEquals(0, snapshot.packetsWritten)
        assertFalse(snapshot.alwaysOn)
        assertFalse(snapshot.lockdown)
        assertEquals(0, snapshot.maxReconnectAttempts)
        assertEquals(null, snapshot.runtimeRequestId)
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

    @Test
    fun readinessPollingMakesStopBoundedWithoutClosingFromAnotherThread() {
        val result = AtomicReference<TunPacketLoop.ExitReason>()
        val loop = TunPacketLoop(
            ByteArrayInputStream(byteArrayOf()),
            ByteArrayOutputStream(),
            kurdRoundTrip = { it.copyOf() },
            onPacketCount = { _, _, _ -> },
            awaitReadable = {
                Thread.sleep(10)
                false
            },
        )
        val worker = Thread({ result.set(loop.run()) }, "tun-loop-stop-test")

        worker.start()
        Thread.sleep(30)
        loop.requestStop()
        worker.join(1_000)

        assertFalse("readiness polling did not stop within the bound", worker.isAlive)
        assertEquals(TunPacketLoop.ExitReason.STOP_REQUESTED, result.get())
        loop.close()
    }
}

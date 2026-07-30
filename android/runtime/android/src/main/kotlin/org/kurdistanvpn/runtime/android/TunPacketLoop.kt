// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.android

import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

internal class TunPacketLoop(
    private val input: InputStream,
    private val output: OutputStream,
    private val kurdRoundTrip: (ByteArray) -> ByteArray?,
    private val onPacketCount: (Long, Long, String) -> Unit,
) : AutoCloseable {
    enum class ExitReason {
        STOP_REQUESTED,
        INPUT_EOF,
        INPUT_FAILURE,
    }

    private val running = AtomicBoolean(true)
    private val packets = AtomicLong(0)
    private val replies = AtomicLong(0)

    fun run(): ExitReason {
        val packet = ByteArray(MAX_PACKET_BYTES)
        while (running.get()) {
            val read = try {
                input.read(packet)
            } catch (_: Exception) {
                packet.fill(0)
                return if (running.get()) ExitReason.INPUT_FAILURE else ExitReason.STOP_REQUESTED
            }
            if (read < 0) {
                packet.fill(0)
                return if (running.get()) ExitReason.INPUT_EOF else ExitReason.STOP_REQUESTED
            }
            if (read == 0) {
                continue
            }
            val count = packets.incrementAndGet()
            val result = DeterministicPacketEngine.reply(packet, read, kurdRoundTrip)
            result.response?.let { response ->
                output.write(response)
                replies.incrementAndGet()
                response.fill(0)
            }
            onPacketCount(count, replies.get(), result.disposition)
            packet.fill(0, 0, read)
        }
        packet.fill(0)
        return ExitReason.STOP_REQUESTED
    }

    override fun close() {
        running.set(false)
        runCatching { input.close() }
        runCatching { output.close() }
    }

    private companion object {
        const val MAX_PACKET_BYTES = 32 * 1024
    }
}

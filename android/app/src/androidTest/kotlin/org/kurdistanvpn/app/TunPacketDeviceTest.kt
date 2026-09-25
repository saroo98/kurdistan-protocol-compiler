// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.os.ParcelFileDescriptor
import android.system.Os
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.android.AndroidTunPacketEndpoint

/** Local descriptor checks only: no profiles, VPN consent, routing or external traffic. */
class TunPacketDeviceTest {
    @Test fun directBufferIoKeepsExactBytesAndCloseReleasesAWaitingRead() {
        val pair = ParcelFileDescriptor.createSocketPair()
        val endpoint = AndroidTunPacketEndpoint()
        endpoint.acquire { pair[0] }
        try {
            val packet = ByteArray(40).apply { this[0] = 0x60 }
            assertEquals(40, Os.write(pair[1].fileDescriptor, packet, 0, packet.size))
            val input = ByteBuffer.allocateDirect(65535)
            assertEquals(40, endpoint.read(input))
            assertEquals(0x60, input.get(0).toInt())
            input.position(0); input.limit(40)
            assertEquals(40, endpoint.write(input))
            val returned = ByteArray(40)
            assertEquals(40, Os.read(pair[1].fileDescriptor, returned, 0, returned.size))
            assertArrayEquals(packet, returned)
            val waiting = CountDownLatch(1)
            val finished = CountDownLatch(1)
            var result = 0
            val worker = Thread {
                waiting.countDown()
                try { result = endpoint.read(ByteBuffer.allocateDirect(65535)) }
                finally { finished.countDown() }
            }
            worker.start()
            assertTrue(waiting.await(2, TimeUnit.SECONDS))
            assertFalse(finished.await(100, TimeUnit.MILLISECONDS))
            val written = CountDownLatch(1)
            var writeFailure: Throwable? = null
            val writer = Thread {
                try {
                    val outbound = ByteBuffer.allocateDirect(packet.size).apply { put(packet); flip() }
                    assertEquals(packet.size, endpoint.write(outbound))
                } catch (failure: Throwable) { writeFailure = failure }
                finally { written.countDown() }
            }
            writer.start()
            try {
                assertTrue("An idle read must not starve the reply writer", written.await(2, TimeUnit.SECONDS))
                writeFailure?.let { throw AssertionError("Concurrent packet write failed", it) }
                assertEquals(40, Os.read(pair[1].fileDescriptor, returned, 0, returned.size))
                assertArrayEquals(packet, returned)
            } finally {
                endpoint.close()
                writer.join(2000)
                worker.join(2000)
            }
            endpoint.close()
            assertTrue(finished.await(2, TimeUnit.SECONDS))
            worker.join(2000)
            assertEquals(-1, result)
            endpoint.close()
        } finally { endpoint.close(); pair[1].close() }
    }
}

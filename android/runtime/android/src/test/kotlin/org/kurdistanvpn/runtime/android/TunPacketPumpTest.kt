// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class TunPacketPumpTest {
    @Test fun rejectedPacketIsDroppedWithoutDisconnectingOrCountingItAsForwarded() {
        val native = Session(waitForCancel = true, submitFailure = ProductFailureCode.ROUTE_POLICY_REJECTED)
        val failures = AtomicInteger()
        val tun = object : TunPacketEndpoint {
            var remaining = 2
            val closed = CountDownLatch(1)
            override fun read(output: ByteBuffer): Int {
                if (remaining-- > 0) { output.put(0, 0x45); return 40 }
                check(closed.await(5, TimeUnit.SECONDS)); return -1
            }
            override fun write(input: ByteBuffer) = error("unused")
            override fun close() { closed.countDown() }
        }
        val pump = TunPacketPump(native, tun, 1280) { failures.incrementAndGet() }
        pump.start()
        assertTrue(native.sent.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(2, native.submitted.get())
        assertEquals(1L, pump.snapshot().outboundPackets)
        assertEquals(40L, pump.snapshot().outboundBytes)
        assertEquals(0, failures.get())
    }
    @Test fun outboundIpv4AndMaximumIpv6FramesKeepTheirExactLength() {
        for ((length, version) in listOf(20 to 0x45, 1280 to 0x60)) {
            val native = Session(waitForCancel = true)
            val pump = TunPacketPump(native, Endpoint(outboundLength = length, version = version), 1280) {}
            pump.start()
            assertTrue(native.sent.await(3, TimeUnit.SECONDS))
            pump.close()
            assertEquals(length, native.sentLength)
            assertEquals(version, native.sentVersion)
            assertEquals(length.toLong(), pump.snapshot().outboundBytes)
        }
    }

    @Test fun zeroAndOversizedFramesNeverReachNative() {
        for (length in listOf(0, 1281, 65535)) {
            val native = Session(waitForCancel = true)
            val failed = CountDownLatch(1)
            val pump = TunPacketPump(native, Endpoint(outboundLength = length), 1280) { failed.countDown() }
            pump.start()
            assertTrue(failed.await(3, TimeUnit.SECONDS))
            pump.close()
            assertEquals(0, native.submitted.get())
        }
    }
    @Test fun idleNativeReadTimeoutDoesNotDisconnectTheTunnel() {
        val native = Session(firstFailure = ProductFailureCode.OPERATION_TIMED_OUT)
        val pump = TunPacketPump(native, Endpoint(), 1280) {}
        pump.start()
        assertTrue(native.confirmed.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(1L, pump.snapshot().inboundPackets)
    }

    @Test fun receiptRetirementBackpressureRetriesWithoutAddingAPacketQueue() {
        val native = Session(firstFailure = ProductFailureCode.RESOURCE_LIMIT)
        val pump = TunPacketPump(native, Endpoint(), 1280) {}
        pump.start()
        assertTrue(native.confirmed.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(1L, pump.snapshot().inboundPackets)
    }
    @Test fun exactWriteAcknowledgesReceiptAndCancellationReleasesBothWorkers() {
        val native = Session()
        val tun = Endpoint()
        val pump = TunPacketPump(native, tun, 1280) {}
        pump.start()
        assertTrue(native.confirmed.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(7L, native.confirmedToken)
        assertEquals(40, native.confirmedLength)
        assertEquals(0, native.rejected.get())
        assertEquals(1, native.cancelled.get())
        assertEquals(1, tun.closed.get())
        assertEquals(40, tun.written)
        assertEquals(1L, pump.snapshot().inboundPackets)
        pump.close()
        assertEquals(1, native.cancelled.get())
    }

    @Test fun shortWriteRejectsReceiptAndNeverAcknowledgesPartialPacket() {
        val native = Session()
        val tun = Endpoint(shortWrite = true)
        val failed = CountDownLatch(1)
        val pump = TunPacketPump(native, tun, 1280) { failed.countDown() }
        pump.start()
        assertTrue(failed.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(1, native.rejected.get())
        assertEquals(1L, native.confirmed.count)
        assertEquals(0L, pump.snapshot().inboundPackets)
    }

    @Test fun outboundEofStopsWithoutSubmittingAnEmptyPacket() {
        val native = Session(waitForCancel = true)
        val failed = CountDownLatch(1)
        val tun = Endpoint(eof = true)
        val pump = TunPacketPump(native, tun, 1280) { failed.countDown() }
        pump.start()
        assertTrue(failed.await(3, TimeUnit.SECONDS))
        pump.close()
        assertEquals(0, native.submitted.get())
        assertEquals(1, native.cancelled.get())
    }

    private class Endpoint(val shortWrite: Boolean = false, val eof: Boolean = false,
        var outboundLength: Int? = null, val version: Int = 0x45) : TunPacketEndpoint {
        val closed = AtomicInteger()
        private val stop = CountDownLatch(1)
        var written = 0
        override fun read(output: ByteBuffer): Int {
            outboundLength?.let { length ->
                outboundLength = null
                output.put(0, version.toByte())
                return length
            }
            if (!eof) check(stop.await(5, TimeUnit.SECONDS))
            return -1
        }
        override fun write(input: ByteBuffer): Int {
            assertTrue(input.isDirect)
            assertEquals(0x60, input.get(0).toInt())
            written = input.remaining()
            return written - if (shortWrite) 1 else 0
        }
        override fun close() { closed.incrementAndGet(); stop.countDown() }
    }

    private class Session(val waitForCancel: Boolean = false,
        var firstFailure: ProductFailureCode? = null, var submitFailure: ProductFailureCode? = null) : ProductionNativeSession {
        val confirmed = CountDownLatch(1)
        val cancelled = AtomicInteger()
        val rejected = AtomicInteger()
        val submitted = AtomicInteger()
        val sent = CountDownLatch(1)
        var sentLength = 0
        var sentVersion = 0
        var confirmedToken = 0L
        var confirmedLength = 0
        private val stop = CountDownLatch(1)
        private var delivered = false
        override val openingSnapshot: NativeOpeningSnapshot get() = error("not used by packet port")
        override fun receiveInboundPacket(output: ByteBuffer): NativeProductResult<NativePacketDelivery> {
            firstFailure?.let { firstFailure = null; return NativeProductResult.Failure(it) }
            if (delivered || waitForCancel) {
                check(stop.await(5, TimeUnit.SECONDS))
                return NativeProductResult.Failure(ProductFailureCode.CANCELLED)
            }
            delivered = true
            assertTrue(output.isDirect)
            output.put(0, 0x60)
            return NativeProductResult.Success(NativePacketDelivery(40, 7))
        }
        override fun confirmInboundDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit> {
            confirmedToken = token; confirmedLength = deliveredLength; confirmed.countDown()
            return NativeProductResult.Success(Unit)
        }
        override fun rejectInboundDelivery(token: Long): NativeProductResult<Unit> {
            assertEquals(7L, token); rejected.incrementAndGet(); return NativeProductResult.Success(Unit)
        }
        override fun submitOutboundPacket(packet: ByteBuffer, length: Int): NativeProductResult<Unit> {
            assertTrue(packet.isDirect)
            assertEquals(length, packet.remaining())
            sentLength = length; sentVersion = packet.get(0).toInt() and 255
            submitted.incrementAndGet()
            submitFailure?.let { submitFailure = null; return NativeProductResult.Failure(it) }
            sent.countDown(); return NativeProductResult.Success(Unit)
        }
        override fun cancel(): NativeProductResult<Unit> {
            cancelled.incrementAndGet(); stop.countDown(); return NativeProductResult.Success(Unit)
        }
        override fun close() = error("pump does not own native retirement")
        override fun nextControl(output: ByteBuffer): NativeProductResult<NativeControlEvent> = error("unused")
        override fun confirmSocketProtection(token: Long, protected: Boolean, networkHandle: Long?): NativeProductResult<Unit> = error("unused")
        override fun openProxyStream(request: NativeProxyRequest): NativeProductResult<NativeProxyStream> = error("unused")
        override fun runProbe(request: NativeProbeRequest): NativeProductResult<NativeProbeResult> = error("unused")
        override fun requestReconnect(reason: NativeReconnectReason): NativeProductResult<Unit> = error("unused")
        override fun requestHandover(networkHandle: Long?): NativeProductResult<Unit> = error("unused")
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.ProductionNativeSession

/** Packet-preserving endpoint. Closing must release a blocked read; writes never retry a short packet. */
interface TunPacketEndpoint : Closeable {
    fun read(output: ByteBuffer): Int
    fun write(input: ByteBuffer): Int
}

internal data class TunPacketCounts(val outboundPackets: Long, val inboundPackets: Long,
    val outboundBytes: Long, val inboundBytes: Long)

/** No queue or native ownership transfer. The service closes this before retiring its native owner. */
internal class TunPacketPump(
    private val session: ProductionNativeSession,
    private val tun: TunPacketEndpoint,
    private val packetMax: Int,
    private val onFailure: () -> Unit,
) : Closeable {
    private val monitor = Any()
    private var started = false
    private val stopping = AtomicBoolean()
    private val cleanupFailed = AtomicBoolean()
    private val sentPackets = AtomicLong()
    private val receivedPackets = AtomicLong()
    private val sentBytes = AtomicLong()
    private val receivedBytes = AtomicLong()
    private val outbound = Thread({ runWorker(::send) }, "kurd-tun-out")
    private val inbound = Thread({ runWorker(::receive) }, "kurd-tun-in")

    init { require(packetMax in 40..65535) }

    fun start() = synchronized(monitor) {
        check(!started && !stopping.get())
        started = true
        try { outbound.start(); inbound.start() }
        catch (failure: Throwable) { requestStop(); throw failure }
    }

    fun snapshot() = TunPacketCounts(sentPackets.get(), receivedPackets.get(), sentBytes.get(), receivedBytes.get())

    private fun runWorker(loop: (ByteBuffer) -> Unit) {
        var buffer: ByteBuffer? = null
        try {
            // Full IP capacity lets us detect an over-limit datagram instead of accepting truncation.
            buffer = ByteBuffer.allocateDirect(65535)
            loop(buffer)
        } catch (_: Exception) {
            if (!stopping.get()) {
                requestStop()
                // The owner schedules teardown; it must not join this worker from this callback.
                try { onFailure() } catch (_: Exception) { }
            }
        } finally {
            buffer?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i, 0) }
        }
    }

    private fun send(buffer: ByteBuffer) {
        while (!stopping.get()) {
            buffer.clear()
            val count = tun.read(buffer)
            if (stopping.get()) return
            check(count in 1..packetMax) { "TUN_PACKET_READ_FAILED" }
            buffer.position(0); buffer.limit(count)
            val submitted = session.submitOutboundPacket(buffer, count)
            when (submitted) {
                is NativeProductResult.Success -> {
                    add(sentPackets, 1); add(sentBytes, count.toLong())
                }
                is NativeProductResult.Failure -> check(submitted.code == ProductFailureCode.ROUTE_POLICY_REJECTED) {
                    "SUBMIT_${submitted.code.name}"
                }
            }
            for (i in 0 until count) buffer.put(i, 0)
        }
    }

    private fun receive(buffer: ByteBuffer) {
        var busySince = 0L
        while (!stopping.get()) {
            buffer.clear()
            val result = session.receiveInboundPacket(buffer)
            if (result !is NativeProductResult.Success) {
                if (stopping.get()) return
                val failure = result as NativeProductResult.Failure
                // Native receive has a 30-second read deadline even on an otherwise healthy idle tunnel.
                if (failure.code == ProductFailureCode.OPERATION_TIMED_OUT) { busySince = 0; continue }
                // Acknowledgement wakes the native writer; its receipt retirement may finish just
                // after the next receive begins. Keep one receive worker and a finite busy deadline.
                if (failure.code == ProductFailureCode.RESOURCE_LIMIT) {
                    val now = System.nanoTime()
                    if (busySince == 0L) busySince = now
                    check(now - busySince < 30_000_000_000L) { "NATIVE_PACKET_BACKPRESSURE_TIMEOUT" }
                    Thread.sleep(1)
                    continue
                }
                check(stopping.get()) { "RECEIVE_${failure.code.name}" }
                return
            }
            busySince = 0
            val delivery = result.value
            var acknowledged = false
            try {
                check(!stopping.get() && delivery.length <= packetMax)
                buffer.position(0); buffer.limit(delivery.length)
                check(tun.write(buffer) == delivery.length) { "TUN_PACKET_WRITE_FAILED" }
                check(session.confirmInboundDelivery(delivery.token, delivery.length) is NativeProductResult.Success)
                acknowledged = true
                add(receivedPackets, 1); add(receivedBytes, delivery.length.toLong())
            } finally {
                if (!acknowledged) session.rejectInboundDelivery(delivery.token)
                buffer.clear()
                for (i in 0 until delivery.length) buffer.put(i, 0)
            }
        }
    }

    private fun requestStop() {
        if (!stopping.compareAndSet(false, true)) return
        try {
            if (session.cancel() !is NativeProductResult.Success) cleanupFailed.set(true)
        } catch (_: Exception) { cleanupFailed.set(true) }
        finally {
            try { tun.close() } catch (_: Exception) { cleanupFailed.set(true) }
        }
    }

    override fun close() {
        check(Thread.currentThread() !== outbound && Thread.currentThread() !== inbound)
        synchronized(monitor) { requestStop() }
        val deadline = System.nanoTime() + 5_000_000_000L
        for (worker in arrayOf(outbound, inbound)) {
            while (worker.isAlive) {
                val remaining = deadline - System.nanoTime()
                check(remaining > 0) { "PACKET_WORKER_CLEANUP_UNPROVEN" }
                worker.join(maxOf(1, remaining / 1_000_000))
            }
        }
        check(!cleanupFailed.get()) { "PACKET_WORKER_CLEANUP_UNPROVEN" }
    }

    private fun add(counter: AtomicLong, count: Long) {
        counter.updateAndGet { if (it > Long.MAX_VALUE - count) Long.MAX_VALUE else it + count }
    }
}

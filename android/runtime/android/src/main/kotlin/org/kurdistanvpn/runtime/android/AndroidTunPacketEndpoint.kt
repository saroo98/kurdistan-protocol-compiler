// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Owns only a service-provided TUN descriptor, never a native upstream socket. */
class AndroidTunPacketEndpoint : TunPacketEndpoint {
    // An idle poll must yield to a queued reply writer before polling again.
    private val monitor = ReentrantLock(true)
    private val closing = AtomicBoolean()
    private var descriptor: ParcelFileDescriptor? = null
    private var acquired = false
    private var closeFailed = false
    private val poll = StructPollfd()
    private val polls = arrayOf(poll)

    /** Allocate this owner before acquiring the descriptor so partial setup remains owned. */
    fun acquire(source: () -> ParcelFileDescriptor) = monitor.withLock {
        check(!acquired && !closing.get())
        acquired = true
        try {
            descriptor = source()
            check(prepareNonblocking(checkNotNull(descriptor).fd)) { "TUN_NONBLOCKING_SETUP_FAILED" }
        } catch (failure: Throwable) { close(); throw failure }
    }

    override fun read(output: ByteBuffer): Int = io(output, false)

    // Os.fcntlInt is public only from API30; the existing JNI library supports min26.
    private external fun prepareNonblocking(fd: Int): Boolean

    companion object {
        init {
            System.loadLibrary("kurdistan_bridge")
            System.loadLibrary("kurdistan_jni")
        }
    }
    override fun write(input: ByteBuffer): Int = io(input, true)

    private fun io(buffer: ByteBuffer, writing: Boolean): Int {
        require(buffer.isDirect && buffer.hasRemaining() && (!buffer.isReadOnly || writing))
        val deadline = if (writing) SystemClock.elapsedRealtime() + 5000 else Long.MAX_VALUE
        var interrupted = 0
        while (!closing.get()) {
            check(SystemClock.elapsedRealtime() < deadline) { "TUN_WRITE_TIMEOUT" }
            val count = monitor.withLock {
                if (closing.get()) return -1
                val fd = checkNotNull(descriptor).fileDescriptor
                try {
                    poll.apply {
                        this.fd = fd
                        events = (if (writing) OsConstants.POLLOUT else OsConstants.POLLIN).toShort()
                        revents = 0
                    }
                    if (Os.poll(polls, 25) == 0) null
                    else {
                        check(poll.revents.toInt() and (OsConstants.POLLNVAL or OsConstants.POLLERR) == 0)
                        if (writing) Os.write(fd, buffer) else Os.read(fd, buffer).let { if (it == 0) -1 else it }
                    }
                } catch (failure: ErrnoException) {
                    when (failure.errno) {
                        OsConstants.EINTR -> { check(++interrupted <= 32); null }
                        OsConstants.EAGAIN -> null
                        else -> throw failure
                    }
                }
            }
            if (count != null) return count
        }
        return -1
    }

    override fun close() {
        closing.set(true)
        monitor.withLock {
            val owned = descriptor
            descriptor = null // Never retry an uncertain descriptor close.
            try { owned?.close() } catch (failure: Throwable) { closeFailed = true; throw failure }
            check(!closeFailed) { "TUN_DESCRIPTOR_CLEANUP_UNPROVEN" }
        }
    }
}

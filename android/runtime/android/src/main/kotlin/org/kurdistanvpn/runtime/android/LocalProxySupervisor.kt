// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.kurdistanvpn.core.model.LocalProxyPreferences
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

/** Four loopback-only listeners and a bounded set of native-stream clients. No destination sockets. */
internal class LocalProxySupervisor(
    private val preferences: LocalProxyPreferences,
    private val limits: NativeProxyLimits,
    private val open: (NativeProxyRequest) -> NativeProductResult<NativeProxyStream>,
    private val listenerFailed: () -> Unit,
    private val diagnostic: ((String) -> Unit)? = null,
) : Closeable {
    val credentials = ProxyCredentialVault()
    private val monitor = Any()
    private val stopped = AtomicBoolean(false)
    private val cleanupUnproven = AtomicBoolean(false)
    private val listeners = ArrayList<ServerSocket>(4)
    private val acceptors = ArrayList<Thread>(4)
    private val clients = LinkedHashSet<Client>()
    private var started = false
    fun isListening(): Boolean = synchronized(monitor) {
        started && !stopped.get() && !cleanupUnproven.get() && listeners.size == 4 &&
            listeners.all { it.isBound && !it.isClosed }
    }
    private val chunk = limits.streamChunkMax
    private val clientLimit = minOf(limits.effectiveClientMax, limits.effectiveStreamMax,
        preferences.limits.clients, preferences.limits.streams,
        (minOf(limits.effectiveTotalBufferBytes, preferences.limits.memoryMiB.toLong() shl 20) / (4L * chunk + 8192)).toInt())
    private val watchdog = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "kurd-proxy-deadlines").apply { isDaemon = true }
    }

    fun start(isActive: () -> Boolean) {
        try {
            synchronized(monitor) {
                check(isActive()) { "PROXY_REQUIRES_ACTIVE_SESSION" }
                check(!started && !stopped.get()); started = true
                val v4 = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
                val v6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
                for (port in listOf(preferences.socksPort, preferences.httpConnectPort)) for (address in listOf(v4, v6)) {
                    val socket = ServerSocket()
                    listeners.add(socket)
                    // A rejected client can leave this local port in TIME_WAIT.
                    // Permit the next session to bind after all listeners close.
                    socket.reuseAddress = true
                    socket.bind(InetSocketAddress(address, port), clientLimit)
                }
                // Bind all four before any client can authenticate or open a native stream.
                listeners.forEachIndexed { index, listener ->
                    val worker = Thread({ accept(listener, index < 2) }, "kurd-proxy-listener").apply { isDaemon = true }
                    acceptors.add(worker); worker.start()
                }
                watchdog.scheduleAtFixedRate({
                    val now = System.nanoTime()
                    synchronized(monitor) { clients.toList() }.forEach { if (now >= it.deadline) it.cancel("WATCHDOG") }
                }, 100, 100, TimeUnit.MILLISECONDS)
            }
        } catch (failure: Throwable) { close(); throw failure }
    }

    private fun accept(listener: ServerSocket, socks: Boolean) {
        try {
            while (!stopped.get()) {
                val socket = listener.accept()
                synchronized(monitor) {
                    if (stopped.get() || clients.size >= clientLimit) socket.close()
                    else {
                        val client = Client(socket, socks)
                        clients.add(client)
                        try { client.worker.start() } catch (failure: Throwable) {
                            clients.remove(client); client.cancel(); throw failure
                        }
                    }
                }
            }
        } catch (_: Throwable) { if (!stopped.get()) listenerFailed() }
    }

    private inner class Client(private val socket: Socket, private val socks: Boolean) {
        private val cancelled = AtomicBoolean(false)
        private val failureObserved = AtomicBoolean(false)
        private fun observe(stage: String, failure: Throwable? = null, terminal: Boolean = true) {
            val observer = diagnostic ?: return
            if (terminal && !failureObserved.compareAndSet(false, true)) return
            val code = when (failure) {
                is ProxyFailure -> failure.code.name
                is IOException -> "IO"
                null -> "NONE"
                else -> "OTHER"
            }
            // Fixed categories only. Observer failure must never change cleanup.
            runCatching { observer("${if (socks) "SOCKS" else "HTTP"}_${stage}_$code") }
        }
        @Volatile var deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        @Volatile private var stream: NativeProxyStream? = null
        @Volatile private var reader: Thread? = null
        @Volatile private var streamClosed = false
        val worker = Thread({ run() }, "kurd-proxy-client").apply { isDaemon = true }
        private fun activity() { deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(
            minOf(limits.effectiveIdleSeconds, preferences.limits.idleSeconds).toLong()) }
        fun cancel(reason: String = "CANCELLED") {
            if (!cancelled.compareAndSet(false, true)) return
            observe(reason)
            try { socket.close() } catch (_: Throwable) { cleanupUnproven.set(true) }
            // Cancellation wakes I/O; only close below supplies retirement proof.
            try { stream?.cancel() } catch (_: Throwable) { }
        }
        fun closeStream(): Boolean {
            if (streamClosed) return true
            if (reader?.isAlive == true) return false
            return try { stream?.close(); streamClosed = true; true } catch (_: Throwable) { false }
        }
        private fun run() {
            var stage = "HANDSHAKE"
            try {
                socket.tcpNoDelay = true
                val request = if (socks) LocalProxyHandshake.socks(socket.getInputStream(), socket.getOutputStream(), credentials)
                    else LocalProxyHandshake.http(socket.getInputStream(), credentials)
                if (cancelled.get() || stopped.get()) return
                deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(limits.signedConnectMillis.toLong())
                stage = "OPEN"
                val native = when (val result = open(request)) {
                    is NativeProductResult.Success -> result.value
                    is NativeProductResult.Failure -> throw ProxyFailure(result.code)
                }
                stream = native
                if (cancelled.get() || stopped.get()) { native.cancel(); return }
                stage = "LOCAL_WRITE"
                socket.getOutputStream().write(if (socks) byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)
                    else "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.US_ASCII))
                activity()
                reader = Thread({ downstream(native) }, "kurd-proxy-receive").apply { isDaemon = true; start() }
                val bytes = ByteArray(chunk)
                val direct = ByteBuffer.allocateDirect(chunk)
                try {
                    while (!cancelled.get()) {
                        stage = "LOCAL_READ"
                        val length = socket.getInputStream().read(bytes)
                        if (length < 0) { stage = "HALF_CLOSE"; native.halfClose().requireSuccess(); break }
                        direct.clear(); direct.put(bytes, 0, length); direct.flip()
                        stage = "SEND"
                        native.send(direct, length).requireSuccess(); activity()
                    }
                    // A local half-close keeps the response direction alive until its EOF or idle deadline.
                    stage = "WAIT_EOF"
                    reader?.join()
                } finally { bytes.fill(0); direct.clear(); while (direct.hasRemaining()) direct.put(0) }
            } catch (failure: Throwable) { observe(stage, failure); cancel() }
            finally {
                cancel()
                try { reader?.let { if (it !== Thread.currentThread()) it.join(5000) } }
                catch (_: InterruptedException) { Thread.currentThread().interrupt(); cleanupUnproven.set(true) }
                // Retain failed retirement until service cancellation supplies the
                // native parent proof. Never discard an unproven stream owner.
                val clean = closeStream()
                synchronized(monitor) { if (clean) clients.remove(this) }
            }
        }
        private fun downstream(native: NativeProxyStream) {
            val bytes = ByteArray(chunk)
            val direct = ByteBuffer.allocateDirect(chunk)
            var stage = "RECEIVE"
            try {
                while (!cancelled.get()) {
                    stage = "RECEIVE"
                    direct.clear()
                    val result = native.receive(direct)
                    if (result is NativeProductResult.Failure && result.code == ProductFailureCode.OPERATION_TIMED_OUT) continue
                    when (val value = result.requireSuccess()) {
                        NativeStreamRead.EndOfStream -> {
                            // Read EOF is not a terminal failure: a later half-close can still fail.
                            observe("REMOTE_EOF", terminal = false); socket.shutdownOutput(); return
                        }
                        is NativeStreamRead.Data -> {
                            var delivered = false
                            try {
                                if (value.length > bytes.size) throw IOException("Proxy stream size rejected")
                                direct.position(0); direct.get(bytes, 0, value.length)
                                stage = "LOCAL_WRITE"
                                socket.getOutputStream().write(bytes, 0, value.length)
                                stage = "CONFIRM"
                                native.confirmDelivery(value.token, value.length).requireSuccess()
                                delivered = true; activity()
                            } finally { if (!delivered) native.rejectDelivery(value.token) }
                        }
                    }
                }
            } catch (failure: Throwable) { observe(stage, failure); cancel() }
            finally { bytes.fill(0); direct.clear(); while (direct.hasRemaining()) direct.put(0) }
        }
    }

    @Synchronized override fun close() {
        if (!stopped.compareAndSet(false, true)) {
            check(!cleanupUnproven.get()) { "PROXY_CLEANUP_UNPROVEN" }
            return
        }
        val held = synchronized(monitor) {
            listeners.forEach { try { it.close() } catch (_: IOException) { cleanupUnproven.set(true) } }
            clients.toList()
        }
        credentials.close(); watchdog.shutdownNow()
        held.forEach { it.cancel("SERVICE_STOP") }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        (acceptors + held.map { it.worker }).forEach {
            if (it !== Thread.currentThread()) it.join(maxOf(1, TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())))
        }
        if (acceptors.any { it.isAlive } || held.any { it.worker.isAlive }) cleanupUnproven.set(true)
        held.forEach { if (!it.worker.isAlive && !it.closeStream()) cleanupUnproven.set(true) }
        check(!cleanupUnproven.get()) { "PROXY_CLEANUP_UNPROVEN" }
    }

    private class ProxyFailure(val code: ProductFailureCode) : IOException("Proxy stream failed")
    private fun <T> NativeProductResult<T>.requireSuccess(): T = when (this) {
        is NativeProductResult.Success -> value
        is NativeProductResult.Failure -> throw ProxyFailure(code)
    }
}

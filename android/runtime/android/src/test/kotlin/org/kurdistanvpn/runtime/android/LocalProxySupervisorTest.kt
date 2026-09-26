// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.LocalProxyPreferences
import org.kurdistanvpn.core.nativeapi.*

class LocalProxySupervisorTest {
    @Test fun nativeRejectionRetainsOnlyTheFirstSafeCauseAndStillClosesTheClient() {
        val socks = port(); var http = port(); while (http == socks) http = port()
        val observations = java.util.concurrent.CopyOnWriteArrayList<String>()
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http), limits(),
            { NativeProductResult.Failure(org.kurdistanvpn.core.model.ProductFailureCode.RESOURCE_LIMIT) },
            { fail("Unexpected listener failure") }, diagnostic = {
                observations.add(it)
                throw IllegalStateException("The observer must not interfere with cleanup")
            })
        try {
            supervisor.start { true }
            val credentials = supervisor.credentials.copyForReveal()
            try {
                Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), socks).use { socket ->
                    socket.soTimeout = 3000
                    socket.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 16) + credentials.copyOfRange(0, 16) +
                        byteArrayOf(43) + credentials.copyOfRange(17, 60) + byteArrayOf(5, 1, 0, 3, 11) +
                        "example.com".toByteArray() + byteArrayOf(1, -69))
                    val response = ByteArray(4)
                    java.io.DataInputStream(socket.getInputStream()).readFully(response)
                    assertArrayEquals(byteArrayOf(5, 2, 1, 0), response)
                    assertEquals(-1, socket.getInputStream().read())
                }
            } finally { credentials.fill(0) }
        } finally { supervisor.close() }
        assertEquals(listOf("SOCKS_OPEN_RESOURCE_LIMIT"), observations.toList())
    }

    @Test fun failedAuthenticationFloodCannotOpenNativeStreamsOrRetainCapacity() {
        val socks = port(); var http = port(); while (http == socks) http = port()
        val opens = java.util.concurrent.atomic.AtomicInteger()
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http), limits(),
            { opens.incrementAndGet(); error("Unauthenticated native open") }, { })
        val workers = java.util.concurrent.Executors.newFixedThreadPool(8)
        try {
            supervisor.start { true }
            val clients = (0 until 32).map { index -> workers.submit {
                Socket(InetAddress.getLoopbackAddress(), if (index % 2 == 0) socks else http).use { client ->
                    client.soTimeout = 2000
                    try {
                        val request = if (index % 2 == 0) byteArrayOf(5, 1, 2, 1, 1, 120, 1, 120)
                            else "CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic eDp4\r\n\r\n".toByteArray()
                        client.getOutputStream().write(request)
                        while (client.getInputStream().read() != -1) { }
                    } catch (_: java.net.SocketException) { /* Excess clients may be reset immediately. */ }
                }
            } }
            clients.forEach { it.get(5, TimeUnit.SECONDS) }
            assertEquals(0, opens.get())
            Socket(InetAddress.getLoopbackAddress(), socks).use { client ->
                client.soTimeout = 2000
                client.getOutputStream().write(byteArrayOf(5, 1, 2))
                assertEquals(5, client.getInputStream().read()); assertEquals(2, client.getInputStream().read())
            }
        } finally { workers.shutdownNow(); supervisor.close() }
    }

    @Test fun nativeAndUserStreamCeilingsBoundClientsAcrossBothListeners() {
        for (nativeCeiling in listOf(true, false)) {
            val socks = port(); var http = port(); while (http == socks) http = port()
            val preferences = LocalProxyPreferences(socks, http, org.kurdistanvpn.core.model.ProxyLimits(
                streams = if (nativeCeiling) 64 else 1))
            val native = limits().copy(effectiveStreamMax = if (nativeCeiling) 1 else 16)
            val supervisor = LocalProxySupervisor(preferences, native, { error("Unauthenticated native open") }, { })
            try {
                supervisor.start { true }
                Socket(InetAddress.getLoopbackAddress(), socks).use { first ->
                    first.soTimeout = 2000
                    first.getOutputStream().write(byteArrayOf(5, 1, 2))
                    assertEquals(5, first.getInputStream().read()); assertEquals(2, first.getInputStream().read())
                    Socket(InetAddress.getLoopbackAddress(), http).use { excess ->
                        excess.soTimeout = 2000; assertEquals(-1, excess.getInputStream().read())
                    }
                }
            } finally { supervisor.close() }
        }
    }

    @Test fun slowUnauthenticatedClientExpiresAndReleasesCapacity() {
        val socks = port(); var http = port(); while (http == socks) http = port()
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http,
            org.kurdistanvpn.core.model.ProxyLimits(clients = 1)), limits(),
            { error("Unauthenticated native open") }, { fail("Listener stopped") })
        try {
            supervisor.start { true }
            Socket(InetAddress.getLoopbackAddress(), http).use { slow ->
                slow.soTimeout = 12000
                slow.getOutputStream().write('C'.code)
                assertEquals(-1, slow.getInputStream().read())
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            var admitted = false
            while (!admitted && System.nanoTime() < deadline) {
                Socket(InetAddress.getLoopbackAddress(), socks).use { next ->
                    next.soTimeout = 1000
                    next.getOutputStream().write(byteArrayOf(5, 1, 2))
                    if (next.getInputStream().read() == 5) {
                        assertEquals(2, next.getInputStream().read()); admitted = true
                    }
                }
            }
            assertTrue("Expired handshake retained client capacity", admitted)
        } finally { supervisor.close() }
    }
    @Test fun inactiveSessionCannotExposeListeners() {
        val socks = port(); var http = port(); while (http == socks) http = port()
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http), limits(),
            { error("Inactive native open") }, { })
        assertThrows(IllegalStateException::class.java) { supervisor.start { false } }
        ServerSocket(socks, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { }
        ServerSocket(http, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { }
    }
    private fun port() = ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { it.localPort }
    private fun limits() = NativeProxyLimits(16, 16, 16, 4, 4, 32L shl 20, 32L shl 20, 300, 1000, 16384, 16384)
    @Test fun ipv6RequiresAuthenticationAndUnauthenticatedClientsCannotExceedLimit() {
        val socks = port(); var http = port(); while (http == socks) http = port()
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http,
            org.kurdistanvpn.core.model.ProxyLimits(clients = 1)), limits(),
            { error("Unauthenticated native open") }, { })
        supervisor.start { true }
        try {
            Socket(InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 }), socks).use { first ->
                first.soTimeout = 2000
                first.getOutputStream().write(byteArrayOf(5, 1, 2))
                assertEquals(5, first.getInputStream().read()); assertEquals(2, first.getInputStream().read())
                Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), http).use { second ->
                    second.soTimeout = 2000
                    assertEquals(-1, second.getInputStream().read())
                }
                supervisor.close()
                assertEquals(-1, first.getInputStream().read())
            }
        } finally { supervisor.close() }
    }
    @Test fun authenticatedConnectUsesNativeStreamAndAcknowledgesOnlyDeliveredBytes() {
        exerciseStream(false)
    }
    @Test fun completedSessionReleasesPortsForAnImmediateNewSession() {
        exerciseStream(false, restartAfterClose = true)
    }
    @Test fun nativeCleanupFailureIsNotReportedAsClean() {
        exerciseStream(true)
    }
    @Test fun concurrentCloseWaitsForNativeRetirementInsteadOfReportingEarlySuccess() {
        exerciseStream(false, true)
    }
    private fun exerciseStream(closeFails: Boolean, concurrentClose: Boolean = false, restartAfterClose: Boolean = false) {
        val socks = port()
        var http = port(); while (http == socks) http = port()
        val released = CountDownLatch(1)
        val halfClosed = CountDownLatch(1)
        val acknowledged = CountDownLatch(1)
        val received = java.util.concurrent.atomic.AtomicInteger()
        val closeEntered = CountDownLatch(1)
        val finishClose = CountDownLatch(if (concurrentClose) 1 else 0)
        val stream = object : NativeProxyStream {
            override fun send(input: ByteBuffer, length: Int) = NativeProductResult.Success(Unit)
            override fun receive(output: ByteBuffer): NativeProductResult<NativeStreamRead> {
                when (received.getAndIncrement()) {
                    0 -> { output.put(0, 42); return NativeProductResult.Success(NativeStreamRead.Data(1, 77)) }
                    1 -> {
                        check(halfClosed.await(3, TimeUnit.SECONDS))
                        output.put(0, 43)
                        return NativeProductResult.Success(NativeStreamRead.Data(1, 78))
                    }
                }
                released.await(5, TimeUnit.SECONDS)
                return NativeProductResult.Success(NativeStreamRead.EndOfStream)
            }
            override fun confirmDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit> {
                assertTrue(token == 77L || token == 78L); assertEquals(1, deliveredLength); acknowledged.countDown()
                return NativeProductResult.Success(Unit)
            }
            override fun rejectDelivery(token: Long) = NativeProductResult.Success(Unit)
            override fun halfClose(): NativeProductResult<Unit> {
                halfClosed.countDown()
                return NativeProductResult.Success(Unit)
            }
            override fun cancel(): NativeProductResult<Unit> { released.countDown(); return NativeProductResult.Success(Unit) }
            override fun close() {
                released.countDown(); closeEntered.countDown()
                check(finishClose.await(4, TimeUnit.SECONDS))
                if (closeFails) throw java.io.IOException("injected cleanup failure")
            }
        }
        val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, http), limits(), { request ->
            assertEquals(NativeProxyAddressKind.DOMAIN, request.kind)
            assertArrayEquals("example.com".toByteArray(), request.address)
            NativeProductResult.Success(stream)
        }, { fail("Unexpected listener failure") })
        try {
            supervisor.start { true }
            val credentials = supervisor.credentials.copyForReveal()
            try {
                Socket(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), socks).use { socket ->
                    socket.soTimeout = 3000
                    socket.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 16) + credentials.copyOfRange(0, 16) +
                        byteArrayOf(43) + credentials.copyOfRange(17, 60) + byteArrayOf(5, 1, 0, 3, 11) +
                        "example.com".toByteArray() + byteArrayOf(1, -69))
                    val response = ByteArray(15)
                    java.io.DataInputStream(socket.getInputStream()).readFully(response)
                    assertArrayEquals(byteArrayOf(5, 2, 1, 0, 5, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42), response)
                    assertTrue(acknowledged.await(3, TimeUnit.SECONDS))
                    socket.shutdownOutput()
                    assertEquals("Half-close discarded the remaining response", 43, socket.getInputStream().read())
                    assertEquals(0L, halfClosed.count)
                    if (concurrentClose) {
                        val workers = java.util.concurrent.Executors.newFixedThreadPool(2)
                        try {
                            val first = workers.submit { supervisor.close() }
                            assertTrue(closeEntered.await(2, TimeUnit.SECONDS))
                            val second = workers.submit { supervisor.close() }
                            assertThrows(java.util.concurrent.TimeoutException::class.java) { second.get(100, TimeUnit.MILLISECONDS) }
                            finishClose.countDown()
                            first.get(3, TimeUnit.SECONDS); second.get(3, TimeUnit.SECONDS)
                        } finally { finishClose.countDown(); workers.shutdownNow() }
                    } else if (closeFails) assertThrows(IllegalStateException::class.java) { supervisor.close() }
                    else supervisor.close()
                    assertEquals(-1, socket.getInputStream().read())
                }
            } finally { credentials.fill(0) }
        } finally {
            if (closeFails) assertThrows(IllegalStateException::class.java) { supervisor.close() }
            else supervisor.close()
        }
        assertThrows(IllegalStateException::class.java) { supervisor.credentials.copyForReveal() }
        if (restartAfterClose) {
            LocalProxySupervisor(LocalProxyPreferences(socks, http), limits(),
                { error("No client in replacement") }, { fail("Unexpected listener failure") }).use {
                it.start { true }
            }
        }
    }

    @Test fun occupiedPortClosesEveryPartialListenerAndCredentials() {
        val socks = port()
        ServerSocket(0, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { occupied ->
            val supervisor = LocalProxySupervisor(LocalProxyPreferences(socks, occupied.localPort), limits(),
                { error("Must not open native stream") }, { })
            assertThrows(java.io.IOException::class.java) { supervisor.start { true } }
            supervisor.close()
            ServerSocket(socks, 1, InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))).use { assertTrue(it.isBound) }
            assertThrows(IllegalStateException::class.java) { supervisor.credentials.copyForReveal() }
        }
    }
}

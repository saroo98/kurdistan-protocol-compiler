// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.runtime.api.*

class RuntimeAuthorityReissueClientTest {
    @Test fun invalidationCannotAcknowledgeUnprovenTunnelCleanup() {
        val guard = RuntimeActivationGuard()
        var closes = 0
        guard.own(RuntimeResourceKind.TUN, java.io.Closeable { closes++; throw java.io.IOException("synthetic") })
        assertThrows(RuntimeAuthorityCleanupUnprovenException::class.java) { RuntimeReissueInvalidation.apply(guard) {} }
        assertEquals(1, closes)
        assertFalse(guard.isActive())
        assertEquals(RuntimeCleanupState.UNPROVEN, guard.cleanupState())
    }

    @Test fun strictPipeReadRequiresExactLengthEofAndUnchangedPhysicalIdentity() {
        for (case in 0..4) {
            val pipe = Input(byteArrayOf(1, 2, 3), zero = case == 3, substitute = case == 4)
            val expected = when (case) { 1 -> 2; 2 -> 4; else -> 3 }
            val result = runCatching { RuntimeReissuePipeIo.readExact(pipe, expected) { true } }.getOrNull()
            if (case == 0) assertArrayEquals(byteArrayOf(1, 2, 3), result) else assertNull(result)
        }
    }

    @Test fun strictPipeIoChecksCancellationBeforeEveryShortOperation() {
        var calls = 0
        assertThrows(IllegalStateException::class.java) {
            RuntimeReissuePipeIo.readExact(Input(byteArrayOf(1, 2, 3)), 3) { ++calls < 3 }
        }
        val output = Output()
        assertThrows(IllegalStateException::class.java) {
            var checks = 0
            RuntimeReissuePipeIo.writeExact(output, byteArrayOf(1, 2, 3)) { ++checks < 3 }
        }
        assertEquals(2, output.written.size)
    }

    @Test fun clientExchangeNeverReusesAKeyOrAcceptsAChangedContext() {
        val offer = offer()
        val readIdentity = RuntimePipeIdentity(1, 9, 1000, 4480, 0)
        val request = offer.request(RuntimeAuthorityPurpose.FULL_AUTHORITY, readIdentity.descriptor("4".repeat(32), 214))
        val key = ByteArray(32) { 7 }
        val exchange = RuntimeReissueClientExchange(request, key)
        assertTrue(key.all { it == 0.toByte() })
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(6))!!
        val accepted = exchange.consume(frame, request.descriptor, 100)
        assertTrue(accepted is RuntimeFrameVerification.Verified)
        assertTrue(exchange.consume(frame, request.descriptor, 100) is RuntimeFrameVerification.Rejected)
        val altered = RuntimeReissueClientExchange(request.copy(providerEpoch = "9".repeat(32)), ByteArray(32) { 7 })
        assertTrue(altered.consume(frame, request.descriptor, 100) is RuntimeFrameVerification.Rejected)
        frame.fill(0)
    }

    @Test fun cancelledExchangeAndExpiredOfferCannotSupplyAuthority() {
        val offer = offer()
        val descriptor = RuntimePipeIdentity(1, 9, 1000, 4480, 0).descriptor("4".repeat(32), 214)
        val request = offer.request(RuntimeAuthorityPurpose.FULL_AUTHORITY, descriptor)
        val exchange = RuntimeReissueClientExchange(request, ByteArray(32) { 7 })
        exchange.close()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(6))!!
        assertTrue(exchange.consume(frame, descriptor, 100) is RuntimeFrameVerification.Rejected)
        assertFalse(offer.start.isLiveAt(1000))
        assertFalse(offer.start.isLiveAt(-1))
    }

    @Test fun failedPipeValidationClosesItsLocalOwnerAndPreservesCloseUncertainty() {
        for (uncertain in listOf(false, true)) {
            val pipe = Output(uncertain)
            val failure = runCatching { RuntimePipeAcquisition.validateOwned(pipe) { error("synthetic validation") } }.exceptionOrNull()
            assertNotNull(failure); assertEquals(1, pipe.closes)
            assertEquals(uncertain, failure is RuntimeAuthorityCleanupUnprovenException)
        }
    }

    @Test fun invalidationAlwaysClosesTheActivationOwnerEvenIfItsCallbackThrows() {
        val guard = RuntimeActivationGuard(); var closed = 0
        guard.own(RuntimeResourceKind.NATIVE_SESSION, java.io.Closeable { closed++ })
        guard.own(RuntimeResourceKind.TUN, java.io.Closeable { closed++ })
        assertThrows(IllegalStateException::class.java) {
            RuntimeReissueInvalidation.apply(guard) { error("synthetic callback failure") }
        }
        assertEquals(2, closed)
        assertEquals(RuntimeCleanupState.CLEAN, guard.cleanupState())
        assertFalse(guard.isActive())
    }

    private fun offer() = RuntimeAuthorityOffer(RuntimeReissueStart("1".repeat(32), "2".repeat(32), 1,
        RuntimeAuthorityTrigger.MANUAL, 0, 1000), "5".repeat(32), 2, 2, 1, "3".repeat(32), "6".repeat(32))
    private class Input(private val bytes: ByteArray, private val zero: Boolean = false, private val substitute: Boolean = false) : RuntimeReissueReadPipe {
        private var at = 0
        override val identity get() = RuntimePipeIdentity(1, if (substitute && at > 0) 10 else 9, 1000, 4480, 0)
        override fun read(target: ByteArray, offset: Int, count: Int): Int {
            if (zero) return 0
            if (at == bytes.size) return -1
            target[offset] = bytes[at++]; return 1
        }
        override fun close() {}
    }
    private class Output(private val failClose: Boolean = false) : RuntimeReissueWritePipe {
        val written = mutableListOf<Byte>()
        var closes = 0
        override val identity = RuntimePipeIdentity(1, 10, 1000, 4480, 1)
        override fun write(source: ByteArray, offset: Int, count: Int): Int { written += source[offset]; return 1 }
        override fun close() { closes++; if (failClose) throw java.io.IOException("synthetic close uncertainty") }
    }
}

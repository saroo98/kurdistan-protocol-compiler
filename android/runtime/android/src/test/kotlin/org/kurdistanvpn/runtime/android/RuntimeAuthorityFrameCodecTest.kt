// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import org.junit.Assert.*
import org.junit.Test
import java.security.Key
import java.security.Provider
import java.security.Security
import java.security.spec.AlgorithmParameterSpec
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.MacSpi
import javax.crypto.spec.SecretKeySpec
import org.kurdistanvpn.runtime.api.*

class RuntimeAuthorityFrameCodecTest {
    @Test fun canonicalFrameMatchesIndependentlyCalculatedLiteralVector() {
        // Independently framed literal and .NET HMAC-SHA256, not this codec's output.
        val expected = hex("4b524146020000b5000000d700000002" +
            "1111111111111111111111111111111155555555555555555555555555555555" +
            "22222222222222222222222222222222" +
            "00000000000000010101000000000000000200000000000003e8" +
            "3333333333333333333333333333333366666666666666666666666666666666" +
            "44444444444444444444444444444444" +
            "0000000000000001000000000000000200000000000003e80000000000001180" +
            "00000000000000d70002000304" +
            "af55bd69209eb7a2cbc1af25914d60b9cd41046753c4106f9f7d6d257c0eab02")
        val request = request()
        val payload = byteArrayOf(3, 4)
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(payload)!!
        assertArrayEquals(expected, frame)
        assertArrayEquals(byteArrayOf(3, 4), payload)
        val authority = (RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
            .verifyAndConsume(expected, request.descriptor, 100) as RuntimeFrameVerification.Verified).authority
        val transferred = authority.takePayload()!!
        assertArrayEquals(byteArrayOf(3, 4), transferred)
        authority.close()
        assertArrayEquals(byteArrayOf(3, 4), transferred)
        assertNull(authority.takePayload())
        transferred.fill(0)
    }

    @Test fun verifiedAuthorityCannotRetainCallerOwnedPayloadAlias() {
        val input = byteArrayOf(3, 4)
        val authority = RuntimeVerifiedAuthority(request(), input)
        input.fill(99)
        val transferred = authority.takePayload()!!
        assertArrayEquals(byteArrayOf(3, 4), transferred)
        transferred.fill(0)
        authority.close()

        val borrowed = byteArrayOf(5, 6)
        RuntimeVerifiedAuthority(request(), borrowed).close()
        assertArrayEquals(byteArrayOf(5, 6), borrowed)
    }

    @Test fun untransferredAuthorityClosesItsOwnedPayloadAndCloseIsIdempotent() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val authority = (RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
            .verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Verified).authority
        val owned = authority.javaClass.getDeclaredField("owned").run {
            isAccessible = true
            get(authority) as ByteArray
        }
        assertArrayEquals(byteArrayOf(3, 4), owned)
        authority.close()
        authority.close()
        assertTrue(owned.all { it == 0.toByte() })
        assertNull(authority.takePayload())
    }

    @Test fun payloadBoundsRejectBeforeEncodingAndValidMaximumRemainsOneUse() {
        assertEquals(213, RuntimeAuthorityFrameCodec.encodedLength(0))
        assertEquals(2_733_621, RuntimeAuthorityFrameCodec.encodedLength(2_733_408))
        for (length in listOf(-1, 2_733_409, Int.MAX_VALUE)) {
            assertThrows(IllegalArgumentException::class.java) { RuntimeAuthorityFrameCodec.encodedLength(length) }
        }
        val request = request().let { it.copy(descriptor = it.descriptor.copy(length = 2_733_621)) }
        val payload = ByteArray(2_733_408) { 17 }
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(payload)!!
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val authority = (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Verified).authority
        val transferred = authority.takePayload()!!
        try {
            assertEquals(2_733_408, transferred.size)
            assertTrue(transferred.all { it == 17.toByte() })
            assertTrue(payload.all { it == 17.toByte() })
            assertEquals(RuntimeFrameRejection.TERMINAL,
                (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
        } finally { payload.fill(0); frame.fill(0); transferred.fill(0); authority.close() }
        val oversize = ByteArray(2_733_409) { 18 }
        val sealer = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request)
        val ownedKey = keyBacking(sealer)
        assertNull(sealer.seal(oversize))
        assertTrue(ownedKey.all { it == 0.toByte() })
        assertTrue(oversize.all { it == 18.toByte() })
        assertNull(sealer.seal(byteArrayOf(3, 4)))
        oversize.fill(0)
    }

    @Test fun revisionLeaseFramesRequireZeroPayloadAndRemainPurposeBound() {
        for (purpose in listOf(RuntimeAuthorityPurpose.PRE_TUN, RuntimeAuthorityPurpose.PRE_ACTIVE)) {
            val request = request().let { it.forPurpose(purpose, it.descriptor.copy(length = 213)) }
            val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf())!!
            val authority = (RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
                .verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Verified).authority
            assertEquals(purpose, authority.request.purpose)
            assertEquals(0, authority.takePayload()!!.size)
            authority.close()
            val wrongLength = request.copy(descriptor = request.descriptor.copy(length = 214))
            val rejected = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, wrongLength)
            val key = keyBacking(rejected)
            assertNull(rejected.seal(byteArrayOf(9)))
            assertTrue(key.all { it == 0.toByte() })
            assertNull(rejected.seal(byteArrayOf()))
        }
    }

    @Test fun eachVerifierRejectionWipesOwnedKeyAndPreservesBorrowedFrame() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val cases = listOf(
            Triple(frame.copyOf(), request.descriptor, 1000L),
            Triple(frame.copyOf(), request.descriptor.copy(inode = 3), 100L),
            Triple(frame.copyOf().also { it[170] = 1 }, request.descriptor, 100L),
            Triple(byteArrayOf(), request.descriptor, 100L),
            Triple(frame + byteArrayOf(0), request.descriptor, 100L),
        )
        for ((input, descriptor, now) in cases) {
            val before = input.copyOf()
            val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
            val key = keyBacking(verifier)
            assertTrue(verifier.verifyAndConsume(input, descriptor, now) is RuntimeFrameVerification.Rejected)
            assertTrue(key.all { it == 0.toByte() })
            assertArrayEquals(before, input)
            assertEquals(RuntimeFrameRejection.TERMINAL,
                (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
            verifier.close()
        }
        val closed = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val key = keyBacking(closed)
        closed.close()
        closed.close()
        assertTrue(key.all { it == 0.toByte() })
        assertEquals(RuntimeFrameRejection.TERMINAL,
            (closed.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
    }

    @Test fun sealerWipesItsMacBodyAndProducedTagWithoutWipingReturnedFrame() {
        val request = request()
        val sealer = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request)
        val ownedKey = keyBacking(sealer)
        captureMac { capture ->
            val result = sealer.seal(byteArrayOf(3, 4))!!
            assertEquals(215, result.size)
            assertTrue(result.any { it != 0.toByte() })
            assertTrue(capture.inputs.last().all { it == 0.toByte() })
            assertTrue(capture.tags.single().all { it == 0.toByte() })
            assertTrue(ownedKey.all { it == 0.toByte() })
        }
    }

    @Test fun callerFrameMutationDuringAuthenticationCannotChangeOwnedSnapshot() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val ownedKey = keyBacking(verifier)
        captureMac(onFinal = { frame.fill(0) }) { capture ->
            val result = verifier.verifyAndConsume(frame, request.descriptor, 100)
            assertTrue(result is RuntimeFrameVerification.Verified)
            val authority = (result as RuntimeFrameVerification.Verified).authority
            val payload = authority.takePayload()!!
            assertArrayEquals(byteArrayOf(3, 4), payload)
            payload.fill(0)
            assertTrue(capture.inputs.last().all { it == 0.toByte() })
            assertTrue(capture.tags.single().all { it == 0.toByte() })
            assertTrue(ownedKey.all { it == 0.toByte() })
            assertEquals(RuntimeFrameRejection.TERMINAL,
                (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
        }
    }

    @Test fun excessiveAutomaticDeadlineConsumesCapabilityBeforeItCouldBecomeLive() {
        val request = request().copy(trigger = RuntimeAuthorityTrigger.AUTOMATIC, deadlineElapsedMillis = 60_101)
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val result = verifier.verifyAndConsume(frame, request.descriptor, 100)
        assertTrue(result is RuntimeFrameVerification.Rejected)
        assertEquals(RuntimeFrameRejection.EXPIRED,
            (result as RuntimeFrameVerification.Rejected).reason)
        assertEquals(RuntimeFrameRejection.TERMINAL,
            (verifier.verifyAndConsume(frame, request.descriptor, 101) as RuntimeFrameVerification.Rejected).reason)
    }

    @Test fun concurrentSubmissionsYieldOnePayloadAndEveryOtherCallIsTerminal() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val ownedKey = keyBacking(verifier)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(8)
        try {
            val futures = (1..16).map {
                pool.submit<RuntimeFrameVerification> {
                    check(start.await(5, TimeUnit.SECONDS))
                    verifier.verifyAndConsume(frame, request.descriptor, 100)
                }
            }
            start.countDown()
            val outcomes = futures.map { it.get(5, TimeUnit.SECONDS) }
            val winners = outcomes.filterIsInstance<RuntimeFrameVerification.Verified>()
            assertEquals(1, winners.size)
            assertEquals(15, outcomes.count { it == RuntimeFrameVerification.Rejected(RuntimeFrameRejection.TERMINAL) })
            winners.single().authority.close()
            assertTrue(ownedKey.all { it == 0.toByte() })
        } finally {
            start.countDown()
            pool.shutdownNow()
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
            verifier.close()
        }
    }

    @Test fun invalidTransferredKeysAndFailurePathsAreWipedAndCannotBeRearmed() {
        for (length in listOf(0, 1, 31, 33, 64)) {
            val signing = ByteArray(length) { 6 }
            assertThrows(IllegalArgumentException::class.java) { RuntimeAuthorityFrameCodec.sealer(signing, request()) }
            assertTrue(signing.all { it == 0.toByte() })
            val checking = ByteArray(length) { 6 }
            assertThrows(IllegalArgumentException::class.java) { RuntimeAuthorityFrameCodec.verifier(checking, request()) }
            assertTrue(checking.all { it == 0.toByte() })
        }
        val request = request()
        val sealer = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request)
        val signing = keyBacking(sealer)
        captureMac(onUpdate = { throw IllegalStateException("synthetic MAC failure") }) {
            assertNull(sealer.seal(byteArrayOf(3, 4)))
            assertNull(sealer.seal(byteArrayOf(3, 4)))
        }
        assertTrue(signing.all { it == 0.toByte() })
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, request).seal(byteArrayOf(3, 4))!!
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, request)
        val checking = keyBacking(verifier)
        captureMac(onUpdate = { throw IllegalStateException("synthetic MAC failure") }) {
            assertEquals(RuntimeFrameRejection.MALFORMED,
                (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
            assertEquals(RuntimeFrameRejection.TERMINAL,
                (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
        }
        assertTrue(checking.all { it == 0.toByte() })
    }

    @Test fun hmacUsesIndependentDomainAndRejectsAuthenticatedNoncanonicalFlags() {
        val request = request()
        val key = ByteArray(32) { 6 }
        val frame = RuntimeAuthorityFrameCodec.sealer(key.copyOf(), request).seal(byteArrayOf(3, 4))!!
        fun tag(body: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            update("KURDISTAN-RUNTIME-AUTHORITY-V2\u0000".toByteArray(Charsets.US_ASCII))
            doFinal(body)
        }
        val body = frame.copyOfRange(0, frame.size - 32)
        assertArrayEquals(tag(body), frame.copyOfRange(frame.size - 32, frame.size))
        body[5] = 1
        val noncanonical = body + tag(body)
        assertEquals(RuntimeFrameRejection.MALFORMED,
            (RuntimeAuthorityFrameCodec.verifier(key.copyOf(), request).verifyAndConsume(noncanonical, request.descriptor, 100)
                as RuntimeFrameVerification.Rejected).reason)
    }

    @Test fun authenticatedFrameConsumesKeyAndAuthorityExactlyOnce() {
        val request = request()
        val signing = ByteArray(32) { 7 }
        val checking = signing.copyOf()
        val sealer = RuntimeAuthorityFrameCodec.sealer(signing, request)
        val verifier = RuntimeAuthorityFrameCodec.verifier(checking, request)
        assertTrue(signing.all { it == 0.toByte() })
        assertTrue(checking.all { it == 0.toByte() })
        val frame = sealer.seal(byteArrayOf(3, 4))!!
        assertNull(sealer.seal(byteArrayOf(3, 4)))
        val result = verifier.verifyAndConsume(frame, request.descriptor, 100)
        assertTrue(result is RuntimeFrameVerification.Verified)
        val authority = (result as RuntimeFrameVerification.Verified).authority
        assertArrayEquals(byteArrayOf(3, 4), authority.takePayload())
        assertNull(authority.takePayload())
        authority.close()
        assertEquals(RuntimeFrameRejection.TERMINAL, (verifier.verifyAndConsume(frame, request.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
    }

    @Test fun everyTamperedByteAndTrailingDataFailsWithoutTerminalRearm() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 9 }, request).seal(byteArrayOf(3, 4))!!
        for (index in frame.indices) {
            val corrupted = frame.copyOf().also { it[index] = (it[index].toInt() xor 1).toByte() }
            val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 9 }, request)
            assertTrue("byte $index", verifier.verifyAndConsume(corrupted, request.descriptor, 100) is RuntimeFrameVerification.Rejected)
            assertTrue(verifier.verifyAndConsume(frame, request.descriptor, 100) is RuntimeFrameVerification.Rejected)
        }
        assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 9 }, request)
            .verifyAndConsume(frame + byteArrayOf(0), request.descriptor, 100) is RuntimeFrameVerification.Rejected)
    }

    @Test fun equalMacBytesCannotAuthorizeDifferentEpochRevisionChannelDescriptorOrPurpose() {
        val request = request()
        val frame = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 1 }, request).seal(byteArrayOf(3, 4))!!
        listOf(request.copy(consumerEpoch = "9".repeat(32)), request.copy(providerEpoch = "a".repeat(32)), request.copy(revision = 4),
            request.copy(capabilityChannelId = "8".repeat(32)), request.copy(frameChannelId = "b".repeat(32)), request.copy(generation = 2),
            request.copy(requestId = "7".repeat(32)), request.copy(purpose = RuntimeAuthorityPurpose.PRE_TUN),
            request.copy(signedRetryBudget = 3)).forEach { expected ->
            assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, expected)
                .verifyAndConsume(frame, request.descriptor, 100) is RuntimeFrameVerification.Rejected)
        }
        assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, request)
            .verifyAndConsume(frame, request.descriptor.copy(inode = 99), 100) is RuntimeFrameVerification.Rejected)
        assertTrue(RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, request)
            .verifyAndConsume(frame, request.descriptor, 1000) is RuntimeFrameVerification.Rejected)
    }

    @Test fun producerEpochOrEitherPipeSwapCannotSurviveEvenAValidMac() {
        val original = request()
        val altered = listOf(original.copy(providerEpoch = "a".repeat(32)),
            original.copy(consumerEpoch = "b".repeat(32)),
            original.copy(capabilityChannelId = "c".repeat(32)),
            original.copy(frameChannelId = "d".repeat(32)),
            original.copy(capabilityChannelId = original.frameChannelId, frameChannelId = original.capabilityChannelId))
        for (substitution in altered) {
            val signed = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 7 }, substitution).seal(byteArrayOf(3, 4))!!
            val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 7 }, original)
            assertEquals(RuntimeFrameRejection.BINDING,
                (verifier.verifyAndConsume(signed, original.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
            assertEquals(RuntimeFrameRejection.TERMINAL,
                (verifier.verifyAndConsume(signed, original.descriptor, 100) as RuntimeFrameVerification.Rejected).reason)
        }
    }

    @Test fun legacyFrameVersionCannotBeReinterpretedAsTheTwoProcessContext() {
        val request = request(); val key = ByteArray(32) { 7 }
        val frame = RuntimeAuthorityFrameCodec.sealer(key.clone(), request).seal(byteArrayOf(3, 4))!!
        val body = frame.copyOfRange(0, frame.size - 32).also { it[4] = 1 }
        val tag = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256")); update("KURDISTAN-RUNTIME-AUTHORITY-V2\u0000".toByteArray()); doFinal(body)
        }
        assertEquals(RuntimeFrameRejection.MALFORMED,
            (RuntimeAuthorityFrameCodec.verifier(key.clone(), request).verifyAndConsume(body + tag, request.descriptor, 100)
                as RuntimeFrameVerification.Rejected).reason)
        key.fill(0); body.fill(0); tag.fill(0); frame.fill(0)
    }

    @Test fun cancellationAndMalformedPayloadAreTerminal() {
        val request = request()
        val verifier = RuntimeAuthorityFrameCodec.verifier(ByteArray(32) { 1 }, request)
        verifier.close()
        assertTrue(verifier.verifyAndConsume(byteArrayOf(), request.descriptor, 100) is RuntimeFrameVerification.Rejected)
        val sealer = RuntimeAuthorityFrameCodec.sealer(ByteArray(32) { 1 }, request)
        assertNull(sealer.seal(byteArrayOf()))
        assertNull(sealer.seal(byteArrayOf(3, 4)))
    }

    private fun request() = RuntimeAuthorityRequest("1".repeat(32), "5".repeat(32), "2".repeat(32), 1,
        RuntimeAuthorityPurpose.FULL_AUTHORITY, RuntimeAuthorityTrigger.MANUAL, 2, 1000,
        "3".repeat(32), "6".repeat(32), RuntimeDescriptorBinding("4".repeat(32), 1, 2, 1000, 4480,
            RuntimeAuthorityFrameCodec.encodedLength(2).toLong(), 0), 2, 0)

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun keyBacking(owner: Any): ByteArray = checkNotNull(owner.javaClass.superclass).getDeclaredField("key").run {
        isAccessible = true
        get(owner) as ByteArray
    }

    private fun captureMac(onFinal: () -> Unit = {}, onUpdate: () -> Unit = {}, block: (MacCapture) -> Unit) {
        val capture = MacCapture(Mac.getInstance("HmacSHA256").provider, onFinal, onUpdate)
        check(activeCapture == null && Security.getProvider(CAPTURE_PROVIDER) == null)
        activeCapture = capture
        val provider = object : Provider(CAPTURE_PROVIDER, 1.0, "Synthetic ownership observation") {
            init { put("Mac.HmacSHA256", CapturingMac::class.java.name) }
        }
        try {
            check(Security.insertProviderAt(provider, 1) == 1)
            block(capture)
        } finally {
            if (Security.getProvider(CAPTURE_PROVIDER) === provider) Security.removeProvider(CAPTURE_PROVIDER)
            activeCapture = null
        }
    }

    class CapturingMac : MacSpi() {
        private val capture = checkNotNull(activeCapture)
        private val delegate = Mac.getInstance("HmacSHA256", capture.provider)
        override fun engineGetMacLength(): Int = delegate.macLength
        override fun engineInit(key: Key, params: AlgorithmParameterSpec?) { delegate.init(key, params) }
        override fun engineUpdate(input: Byte) { delegate.update(input) }
        override fun engineUpdate(input: ByteArray, offset: Int, length: Int) {
            capture.inputs.add(input)
            capture.onUpdate()
            delegate.update(input, offset, length)
        }
        override fun engineDoFinal(): ByteArray = delegate.doFinal().also {
            capture.tags.add(it)
            capture.onFinal()
        }
        override fun engineReset() { delegate.reset() }
    }

    class MacCapture(val provider: Provider, val onFinal: () -> Unit, val onUpdate: () -> Unit) {
        val inputs = mutableListOf<ByteArray>()
        val tags = mutableListOf<ByteArray>()
    }

    companion object {
        private const val CAPTURE_PROVIDER = "RuntimeFrameOwnershipTests"
        private var activeCapture: MacCapture? = null
    }
}

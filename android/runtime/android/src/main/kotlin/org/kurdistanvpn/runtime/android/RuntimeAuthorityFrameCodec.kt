// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.kurdistanvpn.runtime.api.*

enum class RuntimeFrameRejection { MALFORMED, AUTHENTICATION, BINDING, EXPIRED, TERMINAL }
sealed interface RuntimeFrameVerification {
    class Verified(val authority: RuntimeVerifiedAuthority) : RuntimeFrameVerification
    data class Rejected(val reason: RuntimeFrameRejection) : RuntimeFrameVerification
}

/** Owns only verified payload, never capability key material. Transfer is one-use. */
class RuntimeVerifiedAuthority internal constructor(val request: RuntimeAuthorityRequest, payload: ByteArray) : Closeable {
    private var owned: ByteArray? = payload.copyOf()
    @Synchronized fun takePayload(): ByteArray? = owned.also { owned = null }
    @Synchronized override fun close() { owned?.fill(0); owned = null }
}

/** Separate roles prevent a frame recipient from using its capability as a signing oracle. */
interface RuntimeAuthorityFrameSealer : Closeable { fun seal(payload: ByteArray): ByteArray? }
interface RuntimeAuthorityFrameVerifier : Closeable {
    fun verifyAndConsume(frame: ByteArray, observed: RuntimeDescriptorBinding, nowElapsedMillis: Long): RuntimeFrameVerification
}

object RuntimeAuthorityFrameCodec {
    // KRAF v2: fixed 181-byte big-endian header, payload, then a 32-byte HMAC.
    // There is deliberately no v1 compatibility path: v1 lacks provider/channel separation.
    private const val HEADER_BYTES = 181
    private const val TAG_BYTES = 32
    private const val DOMAIN = "KURDISTAN-RUNTIME-AUTHORITY-V2\u0000"
    fun encodedLength(payloadLength: Int): Int {
        require(payloadLength in 0..RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES)
        return HEADER_BYTES + payloadLength + TAG_BYTES
    }

    /** Input key transfers ownership and is wiped. No key-export method exists. */
    fun sealer(transferredKey: ByteArray, request: RuntimeAuthorityRequest): RuntimeAuthorityFrameSealer {
        val owned = takeKey(transferredKey)
        return try { Sealer(owned, request) } catch (failure: Throwable) { owned.fill(0); throw failure }
    }
    fun verifier(transferredKey: ByteArray, request: RuntimeAuthorityRequest): RuntimeAuthorityFrameVerifier {
        val owned = takeKey(transferredKey)
        return try { Verifier(owned, request) } catch (failure: Throwable) { owned.fill(0); throw failure }
    }

    private fun takeKey(input: ByteArray): ByteArray {
        var owned: ByteArray? = null
        try {
            owned = input.copyOf()
            require(owned.size == 32)
            return owned.also { owned = null }
        } finally { input.fill(0); owned?.fill(0) }
    }
    private abstract class KeyOwner(private var key: ByteArray?) : Closeable {
        @Synchronized protected fun <T> consume(terminal: T, use: (ByteArray) -> T): T {
            val owned = key ?: return terminal
            key = null
            return try { use(owned) } finally { owned.fill(0) }
        }
        @Synchronized final override fun close() { key?.fill(0); key = null }
    }

    private class Sealer(key: ByteArray, private val request: RuntimeAuthorityRequest) : KeyOwner(key), RuntimeAuthorityFrameSealer {
        @Synchronized override fun seal(payload: ByteArray): ByteArray? = consume(null) { key ->
            var ownedPayload: ByteArray? = null
            var body: ByteArray? = null
            var tag: ByteArray? = null
            var encoded: ByteArray? = null
            try {
                ownedPayload = payload.copyOf()
                val length = encodedLength(ownedPayload.size)
                require(request.descriptor.length == length.toLong())
                require(if (request.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) ownedPayload.isNotEmpty() else ownedPayload.isEmpty())
                body = ByteArray(length - TAG_BYTES)
                ByteBuffer.wrap(body).order(ByteOrder.BIG_ENDIAN).apply {
                    put(byteArrayOf(75, 82, 65, 70)); put(2); put(0); putShort(HEADER_BYTES.toShort())
                    putInt(length); putInt(ownedPayload.size); putRequest(request); put(ownedPayload)
                }
                tag = mac(key, body)
                require(tag.size == TAG_BYTES)
                encoded = ByteArray(length)
                body.copyInto(encoded)
                tag.copyInto(encoded, body.size)
                encoded.also { encoded = null }
            } catch (_: Exception) { null }
            finally { ownedPayload?.fill(0); body?.fill(0); tag?.fill(0); encoded?.fill(0) }
        }
    }

    private class Verifier(key: ByteArray, private val expected: RuntimeAuthorityRequest) : KeyOwner(key), RuntimeAuthorityFrameVerifier {
        @Synchronized override fun verifyAndConsume(frame: ByteArray, observed: RuntimeDescriptorBinding, nowElapsedMillis: Long): RuntimeFrameVerification =
            consume(RuntimeFrameVerification.Rejected(RuntimeFrameRejection.TERMINAL)) { key ->
                var ownedFrame: ByteArray? = null
                var body: ByteArray? = null
                var tag: ByteArray? = null
                var receivedTag: ByteArray? = null
                var payload: ByteArray? = null
                var authority: RuntimeVerifiedAuthority? = null
                try {
                    ownedFrame = frame.copyOf()
                    if (!expected.isLiveAt(nowElapsedMillis)) return@consume RuntimeFrameVerification.Rejected(RuntimeFrameRejection.EXPIRED)
                    if (observed != expected.descriptor || observed.length != ownedFrame.size.toLong()) return@consume RuntimeFrameVerification.Rejected(RuntimeFrameRejection.BINDING)
                    require(ownedFrame.size in encodedLength(0)..encodedLength(RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES))
                    body = ownedFrame.copyOfRange(0, ownedFrame.size - TAG_BYTES)
                    receivedTag = ownedFrame.copyOfRange(ownedFrame.size - TAG_BYTES, ownedFrame.size)
                    tag = mac(key, body)
                    if (tag.size != TAG_BYTES || !MessageDigest.isEqual(tag, receivedTag))
                        return@consume RuntimeFrameVerification.Rejected(RuntimeFrameRejection.AUTHENTICATION)
                    val reader = ByteBuffer.wrap(body).order(ByteOrder.BIG_ENDIAN)
                    require(reader.int == 0x4b524146 && reader.get() == 2.toByte() && reader.get() == 0.toByte())
                    require(reader.short.toInt() == HEADER_BYTES && reader.int == ownedFrame.size)
                    val length = reader.int
                    require(length in 0..RuntimeAuthorityLimits.MAX_PAYLOAD_BYTES && encodedLength(length) == ownedFrame.size)
                    val actual = reader.readRequest()
                    if (actual != expected) return@consume RuntimeFrameVerification.Rejected(RuntimeFrameRejection.BINDING)
                    require(reader.remaining() == length)
                    require(if (actual.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) length > 0 else length == 0)
                    payload = ByteArray(length)
                    reader.get(payload)
                    authority = RuntimeVerifiedAuthority(actual, payload)
                    RuntimeFrameVerification.Verified(authority).also { authority = null }
                } catch (_: Exception) { RuntimeFrameVerification.Rejected(RuntimeFrameRejection.MALFORMED) }
                finally {
                    ownedFrame?.fill(0); body?.fill(0); tag?.fill(0); receivedTag?.fill(0); payload?.fill(0)
                    authority?.close()
                }
            }
    }

    private fun mac(key: ByteArray, body: ByteArray): ByteArray {
        val domain = DOMAIN.toByteArray(Charsets.US_ASCII)
        return try {
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(key, "HmacSHA256")); update(domain); doFinal(body)
            }
        } finally { domain.fill(0) }
    }
    private fun ByteBuffer.putId(id: String) { repeat(16) { put(id.substring(it * 2, it * 2 + 2).toInt(16).toByte()) } }
    private fun ByteBuffer.readId(): String = buildString(32) {
        repeat(16) { val value = this@readId.get().toInt() and 255; append("0123456789abcdef"[value ushr 4]); append("0123456789abcdef"[value and 15]) }
    }
    private fun ByteBuffer.putRequest(r: RuntimeAuthorityRequest) {
        putId(r.consumerEpoch); putId(r.providerEpoch); putId(r.requestId)
        putLong(r.generation); put(r.purpose.wire.toByte()); put(r.trigger.wire.toByte())
        putLong(r.revision); putLong(r.deadlineElapsedMillis); putId(r.capabilityChannelId); putId(r.frameChannelId)
        putId(r.descriptor.id); putLong(r.descriptor.device); putLong(r.descriptor.inode); putLong(r.descriptor.ownerUid)
        putLong(r.descriptor.mode); putLong(r.descriptor.length); put(r.descriptor.accessMode.toByte())
        put(r.signedRetryBudget.toByte()); put(r.retryAttempt.toByte())
    }
    private fun ByteBuffer.readRequest(): RuntimeAuthorityRequest {
        val consumerEpoch = readId(); val providerEpoch = readId(); val id = readId(); val generation = long
        val purposeCode = get().toInt() and 255
        val triggerCode = get().toInt() and 255
        val purpose = RuntimeAuthorityPurpose.entries.single { it.wire == purposeCode }
        val trigger = RuntimeAuthorityTrigger.entries.single { it.wire == triggerCode }
        val revision = long; val deadline = long; val capabilityChannel = readId(); val frameChannel = readId()
        val descriptor = RuntimeDescriptorBinding(readId(), long, long, long, long, long, get().toInt() and 255)
        return RuntimeAuthorityRequest(consumerEpoch, providerEpoch, id, generation, purpose, trigger, revision, deadline,
            capabilityChannel, frameChannel, descriptor,
            get().toInt() and 255, get().toInt() and 255)
    }
}

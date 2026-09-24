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

data class RuntimeProductionAuthorityOfferV1(val offer: RuntimeAuthorityOffer) {
    val captureFormat: Int get() = 1
    fun request(purpose: RuntimeAuthorityPurpose, descriptor: RuntimeDescriptorBinding) =
        RuntimeProductionAuthorityRequestV1(offer.request(purpose, descriptor))
    override fun toString() = "RuntimeProductionAuthorityOfferV1(redacted)"
}
sealed interface RuntimeProductionFrameVerificationV1 {
    class Verified(val authority: RuntimeVerifiedProductionCaptureV1) : RuntimeProductionFrameVerificationV1
    data class Rejected(val reason: RuntimeFrameRejection) : RuntimeProductionFrameVerificationV1
}
/** Authenticated transfer syntax, not a live native authority or registered session. */
class RuntimeVerifiedProductionCaptureV1 internal constructor(val request: RuntimeProductionAuthorityRequestV1,
    private var capture: RuntimeCaptureSnapshotV1?) : Closeable {
    init { require((capture != null) == (request.request.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY)) }
    @Synchronized fun takeCapture(): RuntimeCaptureSnapshotV1? = capture.also { capture = null }
    @Synchronized override fun close() { capture?.close(); capture = null }
    override fun toString() = "RuntimeVerifiedProductionCaptureV1(redacted)"
}
interface RuntimeProductionAuthorityFrameSealerV1 : Closeable { fun seal(payload: ByteArray): ByteArray? }
interface RuntimeProductionAuthorityFrameVerifierV1 : Closeable {
    fun verifyAndConsume(frame: ByteArray, observed: RuntimeDescriptorBinding, nowElapsedMillis: Long): RuntimeProductionFrameVerificationV1
}
object RuntimeProductionAuthorityFrameCodecV1 {
    private const val HEADER_BYTES = 182
    private const val TAG_BYTES = 32
    private const val DOMAIN = "KURDISTAN-RUNTIME-AUTHORITY-V3\u0000"
    fun encodedLength(payloadLength: Int): Int {
        require(payloadLength in 0..RuntimeCaptureCodecV1.MAX_BYTES)
        return HEADER_BYTES + payloadLength + TAG_BYTES
    }
    fun sealer(transferredKey: ByteArray, request: RuntimeProductionAuthorityRequestV1): RuntimeProductionAuthorityFrameSealerV1 {
        val key=takeKey(transferredKey)
        return try { Sealer(key,request) } catch(failure: Throwable) { key.fill(0); throw failure }
    }
    fun verifier(transferredKey: ByteArray, request: RuntimeProductionAuthorityRequestV1): RuntimeProductionAuthorityFrameVerifierV1 {
        val key=takeKey(transferredKey)
        return try { Verifier(key,request) } catch(failure: Throwable) { key.fill(0); throw failure }
    }
    private fun takeKey(input: ByteArray): ByteArray = try {
        require(input.size == 32)
        input.copyOf()
    } finally { input.fill(0) }
    private abstract class KeyOwner(private var key: ByteArray?) : Closeable {
        @Synchronized protected fun <T> consume(terminal: T, use: (ByteArray) -> T): T {
            val owned=key ?: return terminal
            key=null
            return try { use(owned) } finally { owned.fill(0) }
        }
        @Synchronized final override fun close() { key?.fill(0); key=null }
    }
    private class Sealer(key: ByteArray, private val expected: RuntimeProductionAuthorityRequestV1) :
        KeyOwner(key), RuntimeProductionAuthorityFrameSealerV1 {
        override fun seal(payload: ByteArray): ByteArray? = consume(null) { key ->
            var owned: ByteArray?=null
            var frame: ByteArray?=null
            var tag: ByteArray?=null
            try {
                val length=encodedLength(payload.size)
                val request=expected.request
                require(request.descriptor.length == length.toLong())
                require(if(request.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) payload.isNotEmpty() else payload.isEmpty())
                owned=payload.copyOf()
                if(owned.isNotEmpty()) RuntimeCaptureCodecV1.decode(ByteBuffer.wrap(owned)).close()
                frame=ByteArray(length)
                ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN).apply {
                    putInt(0x4b524146); put(3); put(0); putShort(HEADER_BYTES.toShort())
                    putInt(length); putInt(owned.size); RuntimeAuthorityRequestWire.write(this,request); put(1); put(owned)
                }
                tag=mac(key,frame,length-TAG_BYTES)
                require(tag.size == TAG_BYTES)
                tag.copyInto(frame,length-TAG_BYTES)
                frame.also { frame=null }
            } catch(_: Exception) { null }
            finally { owned?.fill(0); frame?.fill(0); tag?.fill(0) }
        }
    }
    private class Verifier(key: ByteArray, private val expected: RuntimeProductionAuthorityRequestV1) :
        KeyOwner(key), RuntimeProductionAuthorityFrameVerifierV1 {
        override fun verifyAndConsume(frame: ByteArray, observed: RuntimeDescriptorBinding, nowElapsedMillis: Long): RuntimeProductionFrameVerificationV1 =
            consume(RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.TERMINAL)) { key ->
                var owned: ByteArray?=null
                var tag: ByteArray?=null
                var received: ByteArray?=null
                var capture: RuntimeCaptureSnapshotV1?=null
                try {
                    if(!expected.request.isLiveAt(nowElapsedMillis)) return@consume RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.EXPIRED)
                    if(observed != expected.request.descriptor || observed.length != frame.size.toLong())
                        return@consume RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.BINDING)
                    require(frame.size in encodedLength(0)..encodedLength(RuntimeCaptureCodecV1.MAX_BYTES))
                    owned=frame.copyOf()
                    tag=mac(key,owned,owned.size-TAG_BYTES)
                    received=owned.copyOfRange(owned.size-TAG_BYTES,owned.size)
                    if(tag.size != TAG_BYTES || !MessageDigest.isEqual(tag,received))
                        return@consume RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.AUTHENTICATION)
                    val reader=ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
                    require(reader.int == 0x4b524146 && reader.get() == 3.toByte() && reader.get() == 0.toByte())
                    require(reader.short.toInt() == HEADER_BYTES && reader.int == owned.size)
                    val length=reader.int
                    require(encodedLength(length) == owned.size)
                    val actual=RuntimeProductionAuthorityRequestV1(RuntimeAuthorityRequestWire.read(reader))
                    if(actual != expected) return@consume RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.BINDING)
                    require(reader.get() == 1.toByte())
                    require(if(actual.request.purpose == RuntimeAuthorityPurpose.FULL_AUTHORITY) length > 0 else length == 0)
                    if(length > 0) {
                        reader.limit(HEADER_BYTES+length)
                        capture=RuntimeCaptureCodecV1.decode(reader)
                    }
                    val result=RuntimeVerifiedProductionCaptureV1(actual,capture)
                    capture=null
                    RuntimeProductionFrameVerificationV1.Verified(result)
                } catch(_: Exception) { RuntimeProductionFrameVerificationV1.Rejected(RuntimeFrameRejection.MALFORMED) }
                finally { owned?.fill(0); tag?.fill(0); received?.fill(0); capture?.close() }
            }
    }
    private fun mac(key: ByteArray, bytes: ByteArray, count: Int): ByteArray {
        val domain=DOMAIN.toByteArray(Charsets.US_ASCII)
        return try {
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(key,"HmacSHA256")); update(domain); update(bytes,0,count); doFinal()
            }
        } finally { domain.fill(0) }
    }
}

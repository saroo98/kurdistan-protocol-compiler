// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

/** Named typed calls, never an operation-code dispatcher. */
internal interface ProductionNativeCallsV1 {
    fun runProbe(parent: Long, request: ByteBuffer, position: Int, limit: Int, output: ByteBuffer, outputPosition: Int, outputLimit: Int, metadata: LongArray): Int
    fun openStream(parent: Long, request: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int
    fun receivePacket(parent: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int
    fun nextControl(parent: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int
    fun submitPacket(parent: Long, input: ByteBuffer, position: Int, limit: Int): Int
    fun confirmSocket(parent: Long, token: Long, protected: Int, hasNetwork: Int, network: Long): Int
    fun confirmPacket(parent: Long, token: Long, length: Long): Int
    fun rejectPacket(parent: Long, token: Long): Int
    fun reconnect(parent: Long, reason: Int): Int
    fun handover(parent: Long, hasNetwork: Int, network: Long): Int
}

internal class ProductionNativeSessionV1(
    override val openingSnapshot: NativeOpeningSnapshot,
    private val parent: ProductionNativeParentV1,
    private val calls: ProductionNativeCallsV1,
    private val probeBinding: AndroidProductionProbeBindingV1? = null,
    private val newStream: (ProductionNativeParentV1) -> ProductionNativeStreamV1,
) : ProductionNativeSession {
    override fun runProbe(request: NativeProbeRequest): NativeProductResult<NativeProbeResult> {
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var input: ByteBuffer? = null
        var output: ByteBuffer? = null
        var metadata: LongArray? = null
        try {
            if (probeBinding?.permits(request.targetId) == false)
                return NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED)
            try { input = ByteBuffer.allocateDirect(9); output = ByteBuffer.allocateDirect(21); metadata = LongArray(1) }
            catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            val encoded = try { ProductionOperationCodecV1.encodeProbe(request,input) }
                catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            if (encoded !is NativeProductResult.Success) return encoded as NativeProductResult.Failure
            val status = try { calls.runProbe(parent.rawHandle(),input,0,encoded.value,output,0,21,metadata) }
                catch (_: Throwable) { -1 }
            if (status !in 0..26 || status == 18 || status == 19 || status == 20 ||
                (status != 0 && metadata[0] != 0L) || (status == 0 && metadata[0] != 21L)) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            if (probeBinding?.isCurrent() == false)
                return NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED)
            val decoded = try { ProductionOperationCodecV1.decodeProbe(output,request,NativeProbePath.ACTIVE_RELAY_END_TO_END) }
                catch (_: Throwable) { null }
            if (decoded !is NativeProductResult.Success) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            return decoded
        } finally {
            input?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            output?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            metadata?.fill(0)
            parent.finishCall()
        }
    }

    override fun openProxyStream(request: NativeProxyRequest): NativeProductResult<NativeProxyStream> {
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var input: ByteBuffer? = null
        var metadata: LongArray? = null
        var stream: ProductionNativeStreamV1? = null
        var transferred = false
        try {
            try { stream = newStream(parent); input = ByteBuffer.allocateDirect(259); metadata = LongArray(1) }
            catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            val encoded = try { ProductionOperationCodecV1.encodeProxy(request,input) }
                catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            if (encoded !is NativeProductResult.Success) return encoded as NativeProductResult.Failure
            val status = try { calls.openStream(parent.rawHandle(),input,0,encoded.value,metadata) }
                catch (_: Throwable) { -1 }
            // Preallocated exact child owner adopts before status validation or result allocation.
            if (metadata[0] != 0L) stream.bind(metadata[0])
            if (status !in 0..26 || status == 18 || status == 19 || status == 20 || (status != 0 && stream.isBound()) || (status == 0 && !stream.isBound())) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            val result = try { NativeProductResult.Success<NativeProxyStream>(stream) }
                catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            transferred = true
            return result
        } finally {
            input?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            metadata?.fill(0)
            try { if (!transferred && stream?.isBound() == true) stream.close() }
            finally { parent.finishCall() }
        }
    }

    override fun receiveInboundPacket(output: ByteBuffer): NativeProductResult<NativePacketDelivery> {
        val position = output.position()
        val limit = output.limit()
        if (!output.isDirect || output.isReadOnly || limit <= position)
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        if (limit - position > 65535) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var metadata: LongArray? = null
        try {
            metadata = LongArray(2)
            val status = try { calls.receivePacket(parent.rawHandle(),output,position,limit,metadata) }
                catch (_: Throwable) { -1 }
            if (status !in 0..26 || status == 18 || status == 19 || status == 20 ||
                (status != 0 && (metadata[0] != 0L || metadata[1] != 0L))) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            if (metadata[0] <= 0 || metadata[0] > (limit-position).toLong() || metadata[1] == 0L) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            // A delivery receipt remains owned until explicit destination confirmation.
            // Construction failure retires this exact parent, never acknowledges a copy.
            val result = try { NativeProductResult.Success(NativePacketDelivery(metadata[0].toInt(),metadata[1])) }
                catch (_: Throwable) { null }
            if (result == null) {
                parent.close()
                return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
            }
            return result
        } finally { metadata?.fill(0); parent.finishCall() }
    }

    private val controlMonitor = Any()
    private var controlPolling = false
    private var controlSequence = 0uL
    private var controlGeneration = 0uL

    override fun nextControl(output: ByteBuffer): NativeProductResult<NativeControlEvent> {
        val position = output.position()
        val limit = output.limit()
        if (!output.isDirect || output.isReadOnly || limit <= position)
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        if (limit - position > 32800) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
        synchronized(controlMonitor) {
            if (controlPolling) return NativeProductResult.Failure(ProductFailureCode.RESOURCE_LIMIT)
            controlPolling = true
        }
        var admitted = false
        var metadata: LongArray? = null
        try {
            val admission = parent.beginCall()
            if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
            admitted = true
            metadata = LongArray(1)
            while (parent.isLive()) {
                metadata[0] = 0
                val status = try { calls.nextControl(parent.rawHandle(), output, position, limit, metadata) }
                    catch (_: Throwable) { -1 }
                if (status !in 0..26 || status == 19 || status == 18 || (status != 0 && metadata[0] != 0L))
                    return unsafeControl()
                if (status == 20) continue
                if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
                if (metadata[0] < 32 || metadata[0] > (limit - position).toLong()) return unsafeControl()
                val decoded = try {
                    val span = output.duplicate().apply { position(position); limit(position + metadata[0].toInt()) }
                    ProductionResultCodecV1.decodeControl(span, controlSequence, controlGeneration)
                } catch (_: Throwable) { null }
                if (decoded !is NativeProductResult.Success) return unsafeControl()
                controlSequence = decoded.value.eventSequence
                controlGeneration = decoded.value.connectionGeneration
                probeBinding?.observe(decoded.value)
                return decoded
            }
            return NativeProductResult.Failure(ProductFailureCode.CANCELLED)
        } finally {
            metadata?.fill(0)
            if (admitted) parent.finishCall()
            synchronized(controlMonitor) { controlPolling = false }
        }
    }
    private fun unsafeControl(): NativeProductResult<NativeControlEvent> {
        parent.close()
        return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    }

    override fun submitOutboundPacket(packet: ByteBuffer, length: Int): NativeProductResult<Unit> {
        val position = packet.position()
        if (!packet.isDirect || length <= 0 || length > packet.limit() - position)
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        if (length > 65535) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
        return scalar { calls.submitPacket(it, packet, position, position + length) }
    }
    override fun confirmSocketProtection(token: Long, protected: Boolean, networkHandle: Long?): NativeProductResult<Unit> = scalar {
        calls.confirmSocket(it, token, if (protected) 1 else 0, if (networkHandle == null) 0 else 1, networkHandle ?: 0)
    }
    override fun confirmInboundDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit> {
        if (deliveredLength < 0) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        return scalar { calls.confirmPacket(it, token, deliveredLength.toLong()) }
    }
    override fun rejectInboundDelivery(token: Long): NativeProductResult<Unit> = scalar { calls.rejectPacket(it, token) }
    override fun requestReconnect(reason: NativeReconnectReason): NativeProductResult<Unit> {
        val value = when (reason) {
            NativeReconnectReason.USER_REQUEST -> 1
            NativeReconnectReason.NETWORK_FAILURE -> 2
            NativeReconnectReason.SETTINGS_CHANGE -> 3
            NativeReconnectReason.HANDOVER -> return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        }
        probeBinding?.invalidate()
        return scalar { calls.reconnect(it, value) }
    }
    override fun requestHandover(networkHandle: Long?): NativeProductResult<Unit> = scalar {
        probeBinding?.invalidate()
        calls.handover(it, if (networkHandle == null) 0 else 1, networkHandle ?: 0)
    }
    override fun cancel(): NativeProductResult<Unit> { probeBinding?.invalidate(); return result(parent.cancelStatus()) }
    override fun close() { probeBinding?.invalidate(); parent.close() }

    private fun scalar(operation: (Long) -> Int): NativeProductResult<Unit> {
        val admitted = parent.beginCall()
        if (admitted != 0) return result(admitted)
        val status = try { operation(parent.rawHandle()) } catch (_: Throwable) { -1 }
            finally { parent.finishCall() }
        if (status !in 0..26 || status == 19 || status == 20) {
            parent.close()
            return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
        }
        return result(status)
    }
    private fun result(status: Int): NativeProductResult<Unit> =
        if (status == 0) NativeProductResult.Success(Unit) else NativeProductResult.Failure(productionFailureV1(status))
}

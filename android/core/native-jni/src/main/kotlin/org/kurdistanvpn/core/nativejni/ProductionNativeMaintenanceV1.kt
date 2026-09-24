// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.io.Closeable
import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

internal interface ProductionNativeMaintenanceCallsV1 {
    fun runProbe(parent: Long, request: ByteBuffer, position: Int, limit: Int, output: ByteBuffer, outputPosition: Int, outputLimit: Int, metadata: LongArray): Int
    fun checkUpdate(parent: Long, request: ByteBuffer, position: Int, limit: Int, output: ByteBuffer, outputPosition: Int, outputLimit: Int, metadata: LongArray): Int
    fun materialize(parent: Long, candidate: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int
    fun release(parent: Long, candidate: Long): Int
}

internal fun <T> openMaintenanceCapturedV1(
    delegate: AndroidProductionPlatformDelegateV1, owner: Long,
    nativeOpen: (ByteBuffer, LongArray) -> Int,
    cancel: (Long) -> Int, close: (Long) -> Int,
    adopt: (Closeable) -> Unit, failedOpening: () -> Unit,
    construct: (ProductionNativeParentV1, ULong) -> T,
): NativeProductResult<T> {
    var generation = 0uL
    return openMaintenanceOwnedV1(
        acquire = { metadata ->
            generation = delegate.capturedGeneration(owner).toULong()
            check(generation != 0uL)
            captureProductionOpeningV1(delegate, owner, ProductionOpeningPurposeV1.MAINTENANCE) {
                request -> nativeOpen(request, metadata)
            }
        }, cancel = cancel, close = close, adopt = adopt, failedOpening = failedOpening,
        construct = { parent ->
            // Already adopted: a lost capture or failed second read closes the exact parent.
            check(delegate.capturedGeneration(owner).toULong() == generation)
            construct(parent, generation)
        })
}

/** Candidate state is ownership bookkeeping, never authority for a native call. */
internal class ProductionNativeMaintenanceV1(
    private val parent: ProductionNativeParentV1,
    private val currentGeneration: ULong,
    private val calls: ProductionNativeMaintenanceCallsV1,
    private val probeBinding: AndroidProductionProbeBindingV1? = null,
) : ProductionNativeMaintenance {
    private var candidate = 0L
    init { require(currentGeneration != 0uL) }

    override fun checkSameDeploymentUpdate(request: NativeUpdateRequest, previewOutput: ByteBuffer): NativeProductResult<NativeUpdateCheck> {
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var input: ByteBuffer? = null
        var metadata: LongArray? = null
        try {
            try { input = ByteBuffer.allocateDirect(3); metadata = LongArray(1) }
            catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            val encoded = try { ProductionOperationCodecV1.encodeUpdate(request,input) }
                catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            if (encoded !is NativeProductResult.Success) return encoded as NativeProductResult.Failure
            val position = previewOutput.position()
            val status = try { calls.checkUpdate(parent.rawHandle(),input,0,encoded.value,previewOutput,position,previewOutput.limit(),metadata) }
                catch (_: Throwable) { -1 }
            if (unsafeStatus(status) || status != 0 && metadata[0] != 0L) return unsafe()
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            if (metadata[0] != 3L && metadata[0] != 38L || metadata[0] > previewOutput.remaining()) return unsafe()
            // Acquire any published raw candidate before allocating a decode view.
            var acquired = false
            if (metadata[0] == 38L) {
                var raw = 0L
                for (i in 3..10) raw = (raw shl 8) or (previewOutput.get(position+i).toLong() and 255)
                // Native expiry may retire the previous candidate without a wrapper call.
                // A distinct successful publication is authoritative; replay is not.
                if (candidate != 0L && candidate == raw) return unsafe()
                candidate = raw
                acquired = raw != 0L
            }
            val decoded = try {
                val view = previewOutput.duplicate().apply { limit(position+metadata[0].toInt()) }
                ProductionOperationCodecV1.decodeUpdate(view,currentGeneration)
            } catch (_: Throwable) { null }
            if (decoded == null || decoded is NativeProductResult.Failure &&
                (acquired || decoded.code == ProductFailureCode.INTERNAL_FAILURE)) return unsafe()
            return decoded
        } finally {
            input?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            metadata?.fill(0)
            parent.finishCall()
        }
    }

    override fun materializeVerifiedUpdate(candidateHandle: Long, artifactOutput: ByteBuffer): NativeProductResult<Int> {
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var metadata: LongArray? = null
        try {
            try { metadata = LongArray(1) }
            catch (_: Throwable) { return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE) }
            val remaining = artifactOutput.remaining()
            val status = try { calls.materialize(parent.rawHandle(),candidateHandle,artifactOutput,artifactOutput.position(),artifactOutput.limit(),metadata) }
                catch (_: Throwable) { -1 }
            // Native success consumes the input even if later metadata is invalid.
            if (status == 0 && candidate == candidateHandle) candidate = 0
            if (unsafeStatus(status) || status != 0 && metadata[0] != 0L ||
                status == 0 && (metadata[0] !in 1L..1052763L || metadata[0] > remaining)) return unsafe()
            return if (status == 0) NativeProductResult.Success(metadata[0].toInt())
                else NativeProductResult.Failure(productionFailureV1(status))
        } finally { metadata?.fill(0); parent.finishCall() }
    }

    override fun releaseUpdate(candidateHandle: Long): NativeProductResult<Unit> {
        val admission = parent.beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        try {
            val status = try { calls.release(parent.rawHandle(),candidateHandle) } catch (_: Throwable) { -1 }
            if (status == 0 && candidate == candidateHandle) candidate = 0
            if (unsafeStatus(status)) return unsafe()
            return if (status == 0) NativeProductResult.Success(Unit) else NativeProductResult.Failure(productionFailureV1(status))
        } finally { parent.finishCall() }
    }

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
            if (unsafeStatus(status) || status != 0 && metadata[0] != 0L || status == 0 && metadata[0] != 21L) return unsafe()
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            if (probeBinding?.isCurrent() == false)
                return NativeProductResult.Failure(ProductFailureCode.OPERATION_INTERRUPTED)
            val decoded = try { ProductionOperationCodecV1.decodeProbe(output,request,NativeProbePath.DISCONNECTED_TCP_CONNECT) }
                catch (_: Throwable) { null }
            if (decoded !is NativeProductResult.Success) return unsafe()
            return decoded
        } finally {
            input?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            output?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i,0) }
            metadata?.fill(0)
            parent.finishCall()
        }
    }

    override fun cancel(): NativeProductResult<Unit> {
        probeBinding?.invalidate()
        val status = parent.cancelStatus()
        return if (status == 0) NativeProductResult.Success(Unit) else NativeProductResult.Failure(productionFailureV1(status))
    }

    override fun close() { probeBinding?.invalidate(); parent.close() }

    private fun unsafeStatus(status: Int) = status !in 0..26 || status == 18 || status == 19 || status == 20
    private fun <T> unsafe(): NativeProductResult<T> {
        parent.close()
        return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    }
}

/** The exact parent is allocated before acquisition and adopted before any
 * fallible consumer construction. Maintenance has one ordinary caller. */
internal fun <T> openMaintenanceOwnedV1(
    acquire: (LongArray) -> Int,
    cancel: (Long) -> Int,
    close: (Long) -> Int,
    adopt: (Closeable) -> Unit,
    failedOpening: () -> Unit,
    construct: (ProductionNativeParentV1) -> T,
): NativeProductResult<T> {
    var metadata: LongArray? = null
    var owner: ProductionNativeParentV1? = null
    var bound = false
    var transferred = false
    try {
        val parent = ProductionNativeParentV1(cancel, close, 1).also { owner = it }
        val values = LongArray(1).also { metadata = it }
        val status = acquire(values)
        if (values[0] != 0L) {
            parent.bind(values[0])
            bound = true
            adopt(parent)
        }
        if (status != 0) return NativeProductResult.Failure(
            if (bound) ProductFailureCode.INTERNAL_FAILURE else productionFailureV1(status))
        if (!bound) return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
        val result = NativeProductResult.Success(construct(parent))
        transferred = true
        return result
    } catch (_: Throwable) {
        return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    } finally {
        metadata?.fill(0)
        if (!transferred) {
            if (bound) checkNotNull(owner).close()
            else failedOpening()
        }
    }
}

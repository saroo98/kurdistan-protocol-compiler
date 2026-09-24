// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

internal interface ProductionNativeStreamCallsV1 {
    fun send(parent: Long, child: Long, input: ByteBuffer, position: Int, limit: Int): Int
    fun receive(parent: Long, child: Long, output: ByteBuffer, position: Int, limit: Int, metadata: LongArray): Int
    fun confirm(parent: Long, child: Long, token: Long, length: Long): Int
    fun reject(parent: Long, child: Long, token: Long): Int
    fun halfClose(parent: Long, child: Long): Int
    fun cancel(parent: Long, child: Long): Int
    fun close(parent: Long, child: Long): Int
}

internal class ProductionNativeStreamV1(
    private val parent: ProductionNativeParentV1,
    private val calls: ProductionNativeStreamCallsV1,
) : NativeProxyStream {
    private val child = ProductionNativeParentV1(
        { nativeLifecycle(it, calls::cancel) }, { nativeLifecycle(it, calls::close) },
    )
    fun bind(value: Long) = child.bind(value)
    fun isBound(): Boolean = child.rawHandle() != 0L

    override fun send(input: ByteBuffer, length: Int): NativeProductResult<Unit> {
        val position = input.position()
        if (!input.isDirect || length <= 0 || length > input.limit()-position)
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        if (length > 16384) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
        return scalar { p,c -> calls.send(p,c,input,position,position+length) }
    }
    override fun confirmDelivery(token: Long, deliveredLength: Int): NativeProductResult<Unit> {
        if (deliveredLength < 0) return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        return scalar { p,c -> calls.confirm(p,c,token,deliveredLength.toLong()) }
    }
    override fun rejectDelivery(token: Long): NativeProductResult<Unit> = scalar { p,c -> calls.reject(p,c,token) }
    override fun halfClose(): NativeProductResult<Unit> = scalar(calls::halfClose)
    override fun cancel(): NativeProductResult<Unit> = result(child.cancelStatus())
    override fun close() {
        // Completed parent cancellation joins and retires every child. An earlier
        // interrupted child call is not contrary evidence to that later proof.
        if (parent.childrenRetirementStatus() == 0) return
        child.close()
    }

    override fun receive(output: ByteBuffer): NativeProductResult<NativeStreamRead> {
        val position = output.position(); val limit = output.limit()
        if (!output.isDirect || output.isReadOnly || limit <= position)
            return NativeProductResult.Failure(ProductFailureCode.INVALID_INPUT)
        if (limit-position > 16384) return NativeProductResult.Failure(ProductFailureCode.SIZE_LIMIT)
        val admission = beginCall()
        if (admission != 0) return NativeProductResult.Failure(productionFailureV1(admission))
        var metadata: LongArray? = null
        try {
            metadata = LongArray(2)
            val status = try { calls.receive(parent.rawHandle(),child.rawHandle(),output,position,limit,metadata) }
                catch (_: Throwable) { -1 }
            if (status !in 0..26 || status == 18 || status == 20 ||
                (status != 0 && (metadata[0] != 0L || metadata[1] != 0L))) return unsafeOwner()
            if (status == 19) return NativeProductResult.Success(NativeStreamRead.EndOfStream)
            if (status != 0) return NativeProductResult.Failure(productionFailureV1(status))
            if (metadata[0] <= 0 || metadata[0] > (limit-position).toLong() || metadata[1] == 0L) return unsafeOwner()
            val delivery = try { NativeProductResult.Success(NativeStreamRead.Data(metadata[0].toInt(),metadata[1])) }
                catch (_: Throwable) { null }
            return delivery ?: unsafeOwner()
        } finally { metadata?.fill(0); finishCall() }
    }

    private fun nativeLifecycle(value: Long, operation: (Long,Long)->Int): Int {
        parent.childrenRetirementStatus()?.let { return it }
        val admission = parent.beginCall()
        if (admission != 0) return parent.childrenRetirementStatus() ?: admission
        val status = try { operation(parent.rawHandle(),value) } catch (_: Throwable) { -1 }
            finally { parent.finishCall() }
        if (status !in 0..26 || status == 19 || status == 20) { parent.close(); return 18 }
        return status
    }
    private fun beginCall(): Int {
        val own = child.beginCall()
        if (own != 0) return own
        val outer = parent.beginCall()
        if (outer != 0) child.finishCall()
        return outer
    }
    private fun finishCall() { parent.finishCall(); child.finishCall() }
    private fun scalar(operation: (Long,Long)->Int): NativeProductResult<Unit> {
        val admission = beginCall()
        if (admission != 0) return result(admission)
        val status = try { operation(parent.rawHandle(),child.rawHandle()) } catch (_: Throwable) { -1 }
            finally { finishCall() }
        if (status !in 0..26 || status == 19 || status == 20) return unsafeOwner()
        return result(status)
    }
    private fun <T> unsafeOwner(): NativeProductResult<T> {
        parent.close()
        return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    }
    private fun result(status: Int): NativeProductResult<Unit> =
        if (status == 0) NativeProductResult.Success(Unit) else NativeProductResult.Failure(productionFailureV1(status))
}

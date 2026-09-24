// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativejni

import java.io.Closeable
import java.util.concurrent.CountDownLatch
import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.NativeOpeningSnapshot
import org.kurdistanvpn.core.nativeapi.NativeProductResult

/** Trusted capture SPI only. All five copies and the encoded request remain
 * bounded owned storage until this synchronous acquisition returns. */
internal fun captureProductionOpeningV1(
    delegate: AndroidProductionPlatformDelegateV1,
    owner: Long,
    purpose: ProductionOpeningPurposeV1,
    acquire: (ByteBuffer) -> Int,
): Int {
    if (owner == 0L) return 2
    val sizes = IntArray(5)
    val written = IntArray(5)
    val spans = arrayOfNulls<ByteBuffer>(5)
    var encoded: ByteBuffer? = null
    try {
        if (delegate.captureSizes(owner, sizes) != 0) return 18
        var total = 32L
        for (i in 0..4) {
            val maximum = when (i) { 0 -> 1405996; 1 -> 1118299; 2 -> 512; 3 -> 128; else -> 196608 }
            if (sizes[i] <= 0) return 2
            if (sizes[i] > maximum) return 4
            total += sizes[i]
        }
        if (total > 2721575) return 4
        for (i in 0..4) spans[i] = ByteBuffer.allocateDirect(sizes[i])
        if (delegate.captureCopyInto(owner, checkNotNull(spans[0]), checkNotNull(spans[1]),
            checkNotNull(spans[2]), checkNotNull(spans[3]), checkNotNull(spans[4]), written) != 0) return 18
        if (!sizes.contentEquals(written)) return 18
        val request = ByteBuffer.allocateDirect(total.toInt()).also { encoded = it }
        val packed = ProductionOpeningCodecV1.encodeOpening(purpose, checkNotNull(spans[4]),
            checkNotNull(spans[0]), checkNotNull(spans[1]), checkNotNull(spans[2]), checkNotNull(spans[3]), request)
        if (packed !is NativeProductResult.Success || packed.value != request.capacity()) return 18
        return acquire(request)
    } finally {
        encoded?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i, 0) }
        for (span in spans) span?.let { it.clear(); for (i in 0 until it.capacity()) it.put(i, 0) }
        sizes.fill(0); written.fill(0)
    }
}

internal fun <T> openProductionOwnedV1(
    acquire: (ByteBuffer, LongArray) -> Int,
    cancel: (Long) -> Int,
    close: (Long) -> Int,
    adopt: (Closeable) -> Unit,
    failedOpening: () -> Unit,
    construct: (NativeOpeningSnapshot, ProductionNativeParentV1) -> T,
): NativeProductResult<T> {
    var output: ByteBuffer? = null
    var metadata: LongArray? = null
    var owner: ProductionNativeParentV1? = null
    var bound = false
    var transferred = false
    try {
        val parent = ProductionNativeParentV1(cancel, close).also { owner = it }
        val stage = ByteBuffer.allocateDirect(32768).also { output = it }
        val values = LongArray(2).also { metadata = it }
        val status = acquire(stage, values)
        // Only zero is invalid. Adoption precedes even the written-length check.
        if (values[0] != 0L) {
            parent.bind(values[0])
            bound = true
            adopt(parent)
        }
        if (status != 0) return NativeProductResult.Failure(
            if (bound) ProductFailureCode.INTERNAL_FAILURE else productionFailureV1(status))
        if (!bound || values[1] !in 220L..32768L)
            return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
        val view = stage.duplicate().apply { position(0); limit(values[1].toInt()) }
        val decoded = ProductionResultCodecV1.decodeOpening(view)
        if (decoded is NativeProductResult.Failure) return decoded
        val value = construct((decoded as NativeProductResult.Success).value, parent)
        val result = NativeProductResult.Success(value)
        transferred = true
        return result
    } catch (_: Throwable) {
        return NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    } finally {
        output?.let { stage -> stage.clear(); for (index in 0 until stage.capacity()) stage.put(index, 0) }
        metadata?.fill(0)
        if (!transferred) {
            if (bound) checkNotNull(owner).close()
            else failedOpening()
        }
    }
}

internal fun <T> openProductionCapturedV1(
    delegate: AndroidProductionPlatformDelegateV1,
    owner: Long,
    nativeOpen: (ByteBuffer, ByteBuffer, LongArray) -> Int,
    cancel: (Long) -> Int,
    close: (Long) -> Int,
    adopt: (Closeable) -> Unit,
    failedOpening: () -> Unit,
    construct: (NativeOpeningSnapshot, ProductionNativeParentV1) -> T,
): NativeProductResult<T> = openProductionOwnedV1(
    acquire = { output, metadata ->
        captureProductionOpeningV1(delegate, owner, ProductionOpeningPurposeV1.SESSION) { request ->
            nativeOpen(request, output, metadata)
        }
    }, cancel = cancel, close = close, adopt = adopt, failedOpening = failedOpening, construct = construct,
)

/** Allocated before native open and adopted by the existing runtime guard as
 * soon as native returns a nonzero raw-bit handle, before decoding/constructing
 * the typed owner. No owner monitor spans native work or another caller's wait. */
internal class ProductionNativeParentV1(
    private val cancelOperation: (Long) -> Int,
    private val closeOperation: (Long) -> Int,
    private val maximumCalls: Int = 266,
) : Closeable {
    init { require(maximumCalls == 1 || maximumCalls == 266) }
    private val monitor = Any()
    private val cancelDone = CountDownLatch(1)
    private val closeDone = CountDownLatch(1)
    private var handle = 0L
    private var cancelStarted = false
    private var closeStarted = false
    private var cancelResult = 18
    private var closeResult = 18
    private var activeCalls = 0

    fun bind(value: Long) = synchronized(monitor) {
        check(value != 0L && handle == 0L && !cancelStarted && !closeStarted)
        handle = value
    }

    fun isLive(): Boolean = synchronized(monitor) { handle != 0L && !cancelStarted && !closeStarted }

    /** Taken before any per-call owned buffers or metadata are allocated. */
    fun beginCall(): Int = synchronized(monitor) {
        when {
            handle == 0L -> 3
            cancelStarted || closeStarted -> 7
            activeCalls >= maximumCalls -> 5
            else -> { activeCalls++; 0 }
        }
    }

    fun finishCall() = synchronized(monitor) {
        check(activeCalls > 0)
        activeCalls--
    }

    fun rawHandle(): Long = synchronized(monitor) { handle }

    /** Only this owner's completed close can prove all its children retired. */
    fun retirementStatus(): Int? {
        if (!synchronized(monitor) { closeStarted }) return null
        awaitCompletion(closeDone)
        return synchronized(monitor) { closeResult }
    }

    /** Child-resource proof only. Cancellation never proves platform retirement. */
    fun childrenRetirementStatus(): Int? {
        val action = synchronized(monitor) {
            when { closeStarted -> 2; cancelStarted -> 1; else -> 0 }
        }
        return when (action) {
            2 -> { awaitCompletion(closeDone); synchronized(monitor) { closeResult } }
            1 -> { awaitCompletion(cancelDone); synchronized(monitor) { cancelResult } }
            else -> null
        }
    }

    fun cancelStatus(): Int {
        val action = synchronized(monitor) {
            check(handle != 0L) { "NATIVE_PRODUCTION_CLEANUP_UNPROVEN" }
            when {
                cancelStarted -> 1
                closeStarted -> 2
                else -> { cancelStarted = true; 0 }
            }
        }
        if (action == 2) {
            awaitCompletion(closeDone)
            return synchronized(monitor) { closeResult }
        }
        if (action == 1) awaitCompletion(cancelDone)
        else {
            val result = invoke(cancelOperation)
            synchronized(monitor) { cancelResult = result }
            cancelDone.countDown()
        }
        return synchronized(monitor) { cancelResult }
    }

    override fun close() {
        val action = synchronized(monitor) {
            check(handle != 0L) { "NATIVE_PRODUCTION_CLEANUP_UNPROVEN" }
            if (closeStarted) 2 else {
                closeStarted = true
                if (cancelStarted) 1 else 0
            }
        }
        if (action == 2) awaitCompletion(closeDone)
        else {
            if (action == 1) awaitCompletion(cancelDone)
            val result = invoke(closeOperation)
            synchronized(monitor) { closeResult = result }
            closeDone.countDown()
        }
        check(synchronized(monitor) { closeResult == 0 }) { "NATIVE_PRODUCTION_CLEANUP_UNPROVEN" }
    }

    private fun invoke(operation: (Long) -> Int): Int = try {
        val result = operation(synchronized(monitor) { handle })
        if (result in 0..26 && result != 19 && result != 20) result else 18
    } catch (_: Throwable) { 18 }

    private fun awaitCompletion(done: CountDownLatch) {
        var interrupted = false
        try {
            while (true) {
                try { done.await(); return }
                catch (_: InterruptedException) { interrupted = true }
            }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
}

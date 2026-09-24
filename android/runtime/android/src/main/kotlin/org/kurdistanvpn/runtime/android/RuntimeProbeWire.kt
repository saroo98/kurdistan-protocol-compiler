// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

/** Fixed-size observation only. No address, native handle or executable authority crosses IPC. */
object RuntimeProbeWire {
    fun encode(result: NativeProductResult<NativeProbeResult>): LongArray = when (result) {
        is NativeProductResult.Failure -> longArrayOf(1, result.code.ordinal.toLong() + 1)
        is NativeProductResult.Success -> result.value.let {
            longArrayOf(1, 0, it.path.ordinal.toLong(), it.method.ordinal.toLong(), it.attempted.toLong(),
                it.succeeded.toLong(), it.failed.toLong(), it.unstarted.toLong(),
                it.meanLatencyMicros?.toLong() ?: -1, it.jitterMicros?.toLong() ?: -1,
                it.lossPermille.toLong(), it.stability.ordinal.toLong(), it.completion.ordinal.toLong())
        }
    }

    fun decode(input: LongArray): NativeProductResult<NativeProbeResult> {
        require(input.size == 2 || input.size == 13)
        require(input[0] == 1L)
        fun value(index: Int): Int {
            require(input[index] in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong())
            return input[index].toInt()
        }
        fun <T> entry(values: List<T>, index: Int): T =
            requireNotNull(values.getOrNull(value(index)))
        if (input.size == 2) {
            require(input[1] in 1..ProductFailureCode.entries.size.toLong())
            return NativeProductResult.Failure(ProductFailureCode.entries[value(1) - 1])
        }
        require(input[1] == 0L && input[8] >= -1 && input[9] >= -1)
        return NativeProductResult.Success(NativeProbeResult(entry(NativeProbePath.entries, 2),
            entry(NativeProbeMethod.entries, 3), value(4), value(5), value(6), value(7),
            value(8).takeIf { it != -1 }, value(9).takeIf { it != -1 }, value(10),
            entry(NativeProbeStability.entries, 11), entry(NativeProbeCompletion.entries, 12)))
    }
}

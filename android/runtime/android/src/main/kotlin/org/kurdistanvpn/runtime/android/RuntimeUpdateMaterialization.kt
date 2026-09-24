// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import java.io.Closeable
import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

/** Bounded verified artifact, not a native candidate handle or permission to apply an update. */
class RuntimeVerifiedUpdate(val generation: ULong, val changes: NativeUpdateChanges, val artifact: ByteArray) : Closeable {
    init { require(generation > 0u && artifact.size in 1..1052763) }
    override fun close() { artifact.fill(0) }
    override fun toString() = "RuntimeVerifiedUpdate(redacted)"
}

internal fun materializeRuntimeUpdate(parent: ProductionNativeMaintenance): NativeProductResult<RuntimeVerifiedUpdate?> {
    val preview = ByteBuffer.allocateDirect(38)
    var output: ByteBuffer? = null
    var handle = 0L
    var bytes: ByteArray? = null
    var result: NativeProductResult<RuntimeVerifiedUpdate?> = NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    try {
        result = when (val checked = parent.checkSameDeploymentUpdate(NativeUpdateRequest(30_000), preview)) {
            is NativeProductResult.Failure -> checked
            is NativeProductResult.Success -> when (val update = checked.value) {
                NativeUpdateCheck.NoChange -> NativeProductResult.Success(null)
                is NativeUpdateCheck.Candidate -> {
                    val candidate = update.candidate
                    handle = candidate.handle
                    val target = ByteBuffer.allocateDirect(candidate.artifactLength).also { output = it }
                    when (val built = parent.materializeVerifiedUpdate(handle, target)) {
                        is NativeProductResult.Failure -> built
                        is NativeProductResult.Success -> {
                            handle = 0 // Native success consumes the candidate, including malformed later metadata.
                            check(built.value == candidate.artifactLength)
                            val artifact = ByteArray(built.value).also { bytes = it }
                            for (i in artifact.indices) artifact[i] = target.get(i)
                            NativeProductResult.Success(RuntimeVerifiedUpdate(candidate.generation, candidate.changes, artifact))
                        }
                    }
                }
            }
        }
    } catch (_: Exception) {
        result = NativeProductResult.Failure(ProductFailureCode.INTERNAL_FAILURE)
    } finally {
        for (buffer in listOfNotNull(preview, output)) for (i in 0 until buffer.capacity()) buffer.put(i, 0)
        if (handle != 0L) {
            val retired = try { parent.releaseUpdate(handle) is NativeProductResult.Success } catch (_: Exception) { false }
            if (!retired) result = NativeProductResult.Failure(ProductFailureCode.STORAGE_DEGRADED)
        }
        if (result !is NativeProductResult.Success) bytes?.fill(0)
    }
    return result
}

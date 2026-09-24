// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*


object RuntimeUpdateWire {
    const val MAX_ARTIFACT_BYTES = 1052763
    fun encode(result: NativeProductResult<RuntimeVerifiedUpdate?>): LongArray = when (result) {
        is NativeProductResult.Failure -> longArrayOf(1, result.code.ordinal.toLong() + 1)
        is NativeProductResult.Success -> result.value?.let { value -> value.changes.let {
            longArrayOf(1, 0, value.generation.toLong(), value.artifact.size.toLong(),
                it.identityAuthority.toLong(), it.endpointSet.toLong(), it.tunnelAddressPlan.toLong(),
                it.routePlan.toLong(), it.dnsPlan.toLong(), it.strategyPlan.toLong(), it.transport.toLong(),
                it.runtimeLimits.toLong(), it.services.toLong(), it.validityAuthority.toLong())
        } } ?: longArrayOf(1, 0)
    }

    fun decode(metadata: LongArray, artifact: ByteArray): NativeProductResult<RuntimeVerifiedUpdate?> {
        require(metadata.size == 2 || metadata.size == 14)
        require(metadata[0] == 1L)
        if (metadata.size == 2) {
            require(artifact.isEmpty() && metadata[1] in 0..ProductFailureCode.entries.size.toLong())
            return if (metadata[1] == 0L) NativeProductResult.Success(null)
                else NativeProductResult.Failure(ProductFailureCode.entries[metadata[1].toInt() - 1])
        }
        require(metadata[1] == 0L && metadata[2] != 0L && metadata[3] in 1..MAX_ARTIFACT_BYTES.toLong())
        require(metadata[3] == artifact.size.toLong() && (4..13).all { metadata[it] in 0..1 })
        fun field(i: Int) = metadata[i].toInt()
        return NativeProductResult.Success(RuntimeVerifiedUpdate(metadata[2].toULong(),
            NativeUpdateChanges(field(4), field(5), field(6), field(7), field(8), field(9), field(10),
                field(11), field(12), field(13)), artifact))
    }
}

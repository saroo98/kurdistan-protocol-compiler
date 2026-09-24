// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.runtime.android

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.ProductFailureCode
import org.kurdistanvpn.core.nativeapi.*

class RuntimeUpdateMaterializationTest {
    @Test fun candidateIsMaterializedExactlyAndFailedMaterializationReleasesIt() {
        for (fail in listOf(false, true)) {
            var releases = 0
            val parent = object : ProductionNativeMaintenance {
                override fun checkSameDeploymentUpdate(request: NativeUpdateRequest, previewOutput: ByteBuffer) =
                    NativeProductResult.Success(NativeUpdateCheck.Candidate(NativeUpdateCandidate(7,
                        NativeDeploymentMatch.SAME_DEPLOYMENT, 2u, NativeCandidateExpiry.VALID, 0,
                        NativeCandidateRevocation.NOT_REVOKED, NativeCandidateCompatibility.COMPATIBLE,
                        NativeUpdateChanges(0, 1, 0, 0, 0, 0, 0, 0, 0, 0), 3)))
                override fun materializeVerifiedUpdate(candidateHandle: Long, artifactOutput: ByteBuffer): NativeProductResult<Int> {
                    assertEquals(7L, candidateHandle)
                    artifactOutput.put(byteArrayOf(1, 2, 3))
                    return if (fail) NativeProductResult.Failure(ProductFailureCode.UPDATE_SIGNATURE_INVALID)
                        else NativeProductResult.Success(3)
                }
                override fun releaseUpdate(candidateHandle: Long): NativeProductResult<Unit> {
                    assertEquals(7L, candidateHandle); releases++; return NativeProductResult.Success(Unit)
                }
                override fun runProbe(request: NativeProbeRequest): NativeProductResult<NativeProbeResult> = error("No probe")
                override fun cancel() = NativeProductResult.Success(Unit)
                override fun close() = Unit
            }
            val result = materializeRuntimeUpdate(parent)
            if (fail) {
                assertEquals(NativeProductResult.Failure(ProductFailureCode.UPDATE_SIGNATURE_INVALID), result)
                assertEquals(1, releases)
            } else {
                val value = checkNotNull((result as NativeProductResult.Success).value)
                assertEquals(2uL, value.generation)
                assertArrayEquals(byteArrayOf(1, 2, 3), value.artifact)
                assertEquals(0, releases)
                value.close()
                assertArrayEquals(ByteArray(3), value.artifact)
            }
        }
    }
}

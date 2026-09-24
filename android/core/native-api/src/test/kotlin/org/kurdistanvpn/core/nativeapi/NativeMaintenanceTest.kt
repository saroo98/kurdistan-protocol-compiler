// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import java.nio.ByteBuffer
import org.junit.Assert.*
import org.junit.Test

class NativeMaintenanceTest {
    @Test fun maintenancePortCompilesWithoutAProductFake() {
        val port = object : ProductionNativeMaintenance {
            override fun checkSameDeploymentUpdate(request: NativeUpdateRequest, previewOutput: ByteBuffer) = NativeProductResult.Success(NativeUpdateCheck.NoChange)
            override fun materializeVerifiedUpdate(candidateHandle: Long, artifactOutput: ByteBuffer) = NativeProductResult.Success(1)
            override fun releaseUpdate(candidateHandle: Long) = NativeProductResult.Success(Unit)
            override fun runProbe(request: NativeProbeRequest) = NativeProductResult.Failure(org.kurdistanvpn.core.model.ProductFailureCode.CANCELLED)
            override fun cancel() = NativeProductResult.Success(Unit)
            override fun close() = Unit
        }
        assertEquals(NativeProductResult.Success(NativeUpdateCheck.NoChange), port.checkSameDeploymentUpdate(NativeUpdateRequest(1000), ByteBuffer.allocate(38)))
    }

    @Test fun candidatePreservesOpaqueAndUnsignedValuesAndRedacts() {
        val changes = NativeUpdateChanges(1, 0, 1, 0, 1, 0, 1, 0, 1, 0)
        val candidate = NativeUpdateCandidate(Long.MIN_VALUE, NativeDeploymentMatch.SAME_DEPLOYMENT, ULong.MAX_VALUE,
            NativeCandidateExpiry.EXPIRING_SOON, 7, NativeCandidateRevocation.NOT_REVOKED,
            NativeCandidateCompatibility.COMPATIBLE, changes, 1052763)
        assertEquals(Long.MIN_VALUE, candidate.handle)
        assertEquals(ULong.MAX_VALUE, candidate.generation)
        assertEquals(5, candidate.changes.totalChangedCategories)
        assertEquals("NativeUpdateCandidate(redacted)", candidate.toString())
        assertThrows(IllegalArgumentException::class.java) {
            NativeUpdateCandidate(0, NativeDeploymentMatch.SAME_DEPLOYMENT, 1uL, NativeCandidateExpiry.VALID, 0,
                NativeCandidateRevocation.NOT_REVOKED, NativeCandidateCompatibility.COMPATIBLE, changes, 1)
        }
    }
}

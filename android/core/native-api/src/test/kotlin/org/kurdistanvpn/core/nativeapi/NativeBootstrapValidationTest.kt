// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.core.nativeapi

import org.junit.Assert.*
import org.junit.Test

class NativeBootstrapValidationTest {
    @Test fun returnedPlanFactsRejectImpossibleZeroSignedRetryAndPreserveDigestOwnership() {
        val digest=ByteArray(32){7}
        assertThrows(IllegalArgumentException::class.java){NativeLegacyBootstrapFactsV1(1uL,digest,0)}
        assertThrows(IllegalArgumentException::class.java){NativeProductionBootstrapFactsV1(1uL,digest,1280,0,0)}
        val facts=NativeProductionBootstrapFactsV1(ULong.MAX_VALUE,digest,1280,1,0)
        digest.fill(0);facts.planDigest.fill(0)
        assertEquals(ULong.MAX_VALUE,facts.generation)
        assertArrayEquals(ByteArray(32){7},facts.planDigest)
        assertEquals("NativeProductionBootstrapFactsV1(redacted)",facts.toString())
    }
}

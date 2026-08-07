// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineQrEncoderTest {
    @Test
    fun recipientRequestIsDeterministicBoundedAndDoesNotMutateInput() {
        val request = ByteArray(128) { index -> (index * 17).toByte() }
        val original = request.clone()

        val first = OfflineQrEncoder.recipientRequest(request)
        val second = OfflineQrEncoder.recipientRequest(request)

        assertArrayEquals(original, request)
        assertEquals(first.width, second.width)
        assertTrue(first.width in 21..177)
        assertTrue(first.modules.contentEquals(second.modules))
        assertTrue(first.modules.any { it })
        assertTrue(first.modules.any { !it })
    }

    @Test(expected = IllegalArgumentException::class)
    fun recipientRequestRejectsOversizedInput() {
        OfflineQrEncoder.recipientRequest(ByteArray(513))
    }
}

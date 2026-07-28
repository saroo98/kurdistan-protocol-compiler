// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.platform.importing

import java.io.ByteArrayInputStream
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class ImportBoundaryTest {
    @Test
    fun boundedReaderAcceptsTheLimitAndRejectsOneExtraByte() {
        val exact = ByteArray(8192) { (it and 0xff).toByte() }
        assertArrayEquals(
            exact,
            BoundedInputReader.read(ByteArrayInputStream(exact), exact.size),
        )
        assertThrows(IllegalArgumentException::class.java) {
            BoundedInputReader.read(
                ByteArrayInputStream(exact + byteArrayOf(1)),
                exact.size,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            BoundedInputReader.read(ByteArrayInputStream(byteArrayOf()), exact.size)
        }
    }

    @Test
    fun verifyRequestIsExactBoundedBinary() {
        val encoded = VerifyRequestEncoder.encode(
            ImportCandidate(
                IngressKind.FILE,
                ArtifactClass.SIGNED_PUBLIC,
                listOf(byteArrayOf(1, 2, 3)),
            ),
        )
        assertEquals("KVI1", encoded.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(1, encoded[4].toInt())
        assertEquals(1, encoded[5].toInt())
    }

    @Test
    fun multipartQrIsOrderedAndExpires() {
        var time = 100L
        val accumulator = MultipartQrAccumulator { time }
        assertNull(accumulator.add("KURD1/2/2/Yg", ArtifactClass.SIGNED_PUBLIC))
        val complete = accumulator.add("KURD1/1/2/YQ", ArtifactClass.SIGNED_PUBLIC)
        assertEquals(listOf("KURD1/1/2/YQ", "KURD1/2/2/Yg"), complete!!.parts.map { it.toString(Charsets.UTF_8) })

        assertNull(accumulator.add("KURD1/1/2/YQ", ArtifactClass.SIGNED_PUBLIC))
        time += 5 * 60 * 1000L
        assertNull(accumulator.add("KURD1/2/2/Yg", ArtifactClass.SIGNED_PUBLIC))
    }
}

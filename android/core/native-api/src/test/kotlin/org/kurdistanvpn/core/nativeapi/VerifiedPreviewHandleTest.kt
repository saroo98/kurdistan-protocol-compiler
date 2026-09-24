// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.nativeapi

import org.junit.Assert.*
import org.junit.Test

class VerifiedPreviewHandleTest {
    @Test fun residueOwnsBoundedBytesRedactsAndClearsAllBorrowedCopiesEvenOnFailure() {
        val input = listOf("private-endpoint".encodeToByteArray(), "deployment-local".encodeToByteArray(), byteArrayOf())
        val residue = NativePreviewFields(input)
        input[0].fill(0)
        var borrowed: List<ByteArray> = emptyList()
        residue.withLegacyFields { fields ->
            borrowed = fields
            assertEquals("private-endpoint", fields[0].decodeToString())
        }
        assertTrue(borrowed.all { field -> field.all { it == 0.toByte() } })
        assertFalse(residue.toString().contains("private"))
        assertThrows(IllegalStateException::class.java) {
            residue.withLegacyFields { fields -> borrowed = fields; error("test") }
        }
        assertTrue(borrowed.all { field -> field.all { it == 0.toByte() } })
        residue.close()
        val ownedField = residue.javaClass.getDeclaredField("owned").also { it.isAccessible = true }
        @Suppress("UNCHECKED_CAST") val owned = ownedField.get(residue) as List<ByteArray>
        assertTrue(owned.all { field -> field.all { it == 0.toByte() } })
        assertThrows(IllegalStateException::class.java) { residue.withLegacyFields { } }
        residue.close()
        assertThrows(IllegalArgumentException::class.java) { NativePreviewFields(listOf(ByteArray(256), byteArrayOf(), byteArrayOf())) }
    }
    @Test fun releasingHandleClearsItsResidueAndCannotExposeItByStringification() {
        val residue = NativePreviewFields(listOf(byteArrayOf(1), byteArrayOf(), byteArrayOf()))
        val preview = org.kurdistanvpn.core.model.RedactedProfilePreview("public", "synthetic", "fingerprint", "lineage", 1u, 1, false)
        val handle = VerifiedPreviewHandle(123, preview, residue)
        assertEquals("VerifiedPreviewHandle(redacted)", handle.toString())
        handle.close()
        assertThrows(IllegalStateException::class.java) { handle.withLegacyPreviewFields { } }
    }
}

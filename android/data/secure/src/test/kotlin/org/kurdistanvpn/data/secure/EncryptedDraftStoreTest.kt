// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.OperationKind

class EncryptedDraftStoreTest {
    @Test fun malformedProductOperationFieldsAndSnapshotBoundsFailClosed() {
        ProductOperationState(ByteArray(32) { 1 }, 17, null, null, 10, 0, 2, 4, 0, 0, byteArrayOf(1), byteArrayOf(2)).use { value ->
            val bytes = value.encode()
            checkMalformed(bytes, listOf({ it.fill(0, 6, 38) }, { it[38] = 15 }, { it[39] = 2 }, { it[40] = 2 },
                { it[41] = 11 }, { putLong(it, 42, -1) }, { putLong(it, 50, 0) }, { putLong(it, 50, 3) },
                { putLong(it, 50, Long.MAX_VALUE - 1) }, { putLong(it, 58, 6) }, { putLong(it, 66, -1) },
                { putLong(it, 74, -1) }, { putInt(it, 82, 0) }, { putInt(it, 82, 2 * 1024 * 1024 + 1) },
                { putInt(it, 82, Int.MAX_VALUE) }, { putInt(it, 87, -1) }, { putInt(it, 87, 2 * 1024 * 1024 + 1) })) {
                ProductOperationState.decode(it).use { }
            }
            val decoded = ProductOperationState.decode(bytes); bytes.fill(0)
            decoded.use { assertEquals(10, it.attempt); assertArrayEquals(value.encode(), it.encode()) }
        }
        ProductOperationState(ByteArray(32) { 1 }, 16, OperationKind.UPDATE, "a", 0, Long.MAX_VALUE,
            Long.MAX_VALUE - 3, Long.MAX_VALUE - 1, Long.MAX_VALUE, Long.MAX_VALUE, ByteArray(2 * 1024 * 1024) { 1 }, byteArrayOf(2)).use {
            ProductOperationState.decode(it.encode()).use { decoded ->
                assertEquals(Long.MAX_VALUE - 1, decoded.journalRevisionAfter)
                assertEquals(2 * 1024 * 1024, decoded.priorSnapshot().size)
            }
        }
        for (size in listOf(0, 2 * 1024 * 1024 + 1)) assertThrows(IllegalArgumentException::class.java) {
            ProductOperationState(ByteArray(32) { 1 }, 16, null, null, 0, 0, 2, 4, 0, 0, ByteArray(size), byteArrayOf(2))
        }
    }
    @Test fun productOperationAllowsMetadataEqualityAndOwnsAllArrays() {
        val operation = ByteArray(32) { 1 }; val prior = byteArrayOf(1); val candidate = byteArrayOf(2)
        ProductOperationState(operation, 16, OperationKind.UPDATE, "profile-a", 0, 500000, 2, 4, 7, 7, prior, candidate).use { value ->
            operation.fill(0); prior.fill(0); candidate.fill(0)
            checkRecord(value.encode(), 27, 4 * 1024 * 1024 + 256) { ProductOperationState.decode(it).use { r -> r.encode() } }
            ProductOperationState.decode(value.encode()).use { decoded ->
                assertEquals(7L, decoded.settingsRevisionBefore); assertEquals(7L, decoded.settingsRevisionAfter)
                assertArrayEquals(byteArrayOf(1), decoded.priorSnapshot())
                decoded.priorSnapshot().fill(0); assertArrayEquals(byteArrayOf(1), decoded.priorSnapshot())
                assertTrue(decoded.matches(ByteArray(32) { 1 }, 2, 4))
                decoded.close(); assertThrows(IllegalStateException::class.java) { decoded.encode() }
            }
        }
        for (kind in listOf(0, 15, 18, 255)) assertThrows(IllegalArgumentException::class.java) {
            ProductOperationState(ByteArray(32) { 1 }, kind, null, null, 0, 0, 2, 4, 0, 0, byteArrayOf(1), byteArrayOf(2))
        }
        assertThrows(IllegalArgumentException::class.java) {
            SettingsOperationState(ByteArray(32) { 1 }, 2, 4, 7, 7, byteArrayOf(1), byteArrayOf(2))
        }
    }
    @Test fun frozenSettingsOperationV1BytesRemainCompatible() {
        val expected = ("4b534f31011b" + "01".repeat(32) + "000000000000000200000000000000040000000000000000000000000000000100000001010000000102")
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        SettingsOperationState(ByteArray(32) { 1 }, 2, 4, 0, 1, byteArrayOf(1), byteArrayOf(2)).use {
            assertArrayEquals(expected, it.encode())
        }
        SettingsOperationState.decode(expected).use { assertArrayEquals(expected, it.encode()) }
    }
    @Test fun operationMaterialOwnsBytesAndExactJournalAndSemanticRevisionPairs() {
        val prior = byteArrayOf(1, 2); val target = byteArrayOf(3, 4); val operation = ByteArray(32) { 9 }
        SettingsOperationState(operation, 8, 10, 2, 3, prior, target).use { record ->
            prior.fill(0); target.fill(0); operation.fill(0)
            SettingsOperationState.decode(record.encode()).use { restored ->
                assertTrue(restored.matches(ByteArray(32) { 9 }, 8, 10))
                assertFalse(restored.matches(ByteArray(32) { 8 }, 8, 10))
                assertFalse(restored.matches(ByteArray(32) { 9 }, 6, 10))
                assertEquals(2L, restored.settingsBefore); assertEquals(3L, restored.settingsAfter)
                assertArrayEquals(byteArrayOf(1, 2), restored.priorSnapshot())
                assertArrayEquals(byteArrayOf(3, 4), restored.candidateSnapshot())
                restored.priorSnapshot().fill(0)
                assertArrayEquals(byteArrayOf(1, 2), restored.priorSnapshot())
            }
        }
    }
    @Test fun operationMaterialRejectsUnknownRoleMalformedBytesAndInvalidRevisions() {
        val operation = ByteArray(32) { 1 }
        SettingsOperationState(operation, 2, 4, 0, 1, byteArrayOf(1), byteArrayOf(2)).use { state ->
            val encoded = state.encode()
            for (end in encoded.indices) assertThrows(IllegalArgumentException::class.java) { SettingsOperationState.decode(encoded.copyOf(end)) }
            for (offset in listOf(4, 5)) assertThrows(IllegalArgumentException::class.java) { SettingsOperationState.decode(encoded.clone().also { it[offset] = 99 }) }
            assertThrows(IllegalArgumentException::class.java) { SettingsOperationState.decode(encoded + 0) }
        }
        assertThrows(IllegalArgumentException::class.java) { SettingsOperationState(operation, 2, 8, 0, 1, byteArrayOf(1), byteArrayOf(2)) }
        assertThrows(IllegalArgumentException::class.java) { SettingsOperationState(operation, 2, 4, 2, 2, byteArrayOf(1), byteArrayOf(2)) }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test

class ProtectedStateJournalCodecTest {
    @Test fun everyJournalDigestDomainMatchesIndependentFixedSha256Vectors() {
        // Independently calculated using .NET SHA256 over fixed ASCII labels, u32be(3), 01 02 03.
        val expected = listOf(
            "c7dbf9c872d26ebf6528f2c928e4021119a8377f0235e518074ed963e9e408a9",
            "38d1fd67f928ddee452e6457c28b9e785665b1d13d9e6f727c83f3a94aec912a",
            "38dd17eda15bb87afc476e6ea5ae1c56c18a5d0806a12dec85f4f7dcb451fe37",
            "4ccee570609333ddfc4dd1b2ea840d5e55fc901aff755001ec60db03508556d4",
        )
        val input = byteArrayOf(1, 2, 3)
        val actual = listOf(JournalDigest.record(input), JournalDigest.checkpoint(input),
            JournalDigest.objectContent(input), JournalDigest.projection(input))
        input.fill(0)
        actual.zip(expected).forEach { (digest, literal) ->
            assertArrayEquals(literal.chunked(2).map { it.toInt(16).toByte() }.toByteArray(), digest.bytes())
            digest.bytes().fill(0)
            assertTrue(digest.matches(literal.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))
        }
        for (i in actual.indices) for (j in actual.indices) assertEquals(i == j, actual[i].same(actual[j]))
        assertThrows(IllegalArgumentException::class.java) { actual[0].requireCheckpoint() }
        assertThrows(IllegalArgumentException::class.java) { actual[1].requireRecord() }
        assertThrows(IllegalArgumentException::class.java) { actual[2].requireProjection() }
    }

    @Test fun controlBoundsRejectNegativeOverflowAndExhaustedReservationsWithoutProducingDirty() {
        val initial = JournalControl.initial(ByteArray(16) { 1 }).encode()
        for (offset in listOf(22, 38, 46, 58, 163, 203)) {
            assertThrows("negative u64 at $offset", IllegalArgumentException::class.java) {
                JournalControl.decode(initial.clone().also { java.nio.ByteBuffer.wrap(it).putLong(offset, -1) })
            }
        }
        for (count in listOf(-1, 257, Int.MAX_VALUE)) assertThrows(IllegalArgumentException::class.java) {
            JournalControl.decode(initial.clone().also { java.nio.ByteBuffer.wrap(it).putInt(54, count) })
        }
        for (bytes in listOf(8388609L, Long.MAX_VALUE)) assertThrows(IllegalArgumentException::class.java) {
            JournalControl.decode(initial.clone().also { java.nio.ByteBuffer.wrap(it).putLong(58, bytes) })
        }
        // Both revision fields must be changed, so rejection below is actually reserve overflow,
        // not an unrelated malformed-control decode (the previous single-offset fixture was weaker).
        val exhausted = initial.clone().also {
            java.nio.ByteBuffer.wrap(it).putLong(22, Long.MAX_VALUE - 1).putLong(203, Long.MAX_VALUE - 1)
        }
        val decoded = JournalControl.decode(exhausted)
        assertEquals(Long.MAX_VALUE - 1, decoded.revision)
        assertThrows(IllegalArgumentException::class.java) { decoded.reserve(ByteArray(32) { 2 }, MutationKind.ROUTING) }
        assertArrayEquals(exhausted, decoded.encode())
        for (operation in listOf(ByteArray(0), ByteArray(16) { 1 }, ByteArray(31) { 1 }, ByteArray(32), ByteArray(33) { 1 })) {
            assertThrows(IllegalArgumentException::class.java) { JournalControl.decode(initial).reserve(operation, MutationKind.ROUTING) }
        }
    }

    @Test fun storeIdentityBindsExistingDirectoryLockUidGenerationAndEpochWithoutDiscoveryFallback() {
        val directory = org.kurdistanvpn.core.nativeapi.DurableDirectory(4, 10000,
            org.kurdistanvpn.core.nativeapi.DurableFileIdentity(3, 40))
        val lock = org.kurdistanvpn.core.nativeapi.DurableFileIdentity(3, 41)
        val epoch = ByteArray(16) { 7 }
        val record = ProtectedStoreIdentity.create(directory, lock, epoch, 1)
        val bytes = record.encode()
        epoch.fill(0)
        ProtectedStoreIdentity.decode(bytes).requireMatches(directory, lock, ByteArray(16) { 7 }, 1)
        for (invalid in listOf(directory.copy(expectedUid = 10001),
            directory.copy(identity = org.kurdistanvpn.core.nativeapi.DurableFileIdentity(3, 42)))) {
            assertThrows(IllegalStateException::class.java) { record.requireMatches(invalid, lock, ByteArray(16) { 7 }, 1) }
        }
        assertThrows(IllegalStateException::class.java) {
            record.requireMatches(directory, org.kurdistanvpn.core.nativeapi.DurableFileIdentity(3, 43), ByteArray(16) { 7 }, 1)
        }
        assertThrows(IllegalStateException::class.java) { record.requireMatches(directory, lock, ByteArray(16) { 8 }, 1) }
        assertThrows(IllegalStateException::class.java) { record.requireMatches(directory, lock, ByteArray(16) { 7 }, 2) }
        for (length in bytes.indices) assertThrows(IllegalArgumentException::class.java) {
            ProtectedStoreIdentity.decode(bytes.copyOf(length))
        }
        assertThrows(IllegalArgumentException::class.java) { ProtectedStoreIdentity.decode(bytes + 0) }
        assertArrayEquals(bytes, ProtectedStoreIdentity.decode(bytes).encode())
    }

    @Test fun securityMutationUsesTheApproved256BitOperationIdentity() {
        val clean = JournalControl.initial(ByteArray(16) { 1 })
        assertThrows(IllegalArgumentException::class.java) { clean.reserve(ByteArray(16) { 2 }, MutationKind.PROFILE_IMPORT) }
        val dirty = clean.reserve(ByteArray(32) { 2 }, MutationKind.PROFILE_IMPORT)
        assertArrayEquals(ByteArray(32) { 2 }, JournalControl.decode(dirty.encode()).operationId())
    }
    @Test fun journalCodecRejectsTruncationTrailingDataAndUnknownVersion() {
        val control = JournalControl.initial(ByteArray(16) { (it + 1).toByte() })
        val encoded = control.encode()
        for (end in encoded.indices) assertThrows(IllegalArgumentException::class.java) {
            JournalControl.decode(encoded.copyOf(end))
        }
        assertThrows(IllegalArgumentException::class.java) { JournalControl.decode(encoded + byteArrayOf(0)) }
        val changedVersion = encoded.clone().also { it[4] = 127 }
        assertThrows(IllegalArgumentException::class.java) { JournalControl.decode(changedVersion) }
        assertArrayEquals(encoded, JournalControl.decode(encoded).encode())
    }

    @Test fun journalControlDefensivelyOwnsAllCallerBuffers() {
        val store = ByteArray(16) { 7 }
        val control = JournalControl.initial(store)
        val before = control.encode()
        store.fill(99)
        control.storeId().fill(42)
        assertArrayEquals(before, control.encode())
    }

    @Test fun journalBoundsRejectOverflowBeforeDirtyAndCannotRetagDigests() {
        val digest = JournalDigest.record(byteArrayOf(1, 2, 3))
        assertFalse(digest.same(JournalDigest.checkpoint(byteArrayOf(1, 2, 3))))
        assertThrows(IllegalArgumentException::class.java) {
            JournalControl.decode(exhaustedControlVector()).reserve(ByteArray(JournalLimits.OPERATION_BYTES) { 1 }, MutationKind.PROFILE_IMPORT)
        }
    }

    @Test fun dirtyConsumesPairAndCannotReserveAnotherOperation() {
        val clean = JournalControl.initial(ByteArray(16) { 1 })
        val dirty = clean.reserve(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, MutationKind.PROFILE_IMPORT)
        assertEquals(1L, dirty.revision)
        assertEquals(2L, dirty.reservedCleanRevision)
        assertThrows(IllegalStateException::class.java) {
            dirty.reserve(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, MutationKind.PROFILE_DELETE)
        }
        val completed = dirty.complete(JournalDigest.checkpoint(byteArrayOf(3)), JournalDigest.record(byteArrayOf(4)))
        assertEquals(2L, completed.revision)
        assertEquals(3L, completed.reserve(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, MutationKind.PROFILE_DELETE).revision)
    }
    private fun exhaustedControlVector(): ByteArray = JournalControl.initial(ByteArray(16) { 1 }).encode().also { bytes ->
        java.nio.ByteBuffer.wrap(bytes).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(22, Long.MAX_VALUE - 1)
    }
}

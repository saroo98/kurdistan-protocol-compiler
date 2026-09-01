// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test

class ProtectedStateValidatorTest {
    @Test fun minimalCheckpointMatchesIndependentBigEndianGoldenAndEveryPrefixRejects() {
        // Literal schema oracle, assembled independently of the codec: KPS1, v2, VERIFIED,
        // store[16], revision u64be, operation[32], empty selected ID, two one-byte images, zero refs.
        val golden = hex("4b5053310201" + "0102030405060708090a0b0c0d0e0f10" +
            "0000000000000002" + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
            "00" + "000000017a" + "000000017b" + "00000000")
        assertEquals(77, golden.size)
        val snapshot = ProtectedStateSnapshot.create(ByteArray(16) { (it + 1).toByte() }, 2, null,
            emptyList(), byteArrayOf(0x7a), byteArrayOf(0x7b), ByteArray(32) { (it + 0x20).toByte() })
        assertArrayEquals(golden, snapshot.encode())
        assertArrayEquals(golden, ProtectedStateSnapshot.decode(golden).encode())
        for (length in golden.indices) assertThrows("prefix $length", IllegalArgumentException::class.java) {
            ProtectedStateSnapshot.decode(golden.copyOf(length))
        }
        assertThrows(IllegalArgumentException::class.java) { ProtectedStateSnapshot.decode(golden + 0) }
    }

    @Test fun referenceMatchesIndependentGoldenIncludingDigestDomainAndOperationBinding() {
        val reference = ProtectedObjectReference.fromEncryptedObject(1, "a", "x", 1, byteArrayOf(0x7a),
            org.kurdistanvpn.data.secure.SecureOperationBinding(ByteArray(32) { 2 }, 2))
        // Object digest was independently calculated from ASCII domain + u32be(1) + 0x7a,
        // not obtained from JournalDigest or a production encoder.
        val golden = hex("01" + "0161" + "0178" + "00000001" + "00000001" +
            "47ea8b4fedf4a9488a2fb185a77c7e9cedc3f00a367bdc21d6db378784140db0" + "02" +
            "0202020202020202020202020202020202020202020202020202020202020202" + "0000000000000002")
        val output = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(output).use(reference::write)
        assertEquals(86, golden.size)
        assertArrayEquals(golden, output.toByteArray())
        assertTrue(ProtectedObjectReference.read(java.nio.ByteBuffer.wrap(golden)).matches(byteArrayOf(0x7a)))
    }

    @Test fun reorderedDuplicateUnknownAndFutureReferenceWireCannotBeCanonicalizedIntoAcceptance() {
        val a = ProtectedObjectReference.fromEncryptedObject(1, "a", "x", 1, byteArrayOf(7), syntheticObjectBinding())
        val b = ProtectedObjectReference.fromEncryptedObject(1, "b", "y", 1, byteArrayOf(8), syntheticObjectBinding())
        val canonical = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, listOf(a, b),
            byteArrayOf(2), byteArrayOf(3), ByteArray(32) { 2 }).encode()
        assertEquals(249, canonical.size)
        val reversed = canonical.copyOfRange(0, 77) + canonical.copyOfRange(163, 249) + canonical.copyOfRange(77, 163)
        val malformed = listOf(reversed,
            canonical.clone().also { it[165] = 'a'.code.toByte() },
            canonical.clone().also { it[167] = 'x'.code.toByte() },
            canonical.clone().also { it[77] = 14 },
            canonical.clone().also { it[122] = 1 },
            canonical.clone().also { java.nio.ByteBuffer.wrap(it).putLong(155, 4) })
        for ((index, raw) in malformed.withIndex()) assertThrows("variant $index", IllegalArgumentException::class.java) {
            ProtectedStateSnapshot.decode(raw)
        }
        assertArrayEquals(canonical, ProtectedStateSnapshot.decode(canonical).encode())
    }

    @Test fun checkpointFieldBoundsRejectMalformedClaimsBeforeReadingReferencedObjects() {
        val minimum = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, emptyList(),
            byteArrayOf(2), byteArrayOf(3), ByteArray(32) { 2 }).encode()
        val invalid = mutableListOf<ByteArray>()
        for (value in listOf(-1, 0, 65537, Int.MAX_VALUE)) invalid += minimum.clone().also {
            java.nio.ByteBuffer.wrap(it).putInt(63, value)
        }
        for (value in listOf(-1, 0, 524289, Int.MAX_VALUE)) invalid += minimum.clone().also {
            java.nio.ByteBuffer.wrap(it).putInt(68, value)
        }
        for (value in listOf(-1, 1, 4097, Int.MAX_VALUE)) invalid += minimum.clone().also {
            java.nio.ByteBuffer.wrap(it).putInt(73, value)
        }
        for (value in listOf(-1L, 0L, 1L, Long.MAX_VALUE)) invalid += minimum.clone().also {
            java.nio.ByteBuffer.wrap(it).putLong(22, value)
        }
        invalid += minimum.clone().also { it.fill(0, 6, 22) }
        invalid += minimum.clone().also { it.fill(0, 30, 62) }
        invalid += minimum.clone().also { it[62] = 0xff.toByte() }
        invalid += ByteArray(JournalLimits.CHECKPOINT_BYTES + 1)
        for ((index, raw) in invalid.withIndex()) assertThrows("claim $index", IllegalArgumentException::class.java) {
            ProtectedStateSnapshot.decode(raw)
        }
        val maximumImages = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, Long.MAX_VALUE - 1, null,
            emptyList(), ByteArray(65536), ByteArray(524288), ByteArray(32) { 2 })
        assertArrayEquals(maximumImages.encode(), ProtectedStateSnapshot.decode(maximumImages.encode()).encode())
        for ((settings, catalog) in listOf(byteArrayOf() to byteArrayOf(1), byteArrayOf(1) to byteArrayOf(),
            ByteArray(65537) to byteArrayOf(1), byteArrayOf(1) to ByteArray(524289))) {
            assertThrows(IllegalArgumentException::class.java) {
                ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, emptyList(), settings, catalog, ByteArray(32) { 2 })
            }
        }
    }

    @Test fun objectRoleGenerationLengthAndCountBoundsHaveIndependentBoundaryCases() {
        for (role in listOf(0, 14, -1, Int.MAX_VALUE)) assertThrows(IllegalArgumentException::class.java) {
            ProtectedObjectReference.fromEncryptedObject(role, "a", "x", 1, byteArrayOf(1), syntheticObjectBinding())
        }
        for (generation in listOf(-1, 0)) assertThrows(IllegalArgumentException::class.java) {
            ProtectedObjectReference.fromEncryptedObject(1, "a", "x", generation, byteArrayOf(1), syntheticObjectBinding())
        }
        for (length in listOf(0, JournalLimits.OBJECT_BYTES + 1)) assertThrows(IllegalArgumentException::class.java) {
            ProtectedObjectReference.fromEncryptedObject(1, "a", "x", 1, ByteArray(length), syntheticObjectBinding())
        }
        val maximum = ProtectedObjectReference.fromEncryptedObject(13, "a", "x", Int.MAX_VALUE,
            ByteArray(JournalLimits.OBJECT_BYTES), syntheticObjectBinding())
        assertEquals(JournalLimits.OBJECT_BYTES, maximum.length)
        val refs = (1..4096).map { index -> ProtectedObjectReference.fromEncryptedObject(1,
            "id-$index", "object-$index", 1, byteArrayOf(1), syntheticObjectBinding()) }
        val snapshot = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, refs,
            byteArrayOf(2), byteArrayOf(3), ByteArray(32) { 2 })
        assertEquals(4096, ProtectedStateSnapshot.decode(snapshot.encode()).objects().size)
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, refs + refs.first(),
                byteArrayOf(2), byteArrayOf(3), ByteArray(32) { 2 })
        }
    }

    @Test fun quarantinedCheckpointDispositionRoundTripsAndRejectsUnknownValue() {
        val snapshot = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, emptyList(),
            byteArrayOf(2), byteArrayOf(3), ByteArray(32) { 2 }, ProtectedStateDisposition.QUARANTINED)
        val raw = snapshot.encode()
        assertEquals(2, raw[4].toInt())
        assertEquals(2, raw[5].toInt())
        assertEquals(ProtectedStateDisposition.QUARANTINED, ProtectedStateSnapshot.decode(raw).disposition)
        assertArrayEquals(raw, ProtectedStateSnapshot.decode(raw).encode())
        assertThrows(Exception::class.java) { ProtectedStateSnapshot.decode(raw.clone().also { it[5] = 3 }) }
    }

    @Test fun readOnlyObjectsRequireTheirOwnAuthenticatedOperationNotTheCurrentRevision() {
        val key = JournalTestKey()
        val codec = org.kurdistanvpn.data.secure.SecureEnvelopeCodec()
        val binding = org.kurdistanvpn.data.secure.SecureOperationBinding(ByteArray(32) { 2 }, 2)
        val wrong = org.kurdistanvpn.data.secure.SecureOperationBinding(ByteArray(32) { 3 }, 4)
        val role = org.kurdistanvpn.data.secure.SecureDataClass.IMPORT_REQUEST
        val encoded = codec.sealForOperation("profile-one", role, byteArrayOf(1, 2), key, binding)
        val ref = ProtectedObjectReference.fromEncryptedObject(role.wireValue, "profile-one", "object-one", 1, encoded, binding)
        val view = ReadOnlyProtectedBlobView(listOf(ref), { encoded.clone() }, codec, key)
        assertArrayEquals(byteArrayOf(1, 2), view.reopen("profile-one", role))
        val substituted = ProtectedObjectReference.fromEncryptedObject(role.wireValue, "profile-one", "object-one", 1, encoded, wrong)
        assertThrows(Exception::class.java) {
            ReadOnlyProtectedBlobView(listOf(substituted), { encoded.clone() }, codec, key).reopen("profile-one", role)
        }
        val legacy = codec.seal("profile-one", role, byteArrayOf(1, 2), key)
        val legacyRef = ProtectedObjectReference.fromEncryptedObject(role.wireValue, "profile-one", "object-one", 1, legacy, binding)
        assertThrows(Exception::class.java) {
            ReadOnlyProtectedBlobView(listOf(legacyRef), { legacy.clone() }, codec, key).reopen("profile-one", role)
        }
    }
    @Test fun snapshotOwnsInputAndRejectsDuplicateLogicalObjects() {
        val input = byteArrayOf(1, 2, 3)
        val reference = ProtectedObjectReference.fromEncryptedObject(1, "profile-one", "object-one", 1, input, syntheticObjectBinding())
        input.fill(0)
        assertTrue(reference.matches(byteArrayOf(1, 2, 3)))
        val references = mutableListOf(reference)
        val snapshot = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, "profile-one", references,
            byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        references.clear()
        val first = snapshot.encode()
        snapshot.settingsBytes().fill(0)
        assertArrayEquals(first, snapshot.encode())
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, listOf(reference, reference), byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 2 })
        }
    }
    @Test fun canonicalRoundTripRejectsTrailingUnknownAndUnsortedData() {
        val a = ProtectedObjectReference.fromEncryptedObject(1, "a", "object-a", 1, byteArrayOf(7), syntheticObjectBinding())
        val b = ProtectedObjectReference.fromEncryptedObject(2, "b", "object-b", 1, byteArrayOf(8), syntheticObjectBinding())
        val first = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, "a", listOf(a, b), byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 2 }).encode()
        val reorderedInput = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, "a", listOf(b, a), byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 2 }).encode()
        assertArrayEquals(first, reorderedInput)
        assertArrayEquals(first, ProtectedStateSnapshot.decode(first).encode())
        assertThrows(IllegalArgumentException::class.java) { ProtectedStateSnapshot.decode(first + 0) }
        assertThrows(IllegalArgumentException::class.java) { ProtectedStateSnapshot.decode(first.clone().also { it[4] = 99 }) }
    }
    @Test fun objectReferenceRequiresExactLengthContentClassAndGeneration() {
        val ref = ProtectedObjectReference.fromEncryptedObject(4, "recipient-one", "object-one", 3, byteArrayOf(9, 8), syntheticObjectBinding())
        assertTrue(ref.matches(byteArrayOf(9, 8)))
        assertFalse(ref.matches(byteArrayOf(9)))
        assertFalse(ref.matches(byteArrayOf(9, 7)))
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedObjectReference.fromEncryptedObject(99, "a", "object-a", 0, byteArrayOf(1), syntheticObjectBinding())
        }
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

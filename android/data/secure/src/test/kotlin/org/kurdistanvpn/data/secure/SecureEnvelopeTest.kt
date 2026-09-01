// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SecureEnvelopeTest {
    private val codec = SecureEnvelopeCodec(SecureRandom(byteArrayOf(1, 2, 3, 4)))
    private val kek = InMemoryKek()

    @Test fun versionTwoAuthenticatesTheExactOperationRevisionRoleAndPayload() {
        val operation = ByteArray(32) { 7 }
        val binding = SecureOperationBinding(operation, 6)
        operation.fill(0)
        val secret = ByteArray(128) { (it + 1).toByte() }
        val encoded = codec.sealForOperation("test-record", SecureDataClass.IMPORT_REQUEST, secret, kek, binding)
        assertEquals(2, encoded[4].toInt())
        assertEquals(1, codec.keyGeneration(encoded))
        val opened = codec.openForOperation(encoded, "test-record", SecureDataClass.IMPORT_REQUEST, kek, binding)
        assertArrayEquals(secret, opened.plaintext)
        opened.plaintext.fill(0)
        for (wrong in listOf(SecureOperationBinding(ByteArray(32) { 8 }, 6), SecureOperationBinding(ByteArray(32) { 7 }, 8))) {
            assertThrows(Exception::class.java) {
                codec.openForOperation(encoded, "test-record", SecureDataClass.IMPORT_REQUEST, kek, wrong)
            }
        }
        assertThrows(Exception::class.java) {
            codec.openForOperation(encoded, "test-record", SecureDataClass.RECIPIENT_PRIVATE_MATERIAL, kek, binding)
        }
        // Legacy entry points must not silently ignore the required operation binding.
        assertThrows(Exception::class.java) { codec.open(encoded, "test-record", kek) }
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(secret)
        assertFalse(encoded.asList().windowed(digest.size).any { it == digest.asList() })
    }

    @Test fun versionTwoRejectsLegacyAndUnknownVersionsBeforeKeyAccess() {
        var unwraps = 0
        val counted = object : KeyEncryptionKey by kek {
            override fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey): ByteArray {
                unwraps++; return kek.unwrap(recordId, dataClass, wrapped)
            }
        }
        val binding = SecureOperationBinding(ByteArray(32) { 2 }, 2)
        val legacy = codec.seal("test-record", SecureDataClass.IMPORT_REQUEST, byteArrayOf(1), kek)
        assertThrows(Exception::class.java) {
            codec.openForOperation(legacy, "test-record", SecureDataClass.IMPORT_REQUEST, counted, binding)
        }
        val v2 = codec.sealForOperation("test-record", SecureDataClass.IMPORT_REQUEST, byteArrayOf(1), kek, binding)
        val unknown = v2.clone().also { it[4] = 3 }
        assertThrows(Exception::class.java) {
            codec.openForOperation(unknown, "test-record", SecureDataClass.IMPORT_REQUEST, counted, binding)
        }
        assertEquals(0, unwraps)
        assertArrayEquals(byteArrayOf(1), codec.open(legacy, "test-record", kek).plaintext)
    }

    @Test fun versionTwoBindingIsImmutableAndMalformedBindingIsRejected() {
        for (size in listOf(0, 16, 31, 33)) assertThrows(Exception::class.java) { SecureOperationBinding(ByteArray(size) { 1 }, 2) }
        assertThrows(Exception::class.java) { SecureOperationBinding(ByteArray(32), 2) }
        for (revision in listOf(-2L, 0L, 1L, 3L, Long.MAX_VALUE))
            assertThrows(Exception::class.java) { SecureOperationBinding(ByteArray(32) { 1 }, revision) }
        val binding = SecureOperationBinding(ByteArray(32) { 4 }, 2)
        binding.operationId().fill(0)
        assertArrayEquals(ByteArray(32) { 4 }, binding.operationId())
    }

    @Test fun versionTwoSnapshotsInputAndRejectsEveryTruncatedOrExtendedFrame() {
        val input = byteArrayOf(1, 2, 3)
        val disruptive = object : KeyEncryptionKey by kek {
            override val generation: Int get() { input.fill(9); return 1 }
        }
        val binding = SecureOperationBinding(ByteArray(32) { 5 }, 2)
        val encoded = codec.sealForOperation("test-record", SecureDataClass.IMPORT_REQUEST, input, disruptive, binding)
        assertArrayEquals(byteArrayOf(1, 2, 3), codec.openForOperation(encoded, "test-record", SecureDataClass.IMPORT_REQUEST, kek, binding).plaintext)
        for (length in 0 until encoded.size) assertThrows(Exception::class.java) {
            codec.openForOperation(encoded.copyOf(length), "test-record", SecureDataClass.IMPORT_REQUEST, kek, binding)
        }
        assertThrows(Exception::class.java) {
            codec.openForOperation(encoded + byteArrayOf(0), "test-record", SecureDataClass.IMPORT_REQUEST, kek, binding)
        }
        for (index in 0 until encoded.size) {
            val corrupt = encoded.clone().also { it[index] = (it[index].toInt() xor 1).toByte() }
            assertThrows(Exception::class.java) {
                codec.openForOperation(corrupt, "test-record", SecureDataClass.IMPORT_REQUEST, kek, binding)
            }
        }
    }

    @Test fun malformedUnwrappedKeyIsWipedBeforeRejection() {
        val encoded = codec.seal("test-record", SecureDataClass.PROFILE_ARTIFACT, byteArrayOf(1), kek)
        val owned = ByteArray(31) { 9 }
        val malformed = object : KeyEncryptionKey by kek {
            override fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey) = owned
        }
        assertThrows(IllegalArgumentException::class.java) { codec.open(encoded, "test-record", malformed) }
        assertArrayEquals(ByteArray(31), owned)
    }

    @Test fun envelopeInputIsSnapshottedBeforeAnyExternalKeyInteraction() {
        val input = byteArrayOf(1, 2, 3)
        val disruptive = object : KeyEncryptionKey by kek {
            override val generation: Int get() { input.fill(9); return 1 }
        }
        val encoded = codec.seal("test-record", SecureDataClass.PROFILE_ARTIFACT, input, disruptive)
        assertArrayEquals(byteArrayOf(1, 2, 3), codec.open(encoded, "test-record", kek).plaintext)
        val changedCiphertext = object : KeyEncryptionKey by kek {
            override val generation: Int get() { encoded.fill(0); return 1 }
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), codec.open(encoded, "test-record", changedCiphertext).plaintext)
    }

    @Test
    fun exactBytesRoundTripWithoutPlaintextMetadata() {
        val plaintext = "secret-profile-provider-relay.example".encodeToByteArray()
        val encoded = codec.seal(
            recordId = "018f0f47-aaaa-bbbb-cccc-001122334455",
            dataClass = SecureDataClass.PROFILE_ARTIFACT,
            plaintext = plaintext,
            kek = kek,
        )
        check(!encoded.toString(Charsets.ISO_8859_1).contains("secret-profile"))
        val opened = codec.open(
            encoded,
            "018f0f47-aaaa-bbbb-cccc-001122334455",
            kek,
        )
        assertArrayEquals(plaintext, opened.plaintext)
    }

    @Test
    fun corruptionWrongRecordAndWrongKeyFailClosed() {
        val recordId = "018f0f47-aaaa-bbbb-cccc-001122334455"
        val encoded = codec.seal(
            recordId,
            SecureDataClass.PROFILE_ARTIFACT,
            ByteArray(128) { it.toByte() },
            kek,
        )
        for (index in listOf(0, 8, encoded.lastIndex)) {
            val corrupted = encoded.clone()
            corrupted[index] = (corrupted[index].toInt() xor 0xff).toByte()
            assertThrows(Exception::class.java) {
                codec.open(corrupted, recordId, kek)
            }
        }
        assertThrows(Exception::class.java) {
            codec.open(encoded, "018f0f47-aaaa-bbbb-cccc-001122334456", kek)
        }
        assertThrows(Exception::class.java) {
            codec.open(encoded, recordId, InMemoryKek(fill = 7))
        }
    }
}

private class InMemoryKek(
    private val fill: Byte = 3,
) : KeyEncryptionKey {
    override val generation: Int = 1
    override val hardwareSecurityLevel: String = "test-only"
    private val key = SecretKeySpec(ByteArray(32) { fill }, "AES")

    override fun wrap(
        recordId: String,
        dataClass: SecureDataClass,
        key: ByteArray,
    ): WrappedKey {
        val nonce = ByteArray(12) { 5 }
        return WrappedKey(
            nonce,
            aesGcmEncrypt(
                this.key,
                nonce,
                "$recordId:${dataClass.wireValue}".encodeToByteArray(),
                key,
            ),
        )
    }

    override fun unwrap(
        recordId: String,
        dataClass: SecureDataClass,
        wrapped: WrappedKey,
    ): ByteArray = aesGcmDecrypt(
        key,
        wrapped.nonce,
        "$recordId:${dataClass.wireValue}".encodeToByteArray(),
        wrapped.ciphertext,
    )
}

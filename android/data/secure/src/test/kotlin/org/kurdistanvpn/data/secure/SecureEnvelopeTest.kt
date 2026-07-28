// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class SecureEnvelopeTest {
    private val codec = SecureEnvelopeCodec(SecureRandom(byteArrayOf(1, 2, 3, 4)))
    private val kek = InMemoryKek()

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

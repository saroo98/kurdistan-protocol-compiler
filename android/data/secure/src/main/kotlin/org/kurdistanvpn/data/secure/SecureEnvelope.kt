// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val ENVELOPE_MAGIC = 0x4B564531
private const val ENVELOPE_VERSION = 1
private const val AES_KEY_BITS = 256
private const val GCM_NONCE_BYTES = 12
private const val GCM_TAG_BITS = 128
private const val MAX_RECORD_ID_BYTES = 64
private const val MAX_WRAPPED_KEY_BYTES = 512
const val MAX_SECURE_BLOB_BYTES: Int = 8 * 1024 * 1024

enum class SecureDataClass(val wireValue: Int) {
    PROFILE_ARTIFACT(1),
    VERIFIED_RECEIPT(2),
    LOCAL_ALIAS(3),
    RECIPIENT_PRIVATE_MATERIAL(4),
    IMPORT_REQUEST(5),
    PROFILE_PREVIEW(6),
    ACTIVATION_STAGED(7),
    ACTIVATION_ACTIVE(8),
    ACTIVATION_LAST_KNOWN_GOOD(9),
    RESTORE_BATCH(10),
}

data class WrappedKey(
    val nonce: ByteArray,
    val ciphertext: ByteArray,
)

interface KeyEncryptionKey {
    val generation: Int
    val hardwareSecurityLevel: String

    fun wrap(recordId: String, dataClass: SecureDataClass, key: ByteArray): WrappedKey

    fun unwrap(recordId: String, dataClass: SecureDataClass, wrapped: WrappedKey): ByteArray
}

data class OpenedEnvelope(
    val recordId: String,
    val dataClass: SecureDataClass,
    val keyGeneration: Int,
    val plaintext: ByteArray,
)

class SecureEnvelopeCodec(
    private val random: SecureRandom = SecureRandom(),
) {
    fun keyGeneration(encoded: ByteArray): Int {
        require(encoded.size >= 4 + 1 + 1 + 1 + 1 + 4)
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(input.int == ENVELOPE_MAGIC)
        require(input.get().toInt() and 0xff == ENVELOPE_VERSION)
        val recordLength = input.get().toInt() and 0xff
        require(recordLength in 1..MAX_RECORD_ID_BYTES)
        require(input.remaining() >= recordLength + 1 + 4)
        input.position(input.position() + recordLength + 1)
        return input.int.also { require(it > 0) }
    }

    fun seal(
        recordId: String,
        dataClass: SecureDataClass,
        plaintext: ByteArray,
        kek: KeyEncryptionKey,
    ): ByteArray {
        val recordBytes = validateRecordId(recordId)
        require(plaintext.isNotEmpty() && plaintext.size <= MAX_SECURE_BLOB_BYTES)
        require(kek.generation > 0)

        val rawDek = ByteArray(AES_KEY_BITS / 8).also(random::nextBytes)
        val dek = SecretKeySpec(rawDek, "AES")
        val nonce = ByteArray(GCM_NONCE_BYTES).also(random::nextBytes)
        val ciphertextLength = Math.addExact(plaintext.size, GCM_TAG_BITS / 8)
        val aad = envelopeAAD(
            recordBytes = recordBytes,
            dataClass = dataClass,
            keyGeneration = kek.generation,
            ciphertextLength = ciphertextLength,
        )
        val ciphertext: ByteArray
        val wrapped: WrappedKey
        try {
            ciphertext = aesGcmEncrypt(dek, nonce, aad, plaintext)
            check(ciphertext.size == ciphertextLength)
            wrapped = kek.wrap(recordId, dataClass, rawDek)
        } finally {
            rawDek.fill(0)
        }
        require(wrapped.nonce.size == GCM_NONCE_BYTES)
        require(wrapped.ciphertext.isNotEmpty() && wrapped.ciphertext.size <= MAX_WRAPPED_KEY_BYTES)

        val size = 4 + 1 + 1 + recordBytes.size + 1 + 4 +
            GCM_NONCE_BYTES + 2 + wrapped.nonce.size + 2 + wrapped.ciphertext.size +
            4 + ciphertext.size
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(ENVELOPE_MAGIC)
            put(ENVELOPE_VERSION.toByte())
            put(recordBytes.size.toByte())
            put(recordBytes)
            put(dataClass.wireValue.toByte())
            putInt(kek.generation)
            put(nonce)
            putShort(wrapped.nonce.size.toShort())
            put(wrapped.nonce)
            putShort(wrapped.ciphertext.size.toShort())
            put(wrapped.ciphertext)
            putInt(ciphertext.size)
            put(ciphertext)
        }.array()
    }

    fun open(encoded: ByteArray, expectedRecordId: String, kek: KeyEncryptionKey): OpenedEnvelope {
        require(encoded.isNotEmpty() && encoded.size <= MAX_SECURE_BLOB_BYTES + 2048)
        val expectedRecordBytes = validateRecordId(expectedRecordId)
        val input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(input.remaining() >= 4 + 1 + 1)
        require(input.int == ENVELOPE_MAGIC)
        require(input.get().toInt() and 0xff == ENVELOPE_VERSION)
        val recordLength = input.get().toInt() and 0xff
        require(recordLength in 1..MAX_RECORD_ID_BYTES && input.remaining() >= recordLength)
        val recordBytes = ByteArray(recordLength).also(input::get)
        require(recordBytes.contentEquals(expectedRecordBytes))
        val dataClassWire = input.get().toInt() and 0xff
        val dataClass = SecureDataClass.entries.singleOrNull { it.wireValue == dataClassWire }
            ?: throw IllegalArgumentException("unknown data class")
        val keyGeneration = input.int
        require(keyGeneration > 0 && keyGeneration == kek.generation)
        val nonce = ByteArray(GCM_NONCE_BYTES).also(input::get)
        val wrapNonceLength = input.short.toInt() and 0xffff
        require(wrapNonceLength == GCM_NONCE_BYTES && input.remaining() >= wrapNonceLength)
        val wrapNonce = ByteArray(wrapNonceLength).also(input::get)
        val wrappedLength = input.short.toInt() and 0xffff
        require(wrappedLength in 1..MAX_WRAPPED_KEY_BYTES && input.remaining() >= wrappedLength + 4)
        val wrapped = ByteArray(wrappedLength).also(input::get)
        val ciphertextLength = input.int
        require(
            ciphertextLength >= GCM_TAG_BITS / 8 &&
                ciphertextLength <= MAX_SECURE_BLOB_BYTES + GCM_TAG_BITS / 8 &&
                input.remaining() == ciphertextLength,
        )
        val ciphertext = ByteArray(ciphertextLength).also(input::get)
        val aad = envelopeAAD(recordBytes, dataClass, keyGeneration, ciphertextLength)
        val rawDek = kek.unwrap(
            expectedRecordId,
            dataClass,
            WrappedKey(wrapNonce, wrapped),
        )
        require(rawDek.size == AES_KEY_BITS / 8)
        val plaintext = try {
            aesGcmDecrypt(SecretKeySpec(rawDek, "AES"), nonce, aad, ciphertext)
        } finally {
            rawDek.fill(0)
        }
        return OpenedEnvelope(
            recordId = expectedRecordId,
            dataClass = dataClass,
            keyGeneration = keyGeneration,
            plaintext = plaintext,
        )
    }

    private fun validateRecordId(recordId: String): ByteArray {
        val encoded = recordId.encodeToByteArray()
        require(encoded.isNotEmpty() && encoded.size <= MAX_RECORD_ID_BYTES)
        require(recordId.all { it in 'a'..'z' || it in '0'..'9' || it == '-' })
        return encoded
    }

    private fun envelopeAAD(
        recordBytes: ByteArray,
        dataClass: SecureDataClass,
        keyGeneration: Int,
        ciphertextLength: Int,
    ): ByteArray = ByteBuffer.allocate(4 + 1 + 1 + recordBytes.size + 1 + 4 + 4)
        .order(ByteOrder.BIG_ENDIAN)
        .apply {
            putInt(ENVELOPE_MAGIC)
            put(ENVELOPE_VERSION.toByte())
            put(recordBytes.size.toByte())
            put(recordBytes)
            put(dataClass.wireValue.toByte())
            putInt(keyGeneration)
            putInt(ciphertextLength)
        }
        .array()
}

internal fun aesGcmEncrypt(
    key: SecretKey,
    nonce: ByteArray,
    aad: ByteArray,
    plaintext: ByteArray,
): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
    init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
    updateAAD(aad)
    doFinal(plaintext)
}

internal fun aesGcmDecrypt(
    key: SecretKey,
    nonce: ByteArray,
    aad: ByteArray,
    ciphertext: ByteArray,
): ByteArray = Cipher.getInstance("AES/GCM/NoPadding").run {
    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
    updateAAD(aad)
    doFinal(ciphertext)
}

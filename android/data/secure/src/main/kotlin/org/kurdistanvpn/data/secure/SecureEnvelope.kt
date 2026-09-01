// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.security.MessageDigest
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
    ROUTING_POLICY(11),
    DIAGNOSTIC_EVENTS(12),
    RECIPIENT_KEY_INDEX(13),
    PROTECTED_JOURNAL_CONTROL(14),
    PROTECTED_JOURNAL_RECORD(15),
    PROTECTED_CHECKPOINT(16),
    PROTECTED_RESET_MANIFEST(17),
    PROTECTED_PROJECTION_WITNESS(18),
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

/** Immutable, nonsecret context selected by a durable broker operation, never a runtime token. */
class SecureOperationBinding(operationId: ByteArray, val revision: Long) {
    private val operation = operationId.clone()
    init {
        require(operation.size == 32 && operation.any { it != 0.toByte() })
        require(revision > 0 && revision and 1L == 0L)
    }
    fun operationId(): ByteArray = operation.clone()
    internal fun matches(other: ByteArray, revision: Long): Boolean = this.revision == revision &&
        MessageDigest.isEqual(operation, other)
}

class SecureEnvelopeCodec(
    private val random: SecureRandom = SecureRandom(),
) {
    fun keyGeneration(encoded: ByteArray): Int {
        val owned = encoded.clone()
        try {
        require(owned.size in (4 + 1 + 1 + 1 + 1 + 4)..MAX_SECURE_BLOB_BYTES + 2048)
        val input = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
        require(input.int == ENVELOPE_MAGIC)
        require((input.get().toInt() and 0xff) in 1..2)
        val recordLength = input.get().toInt() and 0xff
        require(recordLength in 1..MAX_RECORD_ID_BYTES)
        require(input.remaining() >= recordLength + 1 + 4)
        input.position(input.position() + recordLength + 1)
        return input.int.also { require(it > 0) }
        } finally { owned.fill(0) }
    }

    /** Version 1 remains explicit migration input. New operation-bound objects use this entry point. */
    fun sealForOperation(recordId: String, dataClass: SecureDataClass, plaintext: ByteArray,
        kek: KeyEncryptionKey, binding: SecureOperationBinding): ByteArray {
        val owned = plaintext.clone()
        val dek = ByteArray(32)
        var body: ByteArray? = null
        var cipherBytes: ByteArray? = null
        try {
            require(owned.size in 1..MAX_SECURE_BLOB_BYTES)
            val record = validateRecordId(recordId)
            val generation = kek.generation.also { require(it > 0) }
            val cipherLength = Math.addExact(owned.size, 32 + GCM_TAG_BITS / 8)
            val aad = operationAAD(record, dataClass, generation, binding, owned.size, cipherLength)
            body = ByteBuffer.allocate(32 + owned.size).put(operationContentDigest(owned)).put(owned).array()
            random.nextBytes(dek)
            val nonce = ByteArray(GCM_NONCE_BYTES).also(random::nextBytes)
            cipherBytes = aesGcmEncrypt(SecretKeySpec(dek, "AES"), nonce, aad, body)
            check(cipherBytes.size == cipherLength)
            val wrapped = kek.wrap(recordId, dataClass, dek)
            require(wrapped.nonce.size == GCM_NONCE_BYTES && wrapped.ciphertext.size in 1..MAX_WRAPPED_KEY_BYTES)
            return ByteBuffer.allocate(aad.size + GCM_NONCE_BYTES + 2 + wrapped.nonce.size + 2 + wrapped.ciphertext.size + cipherLength)
                .order(ByteOrder.BIG_ENDIAN).put(aad).put(nonce).putShort(wrapped.nonce.size.toShort())
                .put(wrapped.nonce).putShort(wrapped.ciphertext.size.toShort()).put(wrapped.ciphertext).put(cipherBytes).array()
        } finally { owned.fill(0); dek.fill(0); body?.fill(0); cipherBytes?.fill(0) }
    }

    /** No version fallback. Both the authenticated header and expected committed context must match. */
    fun openForOperation(encoded: ByteArray, expectedRecordId: String, expectedClass: SecureDataClass,
        kek: KeyEncryptionKey, binding: SecureOperationBinding): OpenedEnvelope {
        val owned = encoded.clone()
        var dek: ByteArray? = null
        var body: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            require(owned.size in 1..MAX_SECURE_BLOB_BYTES + 2048)
            val expected = validateRecordId(expectedRecordId)
            val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
            require(reader.int == ENVELOPE_MAGIC && reader.get().toInt() == 2)
            val recordLength = reader.get().toInt() and 255
            require(recordLength in 1..MAX_RECORD_ID_BYTES && reader.remaining() >= recordLength)
            val record = ByteArray(recordLength).also(reader::get)
            require(MessageDigest.isEqual(record, expected) && (reader.get().toInt() and 255) == expectedClass.wireValue)
            val generation = reader.int
            require(generation > 0 && generation == kek.generation)
            val operation = ByteArray(32).also(reader::get)
            val revision = reader.long
            try { require(binding.matches(operation, revision)) } finally { operation.fill(0) }
            val length = reader.int
            val cipherLength = reader.int
            require(length in 1..MAX_SECURE_BLOB_BYTES && cipherLength == length + 32 + GCM_TAG_BITS / 8)
            val aad = owned.copyOfRange(0, reader.position())
            val nonce = ByteArray(GCM_NONCE_BYTES).also(reader::get)
            val wrapNonceLength = reader.short.toInt() and 65535
            require(wrapNonceLength == GCM_NONCE_BYTES && reader.remaining() >= wrapNonceLength + 2)
            val wrapNonce = ByteArray(wrapNonceLength).also(reader::get)
            val wrappedLength = reader.short.toInt() and 65535
            require(wrappedLength in 1..MAX_WRAPPED_KEY_BYTES && reader.remaining() == wrappedLength + cipherLength)
            val wrapped = ByteArray(wrappedLength).also(reader::get)
            val ciphertext = ByteArray(cipherLength).also(reader::get)
            dek = kek.unwrap(expectedRecordId, expectedClass, WrappedKey(wrapNonce, wrapped))
            require(dek.size == 32)
            body = aesGcmDecrypt(SecretKeySpec(dek, "AES"), nonce, aad, ciphertext)
            require(body.size == length + 32)
            plaintext = body.copyOfRange(32, body.size)
            val digest = operationContentDigest(plaintext)
            try { require(MessageDigest.isEqual(digest, body.copyOfRange(0, 32))) }
            finally { digest.fill(0) }
            val result = OpenedEnvelope(expectedRecordId, expectedClass, generation, plaintext)
            plaintext = null
            return result
        } catch (_: java.nio.BufferUnderflowException) {
            throw IllegalArgumentException("TRUNCATED_OPERATION_ENVELOPE")
        } finally { owned.fill(0); dek?.fill(0); body?.fill(0); plaintext?.fill(0) }
    }

    private fun operationAAD(record: ByteArray, role: SecureDataClass, generation: Int,
        binding: SecureOperationBinding, plaintextLength: Int, cipherLength: Int): ByteArray =
        ByteBuffer.allocate(4 + 1 + 1 + record.size + 1 + 4 + 32 + 8 + 4 + 4).order(ByteOrder.BIG_ENDIAN)
            .putInt(ENVELOPE_MAGIC).put(2).put(record.size.toByte()).put(record).put(role.wireValue.toByte())
            .putInt(generation).put(binding.operationId()).putLong(binding.revision).putInt(plaintextLength).putInt(cipherLength).array()

    // Kept inside the encrypted body: no stable plaintext-derived fingerprint is published in a header.
    private fun operationContentDigest(owned: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
        update("kurdistan-secure-object-content-v2\u0000".toByteArray(Charsets.US_ASCII))
        update(ByteBuffer.allocate(4).putInt(owned.size).array())
        digest(owned)
    }

    fun seal(
        recordId: String,
        dataClass: SecureDataClass,
        plaintext: ByteArray,
        kek: KeyEncryptionKey,
    ): ByteArray {
        val owned = plaintext.clone()
        return try { sealOwned(recordId, dataClass, owned, kek) }
        finally { owned.fill(0) }
    }

    private fun sealOwned(recordId: String, dataClass: SecureDataClass, plaintext: ByteArray,
        kek: KeyEncryptionKey): ByteArray {
        val recordBytes = validateRecordId(recordId)
        require(plaintext.isNotEmpty() && plaintext.size <= MAX_SECURE_BLOB_BYTES)
        val generation = kek.generation
        require(generation > 0)

        val rawDek = ByteArray(AES_KEY_BITS / 8)
        try {
        random.nextBytes(rawDek)
        val dek = SecretKeySpec(rawDek, "AES")
        val nonce = ByteArray(GCM_NONCE_BYTES).also(random::nextBytes)
        val ciphertextLength = Math.addExact(plaintext.size, GCM_TAG_BITS / 8)
        val aad = envelopeAAD(
            recordBytes = recordBytes,
            dataClass = dataClass,
            keyGeneration = generation,
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
            putInt(generation)
            put(nonce)
            putShort(wrapped.nonce.size.toShort())
            put(wrapped.nonce)
            putShort(wrapped.ciphertext.size.toShort())
            put(wrapped.ciphertext)
            putInt(ciphertext.size)
            put(ciphertext)
        }.array()
        } finally { rawDek.fill(0) }
    }

    fun open(encoded: ByteArray, expectedRecordId: String, kek: KeyEncryptionKey): OpenedEnvelope {
        val owned = encoded.clone()
        return try { openOwned(owned, expectedRecordId, kek) }
        finally { owned.fill(0) }
    }

    private fun openOwned(encoded: ByteArray, expectedRecordId: String, kek: KeyEncryptionKey): OpenedEnvelope {
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
        val plaintext = try {
            require(rawDek.size == AES_KEY_BITS / 8)
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

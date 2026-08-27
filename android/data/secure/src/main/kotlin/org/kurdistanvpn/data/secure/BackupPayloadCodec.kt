// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

private const val BACKUP_PAYLOAD_MAGIC = 0x4B425032
private const val LEGACY_BACKUP_PAYLOAD_MAGIC = 0x4B425031
private const val NATIVE_PROFILE_RECORD = 1
private const val LOCAL_ALIAS_RECORD = 3
private const val CLIENT_KEY_BACKUP_MAGIC = 0x4B434B33
private const val LEGACY_CLIENT_KEY_MAGIC = 0x4B434B32
private const val CLIENT_KEY_BACKUP_RECORD_ID = "recipient-keys-v3"
private const val LEGACY_CLIENT_KEY_RECORD_ID = "recipient-keys-v2"
private const val MAX_BACKUP_PAYLOAD_BYTES = 8 * 1024 * 1024
private const val MAX_VERIFY_REQUEST_BYTES = 1024 * 1024
private const val MAX_KEY_PAYLOAD_BYTES = 192 * 1024
private val LOCAL_RECORD_ID = Regex("[a-z0-9-]{1,64}")

data class BackupProfileRecord(val localRecordId: String, val generation: ULong, val verifyRequest: ByteArray)
data class DecodedBackupPayload(
    val profiles: List<BackupProfileRecord>,
    val clientKeys: List<ClientKeyBackupRecord>,
    /** Historical format, never evidence of current trust or lifecycle admission. */
    val sourceVersion: Int = 2,
)

object BackupPayloadCodec {
    fun encode(records: List<BackupProfileRecord>): ByteArray = encode(DecodedBackupPayload(records, emptyList()))

    /** Ordinary exports are v2 only. Legacy material must be validated and rebound first. */
    fun encode(payload: DecodedBackupPayload): ByteArray {
        require(payload.sourceVersion == 2) { "LEGACY_BACKUP_REQUIRES_REVALIDATION" }
        return encodeSource(payload)
    }

    fun decode(encoded: ByteArray): List<BackupProfileRecord> {
        val payload = decodePayload(encoded)
        payload.clientKeys.forEach(ClientKeyBackupRecord::destroy)
        return payload.profiles
    }

    fun decodePayload(encoded: ByteArray): DecodedBackupPayload {
        require(encoded.size in 6..MAX_BACKUP_PAYLOAD_BYTES)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        val version = when (reader.int) {
            BACKUP_PAYLOAD_MAGIC -> 2
            LEGACY_BACKUP_PAYLOAD_MAGIC -> 1
            else -> throw IllegalArgumentException("UNKNOWN_BACKUP_VERSION")
        }
        val count = reader.short.toInt() and 0xffff
        require(count <= 128)
        val profiles = mutableListOf<BackupProfileRecord>()
        var keys = emptyList<ClientKeyBackupRecord>()
        var keyRecordSeen = false
        val names = mutableSetOf<String>()
        try {
            repeat(count) {
                require(reader.remaining() >= 14)
                val kind = reader.get().toInt() and 0xff
                val generation = reader.long.toULong()
                val id = reader.readBackupString(64)
                require(names.add("$kind:$id"))
                require(reader.remaining() >= 4)
                val size = reader.int
                require(size in 1..MAX_VERIFY_REQUEST_BYTES && size <= reader.remaining())
                val exact = ByteArray(size).also(reader::get)
                var transferred = false
                try {
                    when (kind) {
                        NATIVE_PROFILE_RECORD -> {
                            require(generation > 0u)
                            profiles += BackupProfileRecord(id, generation, exact)
                            transferred = true
                        }
                        LOCAL_ALIAS_RECORD -> {
                            val expected = if (version == 2) CLIENT_KEY_BACKUP_RECORD_ID else LEGACY_CLIENT_KEY_RECORD_ID
                            require(generation == 0uL && id == expected && !keyRecordSeen)
                            keyRecordSeen = true
                            keys = decodeClientKeys(exact, version)
                        }
                        else -> throw IllegalArgumentException("UNSUPPORTED_BACKUP_RECORD")
                    }
                } finally { if (!transferred) exact.fill(0) }
            }
            require(!reader.hasRemaining())
            val payload = DecodedBackupPayload(profiles, keys, version)
            val canonical = encodeSource(payload)
            try { require(canonical.contentEquals(encoded)) { "NONCANONICAL_BACKUP" } } finally { canonical.fill(0) }
            return payload
        } catch (error: Throwable) {
            profiles.forEach { it.verifyRequest.fill(0) }
            keys.forEach(ClientKeyBackupRecord::destroy)
            throw error
        }
    }

    private fun encodeSource(payload: DecodedBackupPayload): ByteArray {
        require(payload.sourceVersion == 1 || payload.sourceVersion == 2)
        require(payload.profiles.size <= 128 && payload.clientKeys.size <= 32)
        require(payload.profiles.size + (if (payload.clientKeys.isEmpty()) 0 else 1) <= 128)
        require(payload.profiles.map { it.localRecordId }.distinct().size == payload.profiles.size)
        var size = 6L
        payload.profiles.forEach {
            require(it.localRecordId.matches(LOCAL_RECORD_ID) && it.generation > 0u)
            require(it.verifyRequest.size in 1..MAX_VERIFY_REQUEST_BYTES)
            size += 14L + it.localRecordId.length + it.verifyRequest.size
            require(size <= MAX_BACKUP_PAYLOAD_BYTES)
        }
        validateBackupKeys(payload.clientKeys, payload.sourceVersion, payload.profiles.map { it.localRecordId }.toSet())
        val keyId = if (payload.sourceVersion == 2) CLIENT_KEY_BACKUP_RECORD_ID else LEGACY_CLIENT_KEY_RECORD_ID
        val keyBytes = if (payload.clientKeys.isEmpty()) null else encodeClientKeys(payload.clientKeys, payload.sourceVersion)
        var output: ByteArray? = null
        try {
            if (keyBytes != null) size += 14L + keyId.length + keyBytes.size
            require(size <= MAX_BACKUP_PAYLOAD_BYTES)
            output = ByteArray(size.toInt())
            return ByteBuffer.wrap(output).order(ByteOrder.BIG_ENDIAN).apply {
                putInt(if (payload.sourceVersion == 2) BACKUP_PAYLOAD_MAGIC else LEGACY_BACKUP_PAYLOAD_MAGIC)
                putShort((payload.profiles.size + if (keyBytes == null) 0 else 1).toShort())
                payload.profiles.forEach {
                    put(NATIVE_PROFILE_RECORD.toByte()); putLong(it.generation.toLong()); putBackupString(it.localRecordId)
                    putInt(it.verifyRequest.size); put(it.verifyRequest)
                }
                if (keyBytes != null) {
                    put(LOCAL_ALIAS_RECORD.toByte()); putLong(0); putBackupString(keyId); putInt(keyBytes.size); put(keyBytes)
                }
            }.array()
        } catch (error: Throwable) { output?.fill(0); throw error }
        finally { keyBytes?.fill(0) }
    }
}

/** Source bindings are consistency metadata only; current native admission still revalidates. */
internal fun validateBackupKeys(records: List<ClientKeyBackupRecord>, version: Int, profiles: Set<String>? = null) {
    require(records.size <= 32 && (version == 1 || version == 2))
    val ids = mutableSetOf<String>(); val requests = mutableSetOf<String>(); val privateKeys = mutableSetOf<String>()
    val assigned = mutableSetOf<String>()
    records.forEach { record ->
        require(record.sourceVersion == version && record.sourceRecordId.matches(LOCAL_RECORD_ID) && ids.add(record.sourceRecordId))
        require(record.createdAtEpochSeconds > 0 && record.expiresAtEpochSeconds > record.createdAtEpochSeconds)
        val bindings = record.sourceProfileRecordIds
        if (version == 1) require(record.sourceStatus == null && bindings.isEmpty())
        else {
            require(record.sourceStatus == ClientKeyStatus.PROFILE_VERIFIED && bindings.size in 1..64)
            bindings.forEach { require(it.matches(LOCAL_RECORD_ID) && assigned.add(it) && (profiles == null || it in profiles)) }
        }
        record.withMaterial { request, privateBytes ->
            fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            require(requests.add(digest(request)) && privateKeys.add(digest(privateBytes))) { "DUPLICATE_BACKUP_KEY" }
        }
    }
}

private fun encodeClientKeys(records: List<ClientKeyBackupRecord>, version: Int): ByteArray {
    require(records.size in 1..32)
    val size = records.fold(6L) { total, record ->
        total + 1 + record.sourceRecordId.length + 16 + 2 + record.publicRequestSize + 2 + record.privateBundleSize +
            (if (version == 2) 2 + record.sourceProfileRecordIds.sumOf { 1 + it.length } else 0)
    }
    require(size <= MAX_KEY_PAYLOAD_BYTES)
    val output = ByteArray(size.toInt())
    return try { ByteBuffer.wrap(output).order(ByteOrder.BIG_ENDIAN).apply {
        putInt(if (version == 2) CLIENT_KEY_BACKUP_MAGIC else LEGACY_CLIENT_KEY_MAGIC)
        put((if (version == 2) 3 else 2).toByte()); put(records.size.toByte())
        records.forEach { record ->
            putBackupString(record.sourceRecordId)
            if (version == 2) put(requireNotNull(record.sourceStatus).wireValue.toByte())
            putLong(record.createdAtEpochSeconds); putLong(record.expiresAtEpochSeconds)
            if (version == 2) {
                val bindings = record.sourceProfileRecordIds.sorted()
                put(bindings.size.toByte()); bindings.forEach(::putBackupString)
            }
            record.withMaterial { request, privateBytes ->
                putShort(request.size.toShort()); put(request); putShort(privateBytes.size.toShort()); put(privateBytes)
            }
        }
    }.array() } catch (error: Throwable) { output.fill(0); throw error }
}

private fun decodeClientKeys(encoded: ByteArray, version: Int): List<ClientKeyBackupRecord> {
    require(encoded.size in 6..MAX_KEY_PAYLOAD_BYTES)
    val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
    require(reader.int == if (version == 2) CLIENT_KEY_BACKUP_MAGIC else LEGACY_CLIENT_KEY_MAGIC)
    require(reader.get().toInt() and 0xff == if (version == 2) 3 else 2)
    val count = reader.get().toInt() and 0xff
    require(count in 1..32)
    val records = mutableListOf<ClientKeyBackupRecord>()
    try {
        repeat(count) {
            val sourceId = reader.readBackupString(64)
            val status = if (version == 2) {
                require(reader.hasRemaining()); require(reader.get().toInt() and 0xff == ClientKeyStatus.PROFILE_VERIFIED.wireValue)
                ClientKeyStatus.PROFILE_VERIFIED
            } else null
            require(reader.remaining() >= 16)
            val created = reader.long; val expires = reader.long
            require(created > 0 && expires > created)
            val bindings = if (version == 2) {
                require(reader.hasRemaining()); val bindingCount = reader.get().toInt() and 0xff; require(bindingCount in 1..64)
                List(bindingCount) { reader.readBackupString(64) }.also { require(it == it.sorted() && it.distinct().size == it.size) }
            } else emptyList()
            val request = reader.readBackupBytes(512)
            var privateBytes: ByteArray? = null
            try {
                privateBytes = reader.readBackupBytes(128)
                records += ClientKeyBackupRecord(sourceId, created, expires, request, privateBytes, status, bindings, version)
            } finally { request.fill(0); privateBytes?.fill(0) }
        }
        require(!reader.hasRemaining())
        validateBackupKeys(records, version)
        return records
    } catch (error: Throwable) { records.forEach(ClientKeyBackupRecord::destroy); throw error }
}

private fun ByteBuffer.putBackupString(value: String) { val bytes = value.encodeToByteArray(); put(bytes.size.toByte()); put(bytes) }
private fun ByteBuffer.readBackupBytes(maximum: Int): ByteArray {
    require(remaining() >= 2); val length = short.toInt() and 0xffff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get)
}
private fun ByteBuffer.readBackupString(maximum: Int): String {
    require(hasRemaining()); val length = get().toInt() and 0xff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get).toString(Charsets.US_ASCII).also { require(it.matches(LOCAL_RECORD_ID)) }
}

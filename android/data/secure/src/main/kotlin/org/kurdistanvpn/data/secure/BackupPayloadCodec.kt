// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder

private const val BACKUP_PAYLOAD_MAGIC = 0x4B425031
private const val NATIVE_PROFILE_RECORD = 1
private const val LOCAL_ALIAS_RECORD = 3
private const val CLIENT_KEY_BACKUP_MAGIC = 0x4B434B32
private const val CLIENT_KEY_BACKUP_RECORD_ID = "recipient-keys-v2"
private const val MAX_BACKUP_PAYLOAD_BYTES = 8 * 1024 * 1024
private const val MAX_VERIFY_REQUEST_BYTES = 1024 * 1024
private val LOCAL_RECORD_ID = Regex("[a-z0-9-]{1,64}")

data class BackupProfileRecord(
    val localRecordId: String,
    val generation: ULong,
    val verifyRequest: ByteArray,
)

data class DecodedBackupPayload(
    val profiles: List<BackupProfileRecord>,
    val clientKeys: List<ClientKeyBackupRecord>,
)

object BackupPayloadCodec {
    fun encode(records: List<BackupProfileRecord>): ByteArray {
        return encode(DecodedBackupPayload(records, emptyList()))
    }

    fun encode(payload: DecodedBackupPayload): ByteArray {
        val records = payload.profiles
        require(records.size + (if (payload.clientKeys.isEmpty()) 0 else 1) <= 128)
        val encodedIds = records.map {
            require(it.localRecordId.matches(LOCAL_RECORD_ID))
            it.localRecordId.encodeToByteArray().also { value ->
                require(value.isNotEmpty() && value.size <= 64)
            }
        }
        val encodedClientKeys = if (payload.clientKeys.isEmpty()) {
            null
        } else {
            encodeClientKeys(payload.clientKeys)
        }
        val size = records.indices.fold(6L) { total, index ->
            require(records[index].generation > 0u)
            require(records[index].verifyRequest.size in 1..MAX_VERIFY_REQUEST_BYTES)
            Math.addExact(
                total,
                (1 + 8 + 1 + encodedIds[index].size + 4 + records[index].verifyRequest.size).toLong(),
            )
        } + if (encodedClientKeys == null) 0 else 1 + 8 + 1 + CLIENT_KEY_BACKUP_RECORD_ID.length + 4 + encodedClientKeys.size
        require(size <= MAX_BACKUP_PAYLOAD_BYTES)
        return try {
            ByteBuffer.allocate(size.toInt()).order(ByteOrder.BIG_ENDIAN).apply {
                putInt(BACKUP_PAYLOAD_MAGIC)
                putShort((records.size + if (encodedClientKeys == null) 0 else 1).toShort())
                records.forEachIndexed { index, record ->
                    put(NATIVE_PROFILE_RECORD.toByte())
                    putLong(record.generation.toLong())
                    put(encodedIds[index].size.toByte())
                    put(encodedIds[index])
                    putInt(record.verifyRequest.size)
                    put(record.verifyRequest)
                }
                if (encodedClientKeys != null) {
                    val localId = CLIENT_KEY_BACKUP_RECORD_ID.encodeToByteArray()
                    put(LOCAL_ALIAS_RECORD.toByte())
                    putLong(0)
                    put(localId.size.toByte())
                    put(localId)
                    putInt(encodedClientKeys.size)
                    put(encodedClientKeys)
                }
            }.array()
        } finally {
            encodedClientKeys?.fill(0)
        }
    }

    fun decode(encoded: ByteArray): List<BackupProfileRecord> {
        return decodePayload(encoded).profiles
    }

    fun decodePayload(encoded: ByteArray): DecodedBackupPayload {
        require(encoded.size in 6..MAX_BACKUP_PAYLOAD_BYTES)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(reader.int == BACKUP_PAYLOAD_MAGIC)
        val count = reader.short.toInt() and 0xffff
        require(count <= 128)
        val profiles = mutableListOf<BackupProfileRecord>()
        var clientKeys = emptyList<ClientKeyBackupRecord>()
        try {
            repeat(count) {
                require(reader.remaining() >= 1 + 8 + 1 + 4)
                val kind = reader.get().toInt() and 0xff
                val generation = reader.long.toULong()
                val idLength = reader.get().toInt() and 0xff
                require(idLength in 1..64 && idLength <= reader.remaining() - 4)
                val id = ByteArray(idLength).also(reader::get).toString(Charsets.UTF_8)
                require(id.matches(LOCAL_RECORD_ID))
                val byteLength = reader.int
                require(byteLength in 1..MAX_VERIFY_REQUEST_BYTES && byteLength <= reader.remaining())
                val exactBytes = ByteArray(byteLength).also(reader::get)
                when (kind) {
                    NATIVE_PROFILE_RECORD -> {
                        require(generation > 0u)
                        profiles += BackupProfileRecord(
                            localRecordId = id,
                            generation = generation,
                            verifyRequest = exactBytes,
                        )
                    }
                    LOCAL_ALIAS_RECORD -> {
                        require(generation == 0uL && id == CLIENT_KEY_BACKUP_RECORD_ID && clientKeys.isEmpty())
                        clientKeys = try {
                            decodeClientKeys(exactBytes)
                        } finally {
                            exactBytes.fill(0)
                        }
                    }
                    else -> {
                        exactBytes.fill(0)
                        throw IllegalArgumentException("unsupported backup record")
                    }
                }
            }
            require(!reader.hasRemaining())
            return DecodedBackupPayload(profiles, clientKeys)
        } catch (error: Throwable) {
            profiles.forEach { it.verifyRequest.fill(0) }
            clientKeys.forEach(ClientKeyBackupRecord::destroy)
            throw error
        }
    }
}

private fun encodeClientKeys(records: List<ClientKeyBackupRecord>): ByteArray {
    require(records.size in 1..32)
    val size = records.fold(4 + 1 + 1) { total, record ->
        require(record.sourceRecordId.matches(LOCAL_RECORD_ID))
        require(record.createdAtEpochSeconds > 0 && record.expiresAtEpochSeconds > record.createdAtEpochSeconds)
        require(record.publicRequest.size in 1..512 && record.privateBundle.size in 1..128)
        total + 1 + record.sourceRecordId.encodeToByteArray().size + 8 + 8 + 2 + record.publicRequest.size + 2 + record.privateBundle.size
    }
    require(size <= MAX_BACKUP_PAYLOAD_BYTES)
    return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
        putInt(CLIENT_KEY_BACKUP_MAGIC)
        put(2.toByte())
        put(records.size.toByte())
        records.forEach { record ->
            val sourceId = record.sourceRecordId.encodeToByteArray()
            put(sourceId.size.toByte())
            put(sourceId)
            putLong(record.createdAtEpochSeconds)
            putLong(record.expiresAtEpochSeconds)
            putShort(record.publicRequest.size.toShort())
            put(record.publicRequest)
            putShort(record.privateBundle.size.toShort())
            put(record.privateBundle)
        }
    }.array()
}

private fun decodeClientKeys(encoded: ByteArray): List<ClientKeyBackupRecord> {
    require(encoded.size in 6..MAX_BACKUP_PAYLOAD_BYTES)
    val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
    require(reader.int == CLIENT_KEY_BACKUP_MAGIC)
    require(reader.get().toInt() and 0xff == 2)
    val count = reader.get().toInt() and 0xff
    require(count in 1..32)
    val records = mutableListOf<ClientKeyBackupRecord>()
    try {
        repeat(count) {
            val sourceId = reader.readBackupString(64)
            val created = reader.long
            val expires = reader.long
            require(created > 0 && expires > created)
            val request = reader.readBackupBytes(512)
            val privateBundle = reader.readBackupBytes(128)
            records += ClientKeyBackupRecord(sourceId, created, expires, request, privateBundle)
        }
        require(!reader.hasRemaining())
        require(records.map { it.sourceRecordId }.distinct().size == records.size)
        return records
    } catch (error: Throwable) {
        records.forEach(ClientKeyBackupRecord::destroy)
        throw error
    }
}

private fun ByteBuffer.readBackupBytes(maximum: Int): ByteArray {
    require(remaining() >= 2)
    val length = short.toInt() and 0xffff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get)
}

private fun ByteBuffer.readBackupString(maximum: Int): String {
    require(hasRemaining())
    val length = get().toInt() and 0xff
    require(length in 1..maximum && length <= remaining())
    return ByteArray(length).also(::get).toString(Charsets.UTF_8).also {
        require(it.matches(LOCAL_RECORD_ID))
    }
}

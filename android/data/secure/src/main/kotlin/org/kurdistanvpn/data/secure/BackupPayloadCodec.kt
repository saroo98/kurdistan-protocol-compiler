// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.secure

import java.nio.ByteBuffer
import java.nio.ByteOrder

private const val BACKUP_PAYLOAD_MAGIC = 0x4B425031
private const val NATIVE_PROFILE_RECORD = 1
private const val MAX_BACKUP_PAYLOAD_BYTES = 8 * 1024 * 1024
private const val MAX_VERIFY_REQUEST_BYTES = 1024 * 1024
private val LOCAL_RECORD_ID = Regex("[a-z0-9-]{1,64}")

data class BackupProfileRecord(
    val localRecordId: String,
    val generation: ULong,
    val verifyRequest: ByteArray,
)

object BackupPayloadCodec {
    fun encode(records: List<BackupProfileRecord>): ByteArray {
        require(records.size <= 128)
        val encodedIds = records.map {
            require(it.localRecordId.matches(LOCAL_RECORD_ID))
            it.localRecordId.encodeToByteArray().also { value ->
                require(value.isNotEmpty() && value.size <= 64)
            }
        }
        val size = records.indices.fold(6L) { total, index ->
            require(records[index].generation > 0u)
            require(records[index].verifyRequest.size in 1..MAX_VERIFY_REQUEST_BYTES)
            Math.addExact(
                total,
                (1 + 8 + 1 + encodedIds[index].size + 4 + records[index].verifyRequest.size).toLong(),
            )
        }
        require(size <= MAX_BACKUP_PAYLOAD_BYTES)
        return ByteBuffer.allocate(size.toInt()).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(BACKUP_PAYLOAD_MAGIC)
            putShort(records.size.toShort())
            records.forEachIndexed { index, record ->
                put(NATIVE_PROFILE_RECORD.toByte())
                putLong(record.generation.toLong())
                put(encodedIds[index].size.toByte())
                put(encodedIds[index])
                putInt(record.verifyRequest.size)
                put(record.verifyRequest)
            }
        }.array()
    }

    fun decode(encoded: ByteArray): List<BackupProfileRecord> {
        require(encoded.size in 6..MAX_BACKUP_PAYLOAD_BYTES)
        val reader = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN)
        require(reader.int == BACKUP_PAYLOAD_MAGIC)
        val count = reader.short.toInt() and 0xffff
        require(count <= 128)
        val records = List(count) {
            require(reader.remaining() >= 1 + 8 + 1 + 4)
            require(reader.get().toInt() == NATIVE_PROFILE_RECORD)
            val generation = reader.long.toULong()
            require(generation > 0u)
            val idLength = reader.get().toInt() and 0xff
            require(idLength in 1..64 && idLength <= reader.remaining() - 4)
            val id = ByteArray(idLength).also(reader::get).toString(Charsets.UTF_8)
            require(id.matches(LOCAL_RECORD_ID))
            val byteLength = reader.int
            require(byteLength in 1..MAX_VERIFY_REQUEST_BYTES && byteLength <= reader.remaining())
            BackupProfileRecord(
                localRecordId = id,
                generation = generation,
                verifyRequest = ByteArray(byteLength).also(reader::get),
            )
        }
        require(!reader.hasRemaining())
        return records
    }
}

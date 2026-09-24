// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.metadata

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import java.nio.ByteBuffer
import org.kurdistanvpn.core.model.OperationKind

@Entity(tableName = "product_operation_projection",
    indices = [Index(value = ["state", "startedEpochHour"])])
data class ProductOperationProjectionEntity(
    @PrimaryKey val operationId: String,
    val kind: String,
    val scopeRecordId: String?,
    val state: String,
    val attempt: Int,
    val settingsRevisionBefore: Long,
    val settingsRevisionAfter: Long,
    val startedEpochHour: Long,
    val resumable: Boolean,
) {
    fun validate() {
        require(operationId.matches(Regex("[0-9a-f]{64}")) && operationId.any { it != '0' })
        require(OperationKind.entries.any { it.name == kind })
        require(scopeRecordId == null || scopeRecordId.matches(Regex("[a-z0-9-]{1,64}")))
        require(state in setOf("PREPARED", "SECURE_STAGED", "SETTINGS_WRITTEN", "BOOTSTRAP_WRITTEN",
            "APPLIED", "ROLLBACK_REQUIRED", "ROLLED_BACK", "QUARANTINED"))
        require(attempt in 0..10 && settingsRevisionBefore >= 0 && settingsRevisionAfter >= 0 && startedEpochHour >= 0)
    }
}

class CatalogProjectionContent(rows: List<ProfileCatalogEntity>, val operation: ProductOperationProjectionEntity?) {
    val rows: List<ProfileCatalogEntity> = java.util.Collections.unmodifiableList(ArrayList(rows))
}

/** Authenticated display descriptor. The legacy profile/binding digest domain stays unchanged. */
object ProductCatalogProjectionCodec {
    private const val MAGIC = 0x50365250
    private const val LIMIT = 512 * 1024

    fun isProduct(input: ByteArray): Boolean = input.size >= 4 && ByteBuffer.wrap(input).int == MAGIC

    fun encode(rows: List<ProfileCatalogEntity>, operation: ProductOperationProjectionEntity?): ByteArray {
        operation?.validate()
        val legacy = ProfileCatalogProjectionCodec.encode(rows)
        try {
            val texts = operation?.let { listOf(it.operationId, it.kind, it.state) }.orEmpty()
            val size = 10 + legacy.size + if (operation == null) 0 else
                texts.sumOf { 2 + it.length } + 1 + (operation.scopeRecordId?.let { 2 + it.length } ?: 0) + 1 + 24 + 1
            require(size <= LIMIT)
            return ByteBuffer.allocate(size).apply {
                fun text(value: String) { putShort(value.length.toShort()); put(value.toByteArray(Charsets.US_ASCII)) }
                putInt(MAGIC); put(1); putInt(legacy.size); put(legacy); put(if (operation == null) 0 else 1)
                operation?.let {
                    text(it.operationId); text(it.kind)
                    put(if (it.scopeRecordId == null) 0 else 1); it.scopeRecordId?.let(::text)
                    text(it.state); put(it.attempt.toByte()); putLong(it.settingsRevisionBefore)
                    putLong(it.settingsRevisionAfter); putLong(it.startedEpochHour); put(if (it.resumable) 1 else 0)
                }
            }.array()
        } finally { legacy.fill(0) }
    }

    fun decode(input: ByteArray): CatalogProjectionContent {
        require(input.size in 8..LIMIT)
        if (!isProduct(input)) return CatalogProjectionContent(ProfileCatalogProjectionCodec.decode(input), null)
        val owned = input.clone()
        try {
            val reader = ByteBuffer.wrap(owned)
            require(reader.int == MAGIC && reader.get().toInt() == 1 && reader.remaining() >= 5)
            val size = reader.int
            require(size in 8..LIMIT && size < reader.remaining())
            val legacy = ByteArray(size).also(reader::get)
            val rows = try {
                require(!isProduct(legacy))
                ProfileCatalogProjectionCodec.decode(legacy)
            } finally { legacy.fill(0) }
            fun flag(): Boolean {
                require(reader.hasRemaining()); val value = reader.get().toInt(); require(value in 0..1); return value == 1
            }
            fun text(): String {
                require(reader.remaining() >= 2); val length = reader.short.toInt() and 65535
                require(length in 1..64 && length <= reader.remaining())
                val bytes = ByteArray(length).also(reader::get)
                return try { require(bytes.all { it.toInt() in 1..127 }); String(bytes, Charsets.US_ASCII) }
                finally { bytes.fill(0) }
            }
            val operation = if (!flag()) null else {
                val id = text(); val kind = text(); val scope = if (flag()) text() else null; val state = text()
                require(reader.remaining() >= 26)
                ProductOperationProjectionEntity(id, kind, scope, state, reader.get().toInt() and 255,
                    reader.long, reader.long, reader.long, flag()).also { it.validate() }
            }
            require(!reader.hasRemaining())
            val canonical = encode(rows, operation)
            try { require(canonical.contentEquals(owned)) } finally { canonical.fill(0) }
            return CatalogProjectionContent(rows, operation)
        } finally { owned.fill(0) }
    }
}

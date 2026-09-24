// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import java.io.*
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.OperationKind

/** Temporary broker operation material. The journal alone authorizes its use and resolution. */
class SettingsOperationState(operationId: ByteArray, val journalBefore: Long, val journalAfter: Long,
    val settingsBefore: Long, val settingsAfter: Long, prior: ByteArray, candidate: ByteArray) : AutoCloseable {
    private val operation: ByteArray
    private val previous: ByteArray
    private val replacement: ByteArray
    private var closed = false
    init {
        require(operationId.size == 32 && operationId.any { it != 0.toByte() }) { "INVALID_SETTINGS_OPERATION" }
        require(journalBefore > 0 && journalBefore and 1L == 0L && journalBefore <= Long.MAX_VALUE - 2 && journalAfter == journalBefore + 2) { "INVALID_SETTINGS_OPERATION" }
        require(settingsBefore >= 0 && settingsAfter >= 0 && settingsAfter != settingsBefore) { "INVALID_SETTINGS_OPERATION" }
        require(prior.size in 1..MAX_SNAPSHOT && candidate.size in 1..MAX_SNAPSHOT) { "INVALID_SETTINGS_OPERATION" }
        operation = operationId.clone(); previous = prior.clone(); replacement = candidate.clone()
    }
    fun matches(id: ByteArray, before: Long, after: Long): Boolean { check(!closed); return operation.contentEquals(id) && journalBefore == before && journalAfter == after }
    fun priorSnapshot(): ByteArray { check(!closed); return previous.clone() }
    fun candidateSnapshot(): ByteArray { check(!closed); return replacement.clone() }
    fun encode(): ByteArray {
        check(!closed)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { w ->
            w.writeInt(MAGIC); w.writeByte(1); w.writeByte(SecureDataClass.OPERATION_STATE.wireValue); w.write(operation)
            w.writeLong(journalBefore); w.writeLong(journalAfter); w.writeLong(settingsBefore); w.writeLong(settingsAfter)
            w.writeInt(previous.size); w.write(previous); w.writeInt(replacement.size); w.write(replacement)
        }
        return out.toByteArray()
    }
    override fun close() { if (!closed) { closed = true; operation.fill(0); previous.fill(0); replacement.fill(0) } }
    override fun toString(): String = "SettingsOperationState(redacted)"
    companion object {
        const val RECORD_ID = "settings-operation-current"
        const val MAX_SNAPSHOT = 2 * 1024 * 1024
        const val MAX_BYTES = 2 * MAX_SNAPSHOT + 78
        private const val MAGIC = 0x4b534f31
        fun decode(input: ByteArray): SettingsOperationState {
            require(input.size in 80..MAX_BYTES) { "MALFORMED_SETTINGS_OPERATION" }
            val owned = input.clone(); val arrays = mutableListOf<ByteArray>()
            try {
                val r = DataInputStream(ByteArrayInputStream(owned))
                require(r.readInt() == MAGIC && r.readUnsignedByte() == 1 && r.readUnsignedByte() == SecureDataClass.OPERATION_STATE.wireValue)
                val operation = ByteArray(32).also { arrays += it; r.readFully(it) }
                val before = r.readLong(); val after = r.readLong(); val oldSettings = r.readLong(); val newSettings = r.readLong()
                fun bytes(): ByteArray { val size = r.readInt(); require(size in 1..MAX_SNAPSHOT && size <= r.available()); return ByteArray(size).also { arrays += it; r.readFully(it) } }
                val prior = bytes(); val candidate = bytes(); require(r.available() == 0)
                return SettingsOperationState(operation, before, after, oldSettings, newSettings, prior, candidate)
            } catch (_: IOException) { throw IllegalArgumentException("MALFORMED_SETTINGS_OPERATION") }
            catch (_: RuntimeException) { throw IllegalArgumentException("MALFORMED_SETTINGS_OPERATION") }
            finally { owned.fill(0); arrays.forEach { it.fill(0) } }
        }
    }
}

/** Framing only. The broker must independently validate both authenticated snapshots and intent bindings. */
class ProductOperationState(operationId: ByteArray, val internalMutationKind: Int, val displayKind: OperationKind?,
    val scopeRecordId: String?, val attempt: Int, val startedEpochHour: Long, val journalRevisionBefore: Long,
    val journalRevisionAfter: Long, val settingsRevisionBefore: Long, val settingsRevisionAfter: Long,
    prior: ByteArray, candidate: ByteArray) : AutoCloseable {
    private val operation: ByteArray
    private val previous: ByteArray
    private val replacement: ByteArray
    private var closed = false
    init {
        require(operationId.size == 32 && operationId.any { it != 0.toByte() })
        require(internalMutationKind == 16 || internalMutationKind == 17)
        scopeRecordId?.let(::CatalogId)
        require(attempt in 0..10 && startedEpochHour >= 0)
        require(journalRevisionBefore > 0 && journalRevisionBefore and 1L == 0L &&
            journalRevisionBefore <= Long.MAX_VALUE - 2 && journalRevisionAfter == journalRevisionBefore + 2)
        require(settingsRevisionBefore >= 0 && settingsRevisionAfter >= 0)
        require(prior.size in 1..MAX_SNAPSHOT && candidate.size in 1..MAX_SNAPSHOT)
        operation = operationId.clone(); previous = prior.clone(); replacement = candidate.clone()
    }
    fun operationId(): ByteArray { check(!closed); return operation.clone() }
    fun matches(id: ByteArray, before: Long, after: Long): Boolean {
        check(!closed); return operation.contentEquals(id) && journalRevisionBefore == before && journalRevisionAfter == after
    }
    fun priorSnapshot(): ByteArray { check(!closed); return previous.clone() }
    fun candidateSnapshot(): ByteArray { check(!closed); return replacement.clone() }
    fun encode(): ByteArray {
        check(!closed)
        return encodeRecord(0x50363237, SecureDataClass.OPERATION_STATE, MAX_BYTES) { w ->
            w.write(operation); w.writeByte(internalMutationKind)
            w.recordBoolean(displayKind != null); displayKind?.let(w::recordEnum)
            w.optionalId(scopeRecordId); w.writeByte(attempt); w.writeLong(startedEpochHour)
            w.writeLong(journalRevisionBefore); w.writeLong(journalRevisionAfter)
            w.writeLong(settingsRevisionBefore); w.writeLong(settingsRevisionAfter)
            w.writeInt(previous.size); w.write(previous); w.writeInt(replacement.size); w.write(replacement)
        }
    }
    override fun close() { if (!closed) { closed = true; operation.fill(0); previous.fill(0); replacement.fill(0) } }
    override fun toString(): String = "ProductOperationState(redacted)"
    companion object {
        const val RECORD_ID = "product-operation-current"
        // Secure cannot depend on protected-state; a broker regression binds this to CHECKPOINT_BYTES.
        const val MAX_SNAPSHOT = 2 * 1024 * 1024
        const val MAX_BYTES = 2 * MAX_SNAPSHOT + 256
        fun decode(input: ByteArray): ProductOperationState = decodeRecord(input, MAX_BYTES, 0x50363237, SecureDataClass.OPERATION_STATE, { r ->
            val arrays = mutableListOf<ByteArray>()
            try {
                require(r.available() >= 32)
                val operation = ByteArray(32).also { arrays += it; r.readFully(it) }
                val kind = r.readUnsignedByte()
                val display = if (r.recordBoolean()) r.recordEnum<OperationKind>() else null
                val scope = r.optionalId(); val attempt = r.readUnsignedByte(); val started = r.readLong()
                val before = r.readLong(); val after = r.readLong(); val settingsBefore = r.readLong(); val settingsAfter = r.readLong()
                fun snapshot(): ByteArray {
                    val size = r.readInt(); require(size in 1..MAX_SNAPSHOT && size <= r.available())
                    return ByteArray(size).also { arrays += it; r.readFully(it) }
                }
                ProductOperationState(operation, kind, display, scope, attempt, started, before, after,
                    settingsBefore, settingsAfter, snapshot(), snapshot())
            } finally { arrays.forEach { it.fill(0) } }
        }, { it.encode() })
    }
}

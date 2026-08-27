// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.nio.ByteBuffer
import java.security.MessageDigest
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableReadResult

/** An equality witness reconstructed from observations, never a writer's success receipt. */
internal class ProjectionImageWitness private constructor(
    private val store: ByteArray, private val operation: ByteArray, val revision: Long,
    private val catalogDigest: ByteArray, private val settingsDigest: ByteArray,
) {
    fun requireMatches(snapshot: ProtectedStateSnapshot) {
        check(revision == snapshot.revision && MessageDigest.isEqual(store, snapshot.storeId()) &&
            MessageDigest.isEqual(operation, snapshot.operationId())) { "PROJECTION_COMMIT_MISMATCH" }
        val catalog = snapshot.catalogBytes(); val settings = snapshot.settingsBytes()
        try {
            check(MessageDigest.isEqual(catalogDigest, digest("kurdistan-room-projection-v1\u0000", catalog)) &&
                MessageDigest.isEqual(settingsDigest, digest("kurdistan-settings-projection-v1\u0000", settings))) {
                "PROJECTION_CONTENT_MISMATCH"
            }
        } finally { catalog.fill(0); settings.fill(0) }
    }

    companion object {
        fun reconstruct(storeId: ByteArray, operationId: ByteArray, revision: Long,
            catalogImage: ByteArray, settingsImage: ByteArray): ProjectionImageWitness {
            val store = storeId.clone(); val operation = operationId.clone()
            val catalog = catalogImage.clone(); val settings = settingsImage.clone()
            try {
                require(store.size == 16 && store.any { it != 0.toByte() })
                require(operation.size == JournalLimits.OPERATION_BYTES && operation.any { it != 0.toByte() })
                require(revision > 0 && revision and 1L == 0L)
                require(catalog.size in 1..512 * 1024 && settings.size in 1..64 * 1024)
                return ProjectionImageWitness(store, operation, revision,
                    digest("kurdistan-room-projection-v1\u0000", catalog),
                    digest("kurdistan-settings-projection-v1\u0000", settings))
            } catch (failure: Throwable) { store.fill(0); operation.fill(0); throw failure }
            finally { catalog.fill(0); settings.fill(0) }
        }

        private fun digest(domain: String, owned: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run {
            update(domain.toByteArray(Charsets.US_ASCII))
            update(ByteBuffer.allocate(4).putInt(owned.size).array())
            digest(owned)
        }
    }
}

internal enum class ProjectionFileRole(val wire: Int) {
    ROOM_MAIN(1), ROOM_WAL(2), ROOM_SHM(3), ROOM_JOURNAL(4), DATASTORE(5),
}

/** Created from a bounded native read, never from a caller-supplied content hash. */
internal class ProjectionFileObservation private constructor(
    val role: ProjectionFileRole, private val frame: ByteArray, val length: Int, val present: Boolean,
) {
    internal fun bytes(): ByteArray = frame.clone()
    companion object {
        fun fromRead(role: ProjectionFileRole, result: DurableReadResult): ProjectionFileObservation {
            if (result.code == DurableCode.ABSENT)
                return ProjectionFileObservation(role, byteArrayOf(role.wire.toByte(), 0), 0, false)
            check(result.code == DurableCode.OK) { "PROJECTION_IO_UNPROVEN" }
            val observed = checkNotNull(result.snapshot)
            val owned = observed.bytes
            try {
                require(owned.size <= JournalLimits.OBJECT_BYTES)
                val digest = MessageDigest.getInstance("SHA-256").run {
                    update("kurdistan-projection-file-v1\u0000".toByteArray(Charsets.US_ASCII))
                    update(role.wire.toByte()); update(ByteBuffer.allocate(4).putInt(owned.size).array())
                    digest(owned)
                }
                val frame = ByteBuffer.allocate(54).put(role.wire.toByte()).put(1)
                    .putLong(observed.identity.device).putLong(observed.identity.inode).putInt(owned.size).put(digest).array()
                return ProjectionFileObservation(role, frame, owned.size, true)
            } finally { owned.fill(0) }
        }
    }
}

/**
 * Binds closed projection files to one exact logical checkpoint. It proves equality to captured
 * bytes, not that a live SQLite read is safe or that a caller actually quiesced the stores.
 * Only the broker's independent closed-store reader may produce the observations in production.
 */
internal class PhysicalProjectionWitness private constructor(private val wire: ByteArray) {
    fun encode(): ByteArray = wire.clone()
    fun requireMatches(snapshot: ProtectedStateSnapshot, observed: List<ProjectionFileObservation>) {
        val fresh = capture(snapshot, observed).encode()
        try { check(MessageDigest.isEqual(wire, fresh)) { "PHYSICAL_PROJECTION_CHANGED" } }
        finally { fresh.fill(0) }
    }
    fun requireCheckpoint(snapshot: ProtectedStateSnapshot) {
        val encoded = snapshot.encode()
        val expected = ByteBuffer.allocate(89).put(snapshot.storeId()).put(snapshot.operationId())
            .putLong(snapshot.revision).put(JournalDigest.checkpoint(encoded).bytes()).put(5).array()
        try { check(MessageDigest.isEqual(wire.copyOfRange(5, 94), expected)) { "PHYSICAL_PROJECTION_COMMIT_MISMATCH" } }
        finally { encoded.fill(0); expected.fill(0) }
    }
    companion object {
        private const val MAGIC = 0x4b505731
        const val MAXIMUM = 364
        fun capture(snapshot: ProtectedStateSnapshot, observations: List<ProjectionFileObservation>): PhysicalProjectionWitness {
            val owned = observations.toTypedArray().toList()
            require(owned.size == 5 && owned.map { it.role }.toSet() == ProjectionFileRole.entries.toSet())
            require(owned.filter { it.role == ProjectionFileRole.ROOM_MAIN || it.role == ProjectionFileRole.DATASTORE }
                .all { it.present && it.length > 0 })
            require(owned.sumOf { it.length.toLong() } <= 64L * 1024 * 1024)
            val raw = snapshot.encode()
            val output = java.io.ByteArrayOutputStream(MAXIMUM)
            try {
                val header = ByteBuffer.allocate(94).putInt(MAGIC).put(1).put(snapshot.storeId())
                    .put(snapshot.operationId()).putLong(snapshot.revision).put(JournalDigest.checkpoint(raw).bytes()).put(5).array()
                output.write(header)
                owned.sortedBy { it.role.wire }.forEach { observation ->
                    val bytes = observation.bytes()
                    try { output.write(bytes) } finally { bytes.fill(0) }
                }
                return decode(output.toByteArray())
            } finally { raw.fill(0) }
        }
        fun decode(input: ByteArray): PhysicalProjectionWitness {
            val owned = input.clone()
            try {
                require(owned.size in 104..MAXIMUM)
                val reader = ByteBuffer.wrap(owned)
                require(reader.int == MAGIC && reader.get().toInt() == 1)
                require(ByteArray(16).also(reader::get).any { it != 0.toByte() })
                require(ByteArray(JournalLimits.OPERATION_BYTES).also(reader::get).any { it != 0.toByte() })
                val revision = reader.long; require(revision > 0 && revision and 1L == 0L)
                reader.position(reader.position() + 32)
                require(reader.get().toInt() == 5)
                var total = 0L
                for (role in ProjectionFileRole.entries) {
                    require(reader.get().toInt() == role.wire)
                    when (reader.get().toInt()) {
                        0 -> require(role != ProjectionFileRole.ROOM_MAIN && role != ProjectionFileRole.DATASTORE)
                        1 -> {
                            require(reader.long >= 0 && reader.long > 0)
                            val length = reader.int; require(length in 0..JournalLimits.OBJECT_BYTES)
                            if (role == ProjectionFileRole.ROOM_MAIN || role == ProjectionFileRole.DATASTORE) require(length > 0)
                            total = Math.addExact(total, length.toLong())
                            reader.position(reader.position() + 32)
                        }
                        else -> throw IllegalArgumentException("invalid physical entry")
                    }
                }
                require(!reader.hasRemaining() && total <= 64L * 1024 * 1024)
                return PhysicalProjectionWitness(owned.clone())
            } catch (_: java.nio.BufferUnderflowException) { throw IllegalArgumentException("truncated physical witness") }
            finally { owned.fill(0) }
        }
    }
}

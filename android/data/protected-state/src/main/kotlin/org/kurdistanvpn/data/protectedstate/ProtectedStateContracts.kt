// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.nio.ByteBuffer
import java.security.MessageDigest

internal enum class MutationKind(val wire: Int) {
    PROFILE_IMPORT(1), PROFILE_DELETE(2), PROFILE_SELECTION(3), ROUTING(4),
    ENROLLMENT_CREATE(5), ENROLLMENT_EXPORT(6), CREDENTIAL_DELETE(7),
    RESTORE(8), SCOPED_RESET(9), COMPLETE_RESET(10), RECOVERY(11),
    MIGRATION(12), REVOCATION(13), SETTINGS(14), DIAGNOSTIC_RECORD(15),
}

internal object JournalLimits {
    const val OPERATION_BYTES = 32
    const val RECORD_BYTES = 64 * 1024
    const val RECORDS = 256
    const val EPOCH_BYTES = 8L * 1024 * 1024
    const val COMPACT_RECORDS = 128
    const val COMPACT_BYTES = 4L * 1024 * 1024
    const val RESERVED_RECORDS = 32
    const val RESERVED_BYTES = 1024L * 1024
    const val CHECKPOINT_BYTES = 2 * 1024 * 1024
    const val OBJECTS = 4096
    const val OBJECT_BYTES = 8 * 1024 * 1024 + 2048
    const val LIVE_OBJECT_BYTES = 256L * 1024 * 1024
    const val RETAINED_OBJECT_BYTES = 512L * 1024 * 1024
    const val CONTROL_BYTES = 64L * 1024 * 1024
    const val SCAN_NANOS = 2_000_000_000L
    const val RESTORE_NANOS = 5_000_000_000L
}

/** Computed digests only. Decoded wire digests remain bytes, never retagged values. */
internal class JournalDigest private constructor(private val domain: Int, private val value: ByteArray) {
    fun bytes(): ByteArray = value.clone()
    fun same(other: JournalDigest): Boolean = domain == other.domain && MessageDigest.isEqual(value, other.value)
    fun matches(bytes: ByteArray): Boolean = MessageDigest.isEqual(value, bytes)
    fun requireRecord() { require(domain == 1) }
    fun requireCheckpoint() { require(domain == 2) }
    fun requireProjection() { require(domain == 4) }

    companion object {
        fun record(input: ByteArray): JournalDigest = compute(1, "kurdistan-journal-record-v1\u0000", input)
        fun checkpoint(input: ByteArray): JournalDigest = compute(2, "kurdistan-journal-checkpoint-v1\u0000", input)
        fun objectContent(input: ByteArray): JournalDigest = compute(3, "kurdistan-journal-object-v1\u0000", input)
        fun projection(input: ByteArray): JournalDigest = compute(4, "kurdistan-journal-projection-v1\u0000", input)

        private fun compute(kind: Int, label: String, input: ByteArray): JournalDigest {
            val owned = input.clone()
            return try {
                require(owned.size <= JournalLimits.OBJECT_BYTES)
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update(label.toByteArray(Charsets.US_ASCII))
                digest.update(ByteBuffer.allocate(4).putInt(owned.size).array())
                JournalDigest(kind, digest.digest(owned))
            } finally { owned.fill(0) }
        }
    }
}

internal enum class ProtectedMutationStatus {
    COMMITTED, NO_MUTATION, DIRTY, MUTATION_UNPROVEN, QUARANTINED, CAPACITY_EXHAUSTED,
}

/** An authenticated quarantine is preserved state, never permission to reconstruct authority. */
internal enum class ProtectedStateDisposition(val wire: Int) { VERIFIED(1), QUARANTINED(2) }

/** A locator is not authority. Full operation identity is authenticated by the journal/envelope. */
internal fun operationObjectLeaf(operation: ByteArray, sequence: Long): String {
    val owned = operation.clone()
    try {
        require(owned.size == JournalLimits.OPERATION_BYTES && owned.any { it != 0.toByte() } && sequence > 0)
        val digest = MessageDigest.getInstance("SHA-256").apply {
            update("kurdistan-protected-object-locator-v1\u0000".toByteArray(Charsets.US_ASCII))
            update(owned); update(ByteBuffer.allocate(8).putLong(sequence).array())
        }.digest()
        return "object-" + digest.joinToString("") { "%02x".format(it) }.take(56)
    } finally { owned.fill(0) }
}

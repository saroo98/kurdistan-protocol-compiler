// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.util.Collections
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

internal enum class JournalAdmission { ADMIT, COMPACT_FIRST, REJECT_CAPACITY, RECOVERY_REQUIRED }

/** Hard bounds are policy, never an invitation to silently truncate or adopt a valid prefix. */
internal object ProtectedStateJournalLifecycle {
    fun admission(control: JournalControl, inventory: List<JournalStoredEntry>, projectedAdditionalBytes: Long): JournalAdmission {
        val owned = inventory.toTypedArray().toList()
        if (control.dirty) return JournalAdmission.RECOVERY_REQUIRED
        if (projectedAdditionalBytes < 0 || projectedAdditionalBytes > JournalLimits.LIVE_OBJECT_BYTES ||
            owned.size > JournalLimits.OBJECTS || owned.map { it.name }.toSet().size != owned.size ||
            owned.any { it.length !in 0..JournalLimits.OBJECT_BYTES.toLong() }) return JournalAdmission.REJECT_CAPACITY
        val retained = try { owned.fold(0L) { total, entry -> Math.addExact(total, entry.length) } }
        catch (_: ArithmeticException) { return JournalAdmission.REJECT_CAPACITY }
        if (retained > JournalLimits.RETAINED_OBJECT_BYTES - projectedAdditionalBytes) return JournalAdmission.REJECT_CAPACITY
        val controlBytes = owned.filter { it.name.startsWith("journal-") }.sumOf { it.length }
        if (controlBytes > JournalLimits.CONTROL_BYTES - JournalLimits.RESERVED_BYTES) return JournalAdmission.REJECT_CAPACITY
        if (control.recordCount >= JournalLimits.COMPACT_RECORDS || control.epochBytes >= JournalLimits.COMPACT_BYTES)
            return JournalAdmission.COMPACT_FIRST
        return JournalAdmission.ADMIT
    }

    /** Immutable GC candidates. Execution still requires a durable typed operation and an expected-old CAS. */
    fun garbageCandidates(inventory: List<JournalStoredEntry>, live: Set<String>, priorKnownGood: Set<String>,
        interruptedOperations: Set<String>): List<JournalStoredEntry> {
        val entries = inventory.toTypedArray().toList()
        val retained = live.toTypedArray().toSet() + priorKnownGood.toTypedArray().toSet() + interruptedOperations.toTypedArray().toSet()
        require(entries.size <= JournalLimits.OBJECTS && entries.map { it.name }.toSet().size == entries.size)
        require(retained.all { it.validRecordId() })
        val byName = entries.associateBy { it.name }
        require(retained.all(byName::containsKey)) { "GC cannot compensate for missing live state" }
        val candidates = entries.filter { it.name.startsWith("object-") && it.name.validRecordId() && it.name !in retained }
        require(candidates.all { it.length in 1..JournalLimits.OBJECT_BYTES.toLong() })
        return Collections.unmodifiableList(ArrayList(candidates.sortedBy { it.name }))
    }
}

/** Raw immutable ciphertext access. The broker supplies this under the same directory writer lease. */
internal interface JournalObjectAccess {
    fun inventory(): List<JournalStoredEntry>
    fun read(name: String): ByteArray?
    fun delete(name: String, expected: ByteArray)
}

internal enum class GarbageResult { COMPLETE, MAINTENANCE_UNPROVEN }

/**
 * Maintenance has its own authenticated journal record. It cannot advance or dirty the security head.
 * Failure retains a resumable manifest and never turns a previously verified checkpoint into garbage.
 */
internal class ProtectedStateGarbageCollector(
    private val storage: JournalStorage,
    private val journal: ProtectedStateOperationJournal,
    private val objects: JournalObjectAccess,
) {
    fun collect(operationId: ByteArray, live: Set<String>, prior: Set<String>, pending: Set<String>): GarbageResult {
        val operation = operationId.clone()
        val additionalRetention = live.toTypedArray().toSet() + prior.toTypedArray().toSet() + pending.toTypedArray().toSet()
        return try { storage.exclusive {
            require(operation.size == JournalLimits.OPERATION_BYTES && operation.any { it != 0.toByte() })
            val retained = independentlyRetained() + additionalRetention
            val previous = storage.read(NAME, JournalLimits.RECORD_BYTES)
            try {
                if (previous != null) {
                    val old = Plan.decode(previous)
                    check(old.complete && !MessageDigest.isEqual(old.operation, operation))
                }
                journal.readCheckpoint().fill(0)
                val head = journal.readControl().encode()
                try {
                    val candidates = (ProtectedStateJournalLifecycle.garbageCandidates(objects.inventory(), retained, emptySet(), emptySet()) +
                        journalCandidates()).sortedBy { it.name }.take(MAX_ENTRIES)
                    val entries = candidates.map { entry ->
                        val bytes = checkNotNull(readCandidate(entry.name))
                        try {
                            if (entry.name.startsWith("object-")) check(bytes.size.toLong() == entry.length)
                            // Journal inventory measures ciphertext; the adapter returns authenticated plaintext.
                            Entry(entry.name, bytes.size.toLong(), contentDigest(entry.name, bytes).bytes())
                        } finally { bytes.fill(0) }
                    }
                    val plan = Plan(false, operation.clone(), JournalDigest.record(head).bytes(), entries)
                    val encoded = plan.encode()
                    try {
                        replaceVerified(previous, encoded)
                        finish(plan, encoded, retained)
                    } finally { encoded.fill(0) }
                } finally { head.fill(0) }
            } finally { previous?.fill(0) }
        } } catch (_: Exception) { GarbageResult.MAINTENANCE_UNPROVEN }
        finally { operation.fill(0) }
    }

    /** Resume is explicit maintenance, never an automatic-restoration side effect. */
    fun resume(live: Set<String>, prior: Set<String>, pending: Set<String>): GarbageResult {
        val additionalRetention = live.toTypedArray().toSet() + prior.toTypedArray().toSet() + pending.toTypedArray().toSet()
        return try { storage.exclusive {
            val retained = independentlyRetained() + additionalRetention
            val encoded = storage.read(NAME, JournalLimits.RECORD_BYTES) ?: return@exclusive GarbageResult.COMPLETE
            try {
                val plan = Plan.decode(encoded)
                // A terminal GC operation has no remaining authority to delete or pin a younger head.
                if (plan.complete) GarbageResult.COMPLETE else finish(plan, encoded, retained)
            } finally { encoded.fill(0) }
        } } catch (_: Exception) { GarbageResult.MAINTENANCE_UNPROVEN }
    }

    private fun finish(plan: Plan, encoded: ByteArray, retained: Set<String>): GarbageResult {
        journal.readCheckpoint().fill(0)
        val head = journal.readControl().encode()
        try { check(JournalDigest.record(head).matches(plan.head)) } finally { head.fill(0) }
        check(retained.all { it.validRecordId() })
        val currentRetained = independentlyRetained()
        check(plan.entries.none { it.name in retained || it.name in currentRetained })
        val eligibleJournal = journalCandidates().map { it.name }.toSet()
        val start = System.nanoTime()
        for (entry in plan.entries) {
            check(System.nanoTime() - start <= JournalLimits.SCAN_NANOS) { "BOUNDED_GC_PAUSED" }
            val bytes = readCandidate(entry.name) ?: continue // A prior deletion is already independently observable.
            try {
                check(!plan.complete && bytes.size.toLong() == entry.length && contentDigest(entry.name, bytes).matches(entry.digest))
                if (entry.name.startsWith("object-")) objects.delete(entry.name, bytes)
                else {
                    check(entry.name in eligibleJournal) { "JOURNAL_RECORD_STILL_REQUIRED" }
                    storage.delete(entry.name, bytes)
                }
                val surviving = readCandidate(entry.name)
                try { check(surviving == null) } finally { surviving?.fill(0) }
            } finally { bytes.fill(0) }
        }
        journal.readCheckpoint().fill(0)
        if (!plan.complete) {
            val terminal = plan.copy(complete = true).encode()
            try { replaceVerified(encoded, terminal) } finally { terminal.fill(0) }
        }
        return GarbageResult.COMPLETE
    }

    /** Only records before a verified compaction anchor, and checkpoints older than the retained pair. */
    private fun journalCandidates(): List<JournalStoredEntry> {
        val control = journal.readControl()
        check(!control.dirty && control.revision > 0)
        val entries = storage.inventory(JournalLimits.OBJECTS)
        fun number(name: String): Long = name.substringAfterLast('-').toLong(16)
        val previous = entries.filter { it.name.startsWith("journal-checkpoint-") }
            .map { number(it.name) }.filter { it < control.revision }.maxOrNull()
        return entries.filter { entry -> when {
            entry.name.startsWith("journal-record-") -> control.baseSequence > 0 && number(entry.name) < control.baseSequence
            entry.name.startsWith("journal-intent-") -> control.baseSequence > 0 && number(entry.name) <= control.baseSequence
            entry.name.startsWith("journal-resolution-") -> control.baseSequence > 0 && number(entry.name) <= control.baseSequence
            entry.name.startsWith("journal-checkpoint-") -> previous != null && number(entry.name) < previous
            entry.name.startsWith("journal-projection-") -> previous != null && number(entry.name) < previous
            else -> false
        } }
    }

    private fun readCandidate(name: String): ByteArray? = when {
        name.startsWith("object-") -> objects.read(name)
        name.startsWith("journal-checkpoint-") -> storage.read(name, JournalLimits.CHECKPOINT_BYTES)
        name.startsWith("journal-projection-") -> storage.read(name, PhysicalProjectionWitness.MAXIMUM)
        name.startsWith("journal-record-") || name.startsWith("journal-intent-") || name.startsWith("journal-resolution-") -> storage.read(name, JournalLimits.RECORD_BYTES)
        else -> error("INVALID_GARBAGE_CLASS")
    }

    private fun contentDigest(name: String, bytes: ByteArray): JournalDigest = when {
        name.startsWith("object-") -> JournalDigest.objectContent(bytes)
        name.startsWith("journal-checkpoint-") -> JournalDigest.checkpoint(bytes)
        name.startsWith("journal-projection-") -> JournalDigest.projection(bytes)
        else -> JournalDigest.record(bytes)
    }

    private fun independentlyRetained(): Set<String> {
        val references = journal.retainedSnapshotsForGarbageCollection().flatMap { it.objects() }
        for (reference in references) {
            val observed = checkNotNull(objects.read(reference.physicalId)) { "LIVE_OBJECT_MISSING" }
            try { check(reference.matches(observed)) { "LIVE_OBJECT_MISMATCH" } }
            finally { observed.fill(0) }
        }
        return references.map { it.physicalId }.toSet()
    }

    private fun replaceVerified(expected: ByteArray?, replacement: ByteArray) {
        storage.compareAndReplace(NAME, expected, replacement)
        val observed = checkNotNull(storage.read(NAME, JournalLimits.RECORD_BYTES))
        try { check(MessageDigest.isEqual(replacement, observed)) } finally { observed.fill(0) }
    }

    private data class Entry(val name: String, val length: Long, val digest: ByteArray)
    private data class Plan(val complete: Boolean, val operation: ByteArray, val head: ByteArray, val entries: List<Entry>) {
        fun encode(): ByteArray {
            val size = 71 + entries.sumOf { 1 + it.name.length + 8 + 32 }
            require(size <= JournalLimits.RECORD_BYTES)
            return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
                putInt(MAGIC); put(if (complete) 1 else 0); put(operation); put(head); putShort(entries.size.toShort())
                for (entry in entries) { put(entry.name.length.toByte()); put(entry.name.toByteArray(Charsets.US_ASCII)); putLong(entry.length); put(entry.digest) }
            }.array()
        }
        companion object {
            fun decode(input: ByteArray): Plan {
                val owned = input.clone()
                try {
                    require(owned.size in 71..JournalLimits.RECORD_BYTES)
                    val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
                    require(reader.int == MAGIC)
                    val complete = reader.get().toInt(); require(complete in 0..1)
                    val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(reader::get); require(operation.any { it != 0.toByte() })
                    val head = ByteArray(32).also(reader::get)
                    val count = reader.short.toInt() and 65535; require(count <= MAX_ENTRIES)
                    var prior = ""
                    val entries = ArrayList<Entry>(count)
                    repeat(count) {
                        val length = reader.get().toInt() and 255
                        require(length in 1..64 && reader.remaining() >= length + 40)
                        val nameBytes = ByteArray(length).also(reader::get)
                        require(nameBytes.all { it.toInt() in 1..127 })
                        val name = String(nameBytes, Charsets.US_ASCII)
                        val journalName = listOf("journal-record-", "journal-intent-", "journal-resolution-", "journal-checkpoint-", "journal-projection-").any { prefix ->
                            name.startsWith(prefix) && name.removePrefix(prefix).let { suffix ->
                                suffix.length == 16 && suffix.all { it in '0'..'9' || it in 'a'..'f' }
                            }
                        }
                        require((name.startsWith("object-") || journalName) && name.validRecordId() && name > prior); prior = name
                        val bytes = reader.long; require(bytes in 1..JournalLimits.OBJECT_BYTES.toLong())
                        entries += Entry(name, bytes, ByteArray(32).also(reader::get))
                    }
                    require(!reader.hasRemaining())
                    return Plan(complete == 1, operation, head, entries).also { require(it.encode().contentEquals(owned)) }
                } finally { owned.fill(0) }
            }
        }
    }

    companion object {
        private const val NAME = "journal-gc"
        private const val MAGIC = 0x4b474331
        private const val MAX_ENTRIES = 512

        fun requireNoPendingMutation(storage: JournalStorage) {
            val raw = storage.read(NAME, JournalLimits.RECORD_BYTES) ?: return
            try { check(Plan.decode(raw).complete) { "GC_MUST_FINISH_BEFORE_HEAD_ADVANCES" } }
            finally { raw.fill(0) }
        }
    }
}

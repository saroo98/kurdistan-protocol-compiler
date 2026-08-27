// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** This codec is not a durability receipt. Only authenticated, independently reread bytes may be used. */
internal class JournalControl private constructor(
    private val store: ByteArray,
    val revision: Long,
    val reservedCleanRevision: Long,
    val sequence: Long,
    val reservedSequence: Long,
    val recordCount: Int,
    val epochBytes: Long,
    private val operation: ByteArray,
    val kind: MutationKind?,
    private val checkpoint: ByteArray,
    private val tail: ByteArray,
    val baseSequence: Long = 0,
    private val baseTail: ByteArray = ByteArray(32),
    val checkpointRevision: Long = revision,
    private val projection: ByteArray = ByteArray(32),
) {
    val dirty: Boolean get() = revision and 1L != 0L
    fun storeId(): ByteArray = store.clone()
    fun operationId(): ByteArray = operation.clone()
    fun checkpointDigest(): ByteArray = checkpoint.clone()
    fun tailDigest(): ByteArray = tail.clone()
    fun baseTailDigest(): ByteArray = baseTail.clone()
    fun projectionDigest(): ByteArray = projection.clone()

    fun reserve(operationId: ByteArray, mutation: MutationKind): JournalControl {
        val owned = operationId.clone()
        check(!dirty) { "recovery must finish the existing operation first" }
        require(owned.size == JournalLimits.OPERATION_BYTES && owned.any { it != 0.toByte() })
        require(revision <= Long.MAX_VALUE - 3 && reservedSequence < Long.MAX_VALUE)
        require(recordCount < JournalLimits.RECORDS - JournalLimits.RESERVED_RECORDS)
        require(epochBytes <= JournalLimits.EPOCH_BYTES - JournalLimits.RESERVED_BYTES - JournalLimits.RECORD_BYTES)
        return JournalControl(store.clone(), revision + 1, revision + 2, sequence,
            reservedSequence + 1, recordCount, epochBytes, owned, mutation, checkpoint.clone(), tail.clone(), baseSequence, baseTail.clone(), checkpointRevision, projection.clone())
    }

    fun complete(newCheckpoint: JournalDigest, newTail: JournalDigest, addedBytes: Int = 0, addedRecords: Int = 2,
        newProjection: JournalDigest? = null): JournalControl {
        check(dirty && reservedCleanRevision == revision + 1)
        require(addedBytes in 0..JournalLimits.RECORD_BYTES * 2)
        require(addedRecords in 2..3)
        require(recordCount + addedRecords <= JournalLimits.RECORDS && epochBytes + addedBytes <= JournalLimits.EPOCH_BYTES)
        newCheckpoint.requireCheckpoint()
        newTail.requireRecord()
        newProjection?.requireProjection()
        return JournalControl(store.clone(), reservedCleanRevision, 0, reservedSequence, reservedSequence,
            recordCount + addedRecords, epochBytes + addedBytes, ByteArray(JournalLimits.OPERATION_BYTES), null, newCheckpoint.bytes(), newTail.bytes(), baseSequence, baseTail.clone(),
            reservedCleanRevision, newProjection?.bytes() ?: ByteArray(32))
    }

    fun compacted(anchor: JournalDigest, bytes: Int): JournalControl {
        check(!dirty && revision > 0)
        require(sequence < Long.MAX_VALUE && bytes in 1..JournalLimits.RECORD_BYTES)
        anchor.requireRecord()
        return JournalControl(store.clone(), revision, 0, sequence + 1, sequence + 1,
            1, bytes.toLong(), ByteArray(JournalLimits.OPERATION_BYTES), null, checkpoint.clone(), anchor.bytes(), sequence + 1, anchor.bytes(), checkpointRevision, projection.clone())
    }

    fun encode(): ByteArray = ByteBuffer.allocate(SIZE).order(ByteOrder.BIG_ENDIAN).apply {
        putInt(MAGIC); put(1); put(if (dirty) 1 else 0); put(store)
        putLong(revision); putLong(reservedCleanRevision); putLong(sequence); putLong(reservedSequence)
        putInt(recordCount); putLong(epochBytes); put(operation); put((kind?.wire ?: 0).toByte())
        put(checkpoint); put(tail); putLong(baseSequence); put(baseTail); putLong(checkpointRevision); put(projection)
    }.array()

    companion object {
        private const val MAGIC = 0x4b4a4331
        private const val SIZE = 243
        fun initial(storeId: ByteArray): JournalControl {
            val owned = storeId.clone()
            require(owned.size == 16 && owned.any { it != 0.toByte() })
            return JournalControl(owned, 0, 0, 0, 0, 0, 0, ByteArray(JournalLimits.OPERATION_BYTES), null, ByteArray(32), ByteArray(32))
        }

        fun decode(input: ByteArray): JournalControl {
            val owned = input.clone()
            try {
                require(owned.size == SIZE)
                val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
                require(reader.int == MAGIC && reader.get().toInt() == 1)
                val state = reader.get().toInt()
                require(state in 0..1)
                val store = ByteArray(16).also(reader::get)
                val revision = reader.long
                val target = reader.long
                val sequence = reader.long
                val reserved = reader.long
                val count = reader.int
                val bytes = reader.long
                val operation = ByteArray(JournalLimits.OPERATION_BYTES).also(reader::get)
                val kindWire = reader.get().toInt() and 255
                val kind = MutationKind.entries.singleOrNull { it.wire == kindWire }
                val checkpoint = ByteArray(32).also(reader::get)
                val tail = ByteArray(32).also(reader::get)
                val baseSequence = reader.long
                val baseTail = ByteArray(32).also(reader::get)
                val checkpointRevision = reader.long
                val projection = ByteArray(32).also(reader::get)
                require(store.any { it != 0.toByte() } && revision >= 0 && sequence >= 0 && reserved >= sequence)
                require(checkpointRevision in 0..revision && checkpointRevision and 1L == 0L)
                require(baseSequence in 0..sequence && sequence - baseSequence <= JournalLimits.RECORDS)
                if (baseSequence == 0L) require(baseTail.all { it == 0.toByte() })
                require(count in 0..JournalLimits.RECORDS && bytes in 0..JournalLimits.EPOCH_BYTES)
                if (state == 1) {
                    require(revision and 1L == 1L && revision < Long.MAX_VALUE && target == revision + 1)
                    require(kind != null && operation.any { it != 0.toByte() } && reserved > sequence)
                } else {
                    require(revision and 1L == 0L && target == 0L && reserved == sequence)
                    require(kindWire == 0 && operation.all { it == 0.toByte() })
                    require(checkpointRevision == revision)
                }
                require(!reader.hasRemaining())
                return JournalControl(store, revision, target, sequence, reserved, count, bytes, operation, kind, checkpoint, tail, baseSequence, baseTail, checkpointRevision, projection)
            } finally { owned.fill(0) }
        }
    }
}


/** The adapter owns a single directory/lock lease for the complete block. Reads never repair. */
internal interface JournalStorage {
    fun <T> exclusive(block: () -> T): T
    fun read(name: String, maximum: Int): ByteArray?
    fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray)
    fun delete(name: String, expected: ByteArray)
    fun inventory(maximum: Int): List<JournalStoredEntry>
}

internal data class JournalStoredEntry(val name: String, val length: Long)

/**
 * A product operation whose authenticated expected checkpoint cannot exist until after a
 * durable reservation. This is deliberately internal: only confirmed migration needs to
 * snapshot legacy bytes after the journal has made interruption non-connectable.
 */
internal class DeferredJournalMutation(
    expectedNormalized: ByteArray,
    private val apply: () -> Unit,
    private val reconstruct: () -> ByteArray,
    private val cleanup: () -> Unit,
) : AutoCloseable {
    private val expected = expectedNormalized.clone()
    fun expectedNormalized(): ByteArray = expected.clone()
    fun apply() = apply.invoke()
    fun reconstruct(): ByteArray = reconstruct.invoke()
    override fun close() {
        try { cleanup.invoke() } finally { expected.fill(0) }
    }
}

/** A compensation resolves the existing operation; it is not a new operation or revision pair. */
internal enum class RecoveryResolution(val wire: Int) { RESUME(0), ROLLBACK(1), QUARANTINE(2) }

/**
 * Serial durable operation journal. Storage is encrypted/authenticated by its adapter.
 * Product mutations and independent reconstruction are separate capabilities owned by the broker.
 */
internal class ProtectedStateOperationJournal(private val storage: JournalStorage) {
    fun initialize(storeId: ByteArray) = storage.exclusive {
        check(storage.read(CONTROL, JournalLimits.RECORD_BYTES) == null)
        check(storage.inventory(JournalLimits.OBJECTS).all { it.name == "protected-state.lock" || it.name == "journal-store" }) {
            "EXISTING_STATE_REQUIRES_EXPLICIT_MIGRATION"
        }
        replaceVerified(CONTROL, null, JournalControl.initial(storeId).encode())
    }

    fun readControl(): JournalControl {
        val bytes = requireNotNull(storage.read(CONTROL, JournalLimits.RECORD_BYTES))
        return try { JournalControl.decode(bytes) } finally { bytes.fill(0) }
    }

    fun readCheckpoint(): ByteArray = readCheckpointInternal(allowPendingReset = false)

    /** Reset-only final verification. This never returns a connectable runtime snapshot. */
    fun readCheckpointForReset(storeId: ByteArray, operationId: ByteArray, targetRevision: Long): ByteArray {
        val store = storeId.clone(); val operation = operationId.clone()
        try {
            require(store.size == 16 && operation.size == JournalLimits.OPERATION_BYTES &&
                targetRevision > 0 && targetRevision and 1L == 0L)
            checkNotNull(storage.read("journal-reset", JournalLimits.CHECKPOINT_BYTES)).fill(0)
            val control = readControl()
            check(!control.dirty && control.revision == targetRevision && control.storeId().contentEquals(store))
            val intent = checkNotNull(storage.read(intentName(control.sequence), JournalLimits.RECORD_BYTES))
            try {
                check(intent.size == 141)
                val reader = ByteBuffer.wrap(intent)
                check(reader.int == 0x4b4a4931 && ByteArray(16).also(reader::get).contentEquals(store) &&
                    ByteArray(JournalLimits.OPERATION_BYTES).also(reader::get).contentEquals(operation))
                check(reader.long == targetRevision - 1 && reader.long == targetRevision && reader.long == control.sequence &&
                    reader.get().toInt() == MutationKind.COMPLETE_RESET.wire)
                val value = readCheckpointInternal(allowPendingReset = true)
                try { check(control.encode().contentEquals(readControl().encode())); return value }
                catch (failure: Throwable) { value.fill(0); throw failure }
            } finally { intent.fill(0) }
        } finally { store.fill(0); operation.fill(0) }
    }

    private fun readCheckpointInternal(allowPendingReset: Boolean): ByteArray {
        val reset = storage.read("journal-reset", JournalLimits.CHECKPOINT_BYTES)
        try { check(allowPendingReset || reset == null) { "CONFIRMED_RESET_REQUIRES_ROLL_FORWARD" } }
        finally { reset?.fill(0) }
        val control = readControl()
        check(!control.dirty && control.revision > 0) { "no restoration from dirty or uninitialized state" }
        validateChain(control)
        validateInventory(control)
        val checkpoint = checkNotNull(storage.read(checkpointName(control.revision), JournalLimits.CHECKPOINT_BYTES))
        try {
            check(JournalDigest.checkpoint(checkpoint).matches(control.checkpointDigest())) { "checkpoint binding rejected" }
            val physical = projectionDigestFor(checkpoint)
            check((physical?.bytes() ?: ByteArray(32)).contentEquals(control.projectionDigest())) { "projection binding rejected" }
            check(control.encode().contentEquals(readControl().encode())) { "revision changed during restoration read" }
            return checkpoint
        } catch (failure: Throwable) { checkpoint.fill(0); throw failure }
    }

    /** Called only by independent reconstruction while the existing DIRTY writer lease is held. */
    fun bindProjection(snapshot: ProtectedStateSnapshot, witness: PhysicalProjectionWitness) {
        val control = readControl()
        check(control.dirty && control.reservedCleanRevision == snapshot.revision &&
            control.storeId().contentEquals(snapshot.storeId()) && control.operationId().contentEquals(snapshot.operationId()))
        witness.requireCheckpoint(snapshot)
        val name = projectionName(snapshot.revision)
        val owned = witness.encode()
        val old = storage.read(name, PhysicalProjectionWitness.MAXIMUM)
        try {
            if (old == null) replaceVerified(name, null, owned)
            else check(java.security.MessageDigest.isEqual(old, owned)) { "PROJECTION_RESOLUTION_CANNOT_CHANGE" }
        } finally { owned.fill(0); old?.fill(0) }
    }

    fun readProjectionWitness(snapshot: ProtectedStateSnapshot): PhysicalProjectionWitness {
        val raw = checkNotNull(storage.read(projectionName(snapshot.revision), PhysicalProjectionWitness.MAXIMUM))
        try { return PhysicalProjectionWitness.decode(raw).also { it.requireCheckpoint(snapshot) } }
        finally { raw.fill(0) }
    }

    private fun projectionDigestFor(normalized: ByteArray): JournalDigest? {
        // The journal also records non-authority maintenance bodies. Every KPS checkpoint requires
        // physical evidence; an arbitrary journal body can never pass the restoration decoder.
        if (normalized.size < 4 || ByteBuffer.wrap(normalized).int != 0x4b505331) return null
        val snapshot = ProtectedStateSnapshot.decode(normalized)
        val proof = readProjectionWitness(snapshot).encode()
        return try { JournalDigest.projection(proof) } finally { proof.fill(0) }
    }

    /** Returns prior committed bytes for explicit recovery only. It never makes DIRTY state connectable. */
    fun readPriorCheckpointForExplicitRecovery(): ByteArray {
        val before = readControl()
        check(before.dirty && before.checkpointRevision > 0)
        val recorded = checkNotNull(storage.read(checkpointName(before.checkpointRevision), JournalLimits.CHECKPOINT_BYTES))
        return try {
            check(JournalDigest.checkpoint(recorded).matches(before.checkpointDigest()))
            check(before.encode().contentEquals(readControl().encode()))
            recorded
        } catch (failure: Throwable) { recorded.fill(0); throw failure }
    }

    /** Retention only: these bytes never authorize restoration or repair. */
    fun retainedSnapshotsForGarbageCollection(): List<ProtectedStateSnapshot> {
        val control = readControl()
        check(!control.dirty && control.revision > 0)
        val current = readCheckpoint()
        val result = ArrayList<ProtectedStateSnapshot>(2)
        try { result += ProtectedStateSnapshot.decode(current) } finally { current.fill(0) }
        val prior = storage.inventory(JournalLimits.OBJECTS).asSequence()
            .mapNotNull { entry ->
                if (!entry.name.startsWith("journal-checkpoint-")) null
                else entry.name.removePrefix("journal-checkpoint-").toLongOrNull(16)
            }.filter { it > 0 && it < control.revision }.maxOrNull()
        if (prior != null) {
            val raw = checkNotNull(storage.read(checkpointName(prior), JournalLimits.CHECKPOINT_BYTES))
            try {
                val decoded = ProtectedStateSnapshot.decode(raw)
                check(decoded.revision == prior && decoded.storeId().contentEquals(control.storeId()))
                result += decoded
            } finally { raw.fill(0) }
        }
        check(result.first().revision == control.revision && result.first().storeId().contentEquals(control.storeId()))
        check(control.encode().contentEquals(readControl().encode()))
        return result
    }

    private fun validateInventory(control: JournalControl, unacknowledgedAnchor: Long? = null) {
        val entries = storage.inventory(JournalLimits.OBJECTS)
        check(entries.size <= JournalLimits.OBJECTS && entries.map { it.name }.toSet().size == entries.size)
        var journalBytes = 0L
        var totalBytes = 0L
        for (entry in entries) {
            check(entry.length in 0..JournalLimits.OBJECT_BYTES.toLong())
            totalBytes = Math.addExact(totalBytes, entry.length)
            check(totalBytes <= JournalLimits.RETAINED_OBJECT_BYTES)
            if (!entry.name.startsWith("journal-")) continue
            journalBytes = Math.addExact(journalBytes, entry.length)
            check(journalBytes <= JournalLimits.CONTROL_BYTES)
            val prefixes = listOf("journal-record-", "journal-intent-", "journal-resolution-", "journal-checkpoint-", "journal-projection-")
            val prefix = prefixes.firstOrNull(entry.name::startsWith)
            if (prefix == null) {
                check(entry.name == CONTROL || entry.name == "journal-gc" || entry.name == "journal-store" ||
                    entry.name == ProtectedPresentationOverlay.NAME ||
                    entry.name == "journal-reset" || entry.name == "journal-reset-ready") { "UNRECOGNIZED_JOURNAL_RECORD" }
                continue
            }
            val suffix = entry.name.removePrefix(prefix)
            check(suffix.length == 16 && suffix.all { it in '0'..'9' || it in 'a'..'f' })
            val value = suffix.toLongOrNull(16) ?: error("record sequence invalid")
            val maximum = when (prefix) {
                "journal-checkpoint-", "journal-projection-" -> control.revision
                "journal-record-" -> unacknowledgedAnchor ?: control.sequence
                else -> control.sequence
            }
            check(value > 0 && value <= maximum) {
                "unaccounted newer record; do not adopt a valid prefix"
            }
        }
    }

    private fun validateChain(control: JournalControl) {
        val start = System.nanoTime()
        var prior = control.baseTailDigest()
        var priorRevision = 0L
        try {
            if (control.baseSequence > 0) {
                val anchor = checkNotNull(storage.read(recordName(control.baseSequence), JournalLimits.RECORD_BYTES))
                try {
                    check(anchor.size == 132 && JournalDigest.record(anchor).matches(prior))
                    val decoded = ByteBuffer.wrap(anchor).order(ByteOrder.BIG_ENDIAN)
                    check(decoded.int == 0x4b4a5832)
                    check(ByteArray(16).also(decoded::get).contentEquals(control.storeId()))
                    priorRevision = decoded.long
                    check(priorRevision > 0 && priorRevision and 1L == 0L && priorRevision <= control.revision)
                    check(decoded.long == control.baseSequence - 1)
                    decoded.position(decoded.position() + 32)
                    val anchorCheckpoint = ByteArray(32).also(decoded::get)
                    val anchorProjection = ByteArray(32).also(decoded::get)
                    if (control.baseSequence == control.sequence) check(anchorCheckpoint.contentEquals(control.checkpointDigest()) &&
                        anchorProjection.contentEquals(control.projectionDigest()))
                }
                finally { anchor.fill(0) }
            }
            for (sequence in control.baseSequence + 1..control.sequence) {
                check(System.nanoTime() - start <= JournalLimits.SCAN_NANOS) { "bounded scan expired" }
                val record = checkNotNull(storage.read(recordName(sequence), JournalLimits.RECORD_BYTES))
                var intent: ByteArray? = null
                try {
                    intent = checkNotNull(storage.read(intentName(sequence), JournalLimits.RECORD_BYTES))
                    val source = requireNotNull(intent)
                    check(source.size == 141)
                    val reader = ByteBuffer.wrap(source).order(ByteOrder.BIG_ENDIAN)
                    check(reader.int == 0x4b4a4931)
                    check(ByteArray(16).also(reader::get).contentEquals(control.storeId()))
                    check(ByteArray(JournalLimits.OPERATION_BYTES).also(reader::get).any { it != 0.toByte() })
                    val dirty = reader.long
                    check(dirty == priorRevision + 1 && reader.long == dirty + 1)
                    check(dirty < control.revision && reader.long == sequence)
                    val kind = reader.get().toInt()
                    check(MutationKind.entries.any { it.wire == kind })
                    check(ByteArray(32).also(reader::get).contentEquals(prior))
                    val resolution = storage.read(resolutionName(sequence), JournalLimits.RECORD_BYTES)
                    try {
                        val originalCheckpoint = ByteArray(32).also(reader::get)
                        val expectedCheckpoint = if (resolution == null) originalCheckpoint
                            else resolutionCheckpoint(resolution, source)
                        val terminal = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
                        check(record.size == 4 + source.size + (resolution?.size ?: 0) + 64)
                        check(terminal.int == if (resolution == null) 0x4b4a5433 else 0x4b4a5434)
                        check(ByteArray(source.size).also(terminal::get).contentEquals(source))
                        if (resolution != null) check(ByteArray(resolution.size).also(terminal::get).contentEquals(resolution))
                        check(ByteArray(32).also(terminal::get).contentEquals(expectedCheckpoint))
                        val projection = ByteArray(32).also(terminal::get)
                        if (sequence == control.sequence) check(expectedCheckpoint.contentEquals(control.checkpointDigest()) &&
                            projection.contentEquals(control.projectionDigest()))
                    } finally { resolution?.fill(0) }
                    priorRevision = dirty + 1
                    prior.fill(0)
                    prior = JournalDigest.record(record).bytes()
                } finally { record.fill(0); intent?.fill(0) }
            }
            check(priorRevision == control.revision && prior.contentEquals(control.tailDigest()))
        } finally { prior.fill(0) }
    }

    fun compact(reconstruct: () -> ByteArray): ProtectedMutationStatus = storage.exclusive {
        try {
            ProtectedStateGarbageCollector.requireNoPendingMutation(storage)
            val before = readControl()
            if (before.dirty) return@exclusive ProtectedMutationStatus.DIRTY
            val recorded = readCheckpoint()
            val actual = reconstruct()
            try {
                if (!java.security.MessageDigest.isEqual(recorded, actual)) return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                val anchor = ByteBuffer.allocate(132).order(ByteOrder.BIG_ENDIAN).apply {
                    putInt(0x4b4a5832); put(before.storeId()); putLong(before.revision); putLong(before.sequence)
                    put(before.tailDigest()); put(before.checkpointDigest()); put(before.projectionDigest())
                }.array()
                try {
                    val compacted = before.compacted(JournalDigest.record(anchor), anchor.size)
                    replaceVerified(recordName(compacted.sequence), null, anchor)
                    replaceVerified(CONTROL, before.encode(), compacted.encode())
                    ProtectedMutationStatus.COMMITTED
                } finally { anchor.fill(0) }
            } finally { recorded.fill(0); actual.fill(0) }
        } catch (_: Exception) { ProtectedMutationStatus.MUTATION_UNPROVEN }
    }

    /** Explicit maintenance only. An exact abandoned anchor may finish; a valid prefix alone may not. */
    fun resolveUnacknowledgedCompaction(reconstruct: () -> ByteArray): ProtectedMutationStatus = storage.exclusive {
        try {
            val before = readControl()
            if (before.dirty) return@exclusive ProtectedMutationStatus.DIRTY
            check(before.revision > 0 && before.sequence < Long.MAX_VALUE)
            val nextSequence = before.sequence + 1
            val candidate = storage.read(recordName(nextSequence), JournalLimits.RECORD_BYTES)
            if (candidate == null) {
                readCheckpoint().fill(0)
                return@exclusive ProtectedMutationStatus.NO_MUTATION
            }
            try {
                validateChain(before)
                validateInventory(before, nextSequence)
                val expectedAnchor = ByteBuffer.allocate(132).order(ByteOrder.BIG_ENDIAN).apply {
                    putInt(0x4b4a5832); put(before.storeId()); putLong(before.revision); putLong(before.sequence)
                    put(before.tailDigest()); put(before.checkpointDigest()); put(before.projectionDigest())
                }.array()
                try { check(java.security.MessageDigest.isEqual(candidate, expectedAnchor)) }
                finally { expectedAnchor.fill(0) }
                val checkpoint = checkNotNull(storage.read(checkpointName(before.revision), JournalLimits.CHECKPOINT_BYTES))
                try {
                    check(JournalDigest.checkpoint(checkpoint).matches(before.checkpointDigest()))
                    val observed = reconstruct()
                    try { check(java.security.MessageDigest.isEqual(checkpoint, observed)) }
                    finally { observed.fill(0) }
                    val current = before.encode()
                    val replacement = before.compacted(JournalDigest.record(candidate), candidate.size).encode()
                    try { replaceVerified(CONTROL, current, replacement) }
                    finally { current.fill(0); replacement.fill(0) }
                    readCheckpoint().fill(0)
                    ProtectedMutationStatus.COMMITTED
                } finally { checkpoint.fill(0) }
            } finally { candidate.fill(0) }
        } catch (_: Exception) { ProtectedMutationStatus.MUTATION_UNPROVEN }
    }

    fun mutate(
        kind: MutationKind,
        operationId: ByteArray,
        expectedNormalized: ByteArray,
        mutation: () -> Unit,
        reconstruct: () -> ByteArray,
        expectedOldControl: ByteArray? = null,
        prepareReset: (() -> Unit)? = null,
    ): ProtectedMutationStatus {
        val expected = expectedNormalized.clone()
        val operation = operationId.clone()
        val expectedOld = expectedOldControl?.clone()
        try {
            require(expected.size <= JournalLimits.CHECKPOINT_BYTES)
            require(prepareReset == null || kind == MutationKind.COMPLETE_RESET)
            return storage.exclusive {
                val beforeBytes = requireNotNull(storage.read(CONTROL, JournalLimits.RECORD_BYTES))
                if (expectedOld != null && !java.security.MessageDigest.isEqual(expectedOld, beforeBytes)) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                }
                val before = try { JournalControl.decode(beforeBytes) } catch (_: Exception) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                }
                if (before.dirty) { beforeBytes.fill(0); return@exclusive ProtectedMutationStatus.DIRTY }
                try {
                    ProtectedStateGarbageCollector.requireNoPendingMutation(storage)
                    if (before.revision > 0) readCheckpointInternal(kind == MutationKind.COMPLETE_RESET).fill(0) else validateInventory(before)
                } catch (_: Exception) { beforeBytes.fill(0); return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN }
                val dirty = try { before.reserve(operation, kind) } catch (_: IllegalArgumentException) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.CAPACITY_EXHAUSTED
                }
                val dirtyBytes = dirty.encode()
                try {
                    // Reset intent is the durable point of no return. The hook can only be
                    // composed for this typed operation and runs before any product deletion.
                    prepareReset?.invoke()
                    replaceVerified(CONTROL, beforeBytes, dirtyBytes)
                } catch (_: Exception) {
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                } finally { beforeBytes.fill(0) }
                val intent = encodeIntent(dirty, expected)
                try {
                    replaceVerified(intentName(dirty.reservedSequence), null, intent)
                } catch (_: Exception) {
                    dirtyBytes.fill(0); intent.fill(0)
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                }
                try {
                    try { mutation() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                    val actual = try { reconstruct() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                    try {
                        if (!java.security.MessageDigest.isEqual(expected, actual)) return@exclusive ProtectedMutationStatus.DIRTY
                        publishComplete(dirty, dirtyBytes, intent, actual)
                    } finally { actual.fill(0) }
                } finally { dirtyBytes.fill(0); intent.fill(0) }
            }
        } catch (_: Exception) {
            return ProtectedMutationStatus.MUTATION_UNPROVEN
        } finally { expected.fill(0); operation.fill(0); expectedOld?.fill(0) }
    }

    /**
     * Confirmed legacy migration is the sole operation permitted to read source bytes after
     * writing DIRTY. A failed deferred capture deliberately retains DIRTY and never publishes
     * a checkpoint or repairs the source.
     */
    fun mutateAfterReservation(
        kind: MutationKind,
        operationId: ByteArray,
        expectedOldControl: ByteArray? = null,
        prepare: (before: JournalControl, reservation: JournalControl) -> DeferredJournalMutation,
    ): ProtectedMutationStatus {
        require(kind == MutationKind.MIGRATION)
        val operation = operationId.clone()
        val expectedOld = expectedOldControl?.clone()
        try {
            return storage.exclusive {
                val beforeBytes = requireNotNull(storage.read(CONTROL, JournalLimits.RECORD_BYTES))
                if (expectedOld != null && !java.security.MessageDigest.isEqual(expectedOld, beforeBytes)) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                }
                val before = try { JournalControl.decode(beforeBytes) } catch (_: Exception) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                }
                if (before.dirty) { beforeBytes.fill(0); return@exclusive ProtectedMutationStatus.DIRTY }
                try {
                    ProtectedStateGarbageCollector.requireNoPendingMutation(storage)
                    if (before.revision > 0) readCheckpointInternal(false).fill(0) else validateInventory(before)
                } catch (_: Exception) { beforeBytes.fill(0); return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN }
                val dirty = try { before.reserve(operation, kind) } catch (_: IllegalArgumentException) {
                    beforeBytes.fill(0)
                    return@exclusive ProtectedMutationStatus.CAPACITY_EXHAUSTED
                }
                val dirtyBytes = dirty.encode()
                try {
                    replaceVerified(CONTROL, beforeBytes, dirtyBytes)
                } catch (_: Exception) {
                    return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
                } finally { beforeBytes.fill(0) }
                val deferred = try { prepare(before, dirty) }
                catch (_: Exception) { dirtyBytes.fill(0); return@exclusive ProtectedMutationStatus.DIRTY }
                deferred.use { plan ->
                    val expected = plan.expectedNormalized()
                    val intent = try { encodeIntent(dirty, expected) } finally { expected.fill(0) }
                    try {
                        try { replaceVerified(intentName(dirty.reservedSequence), null, intent) }
                        catch (_: Exception) { return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN }
                        try { plan.apply() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                        val actual = try { plan.reconstruct() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                        try {
                            val expectedAgain = plan.expectedNormalized()
                            try {
                                if (!java.security.MessageDigest.isEqual(expectedAgain, actual)) return@exclusive ProtectedMutationStatus.DIRTY
                            } finally { expectedAgain.fill(0) }
                            publishComplete(dirty, dirtyBytes, intent, actual)
                        } finally { actual.fill(0) }
                    } finally { dirtyBytes.fill(0); intent.fill(0) }
                }
            }
        } catch (_: Exception) {
            return ProtectedMutationStatus.MUTATION_UNPROVEN
        } finally { operation.fill(0); expectedOld?.fill(0) }
    }

    /** Explicit recovery retains the original operation and revision pair. Restoration never calls it. */
    fun recover(operationId: ByteArray, expectedNormalized: ByteArray,
        recovery: () -> Unit, reconstruct: () -> ByteArray,
        resolution: RecoveryResolution = RecoveryResolution.RESUME): ProtectedMutationStatus {
        val expected = expectedNormalized.clone()
        val operation = operationId.clone()
        try {
            require(expected.size <= JournalLimits.CHECKPOINT_BYTES)
            return storage.exclusive {
                val oldBytes = checkNotNull(storage.read(CONTROL, JournalLimits.RECORD_BYTES))
                try {
                    val old = JournalControl.decode(oldBytes)
                    if (!old.dirty) return@exclusive ProtectedMutationStatus.NO_MUTATION
                    check(operation.size == JournalLimits.OPERATION_BYTES && java.security.MessageDigest.isEqual(operation, old.operationId()))
                    val expectedIntent = encodeIntent(old, expected)
                    var intent = storage.read(intentName(old.reservedSequence), JournalLimits.RECORD_BYTES)
                    try {
                        if (intent == null) {
                            // No product mutation was admitted before this intent was durably published.
                            check(resolution == RecoveryResolution.RESUME)
                            replaceVerified(intentName(old.reservedSequence), null, expectedIntent)
                            intent = expectedIntent.clone()
                        }
                        val recordedIntent = checkNotNull(intent)
                        check(recordedIntent.size == expectedIntent.size &&
                            recordedIntent.copyOfRange(0, 109).contentEquals(expectedIntent.copyOfRange(0, 109)))
                        var resolutionBytes = storage.read(resolutionName(old.reservedSequence), JournalLimits.RECORD_BYTES)
                        try {
                            if (resolution == RecoveryResolution.RESUME) {
                                check(resolutionBytes == null && recordedIntent.contentEquals(expectedIntent))
                            } else {
                                val proposed = encodeResolution(resolution, recordedIntent, expected)
                                try {
                                    if (resolutionBytes == null) {
                                        // Never overwrite an uncertain candidate. Independent recognition is separate.
                                        val candidate = storage.read(checkpointName(old.reservedCleanRevision), JournalLimits.CHECKPOINT_BYTES)
                                        val terminal = storage.read(recordName(old.reservedSequence), JournalLimits.RECORD_BYTES)
                                        try { check(candidate == null && terminal == null) }
                                        finally { candidate?.fill(0); terminal?.fill(0) }
                                        replaceVerified(resolutionName(old.reservedSequence), null, proposed)
                                        resolutionBytes = proposed.clone()
                                    } else check(resolutionBytes.contentEquals(proposed))
                                } finally { proposed.fill(0) }
                            }
                            try { recovery() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                            val actual = try { reconstruct() } catch (_: Exception) { return@exclusive ProtectedMutationStatus.DIRTY }
                            try {
                                if (!java.security.MessageDigest.isEqual(expected, actual)) ProtectedMutationStatus.DIRTY
                                else publishComplete(old, oldBytes, recordedIntent, actual, resolutionBytes)
                            } finally { actual.fill(0) }
                        } finally { resolutionBytes?.fill(0) }
                    } finally { expectedIntent.fill(0); intent?.fill(0) }
                } finally { oldBytes.fill(0) }
            }
        } catch (_: Exception) { return ProtectedMutationStatus.MUTATION_UNPROVEN }
        finally { expected.fill(0); operation.fill(0) }
    }

    /** Explicit recovery can recognize an unacknowledged commit; it never guesses or reruns product writes. */
    fun recognizeCompletedOperation(reconstruct: () -> ByteArray): ProtectedMutationStatus = storage.exclusive {
        val controlBytes = requireNotNull(storage.read(CONTROL, JournalLimits.RECORD_BYTES))
        val control = try { JournalControl.decode(controlBytes) } catch (_: Exception) {
            controlBytes.fill(0)
            return@exclusive ProtectedMutationStatus.MUTATION_UNPROVEN
        }
        try {
            if (!control.dirty) {
                val actual = reconstruct()
                val recorded = readCheckpoint()
                try {
                    if (java.security.MessageDigest.isEqual(actual, recorded)) ProtectedMutationStatus.COMMITTED
                    else ProtectedMutationStatus.MUTATION_UNPROVEN
                } finally { actual.fill(0); recorded.fill(0) }
            } else {
                val intent = storage.read(intentName(control.reservedSequence), JournalLimits.RECORD_BYTES)
                    ?: return@exclusive ProtectedMutationStatus.DIRTY
                val actual = reconstruct()
                val resolution = storage.read(resolutionName(control.reservedSequence), JournalLimits.RECORD_BYTES)
                try {
                    val expectedIntent = encodeIntent(control, actual)
                    try {
                        val matches = if (resolution == null) java.security.MessageDigest.isEqual(intent, expectedIntent)
                            else intent.size == expectedIntent.size && intent.copyOfRange(0, 109).contentEquals(expectedIntent.copyOfRange(0, 109)) &&
                                JournalDigest.checkpoint(actual).matches(resolutionCheckpoint(resolution, intent))
                        if (!matches) ProtectedMutationStatus.DIRTY
                        else publishComplete(control, controlBytes, intent, actual, resolution)
                    } finally { expectedIntent.fill(0) }
                } finally { intent.fill(0); actual.fill(0); resolution?.fill(0) }
            }
        } catch (_: Exception) { ProtectedMutationStatus.MUTATION_UNPROVEN }
        finally { controlBytes.fill(0) }
    }

    private fun publishComplete(
        dirty: JournalControl, dirtyBytes: ByteArray, intent: ByteArray, actual: ByteArray,
        resolution: ByteArray? = null,
    ): ProtectedMutationStatus {
        try {
            val projection = projectionDigestFor(actual)
            val name = checkpointName(dirty.reservedCleanRevision)
            val prior = storage.read(name, JournalLimits.CHECKPOINT_BYTES)
            try {
                if (prior != null && !prior.contentEquals(actual)) return ProtectedMutationStatus.MUTATION_UNPROVEN
                if (prior == null) replaceVerified(name, null, actual)
            } finally { prior?.fill(0) }
            val terminal = ByteBuffer.allocate(4 + intent.size + (resolution?.size ?: 0) + 64).order(ByteOrder.BIG_ENDIAN)
                .putInt(if (resolution == null) 0x4b4a5433 else 0x4b4a5434).put(intent).apply {
                    if (resolution != null) put(resolution)
                }.put(JournalDigest.checkpoint(actual).bytes()).put(projection?.bytes() ?: ByteArray(32)).array()
            try {
                val existing = storage.read(recordName(dirty.reservedSequence), JournalLimits.RECORD_BYTES)
                try {
                    if (existing != null && !existing.contentEquals(terminal)) return ProtectedMutationStatus.MUTATION_UNPROVEN
                    if (existing == null) replaceVerified(recordName(dirty.reservedSequence), null, terminal)
                } finally { existing?.fill(0) }
                val completed = dirty.complete(JournalDigest.checkpoint(actual), JournalDigest.record(terminal),
                    intent.size + terminal.size + (resolution?.size ?: 0), if (resolution == null) 2 else 3, projection)
                val completedBytes = completed.encode()
                try { replaceVerified(CONTROL, dirtyBytes, completedBytes) }
                finally { completedBytes.fill(0) }
                return ProtectedMutationStatus.COMMITTED
            } finally { terminal.fill(0) }
        } catch (_: Exception) { return ProtectedMutationStatus.MUTATION_UNPROVEN }
    }

    private fun replaceVerified(name: String, expected: ByteArray?, replacement: ByteArray) {
        storage.compareAndReplace(name, expected, replacement)
        val observed = requireNotNull(storage.read(name, maxOf(JournalLimits.RECORD_BYTES, replacement.size)))
        try { check(java.security.MessageDigest.isEqual(replacement, observed)) }
        finally { observed.fill(0) }
    }

    private fun encodeIntent(dirty: JournalControl, normalized: ByteArray): ByteArray {
        check(dirty.dirty)
        return ByteBuffer.allocate(4 + 16 + JournalLimits.OPERATION_BYTES + 8 * 3 + 1 + 32 * 2).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(0x4b4a4931); put(dirty.storeId()); put(dirty.operationId())
            putLong(dirty.revision); putLong(dirty.reservedCleanRevision); putLong(dirty.reservedSequence)
            put(requireNotNull(dirty.kind).wire.toByte())
            put(dirty.tailDigest()); put(JournalDigest.checkpoint(normalized).bytes())
        }.array()
    }

    private fun encodeResolution(kind: RecoveryResolution, intent: ByteArray, normalized: ByteArray): ByteArray {
        require(kind != RecoveryResolution.RESUME)
        return ByteBuffer.allocate(69).order(ByteOrder.BIG_ENDIAN).putInt(0x4b4a5231).put(kind.wire.toByte())
            .put(JournalDigest.record(intent).bytes()).put(JournalDigest.checkpoint(normalized).bytes()).array()
    }

    private fun resolutionCheckpoint(resolution: ByteArray, intent: ByteArray): ByteArray {
        require(resolution.size == 69)
        val reader = ByteBuffer.wrap(resolution).order(ByteOrder.BIG_ENDIAN)
        require(reader.int == 0x4b4a5231 && reader.get().toInt() in 1..2)
        check(JournalDigest.record(intent).matches(ByteArray(32).also(reader::get)))
        return ByteArray(32).also(reader::get)
    }

    companion object {
        private const val CONTROL = "journal-control"
        private fun recordName(sequence: Long) = "journal-record-" + sequence.toString(16).padStart(16, '0')
        private fun intentName(sequence: Long) = "journal-intent-" + sequence.toString(16).padStart(16, '0')
        private fun resolutionName(sequence: Long) = "journal-resolution-" + sequence.toString(16).padStart(16, '0')
        private fun checkpointName(revision: Long) = "journal-checkpoint-" + revision.toString(16).padStart(16, '0')
        private fun projectionName(revision: Long) = "journal-projection-" + revision.toString(16).padStart(16, '0')
    }
}

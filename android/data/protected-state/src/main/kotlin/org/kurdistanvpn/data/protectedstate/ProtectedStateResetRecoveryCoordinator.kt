// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Collections
import org.kurdistanvpn.core.nativeapi.DurableBounds
import org.kurdistanvpn.core.nativeapi.DurableCode
import org.kurdistanvpn.core.nativeapi.DurableDirectory
import org.kurdistanvpn.core.nativeapi.DurableDirectoryEntry
import org.kurdistanvpn.core.nativeapi.DurableFileIdentity
import org.kurdistanvpn.core.nativeapi.DurableSnapshot
import org.kurdistanvpn.core.nativeapi.DurableWriter

/** All current journal, object and projection leaves share one actual directory and lock. */
internal enum class ResetDirectoryRole(val wire: Int) { JOURNAL(1) }

/** Supplied, already quiesced directories only. No path, discovery, creation or key-generation API. */
internal data class ResetDirectoryBinding(
    val role: ResetDirectoryRole, val directory: DurableDirectory,
    val lockLeaf: String, val lockIdentity: DurableFileIdentity,
) {
    init {
        require(DurableBounds.leaf(lockLeaf) != null)
        require(lockIdentity.device == directory.identity.device && lockIdentity != directory.identity)
    }
}

/** The composition root retains every writer lease across each JournalStorage.exclusive block. */
internal class DurableResetFileAccess(
    directories: List<ResetDirectoryBinding>,
    private val ownedWriter: (ResetDirectoryRole) -> DurableWriter,
) {
    private val bindings = directories.toTypedArray().sortedBy { it.role.wire }
    init {
        require(bindings.size == 1) { "COMPLETE_RESET_REQUIRES_ONE_ACTUAL_ROOT" }
        require(bindings.count { it.role == ResetDirectoryRole.JOURNAL } == 1)
        require(bindings.map { it.role }.toSet().size == bindings.size)
        require(bindings.map { it.directory.identity }.toSet().size == bindings.size)
        require(bindings.map { it.directory.expectedUid }.toSet().size == 1)
    }
    fun bindings(): List<ResetDirectoryBinding> = Collections.unmodifiableList(ArrayList(bindings))
    fun inventory(): List<Pair<ResetDirectoryRole, DurableDirectoryEntry>> {
        val result = ArrayList<Pair<ResetDirectoryRole, DurableDirectoryEntry>>()
        var total = 0L
        for (binding in bindings) {
            val listed = ownedWriter(binding.role).list(JournalLimits.OBJECTS)
            check(listed.code == DurableCode.OK) { "RESET_INVENTORY_UNPROVEN" }
            val entries = checkNotNull(listed.entries).toTypedArray()
            check(entries.map { it.leaf }.toSet().size == entries.size)
            for (entry in entries) {
                check(entry.length <= JournalLimits.OBJECT_BYTES)
                total = Math.addExact(total, entry.length)
                check(total <= JournalLimits.RETAINED_OBJECT_BYTES)
                result += binding.role to entry
                check(result.size <= JournalLimits.OBJECTS)
            }
        }
        return result.sortedWith(compareBy<Pair<ResetDirectoryRole, DurableDirectoryEntry>> { it.first.wire }.thenBy { it.second.leaf })
    }
    fun read(role: ResetDirectoryRole, leaf: String): DurableSnapshot? {
        require(bindings.any { it.role == role } && DurableBounds.leaf(leaf) != null)
        val observed = ownedWriter(role).read(leaf, JournalLimits.OBJECT_BYTES)
        return when (observed.code) {
            DurableCode.ABSENT -> null
            DurableCode.OK -> checkNotNull(observed.snapshot)
            else -> error("RESET_READ_UNPROVEN")
        }
    }
    fun delete(role: ResetDirectoryRole, leaf: String, expected: DurableSnapshot) {
        require(bindings.any { it.role == role } && DurableBounds.leaf(leaf) != null)
        check(bindings.none { it.role == role && it.lockLeaf == leaf }) { "RESET_CANNOT_DELETE_OWNED_LOCK" }
        check(ownedWriter(role).delete(leaf, expected, JournalLimits.OBJECT_BYTES).code == DurableCode.OK) { "RESET_DELETE_UNPROVEN" }
        check(read(role, leaf) == null) { "RESET_TARGET_STILL_PRESENT" }
    }
    fun onlyKnownLocksRemain(): Boolean {
        val inventory = inventory()
        if (inventory.size != bindings.size) return false
        return bindings.all { binding ->
            val entry = inventory.singleOrNull { it.first == binding.role && it.second.leaf == binding.lockLeaf }?.second
                ?: return@all false
            if (entry.identity != binding.lockIdentity || entry.length != 0L) return@all false
            val actual = read(binding.role, binding.lockLeaf) ?: return@all false
            actual.identity == binding.lockIdentity && actual.size == 0
        }
    }
}

internal sealed interface ResetKeyObservation {
    data class Present(val generation: Int) : ResetKeyObservation { init { require(generation > 0) } }
    data object Absent : ResetKeyObservation
    data object Unavailable : ResetKeyObservation
}

/** Existing-key-only capability. eraseExisting returning is not proof: fresh absence is required. */
internal interface ExistingResetKeyAccess {
    fun observe(): ResetKeyObservation
    fun eraseExisting(expectedGeneration: Int)
}

/** NO_RESET_PENDING conveys no permission to initialize and proves no historical reset completion. */
internal enum class ResetRecoveryResult { COMPLETED, NO_RESET_PENDING, RECOVERY_REQUIRED, DIRTY, MUTATION_UNPROVEN, QUARANTINED }

/**
 * Explicit complete reset only. The broker/root owns this object, storage and all supplied leases.
 * It uses the existing operation journal and reservation, not a parallel security-state journal.
 * Same-UID cooperative serialization is not a security boundary against compromised same-UID code.
 */
internal class ProtectedStateResetRecoveryCoordinator(
    private val storage: JournalStorage,
    private val files: DurableResetFileAccess,
    private val key: ExistingResetKeyAccess,
    private val sessions: ActiveSessionMutationPolicy,
    private val monotonicNanos: () -> Long = System::nanoTime,
) {
    private val journal = ProtectedStateOperationJournal(storage)
    private val monitor = Any()

    fun start(operationId: ByteArray): ResetRecoveryResult = synchronized(monitor) {
        val reservation = sessions.reserveMutation() ?: return@synchronized ResetRecoveryResult.RECOVERY_REQUIRED
        val operation = operationId.clone()
        try {
            require(operation.size == JournalLimits.OPERATION_BYTES && operation.any { it != 0.toByte() })
            val budget = Budget(monotonicNanos)
            when (val observedKey = key.observe()) {
                ResetKeyObservation.Absent -> return@synchronized absenceResult()
                ResetKeyObservation.Unavailable -> return@synchronized ResetRecoveryResult.MUTATION_UNPROVEN
                is ResetKeyObservation.Present -> {
                    val plan = storage.exclusive {
                        budget.check()
                        val pending = storage.read(MANIFEST, MAX_MANIFEST)
                        try { if (pending != null) return@exclusive null } finally { pending?.fill(0) }
                        val old = journal.readControl()
                        check(!old.dirty && old.revision > 0)
                        journal.readCheckpoint().fill(0)
                        // Capacity/exhaustion is checked before the authenticated manifest can become controlling.
                        old.reserve(operation, MutationKind.COMPLETE_RESET)
                        capture(old, operation, observedKey.generation, budget)
                    } ?: return@synchronized ResetRecoveryResult.RECOVERY_REQUIRED
                    run(plan, budget, reservation)
                }
            }
        } catch (_: Exception) { failureResult() }
        finally { operation.fill(0); reservation.close() }
    }

    /** Only an explicitly requested recovery path calls this. It never creates state or keys. */
    fun resume(): ResetRecoveryResult = synchronized(monitor) {
        val reservation = sessions.reserveMutation() ?: return@synchronized ResetRecoveryResult.RECOVERY_REQUIRED
        try {
            val budget = Budget(monotonicNanos)
            when (key.observe()) {
                ResetKeyObservation.Absent -> return@synchronized absenceResult()
                ResetKeyObservation.Unavailable -> return@synchronized ResetRecoveryResult.MUTATION_UNPROVEN
                is ResetKeyObservation.Present -> Unit
            }
            val plan = try { storage.exclusive {
                val encoded = storage.read(MANIFEST, MAX_MANIFEST) ?: return@exclusive null
                try { Plan.decode(encoded).also { it.requireDirectories(files.bindings()); requireKey(it) } }
                finally { encoded.fill(0) }
            } } catch (_: Exception) { return@synchronized ResetRecoveryResult.QUARANTINED }
                ?: return@synchronized ResetRecoveryResult.NO_RESET_PENDING
            run(plan, budget, reservation)
        } catch (_: Exception) { failureResult() }
        finally { reservation.close() }
    }

    private fun run(plan: Plan, budget: Budget, reservation: ActiveSessionMutationPolicy.MutationReservation): ResetRecoveryResult {
        val old = plan.oldControl()
        val operation = plan.operationId()
        val expected = plan.readyRecord()
        try {
            val current = journal.readControl()
            val status = when {
                sameControl(current, old) -> journal.mutate(MutationKind.COMPLETE_RESET, operation, expected,
                    mutation = { reservation.retirePriorOwners(); reservation.requireCurrent(); deleteTargets(plan, budget) },
                    reconstruct = { reservation.requireCurrent(); reconstructReady(plan, budget) },
                    expectedOldControl = old.encode(), prepareReset = {
                        budget.check(); requireKey(plan); plan.requireDirectories(files.bindings())
                        verifyOriginalInventory(plan, budget)
                        persistManifest(plan)
                    })
                sameDirty(current, plan) -> journal.recover(operation, expected,
                    recovery = { requireManifest(plan); reservation.retirePriorOwners(); reservation.requireCurrent(); deleteTargets(plan, budget) },
                    reconstruct = { reservation.requireCurrent(); reconstructReady(plan, budget) })
                !current.dirty && current.revision == plan.cleanRevision && current.sequence == plan.sequence &&
                    current.storeId().contentEquals(old.storeId()) -> {
                        reservation.retirePriorOwners(); reservation.requireCurrent()
                        ProtectedMutationStatus.COMMITTED
                    }
                else -> return ResetRecoveryResult.QUARANTINED
            }
            if (status != ProtectedMutationStatus.COMMITTED && sessions.failures().isNotEmpty())
                return ResetRecoveryResult.MUTATION_UNPROVEN
            if (status != ProtectedMutationStatus.COMMITTED) return if (status == ProtectedMutationStatus.DIRTY)
                ResetRecoveryResult.DIRTY else ResetRecoveryResult.MUTATION_UNPROVEN
            reservation.requireCurrent()
            return eraseAndFinish(plan, budget, reservation)
        } finally { operation.fill(0); expected.fill(0) }
    }

    private fun capture(old: JournalControl, operation: ByteArray, generation: Int, budget: Budget): Plan {
        val bindings = files.bindings()
        val entries = files.inventory().map { (role, entry) ->
            budget.check()
            val actual = checkNotNull(files.read(role, entry.leaf))
            check(actual.identity == entry.identity && actual.size.toLong() == entry.length)
            val binding = bindings.single { it.role == role }
            val kind = when {
                entry.leaf == binding.lockLeaf -> EntryKind.PRESERVE
                role == ResetDirectoryRole.JOURNAL && isRecoveryLeaf(entry.leaf) -> EntryKind.RECOVERY
                isProductLeaf(entry.leaf) -> EntryKind.DELETE
                else -> error("UNKNOWN_RESET_OBJECT_MUST_BE_PRESERVED")
            }
            if (kind == EntryKind.PRESERVE) check(actual.identity == binding.lockIdentity && actual.size == 0)
            Entry.capture(role, kind, entry.leaf, actual)
        }
        check(bindings.all { binding -> entries.any { it.role == binding.role && it.kind == EntryKind.PRESERVE } })
        return Plan.create(old, operation, generation, bindings, entries)
    }

    private fun verifyOriginalInventory(plan: Plan, budget: Budget) {
        val observed = files.inventory().map { it.first to it.second.leaf }.toSet()
        val expected = plan.entries.map { it.role to it.leaf }.toMutableSet()
        val pending = storage.read(MANIFEST, MAX_MANIFEST)
        try {
            if (pending != null) {
                val encoded = plan.encode()
                try { check(MessageDigest.isEqual(pending, encoded)) } finally { encoded.fill(0) }
                expected += ResetDirectoryRole.JOURNAL to "$MANIFEST.blob"
            }
        } finally { pending?.fill(0) }
        check(observed == expected) { "RESET_INVENTORY_CHANGED_BEFORE_RESERVATION" }
        for (entry in plan.entries) {
            budget.check()
            val actual = checkNotNull(files.read(entry.role, entry.leaf))
            check(entry.matches(actual)) { "RESET_TARGET_SUBSTITUTED" }
        }
    }

    private fun persistManifest(plan: Plan) {
        val encoded = plan.encode()
        val old = storage.read(MANIFEST, MAX_MANIFEST)
        try {
            if (old == null) storage.compareAndReplace(MANIFEST, null, encoded)
            else check(MessageDigest.isEqual(old, encoded))
            requireManifest(plan)
        } finally { encoded.fill(0); old?.fill(0) }
    }

    private fun requireManifest(plan: Plan) {
        val encoded = plan.encode()
        val observed = checkNotNull(storage.read(MANIFEST, MAX_MANIFEST))
        try { check(MessageDigest.isEqual(encoded, observed)); Plan.decode(observed).requireDirectories(files.bindings()) }
        finally { encoded.fill(0); observed.fill(0) }
    }

    private fun deleteTargets(plan: Plan, budget: Budget) {
        requireManifest(plan); requireKey(plan)
        check(sameDirty(journal.readControl(), plan))
        verifyRemainingInventory(plan, requireAbsentTargets = false, budget)
        for (entry in plan.entries.filter { it.kind == EntryKind.DELETE }) {
            budget.check()
            val observed = files.read(entry.role, entry.leaf) ?: continue
            check(entry.matches(observed)) { "RESET_TARGET_SUBSTITUTED" }
            files.delete(entry.role, entry.leaf, observed)
        }
        verifyRemainingInventory(plan, requireAbsentTargets = true, budget)
        check(sameDirty(journal.readControl(), plan)); requireKey(plan)
    }

    /** Independent observations determine READY. No writer-authored boolean or receipt is consumed. */
    private fun reconstructReady(plan: Plan, budget: Budget): ByteArray {
        requireManifest(plan); requireKey(plan)
        check(sameDirty(journal.readControl(), plan))
        verifyRemainingInventory(plan, requireAbsentTargets = true, budget)
        val expected = plan.readyRecord()
        val previous = storage.read(READY, MAX_READY)
        try {
            if (previous == null) storage.compareAndReplace(READY, null, expected)
            else check(MessageDigest.isEqual(expected, previous))
            val actual = checkNotNull(storage.read(READY, MAX_READY))
            try { check(MessageDigest.isEqual(expected, actual)) } finally { actual.fill(0) }
            return expected.clone()
        } finally { previous?.fill(0); expected.fill(0) }
    }

    private fun verifyRemainingInventory(plan: Plan, requireAbsentTargets: Boolean, budget: Budget) {
        plan.requireDirectories(files.bindings())
        val observed = files.inventory()
        val expected = plan.entries.associateBy { it.role to it.leaf }
        val generated = plan.generatedRecoveryLeaves()
        for ((role, entry) in observed) {
            budget.check()
            val recorded = expected[role to entry.leaf]
            if (recorded == null) {
                check(role == ResetDirectoryRole.JOURNAL && entry.leaf in generated) { "UNMANIFESTED_RESET_RESIDUAL" }
                continue
            }
            check(!requireAbsentTargets || recorded.kind != EntryKind.DELETE) { "RESET_TARGET_STILL_PRESENT" }
            // The control record alone is intentionally replaced by the existing journal reservation.
            if (recorded.role == ResetDirectoryRole.JOURNAL && recorded.leaf == "journal-control.blob") continue
            val actual = checkNotNull(files.read(role, entry.leaf))
            check(recorded.matches(actual)) { "RESET_RESIDUAL_SUBSTITUTED" }
        }
        for (entry in plan.entries.filter { it.kind != EntryKind.DELETE }) {
            check(observed.any { it.first == entry.role && it.second.leaf == entry.leaf }) { "RESET_PRESERVED_RECORD_MISSING" }
        }
    }

    private fun eraseAndFinish(plan: Plan, budget: Budget, reservation: ActiveSessionMutationPolicy.MutationReservation): ResetRecoveryResult = storage.exclusive {
        reservation.requireCurrent()
        requireManifest(plan); requireKey(plan)
        budget.check()
        val checkpoint = journal.readCheckpointForReset(plan.oldControl().storeId(), plan.operationId(), plan.cleanRevision)
        val expected = plan.readyRecord()
        val ready = checkNotNull(storage.read(READY, MAX_READY))
        try { check(MessageDigest.isEqual(expected, checkpoint) && MessageDigest.isEqual(expected, ready)) }
        finally { checkpoint.fill(0); expected.fill(0); ready.fill(0) }
        verifyRemainingInventory(plan, requireAbsentTargets = true, budget)
        // Keep exact raw ciphertext/inodes owned across key deletion. Never decrypt after that point.
        val retained = ArrayList<RetainedRecord>()
        var retainedBytes = 0L
        for ((role, entry) in files.inventory()) {
            budget.check()
            val binding = files.bindings().single { it.role == role }
            if (entry.leaf == binding.lockLeaf) continue
            check(role == ResetDirectoryRole.JOURNAL &&
                (entry.leaf in plan.generatedRecoveryLeaves() || plan.entries.any { it.role == role && it.leaf == entry.leaf && it.kind == EntryKind.RECOVERY }))
            val actual = checkNotNull(files.read(role, entry.leaf))
            check(actual.identity == entry.identity && actual.size.toLong() == entry.length)
            retainedBytes = Math.addExact(retainedBytes, actual.size.toLong())
            check(retainedBytes <= JournalLimits.CONTROL_BYTES)
            retained += RetainedRecord(role, entry.leaf, actual)
        }
        requireKey(plan); budget.check(); reservation.requireCurrent()
        key.eraseExisting(plan.keyGeneration)
        check(key.observe() == ResetKeyObservation.Absent) { "RESET_KEY_ERASURE_UNPROVEN" }
        for (entry in retained) {
            budget.check()
            val current = checkNotNull(files.read(entry.role, entry.leaf))
            check(sameSnapshot(entry.snapshot, current)) { "POST_ERASE_RESIDUAL_SUBSTITUTED" }
            files.delete(entry.role, entry.leaf, current)
        }
        check(files.onlyKnownLocksRemain()) { "POST_ERASE_RESIDUAL_REQUIRES_EXPLICIT_CLEANUP" }
        check(key.observe() == ResetKeyObservation.Absent)
        ResetRecoveryResult.COMPLETED
    }

    private fun requireKey(plan: Plan) {
        val actual = key.observe()
        check(actual is ResetKeyObservation.Present && actual.generation == plan.keyGeneration) { "RESET_EXISTING_KEY_UNAVAILABLE" }
    }
    private fun absenceResult(): ResetRecoveryResult = storage.exclusive {
        // Listing after a restart cannot prove the prior process's fsync/close outcome.
        if (files.onlyKnownLocksRemain() && key.observe() == ResetKeyObservation.Absent) ResetRecoveryResult.NO_RESET_PENDING
        else ResetRecoveryResult.QUARANTINED
    }
    private fun failureResult(): ResetRecoveryResult = try {
        if (key.observe() == ResetKeyObservation.Absent) ResetRecoveryResult.QUARANTINED else ResetRecoveryResult.MUTATION_UNPROVEN
    } catch (_: Exception) { ResetRecoveryResult.MUTATION_UNPROVEN }
    private fun sameControl(left: JournalControl, right: JournalControl): Boolean {
        val a = left.encode(); val b = right.encode()
        return try { MessageDigest.isEqual(a, b) } finally { a.fill(0); b.fill(0) }
    }
    private fun sameDirty(control: JournalControl, plan: Plan): Boolean {
        val operation = plan.operationId()
        return try { sameControl(control, plan.oldControl().reserve(operation, MutationKind.COMPLETE_RESET)) }
        finally { operation.fill(0) }
    }

    private class Budget(private val clock: () -> Long) {
        private val start = clock()
        fun check() { val elapsed = clock() - start; check(elapsed in 0..JournalLimits.RESTORE_NANOS) { "BOUNDED_RESET_PAUSED" } }
    }
    private data class RetainedRecord(val role: ResetDirectoryRole, val leaf: String, val snapshot: DurableSnapshot)
    private enum class EntryKind(val wire: Int) { DELETE(1), PRESERVE(2), RECOVERY(3) }
    private class Entry private constructor(
        val role: ResetDirectoryRole, val kind: EntryKind, val leaf: String,
        val identity: DurableFileIdentity, val length: Int, private val content: ByteArray,
    ) {
        fun matches(snapshot: DurableSnapshot): Boolean {
            if (snapshot.identity != identity || snapshot.size != length) return false
            val digest = hash(role, leaf, snapshot)
            return try { MessageDigest.isEqual(digest, content) } finally { digest.fill(0) }
        }
        fun write(output: DataOutputStream) {
            output.writeByte(role.wire); output.writeByte(kind.wire); output.writeLeaf(leaf)
            output.writeLong(identity.device); output.writeLong(identity.inode); output.writeInt(length); output.write(content)
        }
        companion object {
            fun capture(role: ResetDirectoryRole, kind: EntryKind, leaf: String, observed: DurableSnapshot): Entry =
                Entry(role, kind, leaf, observed.identity, observed.size, hash(role, leaf, observed))
            fun read(input: ByteBuffer): Entry {
                val roleWire = input.get().toInt()
                val role = ResetDirectoryRole.entries.single { it.wire == roleWire }
                val kindWire = input.get().toInt()
                val kind = EntryKind.entries.single { it.wire == kindWire }
                val leaf = input.readLeaf()
                val identity = DurableFileIdentity(input.long, input.long)
                val length = input.int
                require(length in 0..JournalLimits.OBJECT_BYTES)
                val digest = ByteArray(32).also(input::get)
                return Entry(role, kind, leaf, identity, length, digest)
            }
            private fun hash(role: ResetDirectoryRole, leaf: String, observed: DurableSnapshot): ByteArray {
                val bytes = observed.bytes
                val name = leaf.toByteArray(Charsets.US_ASCII)
                return try { MessageDigest.getInstance("SHA-256").run {
                    update("kurdistan-complete-reset-file-v1\u0000".toByteArray(Charsets.US_ASCII))
                    update(role.wire.toByte()); update(ByteBuffer.allocate(2).putShort(name.size.toShort()).array()); update(name)
                    update(ByteBuffer.allocate(20).putLong(observed.identity.device).putLong(observed.identity.inode).putInt(bytes.size).array())
                    digest(bytes)
                } } finally { bytes.fill(0) }
            }
        }
    }

    private class Plan private constructor(
        private val old: ByteArray, private val operation: ByteArray, val keyGeneration: Int,
        private val directories: List<DirectoryRecord>, val entries: List<Entry>,
    ) {
        private val reserved = JournalControl.decode(old).reserve(operation, MutationKind.COMPLETE_RESET)
        val cleanRevision: Long get() = reserved.reservedCleanRevision
        val sequence: Long get() = reserved.reservedSequence
        fun oldControl(): JournalControl = JournalControl.decode(old)
        fun operationId(): ByteArray = operation.clone()
        fun requireDirectories(bindings: List<ResetDirectoryBinding>) {
            check(bindings.size == directories.size)
            for (directory in directories) check(bindings.any(directory::matches)) { "RESET_DIRECTORY_BINDING_CHANGED" }
        }
        fun generatedRecoveryLeaves(): Set<String> = setOf("$MANIFEST.blob", "$READY.blob",
            "journal-intent-${sequence.toString(16).padStart(16, '0')}.blob",
            "journal-record-${sequence.toString(16).padStart(16, '0')}.blob",
            "journal-checkpoint-${cleanRevision.toString(16).padStart(16, '0')}.blob")
        fun encode(): ByteArray {
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { output ->
                output.writeInt(MAGIC); output.writeByte(1); output.writeShort(old.size); output.write(old)
                output.write(operation); output.writeInt(keyGeneration); output.writeByte(directories.size)
                for (directory in directories) directory.write(output)
                output.writeShort(entries.size)
                for (entry in entries) entry.write(output)
            }
            return bytes.toByteArray().also { require(it.size in 1..MAX_MANIFEST) }
        }
        fun readyRecord(): ByteArray {
            val encoded = encode()
            val digest = try { MessageDigest.getInstance("SHA-256").run {
                update("kurdistan-complete-reset-manifest-v1\u0000".toByteArray(Charsets.US_ASCII))
                update(ByteBuffer.allocate(4).putInt(encoded.size).array()); digest(encoded)
            } } finally { encoded.fill(0) }
            return try { ByteBuffer.allocate(MAX_READY).putInt(0x4b525231).put(oldControl().storeId()).put(operation)
                .putLong(cleanRevision).putInt(keyGeneration).put(digest).array() }
            finally { digest.fill(0) }
        }
        companion object {
            fun create(old: JournalControl, operation: ByteArray, generation: Int,
                bindings: List<ResetDirectoryBinding>, entries: List<Entry>): Plan {
                val result = Plan(old.encode(), operation.clone(), generation, bindings.map(DirectoryRecord::capture), entries.toTypedArray().toList())
                val encoded = result.encode()
                return try { decode(encoded) } finally { encoded.fill(0) }
            }
            fun decode(input: ByteArray): Plan {
                val owned = input.clone()
                try {
                    require(owned.size in 1..MAX_MANIFEST)
                    val reader = ByteBuffer.wrap(owned)
                    require(reader.int == MAGIC && reader.get().toInt() == 1)
                    val oldLength = reader.short.toInt() and 65535
                    require(oldLength in 1..JournalLimits.RECORD_BYTES && reader.remaining() >= oldLength + 37)
                    val old = ByteArray(oldLength).also(reader::get)
                    val control = JournalControl.decode(old)
                    require(!control.dirty && control.revision > 0)
                    val operation = ByteArray(32).also(reader::get)
                    val generation = reader.int; require(generation > 0)
                    val directoryCount = reader.get().toInt(); require(directoryCount == ResetDirectoryRole.entries.size)
                    val directories = List(directoryCount) { DirectoryRecord.read(reader) }
                    require(directories.map { it.role.wire } == directories.map { it.role.wire }.distinct().sorted())
                    require(directories.count { it.role == ResetDirectoryRole.JOURNAL } == 1)
                    require(directories.map { it.directory }.toSet().size == directories.size)
                    require(directories.map { it.uid }.toSet().size == 1)
                    val count = reader.short.toInt() and 65535; require(count in directoryCount..JournalLimits.OBJECTS)
                    val entries = List(count) { Entry.read(reader) }
                    require(!reader.hasRemaining())
                    require(entries.map { it.role.wire to it.leaf }.toSet().size == entries.size)
                    require(entries.map { it.identity }.toSet().size == entries.size)
                    require(entries == entries.sortedWith(compareBy<Entry> { it.role.wire }.thenBy { it.leaf }))
                    for (entry in entries) {
                        val directory = directories.single { it.role == entry.role }
                        require(entry.identity.device == directory.directory.device)
                        when (entry.kind) {
                            EntryKind.PRESERVE -> require(entry.leaf == directory.lockLeaf && entry.identity == directory.lock && entry.length == 0)
                            EntryKind.RECOVERY -> require(entry.role == ResetDirectoryRole.JOURNAL && isRecoveryLeaf(entry.leaf))
                            EntryKind.DELETE -> require(entry.leaf != directory.lockLeaf && isProductLeaf(entry.leaf))
                        }
                    }
                    require(directories.all { d -> entries.count { it.role == d.role && it.kind == EntryKind.PRESERVE } == 1 })
                    require(entries.none { it.role == ResetDirectoryRole.JOURNAL && (it.leaf == "$MANIFEST.blob" || it.leaf == "$READY.blob") })
                    val plan = Plan(old, operation, generation, directories, entries)
                    val canonical = plan.encode()
                    try { require(MessageDigest.isEqual(owned, canonical)) } finally { canonical.fill(0) }
                    return plan
                } finally { owned.fill(0) }
            }
        }
    }

    private data class DirectoryRecord(val role: ResetDirectoryRole, val directory: DurableFileIdentity,
        val uid: Long, val lockLeaf: String, val lock: DurableFileIdentity) {
        fun matches(binding: ResetDirectoryBinding): Boolean = role == binding.role && directory == binding.directory.identity &&
            uid == binding.directory.expectedUid && lockLeaf == binding.lockLeaf && lock == binding.lockIdentity
        fun write(output: DataOutputStream) {
            output.writeByte(role.wire); output.writeLong(directory.device); output.writeLong(directory.inode); output.writeLong(uid)
            output.writeLeaf(lockLeaf); output.writeLong(lock.device); output.writeLong(lock.inode)
        }
        companion object {
            fun capture(binding: ResetDirectoryBinding): DirectoryRecord = DirectoryRecord(binding.role, binding.directory.identity,
                binding.directory.expectedUid, binding.lockLeaf, binding.lockIdentity)
            fun read(input: ByteBuffer): DirectoryRecord {
                val roleWire = input.get().toInt()
                val role = ResetDirectoryRole.entries.single { it.wire == roleWire }
                val directory = DurableFileIdentity(input.long, input.long)
                val uid = input.long; require(DurableBounds.validUid(uid))
                val leaf = input.readLeaf()
                val lock = DurableFileIdentity(input.long, input.long)
                require(lock.device == directory.device && lock != directory)
                return DirectoryRecord(role, directory, uid, leaf, lock)
            }
        }
    }

    companion object {
        private const val MANIFEST = "journal-reset"
        private const val READY = "journal-reset-ready"
        private const val MAGIC = 0x4b525331
        private const val MAX_MANIFEST = JournalLimits.CHECKPOINT_BYTES
        private const val MAX_READY = 96
        private fun isProductLeaf(leaf: String): Boolean =
            leaf in setOf("protected-metadata.db", "protected-metadata.db-wal", "protected-metadata.db-shm",
                "protected-metadata.db-journal", "protected-settings.preferences_pb", "migration-legacy-metadata.db") ||
                (leaf.startsWith("object-") && leaf.length == 63 &&
                    leaf.drop(7).all { it in '0'..'9' || it in 'a'..'f' })
        private fun isRecoveryLeaf(leaf: String): Boolean {
            if (leaf in setOf("journal-control.blob", "journal-store.blob", "journal-gc.blob",
                    "${ProtectedPresentationOverlay.NAME}.blob")) return true
            val prefix = listOf("journal-record-", "journal-intent-", "journal-resolution-", "journal-checkpoint-", "journal-projection-").firstOrNull(leaf::startsWith)
                ?: return false
            val suffix = leaf.removePrefix(prefix).removeSuffix(".blob")
            return leaf.endsWith(".blob") && suffix.length == 16 && suffix.all { it in '0'..'9' || it in 'a'..'f' }
        }
        private fun sameSnapshot(left: DurableSnapshot, right: DurableSnapshot): Boolean {
            if (left.identity != right.identity || left.size != right.size) return false
            val a = left.bytes; val b = right.bytes
            return try { MessageDigest.isEqual(a, b) } finally { a.fill(0); b.fill(0) }
        }
        private fun DataOutputStream.writeLeaf(value: String) {
            val bytes = checkNotNull(DurableBounds.leaf(value)); writeShort(bytes.size); write(bytes)
        }
        private fun ByteBuffer.readLeaf(): String {
            val size = short.toInt() and 65535
            require(size in 1..DurableBounds.MAX_LEAF_BYTES && remaining() >= size)
            val bytes = ByteArray(size).also(::get)
            require(bytes.all { it.toInt() in 1..127 })
            return String(bytes, Charsets.US_ASCII).also { require(DurableBounds.leaf(it) != null) }
        }
    }
}

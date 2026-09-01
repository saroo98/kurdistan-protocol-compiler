// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate
import org.junit.Assert.*
import org.junit.Test

class ProtectedStateJournalLifecycleTest {
    @Test fun identicalStateAfterABAStillHasANewerDurableRevisionAndRejectsTheOriginalCas() {
        val storage = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        var source = byteArrayOf(7)
        fun apply(value: Byte, operation: Byte) = journal.mutate(MutationKind.ROUTING,
            ByteArray(32) { operation }, byteArrayOf(value), { source = byteArrayOf(value) }, { source.clone() })
        assertEquals(ProtectedMutationStatus.COMMITTED, apply(7, 2))
        val original = journal.readControl().encode()
        val originalCheckpoint = journal.readCheckpoint()
        assertEquals(ProtectedMutationStatus.COMMITTED, apply(8, 3))
        assertEquals(4L, ProtectedStateOperationJournal(storage).readControl().revision)
        assertEquals(ProtectedMutationStatus.COMMITTED, apply(7, 4))
        val restarted = ProtectedStateOperationJournal(storage)
        assertEquals(6L, restarted.readControl().revision)
        assertArrayEquals(originalCheckpoint, restarted.readCheckpoint())
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, restarted.mutate(MutationKind.ROUTING,
            ByteArray(32) { 5 }, byteArrayOf(9), { writes++ }, { byteArrayOf(9) }, expectedOldControl = original))
        assertEquals(0, writes)
        assertEquals(6L, restarted.readControl().revision)
        assertArrayEquals(byteArrayOf(7), source)
    }

    @Test fun lifecycleCapacityChecksEveryInventoryBoundaryBeforeAdmission() {
        val clean = JournalControl.initial(ByteArray(16) { 1 })
        fun admission(entries: List<JournalStoredEntry>, extra: Long = 0) =
            ProtectedStateJournalLifecycle.admission(clean, entries, extra)
        assertEquals(JournalAdmission.ADMIT, admission(emptyList()))
        assertEquals(JournalAdmission.ADMIT, admission(emptyList(), 268435456))
        for (extra in listOf(-1L, 268435457L, Long.MAX_VALUE))
            assertEquals(JournalAdmission.REJECT_CAPACITY, admission(emptyList(), extra))
        for (length in listOf(-1L, JournalLimits.OBJECT_BYTES.toLong() + 1, Long.MAX_VALUE))
            assertEquals(JournalAdmission.REJECT_CAPACITY, admission(listOf(JournalStoredEntry("object-a", length))))
        assertEquals(JournalAdmission.ADMIT, admission(List(4096) { JournalStoredEntry("object-$it", 0) }))
        assertEquals(JournalAdmission.REJECT_CAPACITY, admission(List(4097) { JournalStoredEntry("object-$it", 0) }))
        assertEquals(JournalAdmission.REJECT_CAPACITY, admission(listOf(JournalStoredEntry("object-a", 1), JournalStoredEntry("object-a", 1))))
        val retainedAtMaximum = List(64) { JournalStoredEntry("object-$it", 8388608) }
        assertEquals(JournalAdmission.ADMIT, admission(retainedAtMaximum))
        assertEquals(JournalAdmission.REJECT_CAPACITY, admission(retainedAtMaximum, 1))
        val controlAtReserve = List(63) { JournalStoredEntry("journal-$it", 1048576) }
        assertEquals(JournalAdmission.ADMIT, admission(controlAtReserve))
        assertEquals(JournalAdmission.REJECT_CAPACITY, admission(controlAtReserve + JournalStoredEntry("journal-extra", 1)))
        val dirty = clean.reserve(ByteArray(32) { 2 }, MutationKind.ROUTING)
        assertEquals(JournalAdmission.RECOVERY_REQUIRED, ProtectedStateJournalLifecycle.admission(dirty, emptyList(), 0))
    }

    @Test fun storageExhaustionBeforeDirtyPreservesThePriorCheckpointWithoutDeletingForSpace() {
        val disk = MemoryJournalStorage()
        val initial = ProtectedStateOperationJournal(disk)
        initial.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.COMMITTED, initial.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) }))
        val before = checkNotNull(disk.read("journal-control", JournalLimits.RECORD_BYTES))
        var mutations = 0
        var deletions = 0
        val exhausted = object : JournalStorage by disk {
            override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
                if (name == "journal-control" && JournalControl.decode(replacement).dirty)
                    throw java.io.IOException("synthetic storage exhausted before DIRTY")
                disk.compareAndReplace(name, expected, replacement)
            }
            override fun delete(name: String, expected: ByteArray) { deletions++; error("unapproved space reclamation") }
        }
        val journal = ProtectedStateOperationJournal(exhausted)
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), { mutations++ }, { byteArrayOf(8) }))
        assertEquals(0, mutations); assertEquals(0, deletions)
        assertArrayEquals(before, disk.read("journal-control", JournalLimits.RECORD_BYTES))
        assertArrayEquals(byteArrayOf(7), journal.readCheckpoint())
    }

    @Test fun storageExhaustionAfterDirtyRetainsItsReservationAndNeverAuthorizesAnotherMutation() {
        for (failingPrefix in listOf("journal-intent-", "journal-checkpoint-")) {
            val disk = MemoryJournalStorage()
            val initial = ProtectedStateOperationJournal(disk)
            initial.initialize(ByteArray(16) { 1 })
            assertEquals(ProtectedMutationStatus.COMMITTED, initial.mutate(MutationKind.ROUTING,
                ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) }))
            var mutations = 0
            var deletions = 0
            val exhausted = object : JournalStorage by disk {
                override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
                    if (name.startsWith(failingPrefix)) throw java.io.IOException("synthetic storage exhausted after DIRTY")
                    disk.compareAndReplace(name, expected, replacement)
                }
                override fun delete(name: String, expected: ByteArray) { deletions++; error("unapproved space reclamation") }
            }
            val journal = ProtectedStateOperationJournal(exhausted)
            assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
                ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), { mutations++ }, { byteArrayOf(8) }))
            assertEquals(if (failingPrefix == "journal-intent-") 0 else 1, mutations)
            assertEquals(3L, journal.readControl().revision)
            assertEquals(4L, journal.readControl().reservedCleanRevision)
            assertArrayEquals(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, journal.readControl().operationId())
            assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
            assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.PROFILE_DELETE,
                ByteArray(JournalLimits.OPERATION_BYTES) { 4 }, byteArrayOf(9), { fail("new mutation while DIRTY") }, { byteArrayOf(9) }))
            assertEquals(3L, journal.readControl().revision)
            assertEquals(0, deletions)
            assertArrayEquals(byteArrayOf(7), journal.readPriorCheckpointForExplicitRecovery())
        }
    }

    @Test fun aCoherentlyRestoredOldStoreCannotBeDistinguishedByItsLocalJournalAlone() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) }))
        val oldCompleteStore = disk.inventory(JournalLimits.OBJECTS).associate { entry ->
            entry.name to checkNotNull(disk.read(entry.name, JournalLimits.OBJECT_BYTES))
        }
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), {}, { byteArrayOf(8) }))
        assertEquals(4L, journal.readControl().revision)
        val rolledBack = MemoryJournalStorage()
        oldCompleteStore.forEach { (name, bytes) -> rolledBack.compareAndReplace(name, null, bytes) }
        val restarted = ProtectedStateOperationJournal(rolledBack)
        // This explicitly records a limitation, not a desired security guarantee. A fresh
        // process has no trusted external high-water counter and must never claim anti-rollback.
        assertEquals(2L, restarted.readControl().revision)
        assertArrayEquals(byteArrayOf(7), restarted.readCheckpoint())
        assertArrayEquals(byteArrayOf(8), journal.readCheckpoint())
    }

    @Test fun unrecognizedJournalRecordCannotHideEvidenceBeyondTheKnownHead() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) })
        disk.compareAndReplace("journal-unrecognized", null, byteArrayOf(1))
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }

    @Test fun unacknowledgedCompactionRequiresExactRereadAndDoesNotAdvanceSecurityRevision() {
        val disk = MemoryJournalStorage()
        var interrupt = false
        val storage = object : JournalStorage by disk {
            override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
                if (interrupt && name == "journal-control") { interrupt = false; error("lost compaction publication") }
                disk.compareAndReplace(name, expected, replacement)
            }
        }
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) })
        interrupt = true
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.compact { byteArrayOf(7) })
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.resolveUnacknowledgedCompaction { byteArrayOf(8) })
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.resolveUnacknowledgedCompaction { byteArrayOf(7) })
        assertEquals(2L, journal.readControl().revision)
        assertEquals(2L, journal.readControl().baseSequence)
        assertArrayEquals(byteArrayOf(7), journal.readCheckpoint())
    }

    @Test fun missingHistoricalRecordDoesNotAllowValidPrefixRestoration() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        repeat(2) { i ->
            assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
                ByteArray(JournalLimits.OPERATION_BYTES) { (i + 2).toByte() }, byteArrayOf((i + 1).toByte()), {}, { byteArrayOf((i + 1).toByte()) }))
        }
        val old = requireNotNull(disk.read("journal-record-0000000000000001", JournalLimits.RECORD_BYTES))
        disk.delete("journal-record-0000000000000001", old)
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }
    @Test fun recoveryRecognizesOnlyExactDurableIntentWithoutReusingItsRevision() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), { error("after mutation crash") }, { byteArrayOf(7) }))
        assertEquals(ProtectedMutationStatus.DIRTY, journal.recognizeCompletedOperation { byteArrayOf(8) })
        assertEquals(1L, journal.readControl().revision)
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.recognizeCompletedOperation { byteArrayOf(7) })
        assertEquals(2L, journal.readControl().revision)
        assertArrayEquals(byteArrayOf(7), journal.readCheckpoint())
    }
}

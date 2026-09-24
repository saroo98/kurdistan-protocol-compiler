// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate
import org.junit.Assert.*
import org.junit.Test

class ProtectedStateJournalLifecycleTest {
    @Test fun explicitMutationCompactsBeforeHistoryDominatesRuntimePublication() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        repeat(16) { index ->
            assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
                ByteArray(32) { (index + 1).toByte() }, byteArrayOf(7), {}, { byteArrayOf(7) }))
        }
        val before = journal.readCheckpoint()
        assertEquals(JournalAdmission.COMPACT_FIRST,
            ProtectedStateJournalLifecycle.admission(journal.readControl(), disk.inventory(JournalLimits.OBJECTS), 0))
        val revision = journal.readControl().revision
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.compact { before.clone() })
        assertEquals(revision, journal.readControl().revision)
        assertArrayEquals(before, journal.readCheckpoint())
        assertEquals(JournalAdmission.ADMIT,
            ProtectedStateJournalLifecycle.admission(journal.readControl(), disk.inventory(JournalLimits.OBJECTS), 0))
    }
    @Test fun preReservationRejectionWritesNothingAndKeepsExactCleanControl() {
        val storage = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(storage)
        journal.initialize(ByteArray(16) { 1 })
        val before = journal.readControl().encode()
        storage.events.clear()
        var calls = 0
        assertEquals(ProtectedMutationStatus.NO_MUTATION, journal.mutate(MutationKind.PROJECTION_SCHEMA,
            ByteArray(32) { 2 }, byteArrayOf(3), { error("mutation must not run") }, { error("reconstruction must not run") },
            beforeReservation = { current ->
                calls++; assertFalse(current.dirty); assertArrayEquals(before, current.encode()); error("SCHEMA_CHANGED")
            }))
        assertEquals(1, calls)
        assertArrayEquals(before, journal.readControl().encode())
        assertFalse(storage.events.any { it.startsWith("write:") })
    }
    @Test fun dirtyProductEnvelopeCannotBeCollectedAndCommittedReadsSurviveGcAndCompaction() {
        val state = BrokerFixture()
        state.projections.beforePublish = { error("SYNTHETIC_INTERRUPTION") }
        assertEquals(ProtectedMutationStatus.DIRTY, state.broker().applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100)).status)
        state.projections.beforePublish = null
        val temporary = operationObjectLeaf(state.journal.readControl().operationId(), 1)
        val objects = object : JournalObjectAccess {
            override fun inventory() = state.objects.map { JournalStoredEntry(it.key, it.value.size.toLong()) }
            override fun read(name: String) = state.objects[name]?.clone()
            override fun delete(name: String, expected: ByteArray) {
                check(state.objects[name]?.contentEquals(expected) == true)
                state.objects.remove(name)?.fill(0)
            }
        }
        val collector = ProtectedStateGarbageCollector(state.storage, state.journal, objects)
        assertEquals(GarbageResult.MAINTENANCE_UNPROVEN, collector.collect(ByteArray(32) { 8 }, emptySet(), emptySet(), emptySet()))
        assertTrue(state.objects.containsKey(temporary))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(false).status)
        assertEquals(GarbageResult.COMPLETE, collector.collect(ByteArray(32) { 9 }, emptySet(), emptySet(), emptySet()))
        assertFalse(state.objects.containsKey(temporary))
        assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(false).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, state.journal.compact { state.snapshot().encode() })
        assertEquals(GarbageResult.COMPLETE, collector.collect(ByteArray(32) { 10 }, emptySet(), emptySet(), emptySet()))
        val snapshot = state.snapshot()
        val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
        assertEquals(100L, org.kurdistanvpn.data.secure.CrashSafeModeStore.readOnly(blobs).load()!!.startedEpochHour)
        assertNotEquals(ProtectedMutationStatus.COMMITTED, state.broker().recoverProductOperationConfirmed(false).status)
    }

    @Test fun noOpAtCompactionBoundaryPerformsNoMaintenanceWrites() {
        val state = BrokerFixture()
        var starts = 0
        while (starts < 11 || state.journal.readControl().recordCount < JournalLimits.COMPACT_RECORDS) {
            val revision = state.journal.readControl().revision
            assertEquals(ProtectedMutationStatus.COMMITTED, state.broker().applyProductStoreCommand(revision, ProductStoreCommand.RecordStart(revision)).status)
            starts++
        }
        val revision = state.journal.readControl().revision
        assertEquals(JournalAdmission.COMPACT_FIRST, ProtectedStateJournalLifecycle.admission(state.journal.readControl(), state.storage.inventory(JournalLimits.OBJECTS), 0))
        state.storage.events.clear()
        val objects = state.objectWrites
        // The count is saturated; the exact prior start hour is the final operation's old revision.
        assertEquals(ProtectedMutationStatus.NO_MUTATION, state.broker().applyProductStoreCommand(revision, ProductStoreCommand.RecordStart(revision - 2)).status)
        assertEquals(objects, state.objectWrites)
        assertFalse(state.storage.events.any { it.startsWith("write:") })
    }
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

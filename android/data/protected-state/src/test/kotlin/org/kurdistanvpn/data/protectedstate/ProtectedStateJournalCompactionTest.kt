// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate
import org.junit.Assert.*
import org.junit.Test

class ProtectedStateJournalCompactionTest {
    @Test fun unfinishedMaintenanceCannotBeStrandedByAYoungerSecurityCommit() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val checkpoint = gcCheckpoint()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, checkpoint, {}, {
            bindSyntheticProjection(journal, checkpoint); checkpoint.clone()
        })
        val objects = TestGarbageObjects(linkedMapOf("object-live" to byteArrayOf(1), "object-old" to byteArrayOf(2)))
        val collector = ProtectedStateGarbageCollector(disk, journal, objects)
        objects.failDelete = true
        assertEquals(GarbageResult.MAINTENANCE_UNPROVEN, collector.collect(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, emptySet(), emptySet(), emptySet()))
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 4 }, checkpoint, { writes++ }, { checkpoint.clone() }))
        assertEquals(0, writes)
        assertEquals(2L, journal.readControl().revision)
        objects.failDelete = false
        assertEquals(GarbageResult.COMPLETE, collector.resume(emptySet(), emptySet(), emptySet()))
        val next = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 4, null,
            ProtectedStateSnapshot.decode(checkpoint).objects(), byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 4 }).encode()
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 4 }, next, { writes++ }, { bindSyntheticProjection(journal, next); next.clone() }))
        assertEquals(GarbageResult.COMPLETE, collector.resume(emptySet(), emptySet(), emptySet()))
        assertArrayEquals(next, journal.readCheckpoint())
    }
    @Test fun compactedJournalGarbageCollectionKeepsCurrentAndPreviousCheckpointOnly() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        var raw = byteArrayOf()
        repeat(3) { index ->
            val operation = ByteArray(JournalLimits.OPERATION_BYTES) { (index + 2).toByte() }
            raw = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, (index + 1L) * 2, null,
                listOf(ProtectedObjectReference.fromEncryptedObject(1, "profile-one", "object-live", 1, byteArrayOf(1), syntheticObjectBinding())),
                byteArrayOf(2), byteArrayOf(3), operation).encode()
            assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING, operation, raw, {}, {
                bindSyntheticProjection(journal, raw); raw.clone()
            }))
        }
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.compact { raw.clone() })
        val objects = TestGarbageObjects(linkedMapOf("object-live" to byteArrayOf(1)))
        assertEquals(GarbageResult.COMPLETE, ProtectedStateGarbageCollector(disk, journal, objects)
            .collect(ByteArray(JournalLimits.OPERATION_BYTES) { 9 }, emptySet(), emptySet(), emptySet()))
        assertNull(disk.read("journal-record-0000000000000001", JournalLimits.RECORD_BYTES))
        assertNull(disk.read("journal-intent-0000000000000003", JournalLimits.RECORD_BYTES))
        assertNull(disk.read("journal-checkpoint-0000000000000002", JournalLimits.CHECKPOINT_BYTES))
        assertNotNull(disk.read("journal-checkpoint-0000000000000004", JournalLimits.CHECKPOINT_BYTES))
        assertNotNull(disk.read("journal-checkpoint-0000000000000006", JournalLimits.CHECKPOINT_BYTES))
        assertArrayEquals(raw, journal.readCheckpoint())
        assertEquals(6L, journal.readControl().revision)
    }

    @Test fun moreThanOneBatchOfGarbageIsBoundedWithoutPermanentCollectionFailure() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val checkpoint = gcCheckpoint()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, checkpoint, {}, {
            bindSyntheticProjection(journal, checkpoint); checkpoint.clone()
        })
        val values = linkedMapOf("object-live" to byteArrayOf(1))
        repeat(513) { values["object-old-" + it.toString().padStart(4, '0')] = byteArrayOf(2) }
        val objects = TestGarbageObjects(values)
        val collector = ProtectedStateGarbageCollector(disk, journal, objects)
        assertEquals(GarbageResult.COMPLETE, collector.collect(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, emptySet(), emptySet(), emptySet()))
        assertEquals(2, values.size)
        assertEquals(GarbageResult.COMPLETE, collector.collect(ByteArray(JournalLimits.OPERATION_BYTES) { 4 }, emptySet(), emptySet(), emptySet()))
        assertEquals(setOf("object-live"), values.keys)
        assertArrayEquals(checkpoint, journal.readCheckpoint())
    }

    @Test fun callerCannotMakeCommittedObjectsGarbageByOmittingLiveSet() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val checkpoint = gcCheckpoint()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, checkpoint, {}, {
            bindSyntheticProjection(journal, checkpoint); checkpoint.clone()
        })
        val objects = TestGarbageObjects(linkedMapOf("object-live" to byteArrayOf(1), "object-garbage" to byteArrayOf(2)))
        assertEquals(GarbageResult.COMPLETE, ProtectedStateGarbageCollector(disk, journal, objects)
            .collect(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, emptySet(), emptySet(), emptySet()))
        assertArrayEquals(byteArrayOf(1), objects.values["object-live"])
        assertNull(objects.values["object-garbage"])
    }
    @Test fun failedGarbageCollectionDoesNotInvalidateVerifiedCheckpoint() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val checkpoint = gcCheckpoint()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, checkpoint, {}, {
            bindSyntheticProjection(journal, checkpoint); checkpoint.clone()
        })
        val objects = TestGarbageObjects(linkedMapOf("object-live" to byteArrayOf(1), "object-garbage" to byteArrayOf(2)))
        objects.failDelete = true
        val collector = ProtectedStateGarbageCollector(disk, journal, objects)
        assertEquals(GarbageResult.MAINTENANCE_UNPROVEN, collector.collect(ByteArray(JournalLimits.OPERATION_BYTES) { 3 },
            setOf("object-live"), emptySet(), emptySet()))
        assertArrayEquals(checkpoint, journal.readCheckpoint())
        assertNotNull(objects.values["object-garbage"])
        objects.failDelete = false
        assertEquals(GarbageResult.COMPLETE, collector.resume(setOf("object-live"), emptySet(), emptySet()))
        assertNull(objects.values["object-garbage"])
        assertArrayEquals(checkpoint, journal.readCheckpoint())
        assertEquals(GarbageResult.COMPLETE, collector.resume(setOf("object-live"), emptySet(), emptySet()))
    }
    @Test fun garbagePlanMustBeDurableBeforeFirstDeleteAndRetainedObjectsCannotBeDeleted() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val checkpoint = gcCheckpoint()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, checkpoint, {}, {
            bindSyntheticProjection(journal, checkpoint); checkpoint.clone()
        })
        val objects = TestGarbageObjects(linkedMapOf("object-live" to byteArrayOf(1), "object-old" to byteArrayOf(2)))
        disk.corruptNextWrite = true
        val collector = ProtectedStateGarbageCollector(disk, journal, objects)
        assertEquals(GarbageResult.MAINTENANCE_UNPROVEN, collector.collect(ByteArray(JournalLimits.OPERATION_BYTES) { 3 },
            setOf("object-live"), emptySet(), emptySet()))
        assertEquals(0, objects.deleteCalls)
        assertArrayEquals(byteArrayOf(1), objects.values["object-live"])
    }
    @Test fun garbageSelectionPreservesLivePriorAndInterruptedObjects() {
        val inventory = listOf("object-live", "object-prior", "object-pending", "object-orphan", "journal-control")
            .map { JournalStoredEntry(it, 100) }
        val candidates = ProtectedStateJournalLifecycle.garbageCandidates(inventory, setOf("object-live"),
            setOf("object-prior"), setOf("object-pending"))
        assertEquals(listOf("object-orphan"), candidates.map { it.name })
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedStateJournalLifecycle.garbageCandidates(inventory, setOf("object-missing"), emptySet(), emptySet())
        }
    }
    @Test fun compactionPreservesSecurityRevisionAndAdvancesOnlyJournalSequence() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) }))
        val before = journal.readControl()
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.compact { byteArrayOf(7) })
        val after = journal.readControl()
        assertEquals(before.revision, after.revision)
        assertEquals(before.sequence + 1, after.sequence)
        assertArrayEquals(byteArrayOf(7), journal.readCheckpoint())
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(8), {}, { byteArrayOf(8) }))
        assertArrayEquals(byteArrayOf(8), journal.readCheckpoint())
        assertEquals(4L, journal.readControl().revision)
    }
    @Test fun compactionDoesNotDeletePriorStateOrAcceptWrongProjection() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7), {}, { byteArrayOf(7) })
        val before = journal.readControl().encode()
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.compact { byteArrayOf(8) })
        assertArrayEquals(before, journal.readControl().encode())
        assertNotNull(disk.read("journal-record-0000000000000001", JournalLimits.RECORD_BYTES))
    }
}

private fun gcCheckpoint(): ByteArray = ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null,
    listOf(ProtectedObjectReference.fromEncryptedObject(1, "profile-one", "object-live", 1, byteArrayOf(1), syntheticObjectBinding())),
    byteArrayOf(2), byteArrayOf(3), ByteArray(JournalLimits.OPERATION_BYTES) { 2 }).encode()

private class TestGarbageObjects(val values: MutableMap<String, ByteArray>) : JournalObjectAccess {
    var failDelete = false
    var deleteCalls = 0
    override fun inventory(): List<JournalStoredEntry> = values.map { JournalStoredEntry(it.key, it.value.size.toLong()) }
    override fun read(name: String): ByteArray? = values[name]?.clone()
    override fun delete(name: String, expected: ByteArray) {
        deleteCalls++
        check(!failDelete)
        check(values[name]?.contentEquals(expected) == true)
        values.remove(name)?.fill(0)
    }
}

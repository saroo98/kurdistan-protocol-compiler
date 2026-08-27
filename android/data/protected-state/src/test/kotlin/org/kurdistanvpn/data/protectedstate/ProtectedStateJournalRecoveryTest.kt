// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test

class ProtectedStateJournalRecoveryTest {
    @Test fun approvedRecoveryRetainsOperationAndReservedPairAcrossRepeatedFailures() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val operation = ByteArray(JournalLimits.OPERATION_BYTES) { 2 }
        journal.mutate(MutationKind.RESTORE, operation, byteArrayOf(9), { error("interrupted") }, { byteArrayOf(9) })
        repeat(3) {
            assertEquals(ProtectedMutationStatus.DIRTY, journal.recover(operation, byteArrayOf(9),
                { error("still interrupted") }, { byteArrayOf(9) }))
            assertArrayEquals(operation, journal.readControl().operationId())
            assertEquals(1L, journal.readControl().revision)
            assertEquals(2L, journal.readControl().reservedCleanRevision)
            assertEquals(1L, journal.readControl().reservedSequence)
        }
        assertEquals(ProtectedMutationStatus.COMMITTED, ProtectedStateOperationJournal(disk)
            .recover(operation, byteArrayOf(9), {}, { byteArrayOf(9) }))
        assertEquals(2L, journal.readControl().revision)
        assertArrayEquals(byteArrayOf(9), journal.readCheckpoint())
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(10), {}, { byteArrayOf(10) }))
        assertEquals(4L, journal.readControl().revision)
    }

    @Test fun stalePreparedMutationCannotOverwriteAConcurrentCommittedRevision() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val expectedOld = journal.readControl().encode()
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(1), {}, { byteArrayOf(1) })
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(2), { writes++ }, { byteArrayOf(2) }, expectedOld))
        assertEquals(0, writes)
        assertArrayEquals(byteArrayOf(1), journal.readCheckpoint())
    }

    @Test fun dirtyRecoveryKeepsTheExactPriorCheckpointRevision() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(1), {}, { byteArrayOf(1) })
        journal.mutate(MutationKind.RESTORE, ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(2), { error("failed") }, { byteArrayOf(2) })
        journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(2), { error("recovery failed") }, { byteArrayOf(2) })
        assertEquals(3L, journal.readControl().revision)
        assertEquals(2L, journal.readControl().checkpointRevision)
        assertArrayEquals(byteArrayOf(1), journal.readPriorCheckpointForExplicitRecovery())
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }

    @Test fun initializationAndMutationCannotAdoptUnaccountedStorage() {
        val disk = MemoryJournalStorage()
        disk.compareAndReplace("journal-record-0000000000000001", null, byteArrayOf(1))
        assertThrows(IllegalStateException::class.java) { ProtectedStateOperationJournal(disk).initialize(ByteArray(16) { 1 }) }
        val clean = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(clean)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(1), {}, { byteArrayOf(1) })
        clean.compareAndReplace("journal-record-0000000000000002", null, byteArrayOf(1))
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(2), { writes++ }, { byteArrayOf(2) }))
        assertEquals(0, writes)
    }

    @Test fun failedCompensationCannotReassignTheReservedPairOrChangeItsResolution() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        assertEquals(ProtectedMutationStatus.DIRTY, journal.mutate(MutationKind.PROFILE_IMPORT,
            ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { error("interrupted product write") }, { byteArrayOf(9) }))
        assertEquals(ProtectedMutationStatus.DIRTY, journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(8),
            { error("interrupted recovery") }, { byteArrayOf(8) }, RecoveryResolution.ROLLBACK))
        assertEquals(1L, journal.readControl().revision)
        assertEquals(2L, journal.readControl().reservedCleanRevision)
        val replacement = ProtectedStateOperationJournal(disk)
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, replacement.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(7),
            { writes++ }, { byteArrayOf(7) }, RecoveryResolution.ROLLBACK))
        assertEquals(0, writes)
        assertEquals(ProtectedMutationStatus.COMMITTED, replacement.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(8),
            {}, { byteArrayOf(8) }, RecoveryResolution.ROLLBACK))
        assertEquals(2L, replacement.readControl().revision)
        assertArrayEquals(byteArrayOf(8), replacement.readCheckpoint())
        assertEquals(ProtectedMutationStatus.COMMITTED, replacement.mutate(MutationKind.ROUTING,
            ByteArray(JournalLimits.OPERATION_BYTES) { 4 }, byteArrayOf(7), {}, { byteArrayOf(7) }))
        assertEquals(4L, replacement.readControl().revision)
        assertArrayEquals(byteArrayOf(7), replacement.readCheckpoint())
    }

    @Test fun recoveryCannotHijackTheInterruptedOperationOrSilentlyChangeItsExpectedEffects() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.RESTORE, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { error("stop") }, { byteArrayOf(9) })
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
            journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(8), { writes++ }, { byteArrayOf(8) }))
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN,
            journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 3 }, byteArrayOf(9), { writes++ }, { byteArrayOf(9) }))
        assertEquals(0, writes)
        assertEquals(1L, journal.readControl().revision)
    }

    @Test fun candidatePublicationCannotBeOverwrittenByCompensation() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.RESTORE, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { error("interrupted") }, { byteArrayOf(9) })
        disk.compareAndReplace("journal-checkpoint-0000000000000002", null, byteArrayOf(9))
        var writes = 0
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(8),
            { writes++ }, { byteArrayOf(8) }, RecoveryResolution.ROLLBACK))
        assertEquals(0, writes)
        assertEquals(ProtectedMutationStatus.DIRTY, journal.recognizeCompletedOperation { byteArrayOf(8) })
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.recognizeCompletedOperation { byteArrayOf(9) })
        assertArrayEquals(byteArrayOf(9), journal.readCheckpoint())
    }

    @Test fun compensationResolutionIsAuthenticatedByTheTerminalChain() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.RESTORE, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(9), { error("interrupted") }, { byteArrayOf(9) })
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.recover(ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(8),
            {}, { byteArrayOf(8) }, RecoveryResolution.QUARANTINE))
        assertArrayEquals(byteArrayOf(8), journal.readCheckpoint())
        val name = "journal-resolution-0000000000000001"
        val original = disk.read(name, 1024)!!
        disk.compareAndReplace(name, original, original.clone().also { it[4] = 1 })
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }

    @Test fun newerUnaccountedRecordRejectsAnOtherwiseValidPrefix() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        journal.mutate(MutationKind.ROUTING, ByteArray(JournalLimits.OPERATION_BYTES) { 2 }, byteArrayOf(1), {}, { byteArrayOf(1) })
        disk.compareAndReplace("journal-record-0000000000000002", null, byteArrayOf(1))
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }
}

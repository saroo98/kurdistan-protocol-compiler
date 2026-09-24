// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.CatalogId
import org.kurdistanvpn.core.model.ProbeMethod
import org.kurdistanvpn.core.model.ProbePreferences

class Task7InstalledDriverLifecycleTest {
    @Test fun dnsCasesHaveOnlyTheirOwnReadOnlyPageAndZeroPressure() {
        for(case in 12..14){assertTrue(task7InstalledCaseAllowedV1(case,0));assertFalse(task7InstalledCaseAllowedV1(case,16))}
        assertFalse(task7InstalledCaseAllowedV1(15,0))
        assertEquals(6,task7InstalledSnapshotPageV1(2,intArrayOf(1,6)))
        for(code in 3..4)assertThrows(IllegalArgumentException::class.java){task7InstalledSnapshotPageV1(code,intArrayOf(1,6))}
        assertThrows(IllegalArgumentException::class.java){task7InstalledSnapshotPageV1(2,intArrayOf(1,4))}
    }
    @Test fun tunPageExtensionIsExactAndNeverAllowedOnMutationVerbs() {
        assertEquals(2, task7InstalledSnapshotPageV1(2, intArrayOf(1, 2)))
        for (code in 3..4) assertThrows(IllegalArgumentException::class.java) {
            task7InstalledSnapshotPageV1(code, intArrayOf(1, 2))
        }
        for (extension in listOf(intArrayOf(2, 2), intArrayOf(1, 4), intArrayOf(1, 2, 0)))
            assertThrows(IllegalArgumentException::class.java) { task7InstalledSnapshotPageV1(2, extension) }
    }
    @Test fun maintenancePageExtensionIsExactAndOnlyOnSnapshot() {
        assertEquals(3, task7InstalledSnapshotPageV1(2,intArrayOf(1,3)))
        for(code in 3..4) assertThrows(IllegalArgumentException::class.java){task7InstalledSnapshotPageV1(code,intArrayOf(1,3))}
        for(extension in listOf(intArrayOf(2,3),intArrayOf(1,3,0),intArrayOf(1,4)))
            assertThrows(IllegalArgumentException::class.java){task7InstalledSnapshotPageV1(2,extension)}
    }
    @Test fun publicationPageFailureLabelsSeparateMissingFromRejectedIdentityWithoutPrintingIt() {
        val page = task7InstalledPublicationPageV1(7, 9, 3, null, null)
        assertEquals("", task7InstalledPublicationPageFailureV1(page, 7, 9))
        assertEquals("_PUBLICATION_PAGE_UNAVAILABLE", task7InstalledPublicationPageFailureV1(null, 7, 9))
        assertEquals("_PUBLICATION_PAGE_MISMATCH", task7InstalledPublicationPageFailureV1(page, 8, 9))
        assertEquals("_PUBLICATION_PAGE_MISMATCH", task7InstalledPublicationPageFailureV1(page.copyOf(39), 7, 9))
    }
    @Test fun publicationPageExtensionIsClosedAndKeepsLegacySnapshotCompatible() {
        for (code in 2..4) assertEquals(0, task7InstalledSnapshotPageV1(code, intArrayOf()))
        assertEquals(1, task7InstalledSnapshotPageV1(2, intArrayOf(1, 1)))
        for (code in 2..4) for (extension in listOf(intArrayOf(1), intArrayOf(1, 0), intArrayOf(2, 1), intArrayOf(1, 1, 1))) {
            assertThrows(IllegalArgumentException::class.java) { task7InstalledSnapshotPageV1(code, extension) }
        }
        for (code in 3..4) assertThrows(IllegalArgumentException::class.java) { task7InstalledSnapshotPageV1(code, intArrayOf(1, 1)) }
        val absent = task7InstalledPublicationPageV1(7, 9, 3, null, null)
        assertEquals(40, absent.size)
        assertArrayEquals(longArrayOf(7, 9, 1, 1, 3, 0, 0, -1), absent.copyOfRange(0, 8))
        assertTrue(absent.drop(8).all { it == -1L })
        assertTrue(task7InstalledPublicationPageMatchesV1(absent, 7, 9))
        assertFalse(task7InstalledPublicationPageMatchesV1(absent, 7, 10))
        assertFalse(task7InstalledPublicationPageMatchesV1(absent, 8, 9))
        assertFalse(task7InstalledPublicationPageMatchesV1(absent.copyOf(39), 7, 9))
        val records = longArrayOf(5, 1, 2000, 0, 0, 0, 4, -1, 3, 2, -1, -1, 1, 0, 5, -1)
        val present = task7InstalledPublicationPageV1(7, 9, 3, records, records)
        assertEquals(1L, present[5]); assertEquals(1L, present[6])
        assertArrayEquals(records, present.copyOfRange(8, 24))
        records[2] = 60001
        assertEquals(0L, task7InstalledPublicationPageV1(7, 9, 3, records, null)[5])
        assertEquals(1L, present[5]) // A snapshot owns its scalar copy.
    }
    @Test fun socketDiagnosticFitsUnusedBitsWithoutChangingExistingFields() {
        val native = longArrayOf(4095, 4095, 4095)
        val baseline = task7PackRejectionV1(-1, -1, 7, 127, native)
        for (socket in listOf(0, 1, 511, 512, 0x7ffff)) {
            val packed = task7PackRejectionV1(-1, -1, 7, 127, native, socket)
            assertTrue(packed.all { it >= 0 })
            assertEquals(socket.toLong(), (packed[0] ushr 42) and 0x7ffff)
            assertEquals(0L, (packed[0] ushr 61) and 1)
            assertEquals(1L, (packed[0] ushr 62) and 1)
            assertEquals(baseline[0], packed[0] and (0x7ffffL shl 42).inv())
            assertEquals(baseline[1], packed[1])
        }
        assertThrows(IllegalArgumentException::class.java) { task7PackRejectionV1(0, 0, 0, 0, native, -1) }
        assertThrows(IllegalArgumentException::class.java) { task7PackRejectionV1(0, 0, 0, 0, native, 0x80000) }
    }
    @Test fun combinedDiagnosticPreservesNativeFieldsSentinelsAndUnsignedBoundaries() {
        fun packed(kind: Long, detail: Long, owner: Int, callback: Int, native: LongArray): LongArray =
            task7PackRejectionV1(kind, detail, owner, callback, native)
        val first = packed(-1, -1, 0, 0, longArrayOf(0, 0, 0))
        assertEquals((1L shl 62) or 255, first[0]); assertEquals(0xfffffL, first[1])
        val maximum = packed(10, 0xaaaaa, 7, 127, longArrayOf(4095, 4095, 4095))
        assertTrue(maximum.all { it >= 0 })
        assertEquals(10L, maximum[0] and 255)
        assertEquals(7L, (maximum[0] ushr 8) and 7)
        assertEquals(127L, (maximum[0] ushr 11) and 127)
        assertEquals(4095L, (maximum[0] ushr 18) and 4095)
        assertEquals(4095L, (maximum[0] ushr 30) and 4095)
        assertEquals(0xaaaaaL, maximum[1] and 0xfffff)
        assertEquals(4095L, (maximum[1] ushr 20) and 4095)
        for (kind in -1L..10L) for (detail in listOf(-1L, 0L, 39L, 0xaaaaaL)) {
            val value = packed(kind, detail, 2, 67, longArrayOf(567, 1091, 1569))
            assertEquals(kind, (value[0] and 255).let { if (it == 255L) -1 else it })
            assertEquals(detail, (value[1] and 0xfffff).let { if (it == 0xfffffL) -1 else it })
            assertEquals(567L, (value[1] ushr 20) and 4095)
            assertEquals(1091L, (value[0] ushr 18) and 4095)
            assertEquals(1569L, (value[0] ushr 30) and 4095)
        }
    }

    @Test fun fixtureMarkerUsesCommittedJournalDomainNotSettingsImageRevision() {
        // Exact pairs asserted after real production settings commits in
        // ProtectedStateAuthorityFactoryTest.productionCaptureRechecksCheckpointAndClosesAvailabilityOnFailure.
        assertTrue(task7InstalledCommittedJournalMatches(2, 4))
        assertTrue(task7InstalledCommittedJournalMatches(4, 6))
        assertFalse(task7InstalledCommittedJournalMatches(2, 3))
        assertFalse(task7InstalledCommittedJournalMatches(4, 5))
        assertFalse(task7InstalledCommittedJournalMatches(2, 1))
        assertFalse(task7InstalledCommittedJournalMatches(4, 2))
    }

    @Test fun fixtureSelectsCanonicalSignedProbeOneWithoutChangingMethodOrTimeout() {
        assertEquals(ProbePreferences(method = ProbeMethod.TCP_CONNECT, signedTargetId = CatalogId("probe-1"), timeoutSeconds = 1),
            Task7InstalledFixturePreparation.selectedProbe())
    }

    private fun completedWorker() = FutureTask<Unit>({ Unit }).apply { run() }

    @Test fun synchronousBinderFlagsAcceptLocalAndNativeAcceptFdsTransport() {
        assertTrue(task7InstalledSynchronousFlagsV1(0))
        assertTrue(task7InstalledSynchronousFlagsV1(0x10))
    }

    @Test fun synchronousBinderFlagsAcceptFrameworkAppOpsCollection() {
        assertTrue(task7InstalledSynchronousFlagsV1(2))
    }

    @Test fun synchronousBinderFlagsAcceptFrameworkAppOpsCollectionWithAcceptFds() {
        assertTrue(task7InstalledSynchronousFlagsV1(0x12))
    }

    @Test fun synchronousBinderFlagsRejectOneWayUnknownBitsAndNegativeValues() {
        assertFalse(task7InstalledSynchronousFlagsV1(1))
        assertFalse(task7InstalledSynchronousFlagsV1(0x11))
        assertFalse(task7InstalledSynchronousFlagsV1(3))
        assertFalse(task7InstalledSynchronousFlagsV1(0x13))
        assertFalse(task7InstalledSynchronousFlagsV1(-1))
        for (bit in 0..31) {
            if (bit == 1 || bit == 4) continue
            val flag = 1 shl bit
            for (allowed in listOf(0, 2, 0x10, 0x12)) {
                assertFalse(task7InstalledSynchronousFlagsV1(flag or allowed))
            }
        }
    }

    @Test fun pausedFinishKeepsAdmissionUntilForegroundRetirementReturns() {
        val monitor = Any()
        var current = 1
        var foreground = 1
        val retirementEntered = CountDownLatch(1)
        val retirementReturn = CountDownLatch(1)
        val startAttempted = CountDownLatch(1)
        val successorAdmitted = CountDownLatch(1)
        val failed = AtomicReference<Throwable?>()
        val finishing = Thread {
            try {
                finishTask7InstalledAdmissionV1(monitor, completedWorker(), { check(current == 1) }, {
                    retirementEntered.countDown()
                    check(retirementReturn.await(5, TimeUnit.SECONDS))
                    foreground = 0
                }, { current = 0 })
            } catch (failure: Throwable) { failed.set(failure) }
        }.apply { isDaemon = true; start() }
        assertTrue(retirementEntered.await(5, TimeUnit.SECONDS))
        val starting = Thread {
            startAttempted.countDown()
            synchronized(monitor) {
                check(current == 0)
                current = 2; foreground = 2
                successorAdmitted.countDown()
            }
        }.apply { isDaemon = true; start() }
        try {
            assertTrue(startAttempted.await(5, TimeUnit.SECONDS))
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (starting.state != Thread.State.BLOCKED && successorAdmitted.count != 0L && System.nanoTime() < deadline) Thread.yield()
            assertEquals("START must block at the actual admission monitor", Thread.State.BLOCKED, starting.state)
            assertEquals(1L, successorAdmitted.count)
        } finally { retirementReturn.countDown(); finishing.join(5000); starting.join(5000) }
        assertFalse(finishing.isAlive); assertFalse(starting.isAlive); assertNull(failed.get())
        synchronized(monitor) { assertEquals(2, current); assertEquals(2, foreground) }
    }

    @Test fun retirementFailureRetainsAdmissionAndCannotPublishIdle() {
        val monitor = Any(); var current = 1
        assertThrows(IllegalStateException::class.java) {
            finishTask7InstalledAdmissionV1(monitor, completedWorker(), { check(current == 1) },
                { error("foreground retirement failed") }, { current = 0 })
        }
        assertEquals(1, current)
    }

    @Test fun terminalCaseCannotFinishBeforeActualExecutorFinallyReturns() {
        val monitor = Any(); var current = 1
        val terminal = LongArray(32).apply { this[2] = 2; this[9] = 1 }
        val finallyEntered = CountDownLatch(1); val finallyReturn = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        val task = executor.submit {
            try { Unit } finally { finallyEntered.countDown(); check(finallyReturn.await(5, TimeUnit.SECONDS)) }
        }
        try {
            assertTrue(finallyEntered.await(5, TimeUnit.SECONDS))
            assertFalse(task.isDone)
            assertEquals(1L, task7InstalledSnapshotV1(terminal.copyOf(), task)[2])
            assertThrows(IllegalStateException::class.java) {
                finishTask7InstalledAdmissionV1(monitor, task, {}, { error("retired before wrapper completed") }, { current = 0 })
            }
            assertEquals(1, current)
        } finally { finallyReturn.countDown(); executor.shutdown(); assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS)) }
        assertEquals(2L, task7InstalledSnapshotV1(terminal.copyOf(), task)[2])
        finishTask7InstalledAdmissionV1(monitor, task, { check(current == 1) }, {}, { current = 0 })
        assertEquals(0, current)
    }

    @Test fun failedExecutorWrapperCannotReleaseAdmissionDespiteTerminalCaseSnapshot() {
        val task = FutureTask<Unit>({ error("timeout cleanup failed") }).apply { run() }
        var current = 1
        assertThrows(java.util.concurrent.ExecutionException::class.java) {
            finishTask7InstalledAdmissionV1(Any(), task, {}, {}, { current = 0 })
        }
        assertEquals(1, current)
    }
}

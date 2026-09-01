// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.core.nativeapi

import java.io.IOException
import java.nio.ByteBuffer
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.*
import org.junit.Test

class DurableFilePrimitivesTest {
    private val identity = DurableFileIdentity(1, 2)
    private val directory = DurableDirectory(7, 1000, identity)

    @Test fun rawResultSnapshotsConstructorArraysAndNeverReturnsItsBackingArrays() {
        val metadata = longArrayOf(1, 2, 1000, 384, 1, 2)
        val bytes = byteArrayOf(4, 8)
        val raw = DurableRawResult(0, metadata, bytes)
        metadata.fill(0)
        bytes.fill(0)
        assertArrayEquals(longArrayOf(1, 2, 1000, 384, 1, 2), raw.metadata)
        assertArrayEquals(byteArrayOf(4, 8), raw.bytes)
        raw.metadata.fill(-1)
        raw.bytes!!.fill(9)
        assertArrayEquals(longArrayOf(1, 2, 1000, 384, 1, 2), raw.metadata)
        assertArrayEquals(byteArrayOf(4, 8), raw.bytes)
    }

    @Test fun directoryResultSnapshotsCallerListAndRejectsMutationThroughItsGetter() {
        val first = DurableDirectoryEntry("first", identity, 4)
        val input = mutableListOf(first)
        val result = DurableListResult(DurableCode.OK, input)
        input.clear()
        input.add(DurableDirectoryEntry("different", DurableFileIdentity(1, 3), 9))
        assertEquals(listOf(first), result.entries)
        @Suppress("UNCHECKED_CAST")
        val exposed = result.entries as MutableList<DurableDirectoryEntry>
        assertThrows(UnsupportedOperationException::class.java) { exposed.clear() }
        assertThrows(UnsupportedOperationException::class.java) { exposed.add(first) }
        assertEquals(listOf(first), result.entries)
    }

    @Test fun directSnapshotCopiesBeforeValidationAndOnlyExportsDefensiveCopies() {
        val bytes = byteArrayOf(2, 7)
        val snapshot = DurableSnapshot(identity, bytes)
        bytes.fill(0)
        snapshot.bytes.fill(0)
        assertArrayEquals(byteArrayOf(2, 7), snapshot.bytes)
        assertEquals(2, snapshot.size)
        assertThrows(IllegalArgumentException::class.java) {
            DurableSnapshot(identity, ByteArray(DurableBounds.MAX_BYTES + 1))
        }
    }

    @Test fun callerMutationBeforeReadCannotChangeTheNativeResultBeingValidated() {
        val metadata = longArrayOf(1, 2, 1000, 384, 1, 2)
        val bytes = byteArrayOf(4, 8)
        val backend = Backend().apply { readResult = DurableRawResult(0, metadata, bytes) }
        metadata[1] = 99
        bytes.fill(0)
        val result = CheckedDurableFilePrimitives(backend).read(directory, "state", 10)
        assertEquals(DurableCode.OK, result.code)
        assertEquals(identity, result.snapshot!!.identity)
        assertArrayEquals(byteArrayOf(4, 8), result.snapshot.bytes)
        assertTrue(backend.readResult.metadata.all { it == 0L })
        assertTrue(backend.readResult.bytes!!.all { it == 0.toByte() })
    }

    @Test fun rawWorkingResultsAreWipedForSuccessfulAndRejectedInventoryDecoding() {
        val name = "state"
        val encoded = ByteBuffer.allocate(1 + name.length + 48).put(name.length.toByte())
            .put(name.toByteArray(Charsets.US_ASCII)).putLong(1).putLong(2).putLong(1000)
            .putLong(384).putLong(1).putLong(3).array()
        for (code in listOf(0, 5)) {
            val raw = DurableRawResult(code, longArrayOf(1), encoded)
            val backend = Backend().apply { listResult = raw }
            val result = CheckedDurableFilePrimitives(backend).list(directory, 4)
            assertEquals(if (code == 0) DurableCode.OK else DurableCode.IO_FAILURE, result.code)
            assertTrue(raw.metadata.all { it == 0L })
            assertTrue(raw.bytes!!.all { it == 0.toByte() })
            assertTrue(encoded.any { it != 0.toByte() })
        }
    }

    @Test fun jniSourceWipesItsConstructorInputArraysAfterSnapshotConstruction() {
        // Static ownership regression only. This is not native execution or device evidence.
        val source = nativeSource("kvpn_durable_fs_jni.c")
        val resultBody = source.substringAfter("static jobject result(").substringBefore("JNIEXPORT")
        assertTrue(resultBody.indexOf("NewObject") < resultBody.indexOf("wipe_result_inputs(env"))
        assertTrue(resultBody.indexOf("wipe_result_inputs(env") < resultBody.indexOf("DeleteLocalRef(env, data)"))
        val wiping = source.substringAfter("static int wipe_result_inputs(").substringBefore("/* Failed operations")
        assertTrue(wiping.contains("SetByteArrayRegion"))
        assertTrue(wiping.contains("SetLongArrayRegion"))
        assertTrue(wiping.contains("ExceptionClear"))
        assertTrue(wiping.contains("Throw(env, pending)"))
        assertTrue(wiping.contains("const jlong empty_info[7]"))
        assertTrue(resultBody.contains("count > 7"))
        assertTrue(resultBody.contains("jlong values[7]"))
    }

    @Test fun acquiredChildIsClosedOnceWhenEveryCopyOrConstructionBoundaryThrows() {
        for (boundary in DurableConstructionBoundary.entries) {
            for (creating in listOf(false, true)) {
                val backend = Backend()
                val failure = OutOfMemoryError("synthetic construction failure")
                val files = CheckedDurableFilePrimitives(backend, DurableConstructionObserver { stage ->
                    if (stage == boundary) throw failure
                })
                val result = if (creating) files.createChildDirectoryExclusive(directory, "journal")
                    else files.openChildDirectory(directory, "journal")
                assertEquals("$boundary creating=$creating", if (creating) DurableCode.MUTATION_UNPROVEN else DurableCode.IO_FAILURE, result.code)
                assertNull(result.owner)
                assertEquals(listOf(11L), backend.closedDirectories)
                assertTrue(backend.childResult.metadata.all { it == 0L })
            }
        }
    }

    @Test fun acquiredWriterIsClosedOnceWhenEveryCopyOrConstructionBoundaryThrows() {
        for (boundary in DurableConstructionBoundary.entries) {
            val backend = Backend()
            val failure = OutOfMemoryError("synthetic construction failure")
            val files = CheckedDurableFilePrimitives(backend, DurableConstructionObserver { stage ->
                if (stage == boundary) throw failure
            })
            val result = files.openWriter(directory, "lock", identity)
            assertEquals(boundary.name, DurableCode.IO_FAILURE, result.code)
            assertNull(result.writer)
            assertEquals(1, backend.closeCalls)
            assertEquals(listOf(listOf(8L, 9L)), backend.closedSessions)
            assertTrue(backend.openResult.metadata.all { it == 0L })
        }
    }

    @Test fun constructionCleanupUncertaintyNeverRetriesOrReturnsAnOwner() {
        for (boundary in DurableConstructionBoundary.entries) {
            for (throws in listOf(false, true)) {
                val backend = Backend().apply {
                    if (throws) {
                        directoryCloseFailure = IOException("synthetic close uncertainty")
                        closeFailure = IOException("synthetic close uncertainty")
                    } else {
                        directoryCloseResult = DurableRawResult(8, longArrayOf(), null)
                        closeResult = DurableRawResult(8, longArrayOf(), null)
                    }
                }
                val files = CheckedDurableFilePrimitives(backend, DurableConstructionObserver { stage ->
                    if (stage == boundary) throw IllegalStateException("synthetic construction failure")
                })
                val child = files.openChildDirectory(directory, "journal")
                val writer = files.openWriter(directory, "lock", identity)
                assertEquals(DurableCode.CLOSE_UNPROVEN, child.code)
                assertEquals(DurableCode.CLOSE_UNPROVEN, writer.code)
                assertNull(child.owner); assertNull(writer.writer)
                assertEquals(listOf(11L), backend.closedDirectories)
                assertEquals(listOf(listOf(8L, 9L)), backend.closedSessions)
                assertEquals(1, backend.closeCalls)
            }
        }
    }

    @Test fun writerMayNotAdoptOrCloseItsBorrowedDirectoryDescriptor() {
        for (metadata in listOf(longArrayOf(7, 9), longArrayOf(8, 7), longArrayOf(8, 8))) {
            val backend = Backend().apply { openResult = DurableRawResult(0, metadata, null) }
            val result = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity)
            assertEquals(DurableCode.IO_FAILURE, result.code)
            assertNull(result.writer)
            assertEquals(0, backend.closeCalls)
        }
    }

    @Test fun terminalCloseUncertaintyRemainsVisibleWithoutRetryingConsumedDescriptors() {
        for (creating in listOf(false, true)) {
            val backend = Backend().apply { directoryCloseResult = DurableRawResult(8, longArrayOf(), null) }
            val files = CheckedDurableFilePrimitives(backend)
            val owner = if (creating) files.createChildDirectoryExclusive(directory, "journal").owner!!
                else files.openChildDirectory(directory, "journal").owner!!
            val expected = if (creating) DurableCode.MUTATION_UNPROVEN else DurableCode.CLOSE_UNPROVEN
            repeat(3) { assertEquals(expected, owner.closeResult()) }
            repeat(2) { assertThrows(IOException::class.java) { owner.close() } }
            assertEquals(listOf(11L), backend.closedDirectories)
            assertNull(owner.borrow())
        }
        for (changed in listOf(false, true)) {
            val backend = Backend().apply { closeResult = DurableRawResult(8, longArrayOf(), null) }
            val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
            if (changed) assertEquals(DurableCode.OK, writer.replace("state", "temp", null, byteArrayOf(1), 10).code)
            val expected = if (changed) DurableCode.MUTATION_UNPROVEN else DurableCode.CLOSE_UNPROVEN
            repeat(3) { assertEquals(expected, writer.closeResult()) }
            repeat(2) { assertThrows(IOException::class.java) { writer.close() } }
            assertEquals(listOf(listOf(8L, 9L)), backend.closedSessions)
            assertEquals(1, backend.closeCalls)
            assertEquals(DurableCode.CLOSED, writer.read("state", 10).code)
        }
    }

    @Test fun rejectsNumericValuesBeforeNarrowing() {
        listOf(-1L, Int.MAX_VALUE.toLong() + 1, Long.MAX_VALUE).forEach {
            assertThrows(IllegalArgumentException::class.java) { DurableDirectory(it, 1000, identity) }
        }
        listOf(-1L, 0xffff_ffffL, 0x1_0000_0000L, Long.MAX_VALUE).forEach {
            assertThrows(IllegalArgumentException::class.java) { DurableDirectory(7, it, identity) }
        }
        assertEquals(Int.MAX_VALUE.toLong(), DurableDirectory(Int.MAX_VALUE.toLong(), 0xffff_fffeL, identity).directoryFd)
        assertThrows(IllegalArgumentException::class.java) { DurableFileIdentity(-1, 1) }
        assertThrows(IllegalArgumentException::class.java) { DurableFileIdentity(1, 0) }
    }

    @Test fun rejectsTraversalNulUnicodeAndOversizedLeavesBeforeNativeCall() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        listOf("", ".", "..", "a/b", "a\\b", "a\u0000b", "é", "a".repeat(256)).forEach {
            assertEquals(DurableCode.INVALID, files.read(directory, it, 10).code)
        }
        assertEquals(0, backend.readCalls)
        assertEquals(DurableCode.INVALID, files.read(directory, "state", 0).code)
        assertEquals(DurableCode.INVALID, files.read(directory, "state", DurableBounds.MAX_BYTES + 1).code)
    }

    @Test fun resultDecoderRejectsFailurePayloadAndMalformedSuccess() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        val invalid = listOf(
            DurableRawResult(0, longArrayOf(), null),
            DurableRawResult(0, longArrayOf(1, 2, 0x1_0000_0000L, 384, 1, 1), byteArrayOf(1)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 420, 1, 1), byteArrayOf(1)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 2, 1), byteArrayOf(1)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, Long.MAX_VALUE), byteArrayOf(1)),
            DurableRawResult(1, longArrayOf(1, 2), byteArrayOf(1)),
            DurableRawResult(987, longArrayOf(), null),
        )
        invalid.forEach {
            backend.readResult = it
            val result = files.read(directory, "state", 10)
            assertEquals(DurableCode.IO_FAILURE, result.code)
            assertNull(result.snapshot)
        }
    }

    @Test fun readSnapshotsDefensivelyOwnBytes() {
        val bytes = byteArrayOf(5)
        val backend = Backend().apply {
            readResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 1), bytes)
        }
        val snapshot = CheckedDurableFilePrimitives(backend).read(directory, "state", 10).snapshot!!
        bytes[0] = 9
        val exported = snapshot.bytes
        exported[0] = 8
        assertArrayEquals(byteArrayOf(5), snapshot.bytes)
    }

    @Test fun sessionCloseConsumesOwnershipExactlyOnceAndReportsUncertainty() {
        val backend = Backend().apply { closeResult = DurableRawResult(8, longArrayOf(), null) }
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertThrows(IOException::class.java) { session.close() }
        assertThrows(IOException::class.java) { session.close() }
        assertEquals(1, backend.closeCalls)
        assertEquals(DurableCode.CLOSED, session.replace("state", "temp", null, byteArrayOf(1), 10).code)
        assertEquals(0, backend.mutationCalls)
    }

    @Test fun malformedMutationPoisonsSessionButKeepsOwnershipUntilExplicitClose() {
        val backend = Backend().apply { mutationResult = DurableRawResult(0, longArrayOf(1), byteArrayOf(7)) }
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.replace("state", "temp", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.CLOSED, session.read("state", 10).code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.closeResult())
        assertEquals(1, backend.mutationCalls)
        assertEquals(1, backend.closeCalls)
        assertEquals(DurableCode.CLOSED, session.delete("state", DurableSnapshot(identity, byteArrayOf(1)), 10).code)
    }

    @Test fun malformedSuccessfulOpenClosesOnlyItsValidatedOwnedDescriptors() {
        val backend = Backend().apply {
            openResult = DurableRawResult(0, longArrayOf(8, 9), byteArrayOf(1))
            closeResult = DurableRawResult(8, longArrayOf(), null)
        }
        val result = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity)
        assertEquals(DurableCode.CLOSE_UNPROVEN, result.code)
        assertNull(result.writer)
        assertEquals(1, backend.closeCalls)
    }

    @Test fun nativeClosedMutationCodePoisonsTheLease() {
        val backend = Backend().apply { mutationResult = DurableRawResult(9, longArrayOf(), null) }
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.replace("state", "temp", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.CLOSED, session.replace("state", "temp", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.closeResult())
        assertEquals(1, backend.mutationCalls)
    }

    @Test fun resultShapesCannotRepresentFailureWithSuccessPayload() {
        assertThrows(IllegalArgumentException::class.java) { DurableReadResult(DurableCode.OK) }
        assertThrows(IllegalArgumentException::class.java) { DurableReadResult(DurableCode.IO_FAILURE, DurableSnapshot(identity, byteArrayOf())) }
        assertThrows(IllegalArgumentException::class.java) { DurableIdentityResult(DurableCode.OK) }
        assertThrows(IllegalArgumentException::class.java) { DurableOpenResult(DurableCode.OK) }
        assertThrows(IllegalArgumentException::class.java) { DurableMutationResult(DurableCode.ABSENT) }
    }

    @Test fun severalProvenMutationsShareLeaseUntilTerminalClose() {
        val backend = Backend()
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.OK, session.replace("dirty", "tmp1", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.OK, session.replace("state", "tmp2", null, byteArrayOf(2), 10).code)
        assertEquals(2, backend.mutationCalls)
        assertEquals(0, backend.closeCalls)
        session.close()
        session.close()
        assertEquals(1, backend.closeCalls)
    }

    @Test fun closeFailureAfterProvenChangeIsMutationUnproven() {
        val backend = Backend().apply { closeResult = DurableRawResult(8, longArrayOf(), null) }
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.OK, session.replace("state", "temp", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.closeResult())
        assertEquals(1, backend.closeCalls)
    }

    @Test fun invalidMutationRetainsCloseableOwnershipAndDoesNotEnterNative() {
        val backend = Backend()
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.INVALID, session.replace("state", "state", null, byteArrayOf(1), 10).code)
        assertEquals(DurableCode.INVALID, session.replace("state", "temp", null, ByteArray(11), 10).code)
        assertEquals(DurableCode.INVALID, session.replace("lock", "temp", null, byteArrayOf(1), 10).code)
        session.close()
        assertEquals(0, backend.mutationCalls)
        assertEquals(1, backend.closeCalls)
    }

    @Test fun incompatibleOpenMetadataCannotCreateOwnedSession() {
        val backend = Backend().apply { openResult = DurableRawResult(0, longArrayOf(Long.MAX_VALUE, 9), null) }
        val result = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity)
        assertEquals(DurableCode.IO_FAILURE, result.code)
        assertNull(result.writer)
        // Do not narrow an untrusted handle and close an unrelated descriptor.
        assertEquals(0, backend.closeCalls)
    }

    @Test fun inventoryRejectsInvalidBoundsWithoutNativeEntry() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        assertEquals(DurableCode.INVALID, files.list(directory, 0).code)
        assertEquals(DurableCode.INVALID, files.list(directory, 4097).code)
        assertEquals(0, backend.listCalls)
    }

    @Test fun inventoryRequiresCompleteUniqueBoundedRecordsWithValidatedMetadata() {
        fun record(name: String, length: Long = 3, links: Long = 1): ByteArray =
            ByteBuffer.allocate(1 + name.length + 48).put(name.length.toByte()).put(name.toByteArray(Charsets.US_ASCII))
                .putLong(1).putLong(2).putLong(1000).putLong(384).putLong(links).putLong(length).array()
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        val good = record("state")
        backend.listResult = DurableRawResult(0, longArrayOf(1), good)
        val listed = files.list(directory, 2)
        assertEquals(DurableCode.OK, listed.code)
        assertEquals("state", listed.entries!!.single().leaf)
        assertEquals(3L, listed.entries.single().length)
        listOf(
            DurableRawResult(0, longArrayOf(Long.MAX_VALUE), good),
            DurableRawResult(0, longArrayOf(1), good.copyOf(good.size - 1)),
            DurableRawResult(0, longArrayOf(1), good + byteArrayOf(0)),
            DurableRawResult(0, longArrayOf(2), good + good),
            DurableRawResult(0, longArrayOf(1), record("../x")),
            DurableRawResult(0, longArrayOf(1), record("state", Long.MAX_VALUE)),
            DurableRawResult(0, longArrayOf(1), record("state", links = 2)),
            DurableRawResult(5, longArrayOf(1), good),
        ).forEach {
            backend.listResult = it
            val rejected = files.list(directory, 2)
            assertEquals(DurableCode.IO_FAILURE, rejected.code)
            assertNull(rejected.entries)
        }
    }

    @Test fun poisonedSessionCannotListAndReadUsesOwnedDirectory() {
        val backend = Backend()
        val session = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        session.read("state", 10)
        assertEquals(8L, backend.readDirectory!!.directoryFd)
        backend.mutationResult = DurableRawResult(7, longArrayOf(), null)
        session.replace("state", "temp", null, byteArrayOf(1), 10)
        assertEquals(DurableCode.CLOSED, session.list(10).code)
        assertEquals(0, backend.listCalls)
        assertEquals(DurableCode.MUTATION_UNPROVEN, session.closeResult())
    }

    @Test fun childOpenIsReadOnlyAndRejectsInvalidNamesBeforeNativeEntry() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        listOf("", ".", "..", "a/b", "a\\b", "a\u0000b", "é", "x".repeat(256)).forEach {
            assertEquals(DurableCode.INVALID, files.openChildDirectory(directory, it).code)
            assertEquals(DurableCode.INVALID, files.createChildDirectoryExclusive(directory, it).code)
        }
        assertEquals(0, backend.childOpenCalls)
        assertEquals(0, backend.childCreateCalls)
        backend.childResult = DurableRawResult(1, longArrayOf(), null)
        assertEquals(DurableCode.ABSENT, files.openChildDirectory(directory, "no_backup").code)
        assertEquals(1, backend.childOpenCalls)
        assertEquals(0, backend.childCreateCalls)
    }

    @Test fun openedChildOwnsOnlyItsDescriptorAndCloseIsNeverRetried() {
        val backend = Backend()
        val owner = CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal").owner!!
        assertEquals(DurableDirectory(11, 1000, DurableFileIdentity(1, 12)), owner.borrow())
        backend.directoryCloseResult = DurableRawResult(8, longArrayOf(), null)
        assertThrows(IOException::class.java) { owner.close() }
        assertNull(owner.borrow())
        assertNull(owner.withBorrow { it.directoryFd })
        assertEquals(DurableCode.CLOSE_UNPROVEN, owner.closeResult())
        assertEquals(listOf(11L), backend.closedDirectories)
    }

    @Test fun childMetadataCannotNarrowOverflowOrCloseBorrowedParent() {
        listOf(Long.MAX_VALUE, -1L, 7L).forEach { fd ->
            val backend = Backend().apply { childResult = DurableRawResult(0, longArrayOf(fd, 1, 12, 1000, 448, 2), null) }
            assertEquals(DurableCode.IO_FAILURE, CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal").code)
            assertTrue(backend.closedDirectories.isEmpty())
        }
        listOf(
            longArrayOf(11, -1, 12, 1000, 448, 2), longArrayOf(11, 1, 0, 1000, 448, 2),
            longArrayOf(11, 1, 12, 0x1_0000_0000L, 448, 2), longArrayOf(11, 1, 12, 1000, 493, 2),
            longArrayOf(11, 1, 12, 1000, 448, 0), longArrayOf(11, 1, 2, 1000, 448, 2),
        ).forEach { metadata ->
            val backend = Backend().apply { childResult = DurableRawResult(0, metadata, null) }
            val result = CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal")
            assertEquals(DurableCode.IO_FAILURE, result.code)
            assertNull(result.owner)
            assertEquals(listOf(11L), backend.closedDirectories)
        }
    }

    @Test fun expectedChildMismatchClosesAcquiredChildAndNeverReturnsOwner() {
        val backend = Backend()
        val result = CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal", DurableFileIdentity(1, 99))
        assertEquals(DurableCode.CONFLICT, result.code)
        assertNull(result.owner)
        assertEquals(listOf(11L), backend.closedDirectories)
    }

    @Test fun ambiguousCreationTransferAndCloseStayMutationUnproven() {
        val backend = Backend().apply { childResult = DurableRawResult(0, longArrayOf(11, 1, 12, 1000, 448, 2), byteArrayOf(1)) }
        val files = CheckedDurableFilePrimitives(backend)
        val malformed = files.createChildDirectoryExclusive(directory, "journal")
        assertEquals(DurableCode.MUTATION_UNPROVEN, malformed.code)
        assertNull(malformed.owner)
        assertEquals(listOf(11L), backend.closedDirectories)
        backend.childResult = DurableRawResult(0, longArrayOf(11, 1, 12, 1000, 448, 2), null)
        val owner = files.createChildDirectoryExclusive(directory, "journal").owner!!
        backend.directoryCloseResult = DurableRawResult(8, longArrayOf(), null)
        assertEquals(DurableCode.MUTATION_UNPROVEN, owner.closeResult())
        assertEquals(DurableCode.MUTATION_UNPROVEN, owner.closeResult())
        assertNull(owner.borrow())
        assertEquals(listOf(11L, 11L), backend.closedDirectories)
    }

    @Test fun childFailureShapesAndCreationAbsenceCannotBecomeSuccess() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        listOf(1, 9, 987).forEach {
            backend.childResult = DurableRawResult(it, longArrayOf(), null)
            assertEquals(DurableCode.MUTATION_UNPROVEN, files.createChildDirectoryExclusive(directory, "journal").code)
        }
        backend.childResult = DurableRawResult(6, longArrayOf(), null)
        assertEquals(DurableCode.UNSUPPORTED, files.createChildDirectoryExclusive(directory, "journal").code)
        backend.childResult = DurableRawResult(5, longArrayOf(11, 1, 12, 1000, 448, 2), null)
        assertEquals(DurableCode.IO_FAILURE, files.openChildDirectory(directory, "journal").code)
        assertTrue(backend.closedDirectories.isEmpty())
        assertThrows(IllegalArgumentException::class.java) { DurableChildDirectoryResult(DurableCode.OK) }
    }

    @Test fun protectedBorrowSerializesCloseUntilNativeDuplicationCanFinish() {
        val backend = Backend()
        val owner = CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal").owner!!
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        var borrowed: Long? = null
        var closeCode: DurableCode? = null
        val reader = Thread { borrowed = owner.withBorrow { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); it.directoryFd } }
        reader.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val closer = Thread { closeStarted.countDown(); closeCode = owner.closeResult() }
        closer.start()
        assertTrue(closeStarted.await(5, TimeUnit.SECONDS))
        assertTrue(backend.closedDirectories.isEmpty())
        release.countDown()
        reader.join(5000); closer.join(5000)
        assertFalse(reader.isAlive); assertFalse(closer.isAlive)
        assertEquals(11L, borrowed)
        assertEquals(DurableCode.OK, closeCode)
        assertEquals(listOf(11L), backend.closedDirectories)
        assertNull(owner.borrow())
    }

    @Test fun reentrantCloseCannotConsumeAnActiveBorrowAndThrowingBorrowReleasesGuard() {
        val backend = Backend()
        val owner = CheckedDurableFilePrimitives(backend).openChildDirectory(directory, "journal").owner!!
        assertThrows(IllegalStateException::class.java) {
            owner.withBorrow {
                assertEquals(DurableCode.CONFLICT, owner.closeResult())
                assertTrue(backend.closedDirectories.isEmpty())
                throw IllegalStateException("callback failure")
            }
        }
        assertNotNull(owner.borrow())
        assertEquals(DurableCode.OK, owner.closeResult())
        assertEquals(listOf(11L), backend.closedDirectories)
    }

    @Test fun transportAllocationAndCloseExceptionsAreUnprovenWithoutRetries() {
        val backend = Backend().apply { childFailure = IllegalStateException("transport unavailable") }
        val files = CheckedDurableFilePrimitives(backend)
        assertEquals(DurableCode.CLOSE_UNPROVEN, files.openChildDirectory(directory, "journal").code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, files.createChildDirectoryExclusive(directory, "journal").code)
        backend.childFailure = null
        val owner = files.openChildDirectory(directory, "journal").owner!!
        backend.directoryCloseFailure = IllegalStateException("close result unavailable")
        assertEquals(DurableCode.CLOSE_UNPROVEN, owner.closeResult())
        assertEquals(DurableCode.CLOSE_UNPROVEN, owner.closeResult())
        assertEquals(listOf(11L), backend.closedDirectories)
        assertNull(owner.borrow())
    }

    @Test fun syncExistingReturnsOnlyTheExactReopenedSnapshotWithoutContentMutation() {
        val bytes = byteArrayOf(4, 8)
        val backend = Backend().apply { syncResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2), bytes) }
        val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        val result = writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10)
        assertEquals(DurableCode.OK, result.code)
        assertEquals(identity, result.snapshot!!.identity)
        assertArrayEquals(byteArrayOf(4, 8), result.snapshot.bytes)
        // The producer retains its source array; the decoder owns and wipes the
        // independent result and its working copies, not unrelated caller memory.
        assertArrayEquals(byteArrayOf(4, 8), bytes)
        assertArrayEquals(byteArrayOf(0, 0), backend.syncResult.bytes)
        assertTrue(backend.syncResult.metadata.all { it == 0L })
        assertEquals(1, backend.syncCalls)
        assertEquals(0, backend.mutationCalls)
        assertEquals(DurableCode.OK, writer.closeResult())
        assertEquals(1, backend.closeCalls)
    }

    @Test fun syncExistingRejectsInvalidNamesAndBoundsBeforeNativeEntry() {
        val backend = Backend()
        val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        val expected = DurableSnapshot(identity, byteArrayOf(1, 2))
        listOf("", ".", "..", "a/b", "a\\b", "a\u0000b", "lock", "x".repeat(256)).forEach {
            assertEquals(DurableCode.INVALID, writer.syncAndObserveExisting(it, expected, 10).code)
        }
        listOf(0, 1, DurableBounds.MAX_BYTES + 1).forEach {
            assertEquals(DurableCode.INVALID, writer.syncAndObserveExisting("projection", expected, it).code)
        }
        assertEquals(0, backend.syncCalls)
        assertEquals(DurableCode.OK, writer.closeResult())
    }

    @Test fun syncExistingImpossibleResultsPoisonTheLeaseAndCannotPublishAnObservation() {
        val malformed = listOf(
            DurableRawResult(0, longArrayOf(), null),
            DurableRawResult(0, longArrayOf(-1, 2, 1000, 384, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 0, 1000, 384, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 3, 1000, 384, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 0x1_0000_0000L, 384, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 420, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 2, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, Long.MAX_VALUE), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 1), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2), byteArrayOf(4, 9)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 3), byteArrayOf(4, 8, 0)),
            DurableRawResult(2, longArrayOf(1, 2), byteArrayOf(4)),
            DurableRawResult(1, longArrayOf(), null),
            DurableRawResult(8, longArrayOf(), null),
            DurableRawResult(9, longArrayOf(), null),
            DurableRawResult(987, longArrayOf(), null),
        )
        malformed.forEach { raw ->
            val backend = Backend().apply { syncResult = raw }
            val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
            val result = writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10)
            assertEquals(DurableCode.MUTATION_UNPROVEN, result.code)
            assertNull(result.snapshot)
            assertTrue(raw.bytes?.all { it == 0.toByte() } != false)
            assertTrue(raw.metadata.all { it == 0L })
            assertEquals(DurableCode.CLOSED, writer.read("projection", 10).code)
            assertEquals(DurableCode.CLOSED, writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10).code)
            assertEquals(DurableCode.MUTATION_UNPROVEN, writer.closeResult())
            assertEquals(DurableCode.MUTATION_UNPROVEN, writer.closeResult())
            assertEquals(1, backend.syncCalls)
            assertEquals(1, backend.closeCalls)
        }
    }

    @Test fun syncExistingKnownPreflightFailuresNeverInvokeAWeakerMutationFallback() {
        listOf(DurableCode.CONFLICT, DurableCode.INVALID, DurableCode.UNSAFE, DurableCode.IO_FAILURE, DurableCode.UNSUPPORTED).forEach { code ->
            val backend = Backend().apply { syncResult = DurableRawResult(code.wire, longArrayOf(), null) }
            val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
            assertEquals(code, writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10).code)
            assertEquals(0, backend.mutationCalls)
            assertEquals(DurableCode.OK, writer.closeResult())
            assertEquals(1, backend.syncCalls)
        }
    }

    @Test fun syncExistingThrowsAndLeaseCloseFailuresCannotCertifyDurability() {
        val failing = Backend().apply { syncFailure = IOException("synthetic sync failure") }
        val first = CheckedDurableFilePrimitives(failing).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.MUTATION_UNPROVEN, first.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10).code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, first.closeResult())
        assertEquals(1, failing.closeCalls)
        val backend = Backend().apply { closeResult = DurableRawResult(8, longArrayOf(), null) }
        val second = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.OK, second.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10).code)
        assertEquals(DurableCode.MUTATION_UNPROVEN, second.closeResult())
        assertEquals(DurableCode.MUTATION_UNPROVEN, second.closeResult())
        assertEquals(1, backend.closeCalls)
    }

    @Test fun syncResultCannotRepresentMissingOrUnprovenSnapshotAsSuccess() {
        assertThrows(IllegalArgumentException::class.java) { DurableSyncResult(DurableCode.OK) }
        assertThrows(IllegalArgumentException::class.java) { DurableSyncResult(DurableCode.MUTATION_UNPROVEN, DurableSnapshot(identity, byteArrayOf())) }
        assertThrows(IllegalArgumentException::class.java) { DurableSyncResult(DurableCode.ABSENT) }
        assertThrows(IllegalArgumentException::class.java) { DurableSyncResult(DurableCode.CLOSE_UNPROVEN) }
    }

    @Test fun syncExistingAcceptsEmptyAndMaximumFilesWithoutChangingTheLimit() {
        listOf(0, DurableBounds.MAX_BYTES).forEach { length ->
            val bytes = ByteArray(length) { 7 }
            val expected = DurableSnapshot(identity, bytes)
            val backend = Backend().apply { syncResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, length.toLong()), bytes) }
            val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
            val result = writer.syncAndObserveExisting("projection", expected, DurableBounds.MAX_BYTES)
            assertEquals(DurableCode.OK, result.code)
            assertEquals(length, result.snapshot!!.size)
            assertArrayEquals(expected.bytes, result.snapshot.bytes)
            assertTrue(bytes.all { it == 7.toByte() })
            assertTrue(backend.syncResult.bytes!!.all { it == 0.toByte() })
            assertTrue(backend.syncResult.metadata.all { it == 0L })
            assertEquals(DurableCode.OK, writer.closeResult())
        }
    }

    @Test fun restrictExistingReturnsOnlyAValidatedRestrictedSnapshotAndChangeFlag() {
        val bytes = byteArrayOf(4, 8)
        val backend = Backend().apply {
            restrictResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2, 1), bytes)
        }
        val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        val result = writer.restrictAndObserveExisting("projection", 10)
        assertEquals(DurableCode.OK, result.code)
        assertTrue(result.modeChanged)
        assertEquals(identity, result.snapshot!!.identity)
        assertArrayEquals(byteArrayOf(4, 8), result.snapshot.bytes)
        assertArrayEquals(byteArrayOf(4, 8), bytes)
        assertArrayEquals(byteArrayOf(0, 0), backend.restrictResult.bytes)
        assertTrue(backend.restrictResult.metadata.all { it == 0L })
        assertEquals(1, backend.restrictCalls)
        assertEquals(DurableCode.OK, writer.closeResult())
    }

    @Test fun restrictExistingPreservesAbsenceAndRejectsInvalidInputBeforeNativeEntry() {
        val backend = Backend().apply { restrictResult = DurableRawResult(DurableCode.ABSENT.wire, longArrayOf(), null) }
        val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        assertEquals(DurableCode.ABSENT, writer.restrictAndObserveExisting("projection", 10).code)
        listOf("", ".", "..", "a/b", "a\\b", "a\u0000b", "lock", "x".repeat(256)).forEach {
            assertEquals(DurableCode.INVALID, writer.restrictAndObserveExisting(it, 10).code)
        }
        listOf(0, DurableBounds.MAX_BYTES + 1).forEach {
            assertEquals(DurableCode.INVALID, writer.restrictAndObserveExisting("projection", it).code)
        }
        assertEquals(1, backend.restrictCalls)
        assertEquals(DurableCode.OK, writer.closeResult())
    }

    @Test fun restrictExistingImpossibleResultsPoisonTheLease() {
        val malformed = listOf(
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 420, 1, 2, 1), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2, 2), byteArrayOf(4, 8)),
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 3, 0), byteArrayOf(4, 8)),
            DurableRawResult(DurableCode.CLOSE_UNPROVEN.wire, longArrayOf(), null),
            DurableRawResult(987, longArrayOf(), null),
        )
        malformed.forEach { raw ->
            val backend = Backend().apply { restrictResult = raw }
            val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
            assertEquals(DurableCode.MUTATION_UNPROVEN, writer.restrictAndObserveExisting("projection", 10).code)
            assertEquals(DurableCode.CLOSED, writer.read("projection", 10).code)
            assertEquals(DurableCode.MUTATION_UNPROVEN, writer.closeResult())
            assertEquals(1, backend.restrictCalls)
        }
    }

    @Test fun syncExistingOwnsTheWriterUntilTheResultIsValidatedBeforeConcurrentClose() {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val backend = Backend().apply { beforeSyncReturn = { entered.countDown(); check(release.await(5, TimeUnit.SECONDS)) } }
        val writer = CheckedDurableFilePrimitives(backend).openWriter(directory, "lock", identity).writer!!
        var result: DurableSyncResult? = null
        var closeCode: DurableCode? = null
        val observer = Thread { result = writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10) }
        observer.start()
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val closer = Thread { closeStarted.countDown(); closeCode = writer.closeResult() }
        closer.start()
        assertTrue(closeStarted.await(5, TimeUnit.SECONDS))
        assertEquals(0, backend.closeCalls)
        release.countDown()
        observer.join(5000); closer.join(5000)
        assertFalse(observer.isAlive); assertFalse(closer.isAlive)
        assertEquals(DurableCode.OK, result!!.code)
        assertEquals(DurableCode.OK, closeCode)
        assertEquals(1, backend.closeCalls)
        assertEquals(DurableCode.CLOSED, writer.syncAndObserveExisting("projection", DurableSnapshot(identity, byteArrayOf(4, 8)), 10).code)
    }

    @Test fun borrowedPipeRejectsFullWidthFdUidAndAccessBeforeNativeCall() {
        val backend = Backend()
        val files = CheckedDurableFilePrimitives(backend)
        for (fd in listOf(Long.MIN_VALUE, -1, Int.MAX_VALUE.toLong() + 1, Long.MAX_VALUE))
            assertEquals(DurableCode.INVALID, files.prepareBorrowedPipe(fd, 1000, 0).code)
        for (uid in listOf(Long.MIN_VALUE, -1, 0xffff_ffffL, Long.MAX_VALUE))
            assertEquals(DurableCode.INVALID, files.prepareBorrowedPipe(7, uid, 0).code)
        for (access in listOf(Int.MIN_VALUE, -1, 2, 3, Int.MAX_VALUE))
            assertEquals(DurableCode.INVALID, files.prepareBorrowedPipe(7, 1000, access).code)
        assertEquals(0, backend.pipeCalls)
        assertEquals(0, backend.closeCalls)
        assertTrue(backend.closedDirectories.isEmpty())
    }

    @Test fun borrowedPipeReturnsOnlyVerifiedFifoIdentityAndPreservesDescriptorOwnership() {
        for (fd in listOf(0L, Int.MAX_VALUE.toLong())) for (access in 0..1) {
            val backend = Backend().apply { pipeResult = DurableRawResult(0, longArrayOf(0, Long.MAX_VALUE, 0xffff_fffeL, 4480, access.toLong(), 1), null) }
            val result = CheckedDurableFilePrimitives(backend).prepareBorrowedPipe(fd, 0xffff_fffeL, access)
            assertEquals(DurableCode.OK, result.code)
            assertEquals(DurableFileIdentity(0, Long.MAX_VALUE), result.observation!!.identity)
            assertEquals(0xffff_fffeL, result.observation.uid)
            assertEquals(4480, result.observation.mode)
            assertEquals(access, result.observation.access)
            assertTrue(result.observation.nonblocking)
            assertEquals(listOf(fd, 0xffff_fffeL, access.toLong()), backend.pipeArguments)
            assertEquals(0, backend.closeCalls)
            assertEquals(0, backend.readCalls)
            assertEquals(0, backend.mutationCalls)
            assertTrue(backend.closedDirectories.isEmpty())
        }
    }

    @Test fun malformedPipeMetadataAndImpossibleCodesAreMutationUnprovenNotUnsupported() {
        val valid = longArrayOf(1, 2, 1000, 4480, 0, 1)
        val invalid = listOf(
            valid.clone().also { it[0] = -1 }, valid.clone().also { it[1] = 0 },
            valid.clone().also { it[1] = -1 }, valid.clone().also { it[2] = -1 },
            valid.clone().also { it[2] = 1001 }, valid.clone().also { it[2] = 0xffff_ffffL },
            valid.clone().also { it[3] = 384 }, valid.clone().also { it[3] = 33152 },
            valid.clone().also { it[3] = Long.MAX_VALUE }, valid.clone().also { it[4] = 1 },
            valid.clone().also { it[4] = 0x1_0000_0000L }, valid.clone().also { it[5] = 0 },
            valid.clone().also { it[5] = 2 }, valid.clone().also { it[5] = Long.MAX_VALUE },
            valid.copyOf(5), valid.copyOf(7), longArrayOf(),
        ).map { DurableRawResult(0, it, null) } + listOf(
            DurableRawResult(0, valid.clone(), byteArrayOf()), DurableRawResult(0, valid.clone(), byteArrayOf(4)),
            DurableRawResult(6, longArrayOf(1), null), DurableRawResult(3, longArrayOf(), byteArrayOf(4)),
            DurableRawResult(1, longArrayOf(), null), DurableRawResult(8, longArrayOf(), null),
            DurableRawResult(9, longArrayOf(), null), DurableRawResult(999, longArrayOf(), null),
        )
        for (raw in invalid) {
            val backend = Backend().apply { pipeResult = raw }
            val result = CheckedDurableFilePrimitives(backend).prepareBorrowedPipe(7, 1000, 0)
            assertEquals(DurableCode.MUTATION_UNPROVEN, result.code)
            assertNull(result.observation)
            assertEquals(0, backend.closeCalls)
            assertTrue(backend.closedDirectories.isEmpty())
            assertTrue(raw.bytes?.all { it == 0.toByte() } != false)
        }
    }

    @Test fun pipeFailureNeverClosesOrFallsBackAndExceptionRemainsUnproven() {
        for (code in listOf(DurableCode.INVALID, DurableCode.UNSAFE, DurableCode.CONFLICT, DurableCode.IO_FAILURE, DurableCode.UNSUPPORTED, DurableCode.MUTATION_UNPROVEN)) {
            val backend = Backend().apply { pipeResult = DurableRawResult(code.wire, longArrayOf(), null) }
            assertEquals(code, CheckedDurableFilePrimitives(backend).prepareBorrowedPipe(7, 1000, 0).code)
            assertEquals(1, backend.pipeCalls)
            assertEquals(0, backend.closeCalls)
            assertEquals(0, backend.mutationCalls)
            assertEquals(0, backend.readCalls)
        }
        val backend = Backend().apply { pipeFailure = IOException("synthetic partial flag mutation") }
        assertEquals(DurableCode.MUTATION_UNPROVEN, CheckedDurableFilePrimitives(backend).prepareBorrowedPipe(7, 1000, 0).code)
        assertEquals(0, backend.closeCalls)
        assertTrue(backend.closedDirectories.isEmpty())
    }

    @Test fun pipeObservationOwnsItsMetadataAndResultRejectsInvalidCombinations() {
        val metadata = longArrayOf(1, 2, 1000, 4480, 0, 1)
        val backend = Backend().apply { pipeResult = DurableRawResult(0, metadata, null) }
        val observed = CheckedDurableFilePrimitives(backend).prepareBorrowedPipe(7, 1000, 0).observation!!
        metadata.fill(0)
        assertEquals(DurableFileIdentity(1, 2), observed.identity)
        assertEquals(1000, observed.uid)
        assertEquals(4480, observed.mode)
        assertEquals(0, observed.access)
        assertTrue(observed.nonblocking)
        assertThrows(IllegalArgumentException::class.java) { DurablePipeResult(DurableCode.OK) }
        assertThrows(IllegalArgumentException::class.java) { DurablePipeResult(DurableCode.MUTATION_UNPROVEN, observed) }
        for (code in listOf(DurableCode.ABSENT, DurableCode.CLOSED, DurableCode.CLOSE_UNPROVEN))
            assertThrows(IllegalArgumentException::class.java) { DurablePipeResult(code) }
    }

    /** Source-boundary check only; installed API-26 coverage proves the platform behavior. */
    @Test fun nativeCreationDurabilityIsProvenByCreatedObjectsNotOptionalUnnamedTemporarySupport() {
        val source = nativeSource("kvpn_durable_fs.c")
        val child = source.substringAfter("int kvpn_fs_create_child_directory_exclusive(")
            .substringBefore("int kvpn_fs_close_directory(")
        val lock = source.substringAfter("int kvpn_fs_bootstrap_lock(")
            .substringBefore("static int expected_old(")
        for (body in listOf(child, lock)) {
            assertFalse(body.contains("bootstrap_preflight"))
            assertFalse(body.contains("O_TMPFILE"))
            assertTrue(body.contains("if (changed) code = KVPN_FS_MUTATION_UNPROVEN"))
        }
        assertTrue(child.indexOf("mkdirat(") < child.indexOf("sync_fd(child)"))
        assertTrue(child.indexOf("sync_fd(child)") < child.indexOf("verify_child_name("))
        assertTrue(child.indexOf("verify_child_name(") < child.lastIndexOf("sync_fd(dir)"))
        assertTrue(lock.indexOf("create_leaf(") < lock.indexOf("sync_fd(fd)"))
        assertTrue(lock.indexOf("sync_fd(fd)") < lock.indexOf("verify_name("))
        val publishedDirectorySync = lock.lastIndexOf("sync_fd(dir)")
        assertTrue(lock.indexOf("verify_name(") < publishedDirectorySync)
        assertTrue(publishedDirectorySync < lock.indexOf("read_leaf("))
        assertTrue(lock.indexOf("read_leaf(") < lock.indexOf("verify_directory("))
    }

    /** Source-boundary check only; installed Android execution is covered by the device test. */
    @Test fun nativeFrameworkProjectionRestrictionIsDescriptorRelativeAndPreflightsBeforeModeMutation() {
        val source = nativeSource("kvpn_durable_fs.c")
        val helper = source.substringAfter("int kvpn_fs_restrict_existing(")
            .substringBefore("int kvpn_fs_mutate(")
        assertTrue(source.contains("mode == 0600 || mode == 0660"))
        assertTrue(helper.contains("open_leaf(dir, name, O_RDWR)"))
        assertTrue(helper.indexOf("sync_fd(lock)") < helper.indexOf("sync_fd(dir)"))
        assertTrue(helper.indexOf("sync_fd(dir)") < helper.indexOf("sync_fd(file)"))
        assertTrue(helper.indexOf("sync_fd(file)") < helper.indexOf("fchmod(file, 0600)"))
        assertTrue(helper.contains("read_restrictable_open_file"))
        assertTrue(helper.contains("read_leaf(dir, d->uid, name"))
        assertTrue(helper.contains("same_identity(&before, &reopened)"))
        assertTrue(helper.contains("KVPN_FS_MUTATION_UNPROVEN"))
        assertFalse(Regex("\\bchmod\\s*\\(").containsMatchIn(helper))
    }

    /** Source-boundary check only; this does not execute Android libc or establish installed behavior. */
    @Test fun nativePipeSourceHasBoundedInterruptedCallsAndNeverClosesBorrowedFd() {
        val source = nativeSource("kvpn_durable_fs.c")
        val helper = source.substringAfter("int kvpn_pipe_prepare_borrowed(").substringBefore("\n}")
        assertTrue(helper.contains("pipe_stat(fd, &before)"))
        assertTrue(helper.contains("pipe_stat(fd, &after)"))
        assertTrue(helper.contains("++retries < KVPN_PIPE_MAX_ATTEMPTS"))
        assertFalse(Regex("\\b(close|close_once|open|openat|read|write|dup|dup2)\\s*\\(").containsMatchIn(helper))
        assertTrue(helper.contains("flags | O_NONBLOCK"))
        assertTrue(helper.contains("KVPN_FS_MUTATION_UNPROVEN"))
        for (name in listOf("pipe_flags", "pipe_stat")) {
            val body = source.substringAfter("static int $name(").substringBefore("\n}")
            assertTrue(body.contains("++retries < KVPN_PIPE_MAX_ATTEMPTS"))
        }
    }

    private fun nativeSource(leaf: String): String {
        require(leaf in setOf("kvpn_durable_fs.c", "kvpn_durable_fs_jni.c"))
        val root = java.nio.file.Paths.get(checkNotNull(System.getProperty("kurdistan.test.sourceRoot")) {
            "An explicit test source root is required"
        })
        require(root.isAbsolute && root.normalize() == root)
        val relative = java.nio.file.Paths.get("android", "core", "native-jni", "src", "main", "cpp", leaf)
        var current = root
        require(!java.nio.file.Files.isSymbolicLink(current))
        for (component in relative) {
            current = current.resolve(component)
            require(current.startsWith(root) && !java.nio.file.Files.isSymbolicLink(current))
        }
        require(java.nio.file.Files.isRegularFile(current, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        require(java.nio.file.Files.size(current) in 1..(1L shl 20))
        return java.nio.file.Files.newInputStream(current).use { stream ->
            val bytes = stream.readBytes()
            try {
                require(bytes.size in 1..(1 shl 20))
                bytes.toString(Charsets.UTF_8)
            } finally { bytes.fill(0) }
        }
    }

    private class Backend : DurableNativeTransport {
        var readCalls = 0
        var listCalls = 0
        var readDirectory: DurableDirectory? = null
        var closeCalls = 0
        var mutationCalls = 0
        var syncCalls = 0
        var restrictCalls = 0
        var pipeCalls = 0
        var pipeArguments: List<Long>? = null
        var pipeResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 4480, 0, 1), null)
        var pipeFailure: Throwable? = null
        var syncResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2), byteArrayOf(4, 8))
        var syncFailure: Throwable? = null
        var restrictResult = DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 2, 0), byteArrayOf(4, 8))
        var restrictFailure: Throwable? = null
        var beforeSyncReturn: (() -> Unit)? = null
        var readResult = DurableRawResult(1, longArrayOf(), null)
        var listResult = DurableRawResult(0, longArrayOf(0), byteArrayOf())
        var openResult = DurableRawResult(0, longArrayOf(8, 9), null)
        var mutationResult = DurableRawResult(0, longArrayOf(), null)
        var closeResult = DurableRawResult(0, longArrayOf(), null)
        var closeFailure: Throwable? = null
        val closedSessions = mutableListOf<List<Long>>()
        var childOpenCalls = 0
        var childCreateCalls = 0
        var childResult = DurableRawResult(0, longArrayOf(11, 1, 12, 1000, 448, 2), null)
        var directoryCloseResult = DurableRawResult(0, longArrayOf(), null)
        var childFailure: Throwable? = null
        var directoryCloseFailure: Throwable? = null
        val closedDirectories = java.util.Collections.synchronizedList(mutableListOf<Long>())
        override fun preparePipe(fd: Long, expectedUid: Long, expectedAccess: Int): DurableRawResult {
            pipeCalls++
            pipeArguments = listOf(fd, expectedUid, expectedAccess.toLong())
            pipeFailure?.let { throw it }
            return pipeResult
        }
        override fun openChildDirectory(directory: DurableDirectory, leaf: ByteArray, expected: DurableFileIdentity?): DurableRawResult {
            childOpenCalls++
            childFailure?.let { throw it }
            return childResult
        }
        override fun createChildDirectoryExclusive(directory: DurableDirectory, leaf: ByteArray): DurableRawResult {
            childCreateCalls++
            childFailure?.let { throw it }
            return childResult
        }
        override fun closeDirectory(fd: Long): DurableRawResult {
            closedDirectories.add(fd)
            directoryCloseFailure?.let { throw it }
            return directoryCloseResult
        }
        override fun read(directory: DurableDirectory, leaf: ByteArray, maxBytes: Int): DurableRawResult {
            readCalls++
            readDirectory = directory
            return readResult
        }
        override fun list(directory: DurableDirectory, maxEntries: Int): DurableRawResult {
            listCalls++
            return listResult
        }
        override fun bootstrapLock(directory: DurableDirectory, leaf: ByteArray) =
            DurableRawResult(0, longArrayOf(1, 2, 1000, 384, 1, 0), null)
        override fun openWriter(directory: DurableDirectory, leaf: ByteArray, lock: DurableFileIdentity) = openResult
        override fun mutate(session: LongArray, directory: DurableDirectory, lockLeaf: ByteArray,
            lock: DurableFileIdentity, leaf: ByteArray, tempLeaf: ByteArray?, expected: DurableSnapshot?,
            replacement: ByteArray?, maxBytes: Int): DurableRawResult {
            mutationCalls++
            return mutationResult
        }
        override fun close(session: LongArray): DurableRawResult {
            closeCalls++
            closedSessions.add(session.toList())
            closeFailure?.let { throw it }
            return closeResult
        }
        override fun syncExisting(session: LongArray, directory: DurableDirectory, lockLeaf: ByteArray,
            lock: DurableFileIdentity, leaf: ByteArray, expected: DurableSnapshot, maxBytes: Int): DurableRawResult {
            syncCalls++
            syncFailure?.let { throw it }
            beforeSyncReturn?.invoke()
            return syncResult
        }
        override fun restrictExisting(session: LongArray, directory: DurableDirectory, lockLeaf: ByteArray,
            lock: DurableFileIdentity, leaf: ByteArray, maxBytes: Int): DurableRawResult {
            restrictCalls++
            restrictFailure?.let { throw it }
            return restrictResult
        }
    }
}

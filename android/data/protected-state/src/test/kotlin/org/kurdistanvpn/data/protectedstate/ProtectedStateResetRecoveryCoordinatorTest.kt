// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*
import java.nio.ByteBuffer
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class ProtectedStateResetRecoveryCoordinatorTest {
    @Test fun explicitFreshInitializationHoldsKnownLockAcrossAbsenceCheckAndKeyCreation() {
        val events = mutableListOf<String>()
        val directory = DurableDirectory(10, 10000, DurableFileIdentity(1, 2))
        val lock = DurableFileIdentity(1, 3)
        val primitives = emptyInitializationFiles(events, lock)
        val created = initializeUnderEmptyRootLease(primitives, directory, lock,
            requireAbsentSource = { events += "check-absence" },
            create = { events += "create-key"; 7 })
        assertEquals(7, created)
        assertEquals(listOf("lock", "list", "read-lock", "check-absence", "create-key", "close"), events)
    }

    @Test fun explicitFreshInitializationRejectsPartialStateChangedLockKeyRaceAndUnprovenClose() {
        val directory = DurableDirectory(10, 10000, DurableFileIdentity(1, 2))
        val lock = DurableFileIdentity(1, 3)
        for (fault in listOf("extra-file", "changed-lock", "key-race", "close", "create")) {
            val events = mutableListOf<String>()
            val primitives = emptyInitializationFiles(events, lock, fault)
            assertThrows("$fault must not report initialization", IllegalStateException::class.java) {
                initializeUnderEmptyRootLease(primitives, directory, lock,
                    requireAbsentSource = { events += "check-absence"; check(fault != "key-race") },
                    create = { events += "create-key"; check(fault != "create"); 7 })
            }
            assertEquals(1, events.count { it == "close" })
            if (fault in listOf("extra-file", "changed-lock", "key-race"))
                assertFalse(events.contains("create-key"))
        }
    }

    private fun emptyInitializationFiles(events: MutableList<String>, lock: DurableFileIdentity,
        fault: String = ""): DurableFilePrimitives = object : DurableFilePrimitives {
        override fun read(directory: DurableDirectory, leaf: String, maxBytes: Int): DurableReadResult = error("unlocked read")
        override fun list(directory: DurableDirectory, maxEntries: Int): DurableListResult = error("unlocked list")
        override fun bootstrapLock(directory: DurableDirectory, lockLeaf: String): DurableIdentityResult = error("unexpected bootstrap")
        override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity): DurableOpenResult {
            assertEquals("protected-state.lock", lockLeaf)
            assertEquals(lock, expectedLock)
            events += "lock"
            return DurableOpenResult(DurableCode.OK, object : DurableWriter {
                override fun list(maxEntries: Int): DurableListResult {
                    events += "list"
                    val observed = if (fault == "changed-lock") DurableFileIdentity(1, 8) else lock
                    val entries = mutableListOf(DurableDirectoryEntry(lockLeaf, observed, 0))
                    if (fault == "extra-file") entries += DurableDirectoryEntry("journal-control", DurableFileIdentity(1, 9), 3)
                    return DurableListResult(DurableCode.OK, entries)
                }
                override fun read(leaf: String, maxBytes: Int): DurableReadResult {
                    events += "read-lock"
                    assertEquals(lockLeaf, leaf)
                    return DurableReadResult(DurableCode.OK, DurableSnapshot(lock, byteArrayOf()))
                }
                override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int): DurableMutationResult = error("unexpected write")
                override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult = error("unexpected delete")
                override fun closeResult(): DurableCode { events += "close"; return if (fault == "close") DurableCode.CLOSE_UNPROVEN else DurableCode.OK }
                override fun close() { closeResult() }
            })
        }
    }

    @Test fun activeSessionRetirementFollowsDirtyAndPrecedesEveryDestructiveOperation() {
        val rig = Rig()
        val session = rig.sessions.register("e".repeat(32), 1, 2,
            AutoCloseable { rig.events += "active-session-retired" })!!
        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        val dirty = rig.events.indexOf("after:put:journal-control")
        val retired = rig.events.indexOf("active-session-retired")
        val deleted = rig.events.indexOfFirst { it.startsWith("before:delete:") }
        assertTrue(dirty in 0 until retired && retired in 0 until deleted)
        session.close()
        assertEquals(1, rig.events.count { it == "active-session-retired" })
    }

    @Test fun finalLeaseAndUnprovenSessionCleanupCannotAuthorizeResetDeletion() {
        val leased = Rig()
        val session = leased.sessions.register("e".repeat(32), 1, 2, AutoCloseable {})!!
        val lease = leased.sessions.acquireFinalLease(session, 2, 110)!!
        assertEquals(ResetRecoveryResult.RECOVERY_REQUIRED, leased.engine().start(OPERATION))
        assertTrue(leased.productFilesPresent())
        assertFalse(leased.events.contains("after:put:journal-reset"))
        lease.close()
        val failed = Rig()
        failed.sessions.register("e".repeat(32), 1, 2, AutoCloseable { error("unproven cleanup") })!!
        assertEquals(ResetRecoveryResult.MUTATION_UNPROVEN, failed.engine().start(OPERATION))
        assertTrue(failed.readControlIfAvailable()!!.dirty)
        assertTrue(failed.productFilesPresent())
        assertTrue(failed.keyPresent)
        assertFalse(failed.events.any { it.startsWith("before:delete:") })
    }

    @Test fun completeResetAuthenticatesManifestBeforeDeletionAndReadyBeforeKeyLast() {
        val rig = Rig()
        val outcome = rig.engine().start(OPERATION)
        assertEquals(rig.events.joinToString("\n"), ResetRecoveryResult.COMPLETED, outcome)
        val manifest = rig.events.indexOf("after:put:journal-reset")
        val dirty = rig.events.indexOf("after:put:journal-control")
        val firstDelete = rig.events.indexOfFirst { it.startsWith("before:delete:") }
        val ready = rig.events.indexOf("after:put:journal-reset-ready")
        val keyErase = rig.events.indexOf("before:key-erase")
        assertTrue(manifest in 0 until dirty)
        assertTrue(dirty in 0 until firstDelete)
        assertTrue(ready in 0 until keyErase)
        assertTrue(rig.events.subList(ready + 1, keyErase).contains("after:read:journal-reset-ready"))
        assertFalse(rig.keyPresent)
        assertTrue(rig.onlyLocksRemain())
        assertEquals(0, rig.decryptAfterKeyErasure)
        assertEquals(1, rig.keyEraseCalls)
        assertEquals(ResetRecoveryResult.NO_RESET_PENDING, rig.engine().resume())
        assertEquals(1, rig.keyEraseCalls)
    }

    @Test fun completeResetRemovesOnlyTheFixedJournalOwnedMigrationSnapshotLeaf() {
        val rig = Rig()
        rig.putProduct(ResetDirectoryRole.JOURNAL, "migration-legacy-metadata.db", byteArrayOf(7, 8, 9))

        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertFalse(rig.hasFile(ResetDirectoryRole.JOURNAL, "migration-legacy-metadata.db"))
        assertTrue(rig.onlyLocksRemain())
    }

    @Test fun completeResetManifestIncludesAndDeletesTheFixedPresentationOverlayLeaf() {
        val rig = Rig()
        rig.putProduct(ResetDirectoryRole.JOURNAL, "${ProtectedPresentationOverlay.NAME}.blob", byteArrayOf(7, 8, 9))

        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertFalse(rig.hasFile(ResetDirectoryRole.JOURNAL, "${ProtectedPresentationOverlay.NAME}.blob"))
        assertTrue(rig.onlyLocksRemain())
    }

    @Test fun manifestOrReadyForgeryNeverBecomesAuthorityToDeleteOrErase() {
        for (name in listOf("journal-reset", "journal-reset-ready")) {
            val rig = Rig()
            rig.corruptAfterWrite = name
            assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
            assertTrue(rig.keyPresent)
            assertEquals(0, rig.keyEraseCalls)
            if (name == "journal-reset") assertTrue(rig.productFilesPresent())
        }
    }

    @Test fun everyCrashBoundaryEitherResumesOriginalOperationOrQuarantinesAfterKeyLoss() {
        val successful = Rig()
        assertEquals(ResetRecoveryResult.COMPLETED, successful.engine().start(OPERATION))
        val count = successful.events.size
        assertTrue(count > 50)
        for (crashPoint in 1..count) {
            val rig = Rig()
            rig.crashAt = crashPoint
            try { rig.engine().start(OPERATION) } catch (_: SimulatedCrash) { }
            rig.crashAt = 0
            val before = rig.readControlIfAvailable()
            val result = rig.engine().resume()
            if (!rig.keyPresent && !rig.onlyLocksRemain()) {
                assertEquals("boundary $crashPoint", ResetRecoveryResult.QUARANTINED, result)
            } else if (result == ResetRecoveryResult.NO_RESET_PENDING) {
                assertTrue("boundary $crashPoint", (rig.keyPresent && rig.productFilesPresent()) || (!rig.keyPresent && rig.onlyLocksRemain()))
            } else {
                assertEquals("boundary $crashPoint", ResetRecoveryResult.COMPLETED, result)
                assertFalse(rig.keyPresent)
                assertTrue(rig.onlyLocksRemain())
            }
            before?.let { control ->
                if (control.dirty) {
                    assertArrayEquals(OPERATION, control.operationId())
                    assertEquals(3L, control.revision)
                    assertEquals(4L, control.reservedCleanRevision)
                    assertEquals(2L, control.reservedSequence)
                }
            }
            assertEquals(0, rig.decryptAfterKeyErasure)
            assertTrue(rig.keyEraseCalls <= 1)
        }
    }

    @Test fun repeatedFailedDeletionRetainsSameDurableOperationAndReservation() {
        val rig = Rig()
        rig.failDeleteLeaf = "protected-settings.preferences_pb"
        repeat(3) {
            val result = if (it == 0) rig.engine().start(OPERATION) else rig.engine().resume()
            assertNotEquals(ResetRecoveryResult.COMPLETED, result)
            val control = rig.readControlIfAvailable()!!
            assertTrue(control.dirty)
            assertEquals(3L, control.revision)
            assertEquals(4L, control.reservedCleanRevision)
            assertEquals(2L, control.reservedSequence)
            assertArrayEquals(OPERATION, control.operationId())
            assertTrue(rig.keyPresent)
        }
        rig.failDeleteLeaf = null
        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().resume())
    }

    @Test fun failedPreDirtyPublicationLeavesOnlyOriginalOperationRecoverable() {
        val rig = Rig()
        rig.crashOnEvent = "after:put:journal-reset"
        assertThrows(SimulatedCrash::class.java) { rig.engine().start(OPERATION) }
        assertEquals(2L, rig.readControlIfAvailable()!!.revision)
        assertTrue(rig.productFilesPresent())
        rig.crashOnEvent = null
        assertEquals(ResetRecoveryResult.RECOVERY_REQUIRED, rig.engine().start(ByteArray(32) { 7 }))
        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().resume())
    }

    @Test fun targetSubstitutionAndUnexpectedFilesCannotBeDeletedFromStaleManifest() {
        for (substitute in listOf(true, false)) {
            val rig = Rig()
            rig.crashOnEvent = "after:put:journal-reset"
            assertThrows(SimulatedCrash::class.java) { rig.engine().start(OPERATION) }
            rig.crashOnEvent = null
            if (substitute) rig.putProduct(ResetDirectoryRole.JOURNAL, "protected-settings.preferences_pb", byteArrayOf(4))
            else rig.putProduct(ResetDirectoryRole.JOURNAL, "surprise.pb", byteArrayOf(4))
            assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().resume())
            assertTrue(rig.keyPresent)
            assertEquals(0, rig.keyEraseCalls)
            assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, if (substitute) "protected-settings.preferences_pb" else "surprise.pb"))
        }
    }

    @Test fun preservationIncludesKnownLocksAndDetectsTheirReplacement() {
        val rig = Rig()
        rig.crashOnEvent = "after:put:journal-reset"
        assertThrows(SimulatedCrash::class.java) { rig.engine().start(OPERATION) }
        rig.crashOnEvent = null
        rig.putProduct(ResetDirectoryRole.JOURNAL, "protected-state.lock", byteArrayOf())
        assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().resume())
        assertTrue(rig.keyPresent)
        assertEquals(0, rig.keyEraseCalls)
    }

    @Test fun keyGenerationMismatchAndUnavailabilityNeverEraseAnything() {
        val absent = Rig()
        absent.keyPresent = false
        assertEquals(ResetRecoveryResult.QUARANTINED, absent.engine().start(OPERATION))
        assertTrue(absent.productFilesPresent())
        val unavailable = Rig()
        unavailable.keyUnavailable = true
        assertEquals(ResetRecoveryResult.MUTATION_UNPROVEN, unavailable.engine().start(OPERATION))
        assertTrue(unavailable.productFilesPresent())
        val changed = Rig()
        changed.crashOnEvent = "after:put:journal-reset"
        assertThrows(SimulatedCrash::class.java) { changed.engine().start(OPERATION) }
        changed.crashOnEvent = null
        changed.generation++
        assertEquals(ResetRecoveryResult.QUARANTINED, changed.engine().resume())
        assertTrue(changed.keyPresent)
        assertEquals(0, changed.keyEraseCalls)
    }

    @Test fun failedOrUnprovenNativeDeleteAndWriterCloseCannotPermitKeyErasure() {
        for (code in listOf(DurableCode.UNSUPPORTED, DurableCode.MUTATION_UNPROVEN, DurableCode.UNSAFE, DurableCode.CONFLICT)) {
            val rig = Rig()
            rig.deleteCode = code
            assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
            assertEquals(0, rig.keyEraseCalls)
        }
        val rig = Rig()
        rig.failLeaseClose = true
        assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertTrue(rig.productFilesPresent())
        assertEquals(0, rig.keyEraseCalls)
    }

    @Test fun successfulDeletionReturnWithoutAbsenceDoesNotAuthorizeReady() {
        val rig = Rig()
        rig.lieAboutDeletion = true
        assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertTrue(rig.keyPresent)
        assertEquals(0, rig.keyEraseCalls)
        assertFalse(rig.events.contains("after:put:journal-reset-ready"))
    }

    @Test fun keyEraseReturnWithoutAbsenceNeverDeletesRecoveryFiles() {
        val rig = Rig()
        rig.lieAboutKeyErase = true
        assertEquals(ResetRecoveryResult.MUTATION_UNPROVEN, rig.engine().start(OPERATION))
        assertTrue(rig.keyPresent)
        assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, "journal-reset-ready.blob"))
        assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, "journal-reset.blob"))
    }

    @Test fun failedPostEraseCleanupQuarantinesAndCannotAutomaticallyResume() {
        val rig = Rig()
        rig.failDeleteLeaf = "journal-reset.blob"
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().start(OPERATION))
        assertFalse(rig.keyPresent)
        val remaining = rig.rawInventory()
        rig.failDeleteLeaf = null
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().resume())
        assertEquals(remaining, rig.rawInventory())
        assertEquals(0, rig.decryptAfterKeyErasure)
    }

    @Test fun postEraseInodeSubstitutionIsNotDeletedAndRemainsQuarantined() {
        val rig = Rig()
        rig.afterKeyErase = { rig.putProduct(ResetDirectoryRole.JOURNAL, "journal-reset.blob", byteArrayOf(7)) }
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().start(OPERATION))
        assertFalse(rig.keyPresent)
        assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, "journal-reset.blob"))
    }

    @Test fun invalidOperationFailsBeforePublishingManifest() {
        for (operation in listOf(ByteArray(31), ByteArray(32), ByteArray(33))) {
            val rig = Rig()
            assertEquals(ResetRecoveryResult.MUTATION_UNPROVEN, rig.engine().start(operation))
            assertTrue(rig.productFilesPresent())
            assertFalse(rig.events.contains("after:put:journal-reset"))
        }
    }

    @Test fun expiredBoundedWorkLeavesResumableManifestWithoutLateKeyErasure() {
        val rig = Rig()
        var clock = 0L
        val engine = rig.engine { clock.also { clock += JournalLimits.RESTORE_NANOS } }
        assertNotEquals(ResetRecoveryResult.COMPLETED, engine.start(OPERATION))
        assertTrue(rig.keyPresent)
        assertEquals(0, rig.keyEraseCalls)
    }

    @Test fun corruptManifestCannotAdoptValidJournalPrefix() {
        val rig = Rig()
        rig.crashOnEvent = "after:put:journal-reset"
        assertThrows(SimulatedCrash::class.java) { rig.engine().start(OPERATION) }
        rig.crashOnEvent = null
        rig.storage.exclusive {
            val old = rig.storage.read("journal-reset", JournalLimits.CHECKPOINT_BYTES)!!
            val bad = old.clone().also { it[4] = 99 }
            rig.storage.compareAndReplace("journal-reset", old, bad)
        }
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().resume())
        assertTrue(rig.productFilesPresent())
        assertEquals(0, rig.keyEraseCalls)
    }

    @Test fun noFilesystemCapabilityCreatesOrReplacesObjectsDuringReset() {
        val rig = Rig()
        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertEquals(0, rig.rawReplacements)
        assertEquals(0, rig.newKeyCalls)
        assertEquals(0, rig.deleteLockCalls)
    }

    @Test fun finalCloseUncertaintyCannotBecomeHistoricalSuccessAfterRestart() {
        val rig = Rig()
        rig.failCloseAfterKeyErase = true
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().start(OPERATION))
        assertFalse(rig.keyPresent)
        assertTrue(rig.onlyLocksRemain())
        rig.failCloseAfterKeyErase = false
        assertEquals(ResetRecoveryResult.NO_RESET_PENDING, rig.engine().resume())
        assertEquals(0, rig.newKeyCalls)
    }

    @Test fun inputOperationIsSnapshottedBeforeCallerCanChangeIt() {
        val rig = Rig()
        val callerOperation = OPERATION.clone()
        rig.onEvent = { event -> if (event == "before:put:journal-reset") callerOperation.fill(9) }
        assertEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(callerOperation))
        assertTrue(callerOperation.all { it == 9.toByte() })
        assertArrayEquals(OPERATION, rig.lastResetOperation)
    }

    @Test fun invalidTraversalAndDuplicateDirectoryCapabilitiesAreRejected() {
        val rig = Rig()
        val binding = rig.bindings.first()
        for (leaf in listOf("..", ".", "a/b", "a\\b", "a\u0000b", "C:root", "a".repeat(256))) {
            assertThrows(IllegalArgumentException::class.java) { binding.copy(lockLeaf = leaf) }
        }
        assertThrows(IllegalArgumentException::class.java) { DurableResetFileAccess(listOf(binding, binding)) { error("no access") } }
        assertThrows(IllegalArgumentException::class.java) { DurableResetFileAccess(emptyList()) { error("no access") } }
    }

    @Test fun completeResetUsesOneActualRootAndRejectsMissingOrAliasedCapabilities() {
        val rig = Rig()
        assertThrows(IllegalArgumentException::class.java) {
            DurableResetFileAccess(rig.bindings.dropLast(1)) { error("no access") }
        }
        assertEquals(1, rig.bindings.size)
        val alias = rig.bindings.single()
        assertThrows(IllegalArgumentException::class.java) { DurableResetFileAccess(listOf(alias, alias)) { error("no access") } }
    }

    @Test fun timeoutAfterKeyErasureLeavesRecoveryResidueQuarantined() {
        val rig = Rig()
        var time = 0L
        rig.afterKeyErase = { time = JournalLimits.RESTORE_NANOS + 1 }
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine { time }.start(OPERATION))
        assertFalse(rig.keyPresent)
        assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, "journal-reset-ready.blob"))
        assertEquals(ResetRecoveryResult.QUARANTINED, rig.engine().resume())
    }

    @Test fun manifestFieldsAndReadyDigestHaveAnIndependentCanonicalOracle() {
        val rig = Rig()
        rig.crashOnEvent = "after:put:journal-reset-ready"
        assertThrows(SimulatedCrash::class.java) { rig.engine().start(OPERATION) }
        rig.crashOnEvent = null
        val manifest = rig.storage.read("journal-reset", JournalLimits.CHECKPOINT_BYTES)!!
        val ready = rig.storage.read("journal-reset-ready", 96)!!
        val reader = ByteBuffer.wrap(manifest)
        assertEquals(0x4b525331, reader.int)
        assertEquals(1, reader.get().toInt())
        assertEquals(243, reader.short.toInt())
        val prior = ByteArray(243).also(reader::get)
        assertEquals(2L, JournalControl.decode(prior).revision)
        assertArrayEquals(OPERATION, ByteArray(32).also(reader::get))
        assertEquals(7, reader.int)
        assertEquals(1, reader.get().toInt())
        val hash = java.security.MessageDigest.getInstance("SHA-256").run {
            update("kurdistan-complete-reset-manifest-v1\u0000".toByteArray(Charsets.US_ASCII))
            update(byteArrayOf((manifest.size ushr 24).toByte(), (manifest.size ushr 16).toByte(), (manifest.size ushr 8).toByte(), manifest.size.toByte()))
            digest(manifest)
        }
        assertEquals(96, ready.size)
        assertArrayEquals(byteArrayOf(0x4b, 0x52, 0x52, 0x31), ready.copyOfRange(0, 4))
        assertArrayEquals(ByteArray(16) { 1 }, ready.copyOfRange(4, 20))
        assertArrayEquals(OPERATION, ready.copyOfRange(20, 52))
        assertEquals(4L, ByteBuffer.wrap(ready, 52, 8).long)
        assertEquals(7, ByteBuffer.wrap(ready, 60, 4).int)
        assertArrayEquals(hash, ready.copyOfRange(64, 96))
    }

    @Test fun unrelatedLeafCannotBeIncludedInAnOtherwiseValidResetManifest() {
        val rig = Rig()
        rig.putProduct(ResetDirectoryRole.JOURNAL, "unrelated-notes.txt", byteArrayOf(8))
        assertNotEquals(ResetRecoveryResult.COMPLETED, rig.engine().start(OPERATION))
        assertTrue(rig.keyPresent)
        assertEquals(0, rig.keyEraseCalls)
        assertTrue(rig.productFilesPresent())
        assertTrue(rig.hasFile(ResetDirectoryRole.JOURNAL, "unrelated-notes.txt"))
        assertFalse(rig.events.any { it.startsWith("before:delete:") })
    }

    private class SimulatedCrash : Error()
    private class FileValue(val identity: DurableFileIdentity, val bytes: ByteArray)

    private class Rig {
        val sessions = ActiveSessionMutationPolicy { 100 }
        val events = ArrayList<String>()
        private val files = ResetDirectoryRole.entries.associateWith { linkedMapOf<String, FileValue>() }
        private var nextInode = 100L
        private var nonce = 1L
        private var held = false
        private var suppressEvents = true
        var crashAt = 0
        var crashOnEvent: String? = null
        var corruptAfterWrite: String? = null
        var failDeleteLeaf: String? = null
        var deleteCode = DurableCode.OK
        var lieAboutDeletion = false
        var lieAboutKeyErase = false
        var failLeaseClose = false
        var failCloseAfterKeyErase = false
        var keyPresent = true
        var keyUnavailable = false
        var generation = 7
        var keyEraseCalls = 0
        var newKeyCalls = 0
        var deleteLockCalls = 0
        var rawReplacements = 0
        var decryptAfterKeyErasure = 0
        var afterKeyErase: (() -> Unit)? = null
        var onEvent: ((String) -> Unit)? = null
        var lastResetOperation: ByteArray? = null
        private val keyBytes = ByteArray(32) { (it + 1).toByte() }
        val bindings = ResetDirectoryRole.entries.map { role ->
            val leaf = if (role == ResetDirectoryRole.JOURNAL) "protected-state.lock" else role.name.lowercase() + ".lock"
            val identity = DurableFileIdentity(1, ++nextInode)
            files.getValue(role)[leaf] = FileValue(identity, byteArrayOf())
            ResetDirectoryBinding(role, DurableDirectory(role.wire.toLong(), 10000, DurableFileIdentity(1, role.wire + 10L)), leaf, identity)
        }
        val storage = object : JournalStorage {
            override fun <T> exclusive(block: () -> T): T {
                check(!held)
                event("before:lease")
                held = true
                try { return block() }
                finally {
                    held = false
                    event("after:lease-close")
                    if (failLeaseClose || (failCloseAfterKeyErase && !keyPresent)) error("MUTATION_UNPROVEN")
                }
            }
            override fun read(name: String, maximum: Int): ByteArray? {
                event("before:read:$name")
                val raw = files.getValue(ResetDirectoryRole.JOURNAL)["$name.blob"]?.bytes ?: return null
                if (!keyPresent) { decryptAfterKeyErasure++; error("key absent") }
                val iv = raw.copyOfRange(0, 12)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
                cipher.updateAAD(name.toByteArray())
                val value = cipher.doFinal(raw, 12, raw.size - 12)
                check(value.size <= maximum)
                event("after:read:$name")
                return value
            }
            override fun compareAndReplace(name: String, expected: ByteArray?, replacement: ByteArray) {
                check(held && keyPresent)
                val old = read(name, JournalLimits.CHECKPOINT_BYTES)
                check(if (expected == null) old == null else old?.contentEquals(expected) == true)
                old?.fill(0)
                event("before:put:$name")
                if (name == "journal-reset") lastResetOperation = replacement.copyOfRange(250, 282)
                val iv = ByteBuffer.allocate(12).putInt(0).putLong(nonce++).array()
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), GCMParameterSpec(128, iv))
                cipher.updateAAD(name.toByteArray())
                val encrypted = iv + cipher.doFinal(replacement)
                if (corruptAfterWrite == name) { encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte(); corruptAfterWrite = null }
                files.getValue(ResetDirectoryRole.JOURNAL)["$name.blob"] = FileValue(DurableFileIdentity(1, ++nextInode), encrypted)
                event("after:put:$name")
            }
            override fun delete(name: String, expected: ByteArray) = error("Reset cannot use plaintext deletion receipts")
            override fun inventory(maximum: Int): List<JournalStoredEntry> = files.getValue(ResetDirectoryRole.JOURNAL).map {
                JournalStoredEntry(if (it.key.startsWith("journal-")) it.key.removeSuffix(".blob") else it.key, it.value.bytes.size.toLong())
            }.also { check(it.size <= maximum) }
        }
        private val key = object : ExistingResetKeyAccess {
            override fun observe(): ResetKeyObservation {
                event("before:key-lookup")
                return if (keyUnavailable) ResetKeyObservation.Unavailable else if (keyPresent) ResetKeyObservation.Present(generation) else ResetKeyObservation.Absent
            }
            override fun eraseExisting(expectedGeneration: Int) {
                check(held && keyPresent && generation == expectedGeneration)
                event("before:key-erase")
                keyEraseCalls++
                if (!lieAboutKeyErase) keyPresent = false
                afterKeyErase?.invoke()
                event("after:key-erase")
            }
        }
        init {
            val journal = ProtectedStateOperationJournal(storage)
            journal.initialize(ByteArray(16) { 1 })
            check(journal.mutate(MutationKind.SETTINGS, ByteArray(32) { 2 }, byteArrayOf(9), {}, { byteArrayOf(9) }) == ProtectedMutationStatus.COMMITTED)
            putProduct(ResetDirectoryRole.JOURNAL, "object-cccccccccccccccccccccccccccccccccccccccccccccccccccccccc", byteArrayOf(1, 2, 3))
            putProduct(ResetDirectoryRole.JOURNAL, "object-dddddddddddddddddddddddddddddddddddddddddddddddddddddddd", byteArrayOf(2, 3, 4))
            putProduct(ResetDirectoryRole.JOURNAL, "protected-metadata.db", byteArrayOf(3, 4, 5))
            putProduct(ResetDirectoryRole.JOURNAL, "protected-settings.preferences_pb", byteArrayOf(4, 5, 6))
            suppressEvents = false
        }
        fun engine(clock: () -> Long = System::nanoTime): ProtectedStateResetRecoveryCoordinator =
            ProtectedStateResetRecoveryCoordinator(storage, DurableResetFileAccess(bindings, ::writer), key, sessions, clock)
        fun event(value: String) {
            if (suppressEvents) return
            events += value
            onEvent?.invoke(value)
            if ((crashAt > 0 && events.size == crashAt) || crashOnEvent == value) throw SimulatedCrash()
        }
        fun putProduct(role: ResetDirectoryRole, leaf: String, bytes: ByteArray) {
            files.getValue(role)[leaf] = FileValue(DurableFileIdentity(1, ++nextInode), bytes.clone())
        }
        fun hasFile(role: ResetDirectoryRole, leaf: String): Boolean = files.getValue(role).containsKey(leaf)
        fun onlyLocksRemain(): Boolean = bindings.all { binding ->
            files.getValue(binding.role).keys == setOf(binding.lockLeaf) && files.getValue(binding.role).getValue(binding.lockLeaf).identity == binding.lockIdentity
        }
        fun productFilesPresent(): Boolean = hasFile(ResetDirectoryRole.JOURNAL, "protected-metadata.db") && hasFile(ResetDirectoryRole.JOURNAL, "protected-settings.preferences_pb")
        fun rawInventory(): Set<String> = files.flatMap { (role, entries) -> entries.keys.map { role.name + ":" + it } }.toSet()
        fun readControlIfAvailable(): JournalControl? = if (!keyPresent) null else storage.read("journal-control", 1024)?.let { JournalControl.decode(it) }
        private fun writer(role: ResetDirectoryRole): DurableWriter {
            check(held)
            return object : DurableWriter {
                override fun read(leaf: String, maxBytes: Int): DurableReadResult {
                    check(held)
                    event("before:raw-read:${role.name}:$leaf")
                    val file = files.getValue(role)[leaf]
                    val result = if (file == null) DurableReadResult(DurableCode.ABSENT)
                        else { check(file.bytes.size <= maxBytes); DurableReadResult(DurableCode.OK, DurableSnapshot(file.identity, file.bytes)) }
                    event("after:raw-read:${role.name}:$leaf")
                    return result
                }
                override fun list(maxEntries: Int): DurableListResult {
                    check(held)
                    event("before:list:${role.name}")
                    val result = files.getValue(role).map { DurableDirectoryEntry(it.key, it.value.identity, it.value.bytes.size.toLong()) }
                    check(result.size <= maxEntries)
                    event("after:list:${role.name}")
                    return DurableListResult(DurableCode.OK, result)
                }
                override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int): DurableMutationResult {
                    rawReplacements++
                    error("No raw replacement capability is used by reset")
                }
                override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult {
                    check(held)
                    event("before:delete:${role.name}:$leaf")
                    if (bindings.any { it.role == role && it.lockLeaf == leaf }) { deleteLockCalls++; error("lock delete") }
                    if (failDeleteLeaf == leaf) error("injected delete failure")
                    if (deleteCode != DurableCode.OK) return DurableMutationResult(deleteCode)
                    val observed = files.getValue(role)[leaf] ?: return DurableMutationResult(DurableCode.CONFLICT)
                    if (observed.identity != expectedOld.identity || !observed.bytes.contentEquals(expectedOld.bytes)) return DurableMutationResult(DurableCode.CONFLICT)
                    if (!lieAboutDeletion) files.getValue(role).remove(leaf)
                    event("after:delete:${role.name}:$leaf")
                    return DurableMutationResult(DurableCode.OK)
                }
                override fun closeResult(): DurableCode = error("lease owner, not reset, closes writer")
                override fun close() = error("lease owner, not reset, closes writer")
            }
        }
    }

    companion object { private val OPERATION = ByteArray(32) { 3 } }
}

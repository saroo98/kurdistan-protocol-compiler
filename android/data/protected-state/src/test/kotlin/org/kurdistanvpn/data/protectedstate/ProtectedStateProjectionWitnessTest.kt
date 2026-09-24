// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.nativeapi.*

class ProtectedStateProjectionWitnessTest {
    @Test fun closedSidecarReadsUseMinimalBuffersAndRejectNonemptyFiles() {
        for (sidecar in listOf("projection.db-wal", "projection.db-shm", "projection.db-journal")) {
            val io = ProjectionFileFixture().apply { maximumSidecarReadBudget = 1 }
            val files = ClosedProjectionFiles(io.directory, io, ProjectionLeafLayout("projection.db", "settings.preferences_pb"))
            assertEquals(5, files.observe().size)
            io.files[sidecar] = DurableSnapshot(DurableFileIdentity(1, 12), byteArrayOf())
            assertEquals(5, files.observe().size)
            for (bytes in listOf(byteArrayOf(1), byteArrayOf(1, 2))) {
                io.files[sidecar] = DurableSnapshot(DurableFileIdentity(1, 12), bytes)
                assertThrows(IllegalStateException::class.java) { files.observe() }
            }
        }
    }

    @Test fun selectionCommitThenPresentationUnderNewWriterReturnsCommittedWithoutInterveningRead() {
        lateinit var state: BrokerFixture
        lateinit var closed: ClosedProjectionFixture
        var ready = false
        state = BrokerFixture(pendingReset = true, selectSeedProfile = false, initialProjection = { seed ->
            closed = ClosedProjectionFixture(seedSnapshot = seed,
                currentControl = { if (ready) state.journal.readControl() else closed.control },
                committedImages = {
                    val snapshot = state.snapshot()
                    val observed = closed.files.observe()
                    state.journal.readProjectionWitness(snapshot).requireMatches(snapshot, observed)
                    ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(), ProjectionImageWitness.reconstruct(
                        snapshot.storeId(), snapshot.operationId(), snapshot.revision, snapshot.catalogBytes(), snapshot.settingsBytes()), observed)
                }, recipientBindings = { snapshot ->
                    listOf(org.kurdistanvpn.data.metadata.RecipientBindingEntity("profile-kept", "bound-key",
                        snapshot.operationId().joinToString("") { "%02x".format(it) }, snapshot.revision))
                })
            closed.adapter.initialize(seed)
            closed.adapter.read()
        })
        ready = true
        val adapter = closed.newAccess()
        var changedWriter = false
        state.storage.afterReplace = { name, _ ->
            if (name == "journal-control" && !state.journal.readControl().dirty) {
                // The following presentation lease has a new identity but the same physical files.
                closed.replacementWriter = object : DurableWriter by closed.io {}
                changedWriter = true
            }
        }
        val original = org.kurdistanvpn.data.settings.SettingsProjectionCodec.toModel(state.snapshot().settingsBytes())
        val requested = original.copy(profiles = original.profiles.copy(activeLocalRecordId = "profile-kept"))
        val result = state.broker(projectionAccess = adapter).replaceSettings(2, requested)
        assertTrue(changedWriter)
        assertEquals("profile-kept", state.snapshot().selectedProfile)
        assertEquals(4L, state.snapshot().revision)
        assertEquals(ProtectedMutationStatus.COMMITTED, result.status)
        assertNull(state.storage.read(ProtectedPresentationOverlay.NAME, JournalLimits.RECORD_BYTES))
        assertEquals(0, closed.factory.liveOwners)
    }

    @Test fun cleanPendingProjectionPropagatesCommittedReaderFailureInsteadOfReturningCache() {
        val failure = IllegalStateException("synthetic authenticated committed read failure")
        val fixture = ClosedProjectionFixture(committedImages = { throw failure })
        fixture.adapter.initialize(fixture.snapshot)
        fixture.control = fixture.control.complete(JournalDigest.checkpoint(fixture.snapshot.encode()), JournalDigest.record(byteArrayOf(1)))
        fixture.replacementWriter = object : DurableWriter by fixture.io {}
        assertSame(failure, assertThrows(IllegalStateException::class.java) { fixture.adapter.read() })
        assertEquals(1, fixture.committedReads)
    }

    @Test fun dirtyPendingProjectionRejectsDifferentWriterWithIdenticalPhysicalFiles() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        fixture.replacementWriter = object : DurableWriter by fixture.io {}
        assertThrows(IllegalStateException::class.java) { fixture.adapter.read() }
        assertEquals(0, fixture.committedReads)
    }

    @Test fun schemaInterruptionsPreserveEveryRecipientBindingProjectionFieldAcrossFreshRecovery() {
        for (point in listOf("before-migration", "after-migration", "before-witness", "after-witness"))
            for (rollback in listOf(false, true)) {
                lateinit var state: BrokerFixture
                lateinit var closed: ClosedProjectionFixture
                var ready = false
                state = BrokerFixture(pendingReset = true, selectSeedProfile = false, initialProjection = { seed ->
                    closed = ClosedProjectionFixture(seedSnapshot = seed,
                        currentControl = { if (ready) state.journal.readControl() else closed.control },
                        committedImages = {
                            val snapshot = state.snapshot()
                            ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(), ProjectionImageWitness.reconstruct(
                                snapshot.storeId(), snapshot.operationId(), snapshot.revision, snapshot.catalogBytes(), snapshot.settingsBytes()),
                                closed.files.observe(closed.io))
                        }, recipientBindings = { snapshot ->
                            // The existing pending-reset seed has exactly this bound key/profile relationship.
                            listOf(org.kurdistanvpn.data.metadata.RecipientBindingEntity("profile-kept", "bound-key",
                                snapshot.operationId().joinToString("") { "%02x".format(it) }, snapshot.revision))
                        })
                    closed.adapter.initialize(seed)
                    closed.adapter.read()
                })
                ready = true
                val before = closed.factory.storedCatalog
                assertEquals(2, before.rows.size)
                assertEquals(listOf(org.kurdistanvpn.data.metadata.RecipientBindingEntity("profile-kept", "bound-key",
                    "02".repeat(32), 2)), before.bindings)
                val recipientRecords = state.readKeys(state.snapshot()).backupRecords()
                try {
                    assertEquals(listOf("profile-kept"), recipientRecords.single { it.sourceRecordId == "bound-key" }.sourceProfileRecordIds)
                    assertTrue(recipientRecords.filter { it.sourceRecordId != "bound-key" }.all { it.sourceProfileRecordIds.isEmpty() })
                } finally { recipientRecords.forEach { it.destroy() } }
                closed.factory.schemaVersion = 2
                var reached = false
                fun interrupt() { reached = true; error("SYNTHETIC_SCHEMA_ROW_BOUNDARY") }
                if (point == "before-migration") closed.factory.beforeMigration = { interrupt() }
                if (point == "after-migration") closed.factory.afterMigration = { interrupt() }
                if (point == "before-witness") state.storage.beforeReplace = { name, _, _ ->
                    if (name.startsWith("journal-projection-")) interrupt()
                }
                if (point == "after-witness") state.storage.afterReplace = { name, _ ->
                    if (name.startsWith("journal-projection-")) interrupt()
                }
                val original = state.broker(projectionAccess = closed.newAccess()).migrateProductProjectionConfirmed(2)
                assertTrue("$point rollback=$rollback", reached)
                assertNotEquals(ProtectedMutationStatus.COMMITTED, original.status)
                assertEquals(if (point == "before-migration") 2 else 3, closed.factory.schemaVersion)
                assertTrue(state.journal.readControl().dirty)
                assertEquals(0, closed.factory.liveOwners)
                closed.factory.beforeMigration = null; closed.factory.afterMigration = null
                state.storage.beforeReplace = null; state.storage.afterReplace = null
                assertEquals("$point rollback=$rollback", ProtectedMutationStatus.COMMITTED,
                    state.broker(projectionAccess = closed.newAccess()).recoverProductSchemaConfirmed(rollback).status)
                val snapshot = state.snapshot()
                val operation = snapshot.operationId().joinToString("") { "%02x".format(it) }
                val after = closed.factory.storedCatalog
                assertEquals(3, closed.factory.schemaVersion)
                assertEquals(4L, snapshot.revision)
                // Compare every row and every field. Only the two committed identity stamps change.
                assertEquals(before.bindings.map { it.copy(operationId = operation, committedRevision = 4) }, after.bindings)
                assertEquals(before.rows.map { it.copy(operationId = operation, committedRevision = 4) }, after.rows)
                assertEquals(org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.imageDigest(after.rows, after.bindings),
                    checkNotNull(after.witness).imageDigest)
                val independentlyRead = closed.newAccess().read()
                independentlyRead.requireMatches(snapshot)
                state.journal.readProjectionWitness(snapshot).requireMatches(snapshot, independentlyRead.physical())
                assertEquals(0, closed.factory.liveOwners)
            }
    }
    @Test fun brokerRecoversAfterCatalogOrDataStoreDurabilityThroughFreshClosedProjectionAccess() {
        for (point in listOf("after-publish-room", "after-publish-settings", "after-close-room")) for (rollback in listOf(false, true)) {
            lateinit var state: BrokerFixture
            lateinit var closed: ClosedProjectionFixture
            var ready = false
            state = BrokerFixture(initialProjection = { seed ->
                closed = ClosedProjectionFixture(seedSnapshot = seed,
                    currentControl = { if (ready) state.journal.readControl() else closed.control },
                    committedImages = {
                        val snapshot = state.snapshot()
                        ProjectionImages(snapshot.catalogBytes(), snapshot.settingsBytes(), ProjectionImageWitness.reconstruct(
                            snapshot.storeId(), snapshot.operationId(), snapshot.revision, snapshot.catalogBytes(), snapshot.settingsBytes()),
                            closed.files.observe(closed.io))
                    })
                closed.adapter.initialize(seed)
                closed.adapter.read()
            })
            ready = true
            closed.factory.failure = point
            val result = state.broker(projectionAccess = closed.newAccess()).applyProductSettings(2, 0,
                org.kurdistanvpn.core.model.ProductSettings(highContrast = true))
            assertTrue(point, closed.factory.events.contains(point))
            assertNotEquals(point, ProtectedMutationStatus.COMMITTED, result.status)
            assertTrue(state.journal.readControl().dirty)
            assertEquals(0, closed.factory.liveOwners)
            closed.factory.failure = null
            assertEquals("$point rollback=$rollback", ProtectedMutationStatus.COMMITTED,
                state.broker(projectionAccess = closed.newAccess()).recoverProductSettingsConfirmed(rollback).status)
            val snapshot = state.snapshot()
            val blobs = ReadOnlyProtectedBlobView(snapshot.objects(), { state.objects[it]?.clone() }, state.codec, state.key)
            assertEquals(org.kurdistanvpn.core.model.ProductSettings(highContrast = !rollback), readProductSettings(snapshot, blobs))
            val read = closed.newAccess().read()
            read.requireMatches(snapshot)
            state.journal.readProjectionWitness(snapshot).requireMatches(snapshot, read.physical())
            assertEquals(0, closed.factory.liveOwners)
            assertSyntheticCanariesAbsent(state, closed.io.files.values.map { it.bytes })
        }
    }
    @Test fun schemaRecoveryRejectsThirdOperationRowBeforeWritableAcquisition() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        fixture.control = fixture.control.complete(JournalDigest.checkpoint(fixture.snapshot.encode()),
            JournalDigest.record(byteArrayOf(1))).reserve(ByteArray(32) { 4 }, MutationKind.PROJECTION_SCHEMA)
        val candidate = ProductProjectionSchemaMigration.candidate(fixture.snapshot, 4, ByteArray(32) { 4 })
        fixture.factory.schemaVersion = 2
        fixture.factory.inspectionOperation = org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity("03".repeat(32), "UPDATE", null,
            "APPLIED", 0, 0, 0, 42, false)
        val opens = fixture.factory.opens
        val before = fixture.io.files.mapValues { it.value.bytes }
        assertThrows(ProjectionSchemaRejected::class.java) { fixture.adapter.migrateSchema(fixture.snapshot, candidate, candidate) {} }
        assertEquals(opens, fixture.factory.opens)
        before.forEach { (id, bytes) -> assertArrayEquals(bytes, fixture.io.files.getValue(id).bytes) }
    }
    @Test fun schemaRecoveryAcceptsPriorLogicalTablesAfterUpgradeWithoutObsoletePhysicalRead() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        fixture.control = fixture.control.complete(JournalDigest.checkpoint(fixture.snapshot.encode()),
            JournalDigest.record(byteArrayOf(1))).reserve(ByteArray(32) { 4 }, MutationKind.PROJECTION_SCHEMA)
        val candidate = ProductProjectionSchemaMigration.candidate(fixture.snapshot, 4, ByteArray(32) { 4 })
        fixture.factory.schemaVersion = 2
        fixture.factory.failure = "publish-room"
        var proofs = 0
        assertThrows(IllegalStateException::class.java) {
            fixture.adapter.migrateSchema(fixture.snapshot, candidate, candidate) { proofs++ }
        }
        assertEquals(3, fixture.factory.schemaVersion)
        assertEquals(0, fixture.committedReads)
        fixture.factory.failure = null
        fixture.adapter.migrateSchema(fixture.snapshot, candidate, candidate) { proofs++ }
        fixture.adapter.read().requireMatches(candidate)
        assertEquals(0, fixture.committedReads)
        assertTrue(proofs >= 4)
        assertEquals(0, fixture.factory.liveOwners)
    }
    @Test fun closedPublicationBindsOperationFromIndependentRoomRead() {
        for (substitution in listOf<String?>(null, "operation")) {
            val fixture = ClosedProjectionFixture(substitution = substitution)
            val descriptor = org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity("03".repeat(32), "UPDATE", null,
                "APPLIED", 0, 0, 0, 42, false)
            val catalog = org.kurdistanvpn.data.metadata.ProductCatalogProjectionCodec.encode(emptyList(), descriptor)
            val target = ProtectedStateSnapshot.create(fixture.snapshot.storeId(), 2, null, emptyList(),
                fixture.snapshot.settingsBytes(), catalog, fixture.snapshot.operationId())
            if (substitution == null) { fixture.adapter.initialize(target); fixture.adapter.read().requireMatches(target) }
            else assertThrows(IllegalStateException::class.java) { fixture.adapter.initialize(target) }
            assertEquals(0, fixture.factory.liveOwners)
        }
    }
    @Test fun typedRecoveryReopensAndRepairsOnlyAuthenticatedPriorCandidateProjectionComponents() {
        for (rollback in listOf(false, true)) {
            val fixture = ClosedProjectionFixture()
            fixture.adapter.initialize(fixture.snapshot)
            val priorImages = fixture.adapter.read()
            val operation = ByteArray(32) { 4 }
            fixture.control = fixture.control.complete(JournalDigest.checkpoint(fixture.snapshot.encode()),
                JournalDigest.record(byteArrayOf(1))).reserve(operation, MutationKind.SETTINGS)
            val nextSettings = org.kurdistanvpn.data.settings.ProductSettingsImage.create(
                org.kurdistanvpn.core.model.ProductSettings(highContrast = true), 1).encode()
            val candidate = ProtectedStateSnapshot.create(fixture.snapshot.storeId(), 4, null, emptyList(), nextSettings,
                fixture.snapshot.catalogBytes(), operation)
            fixture.factory.failure = "publish-settings"
            assertThrows(IllegalStateException::class.java) { fixture.adapter.publish(priorImages, candidate) }
            assertEquals(0, fixture.factory.liveOwners)
            fixture.factory.failure = null
            val target = if (rollback) ProtectedStateSnapshot.create(fixture.snapshot.storeId(), 4, null,
                emptyList(), fixture.snapshot.settingsBytes(), fixture.snapshot.catalogBytes(), operation) else candidate
            fixture.adapter.recover(fixture.snapshot, candidate, target)
            fixture.adapter.read().requireMatches(target)
            assertEquals(0, fixture.factory.liveOwners)
        }
    }
    @Test fun projectionCorruptionAndUnapprovedSchemaTransitionsNeverDelegateToDestructiveRecovery() {
        val calls = mutableListOf<String>()
        val delegate = object : androidx.sqlite.db.SupportSQLiteOpenHelper.Callback(2) {
            override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) { calls += "create" }
            override fun onUpgrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) { calls += "upgrade" }
            override fun onCorruption(db: androidx.sqlite.db.SupportSQLiteDatabase) { calls += "destructive" }
        }
        val database = java.lang.reflect.Proxy.newProxyInstance(javaClass.classLoader,
            arrayOf(androidx.sqlite.db.SupportSQLiteDatabase::class.java)) { _, _, _ -> error("database action not allowed") }
            as androidx.sqlite.db.SupportSQLiteDatabase
        val callback = NonDestructiveProjectionCallback(delegate)
        assertThrows(IllegalStateException::class.java) { callback.onCorruption(database) }
        assertThrows(IllegalStateException::class.java) { callback.onUpgrade(database, 1, 2) }
        assertThrows(IllegalStateException::class.java) { callback.onDowngrade(database, 3, 2) }
        assertTrue(calls.isEmpty())
        callback.onCreate(database)
        assertEquals(listOf("create"), calls)
    }

    @Test fun closedPublicationReopensRoomParsesStoredPreferencesAndOnlyThenExposesPendingObservation() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        fixture.adapter.read().requireMatches(fixture.snapshot)
        assertEquals(2, fixture.factory.opens)
        assertEquals(0, fixture.factory.liveOwners)
        assertTrue(fixture.factory.events.indexOf("close-settings") < fixture.factory.events.indexOf("reader-room"))
        assertTrue(fixture.factory.events.indexOf("close-room") < fixture.factory.events.indexOf("reader-room"))
        assertEquals(4, fixture.io.syncs)
        fixture.activeLease = false
        assertThrows(IllegalStateException::class.java) { fixture.adapter.read() }
        assertEquals(1, fixture.committedReads)
    }

    @Test fun failureBeforeAndAfterEachAcquisitionAndPublicationNeverExposesPendingSuccess() {
        for (point in listOf("before-room", "after-room", "after-settings", "writer-read-room", "read-settings",
            "publish-room", "publish-settings", "reader-room", "reader-read-room", "close-settings", "close-room", "close-reader")) {
            val fixture = ClosedProjectionFixture(point)
            assertThrows(point, IllegalStateException::class.java) { fixture.adapter.initialize(fixture.snapshot) }
            assertThrows(point, IllegalStateException::class.java) { fixture.adapter.read() }
            if (!point.startsWith("close-")) assertEquals(point, 0, fixture.factory.liveOwners)
            if (point == "after-room") assertEquals(listOf("room", "close-room"), fixture.factory.events)
            if (point == "after-settings") assertEquals(listOf("room", "settings", "close-settings", "close-room"), fixture.factory.events)
        }
    }

    @Test fun independentlyRereadRowsAndRawPreferencesCannotBeReplacedByWriterAssertions() {
        for (substitution in listOf("rows", "settings", "bindings")) {
            val fixture = ClosedProjectionFixture(substitution = substitution)
            assertThrows(substitution, IllegalStateException::class.java) { fixture.adapter.initialize(fixture.snapshot) }
            assertEquals(0, fixture.factory.liveOwners)
            assertThrows(substitution, IllegalStateException::class.java) { fixture.adapter.read() }
        }
    }

    @Test fun pendingProjectionIsBoundToTheCurrentWriterOperationAndPhysicalFiles() {
        for (changed in listOf("operation", "revision", "writer", "physical")) {
            val fixture = ClosedProjectionFixture()
            fixture.adapter.initialize(fixture.snapshot)
            when (changed) {
                "operation" -> fixture.control = JournalControl.initial(ByteArray(16) { 1 })
                    .reserve(ByteArray(JournalLimits.OPERATION_BYTES) { 9 }, MutationKind.MIGRATION)
                "revision" -> fixture.control = JournalControl.initial(ByteArray(16) { 1 })
                "writer" -> fixture.replacementWriter = ProjectionFileFixture()
                else -> fixture.io.files["projection.db"] = DurableSnapshot(DurableFileIdentity(1, 777), byteArrayOf(1))
            }
            assertThrows(changed, IllegalStateException::class.java) { fixture.adapter.read() }
        }
    }

    @Test fun automaticProjectionReadNeedsOnlyAnAuthenticatedCheckpointAndNativePhysicalReads() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        val expected = PhysicalProjectionWitness.capture(fixture.snapshot, fixture.adapter.read().physical())
        val reader = ReadOnlyCheckpointProjectionAccess(fixture.files, { fixture.snapshot }, { expected })
        val opens = fixture.factory.opens
        reader.read().requireMatches(fixture.snapshot)
        assertEquals(opens, fixture.factory.opens)
        fixture.io.files["settings.preferences_pb"] = DurableSnapshot(DurableFileIdentity(1, 111), byteArrayOf(0))
        assertThrows(IllegalStateException::class.java) { reader.read() }
        assertEquals(opens, fixture.factory.opens)
    }

    @Test fun suppliedCheckpointAvoidsDuplicateJournalReadButStillChecksPhysicalFiles() {
        val fixture = ClosedProjectionFixture()
        fixture.adapter.initialize(fixture.snapshot)
        val expected = PhysicalProjectionWitness.capture(fixture.snapshot, fixture.adapter.read().physical())
        var checkpointReads = 0
        val reader = ReadOnlyCheckpointProjectionAccess(fixture.files, {
            checkpointReads++; fixture.snapshot
        }, { expected })
        reader.readForCheckpoint(fixture.snapshot).requireMatches(fixture.snapshot)
        assertEquals(0, checkpointReads)
        reader.read().requireMatches(fixture.snapshot)
        assertEquals(1, checkpointReads)
        fixture.io.files["settings.preferences_pb"] = DurableSnapshot(DurableFileIdentity(1, 111), byteArrayOf(0))
        assertThrows(IllegalStateException::class.java) { reader.readForCheckpoint(fixture.snapshot) }
        assertEquals(1, checkpointReads)
    }

    @Test fun closedProjectionRejectsUnexpectedJournalDataBeforeSynchronization() {
        for (leaf in listOf("projection.db-wal", "projection.db-shm", "projection.db-journal", "settings.preferences_pb.tmp")) {
            val io = ProjectionFileFixture()
            io.files[leaf] = DurableSnapshot(DurableFileIdentity(1, 90), byteArrayOf(1))
            val files = ClosedProjectionFiles(io.directory, io, ProjectionLeafLayout("projection.db", "settings.preferences_pb"))
            assertThrows(IllegalStateException::class.java) { files.observe(io, synchronize = true) }
            assertEquals(0, io.syncs)
        }
    }

    @Test fun closedProjectionSynchronizesPresentFilesAndRejectsAmbiguousOrSubstitutedSync() {
        val io = ProjectionFileFixture()
        io.files["projection.db-journal"] = DurableSnapshot(DurableFileIdentity(1, 12), byteArrayOf())
        val files = ClosedProjectionFiles(io.directory, io, ProjectionLeafLayout("projection.db", "settings.preferences_pb"))
        assertEquals(5, files.observe(io, synchronize = true).size)
        assertEquals(5, io.restrictions)
        assertEquals(3, io.syncs)
        for (code in listOf(DurableCode.UNSUPPORTED, DurableCode.IO_FAILURE, DurableCode.MUTATION_UNPROVEN)) {
            io.syncCode = code
            assertThrows(IllegalStateException::class.java) { files.observe(io, synchronize = true) }
        }
        io.syncCode = DurableCode.OK; io.substitute = true
        assertThrows(IllegalStateException::class.java) { files.observe(io, synchronize = true) }
    }

    @Test fun projectionLeafLayoutCannotEscapeOrCollideWithTheBrokerNamespace() {
        for (name in listOf("../outside.db", "/outside.db", "x/y.db", "journal-control.db", "object-x.db", "protected-state.lock")) {
            assertThrows(IllegalArgumentException::class.java) { ProjectionLeafLayout(name, "settings.preferences_pb") }
        }
        assertThrows(IllegalArgumentException::class.java) { ProjectionLeafLayout("projection.db", "../settings.preferences_pb") }
    }

    @Test fun projectionOwnershipAttemptsEveryCloseAndNeverLosesPartialConstruction() {
        val attempts = mutableListOf<String>()
        val scope = ProjectionOwnership()
        scope.own(AutoCloseable { attempts += "room" })
        var fail = true
        scope.own(AutoCloseable { attempts += "settings"; if (fail) throw IllegalStateException("synthetic close failure") })
        assertThrows(IllegalStateException::class.java) { scope.close() }
        assertEquals(listOf("settings", "room"), attempts)
        assertFalse(scope.isClean())
        fail = false; scope.close()
        assertTrue(scope.isClean())
        assertEquals(listOf("settings", "room", "settings"), attempts)
        scope.close()
        assertEquals(3, attempts.size)
    }

    @Test fun ownershipRejectingLateRegistrationStillClosesTheNewlySuppliedResource() {
        val scope = ProjectionOwnership()
        scope.close()
        var closed = 0
        assertThrows(IllegalStateException::class.java) { scope.own(AutoCloseable { closed++ }) }
        assertEquals(1, closed)
    }

    @Test fun unboundSidecarAppearingDuringSyncInvalidatesTheObservation() {
        val io = ProjectionFileFixture().also { it.afterSync = {
            it.files["settings.preferences_pb.tmp"] = DurableSnapshot(DurableFileIdentity(1, 99), byteArrayOf(1))
        } }
        val files = ClosedProjectionFiles(io.directory, io, ProjectionLeafLayout("projection.db", "settings.preferences_pb"))
        assertThrows(IllegalStateException::class.java) { files.observe(io, synchronize = true) }
    }

    @Test fun projectionSubstitutionCannotSurviveCommitOrCompaction() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val state = snapshot(2, 3)
        val bytes = state.encode()
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.mutate(MutationKind.MIGRATION,
            state.operationId(), bytes, {}, { bindSyntheticProjection(journal, bytes); bytes.clone() }))
        val original = journal.readProjectionWitness(state).encode()
        assertArrayEquals(bytes, journal.readCheckpoint())
        assertEquals(ProtectedMutationStatus.COMMITTED, journal.compact { bytes.clone() })
        val altered = PhysicalProjectionWitness.capture(state, physicalObservations()).encode()
        assertFalse(original.contentEquals(altered))
        disk.compareAndReplace("journal-projection-0000000000000002", original, altered)
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }

    @Test fun logicalCheckpointWithoutPhysicalProjectionEvidenceCannotPublishClean() {
        val disk = MemoryJournalStorage()
        val journal = ProtectedStateOperationJournal(disk)
        journal.initialize(ByteArray(16) { 1 })
        val state = snapshot(2, 3)
        val bytes = state.encode()
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, journal.mutate(MutationKind.MIGRATION,
            state.operationId(), bytes, {}, { bytes.clone() }))
        assertTrue(journal.readControl().dirty)
        assertThrows(IllegalStateException::class.java) { journal.readCheckpoint() }
    }

    @Test fun physicalProjectionProofBindsEverySidecarAndExactIdentity() {
        val state = snapshot(2, 3)
        val observations = physicalObservations()
        val proof = PhysicalProjectionWitness.capture(state, observations)
        val wire = proof.encode()
        PhysicalProjectionWitness.decode(wire).requireMatches(state, observations)
        assertThrows(IllegalStateException::class.java) {
            proof.requireMatches(state, physicalObservations(inode = 99))
        }
        assertThrows(IllegalStateException::class.java) {
            proof.requireMatches(state, physicalObservations(wal = byteArrayOf(9)))
        }
        assertThrows(IllegalStateException::class.java) { proof.requireMatches(snapshot(4, 3), observations) }
        assertThrows(IllegalArgumentException::class.java) { PhysicalProjectionWitness.decode(wire + byteArrayOf(0)) }
        assertThrows(IllegalArgumentException::class.java) { PhysicalProjectionWitness.capture(state, observations.dropLast(1)) }
    }

    @Test fun physicalProjectionProofRejectsUnprovenIoAndDuplicateRoles() {
        val state = snapshot(2, 3)
        val failed = physicalObservations().toMutableList()
        failed[0] = ProjectionFileObservation.fromRead(ProjectionFileRole.ROOM_MAIN,
            org.kurdistanvpn.core.nativeapi.DurableReadResult(org.kurdistanvpn.core.nativeapi.DurableCode.ABSENT))
        assertThrows(IllegalArgumentException::class.java) { PhysicalProjectionWitness.capture(state, failed) }
        assertThrows(IllegalStateException::class.java) {
            ProjectionFileObservation.fromRead(ProjectionFileRole.DATASTORE,
                org.kurdistanvpn.core.nativeapi.DurableReadResult(org.kurdistanvpn.core.nativeapi.DurableCode.IO_FAILURE))
        }
        assertThrows(IllegalArgumentException::class.java) {
            PhysicalProjectionWitness.capture(state, physicalObservations() + physicalObservations().first())
        }
    }

    @Test fun physicalProjectionProofOwnsBytesAndUsesOperationalDigestDomains() {
        val state = snapshot(2, 3)
        val bytes = byteArrayOf(7, 8)
        val role = ProjectionFileRole.ROOM_MAIN
        val observation = ProjectionFileObservation.fromRead(role, org.kurdistanvpn.core.nativeapi.DurableReadResult(
            org.kurdistanvpn.core.nativeapi.DurableCode.OK, org.kurdistanvpn.core.nativeapi.DurableSnapshot(
                org.kurdistanvpn.core.nativeapi.DurableFileIdentity(1, 2), bytes)))
        val all = physicalObservations().toMutableList().also { it[0] = observation }
        val proof = PhysicalProjectionWitness.capture(state, all)
        bytes.fill(0); all.clear(); proof.encode().fill(0)
        val unchanged = physicalObservations().toMutableList().also { it[0] = observation }
        PhysicalProjectionWitness.decode(proof.encode()).requireMatches(state, unchanged)
        val sameBytesDifferentRole = physicalObservations().toMutableList().also {
            it[4] = ProjectionFileObservation.fromRead(ProjectionFileRole.DATASTORE, org.kurdistanvpn.core.nativeapi.DurableReadResult(
                org.kurdistanvpn.core.nativeapi.DurableCode.OK, org.kurdistanvpn.core.nativeapi.DurableSnapshot(
                    org.kurdistanvpn.core.nativeapi.DurableFileIdentity(1, 2), byteArrayOf(7, 8))))
        }
        assertThrows(IllegalStateException::class.java) { proof.requireMatches(state, sameBytesDifferentRole) }
    }

    private fun physicalObservations(inode: Long = 10, wal: ByteArray? = null): List<ProjectionFileObservation> =
        ProjectionFileRole.entries.map { role ->
            val bytes = when (role) {
                ProjectionFileRole.ROOM_MAIN -> byteArrayOf(1, 2, 3)
                ProjectionFileRole.DATASTORE -> byteArrayOf(4, 5, 6)
                ProjectionFileRole.ROOM_WAL -> wal
                else -> null
            }
            ProjectionFileObservation.fromRead(role, if (bytes == null) org.kurdistanvpn.core.nativeapi.DurableReadResult(
                org.kurdistanvpn.core.nativeapi.DurableCode.ABSENT) else org.kurdistanvpn.core.nativeapi.DurableReadResult(
                org.kurdistanvpn.core.nativeapi.DurableCode.OK, org.kurdistanvpn.core.nativeapi.DurableSnapshot(
                    org.kurdistanvpn.core.nativeapi.DurableFileIdentity(1, inode + role.wire), bytes)))
        }

    @Test fun sameImagesWithDifferentOperationOrRevisionNeverMatch() {
        val a = snapshot(2, 3)
        val observed = ProjectionImageWitness.reconstruct(a.storeId(), a.operationId(), a.revision,
            a.catalogBytes(), a.settingsBytes())
        observed.requireMatches(a)
        assertThrows(IllegalStateException::class.java) { observed.requireMatches(snapshot(2, 4)) }
        assertThrows(IllegalStateException::class.java) { observed.requireMatches(snapshot(4, 3)) }
        assertThrows(IllegalStateException::class.java) {
            ProjectionImageWitness.reconstruct(a.storeId(), a.operationId(), a.revision,
                byteArrayOf(9), a.settingsBytes()).requireMatches(a)
        }
    }

    @Test fun snapshotAndWitnessDoNotRetainCallerOwnedBuffers() {
        val store = ByteArray(16) { 1 }; val operation = ByteArray(JournalLimits.OPERATION_BYTES) { 3 }
        val settings = byteArrayOf(7); val catalog = byteArrayOf(8)
        val snapshot = ProtectedStateSnapshot.create(store, 2, null, emptyList(), settings, catalog, operation)
        val observed = ProjectionImageWitness.reconstruct(store, operation, 2, catalog, settings)
        store.fill(0); operation.fill(0); settings.fill(0); catalog.fill(0)
        snapshot.operationId().fill(0)
        val encoded = snapshot.encode()
        observed.requireMatches(ProtectedStateSnapshot.decode(encoded))
        assertEquals(3, snapshot.operationId()[0].toInt())
    }

    @Test fun projectionWitnessesRequireTheSameJournalCommitAndFreshImages() {
        val s = snapshot(2, 3)
        val room = ProjectionImageWitness.reconstruct(s.storeId(), s.operationId(), s.revision,
            s.catalogBytes(), s.settingsBytes())
        assertThrows(IllegalStateException::class.java) {
            ProjectionImageWitness.reconstruct(ByteArray(16) { 2 }, s.operationId(), s.revision,
                s.catalogBytes(), s.settingsBytes()).requireMatches(s)
        }
        room.requireMatches(s)
        assertThrows(IllegalArgumentException::class.java) {
            ProjectionImageWitness.reconstruct(s.storeId(), ByteArray(JournalLimits.OPERATION_BYTES), 2, byteArrayOf(1), byteArrayOf(2))
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProjectionImageWitness.reconstruct(s.storeId(), s.operationId(), 3, byteArrayOf(1), byteArrayOf(2))
        }
    }

    private fun snapshot(revision: Long, operation: Byte): ProtectedStateSnapshot =
        ProtectedStateSnapshot.create(ByteArray(16) { 1 }, revision, null, emptyList(),
            byteArrayOf(7), byteArrayOf(8), ByteArray(JournalLimits.OPERATION_BYTES) { operation })
}

private class ProjectionFileFixture : DurableFilePrimitives, DurableWriter {
    val directory = DurableDirectory(3, 1000, DurableFileIdentity(1, 2))
    val files = mutableMapOf(
        "projection.db" to DurableSnapshot(DurableFileIdentity(1, 10), byteArrayOf(1, 2, 3)),
        "settings.preferences_pb" to DurableSnapshot(DurableFileIdentity(1, 11), byteArrayOf(4, 5, 6)),
    )
    var syncs = 0
    var restrictions = 0
    var restrictionCode = DurableCode.OK
    var syncCode = DurableCode.OK
    var substitute = false
    var requireQuiescent: () -> Unit = {}
    var afterSync: () -> Unit = {}
    var maximumSidecarReadBudget = Int.MAX_VALUE
    override fun read(directory: DurableDirectory, leaf: String, maxBytes: Int) = read(leaf, maxBytes)
    override fun list(directory: DurableDirectory, maxEntries: Int) = list(maxEntries)
    override fun bootstrapLock(directory: DurableDirectory, lockLeaf: String) = error("not permitted")
    override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity) = error("not permitted")
    override fun read(leaf: String, maxBytes: Int): DurableReadResult {
        if (leaf in setOf("projection.db-wal", "projection.db-shm", "projection.db-journal"))
            check(maxBytes <= maximumSidecarReadBudget) { "SIDECAR_READ_ALLOCATION_BUDGET" }
        return files[leaf]?.let {
            if (it.size > maxBytes) DurableReadResult(DurableCode.IO_FAILURE) else DurableReadResult(DurableCode.OK, it)
        } ?: DurableReadResult(DurableCode.ABSENT)
    }
    override fun list(maxEntries: Int) = DurableListResult(DurableCode.OK,
        files.map { DurableDirectoryEntry(it.key, it.value.identity, it.value.size.toLong()) })
    override fun replace(leaf: String, tempLeaf: String, expectedOld: DurableSnapshot?, bytes: ByteArray, maxBytes: Int) = error("not permitted")
    override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int) = error("not permitted")
    override fun restrictAndObserveExisting(leaf: String, maxBytes: Int): DurableRestrictionResult {
        requireQuiescent()
        restrictions++
        if (restrictionCode != DurableCode.OK) return DurableRestrictionResult(restrictionCode)
        return files[leaf]?.let { DurableRestrictionResult(DurableCode.OK, it) }
            ?: DurableRestrictionResult(DurableCode.ABSENT)
    }
    override fun syncAndObserveExisting(leaf: String, expected: DurableSnapshot, maxBytes: Int): DurableSyncResult {
        requireQuiescent()
        syncs++
        afterSync()
        if (syncCode != DurableCode.OK) return DurableSyncResult(syncCode)
        return DurableSyncResult(DurableCode.OK, if (substitute) DurableSnapshot(DurableFileIdentity(1, 999), expected.bytes) else expected)
    }
    override fun closeResult() = error("adapter must not close broker lease")
    override fun close() = error("adapter must not close broker lease")
}

private class ClosedProjectionFixture(failure: String? = null, substitution: String? = null,
    seedSnapshot: ProtectedStateSnapshot? = null, private val currentControl: (() -> JournalControl)? = null,
    private val committedImages: (() -> ProjectionImages)? = null,
    private val recipientBindings: (ProtectedStateSnapshot) -> List<org.kurdistanvpn.data.metadata.RecipientBindingEntity> = { emptyList() }) {
    val io = ProjectionFileFixture().also { it.files.clear() }
    val files = ClosedProjectionFiles(io.directory, io, ProjectionLeafLayout("projection.db", "settings.preferences_pb"))
    val snapshot = seedSnapshot ?: ProtectedStateSnapshot.create(ByteArray(16) { 1 }, 2, null, emptyList(),
        org.kurdistanvpn.data.settings.SettingsProjectionCodec.fromModel(org.kurdistanvpn.core.model.ProductSettings()),
        org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.encode(emptyList()), ByteArray(JournalLimits.OPERATION_BYTES) { 3 })
    var control = JournalControl.initial(snapshot.storeId()).reserve(snapshot.operationId(), MutationKind.MIGRATION)
    var activeLease = true
    var replacementWriter: DurableWriter? = null
    var committedReads = 0
    val factory = ProjectionOwnerFixture(io, failure, substitution)
    val adapter = newAccess()
    fun newAccess() = ClosedStoreProjectionAccess(factory, files, object : ProjectionWriterLeaseAccess {
        override fun <T> withCurrentWriter(block: (DurableWriter) -> T): T? =
            if (activeLease) block(replacementWriter ?: io) else null
    }, { currentControl?.invoke() ?: control }, object : ProtectedProjectionReadAccess {
        override fun read(): ProjectionImages {
            committedReads++
            return committedImages?.invoke() ?: error("no authenticated committed checkpoint in this fixture")
        }
    }, recipientBindings)
    init { io.requireQuiescent = { check(factory.liveOwners == 0) { "raw synchronization while owner live" } } }
}

private class ProjectionOwnerFixture(private val io: ProjectionFileFixture, var failure: String?,
    private val substitution: String?) : ProjectionStoreOwnerFactory {
    var opens = 0
    var schemaVersion = 3
    var beforeMigration: (() -> Unit)? = null
    var afterMigration: (() -> Unit)? = null
    var inspectionOperation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity? = null
    override fun inspectClosed(writer: DurableWriter, files: ClosedProjectionFiles): ClosedSchemaProjection {
        check(writer === io && schemaVersion in 2..3)
        val observed = if (inspectionOperation == null) room else org.kurdistanvpn.data.metadata.CatalogProjection(room.rows, room.witness, room.bindings, inspectionOperation)
        return ClosedSchemaProjection(schemaVersion, observed, preferences, files.observe(writer))
    }
    override fun openMigrating(ownership: ProjectionOwnership, withSettings: Boolean,
        permit: ProductProjectionSchemaMigration.Permit): ProjectionStoreSession {
        permit.claimOpen()
        permit.requireCurrentWriterAndDirtySchemaOperation()
        check(schemaVersion in 2..3)
        beforeMigration?.invoke()
        schemaVersion = 3
        io.files["projection.db"] = DurableSnapshot(DurableFileIdentity(1, 10), io.files.getValue("projection.db").bytes + byteArrayOf(3))
        afterMigration?.invoke()
        return open(ownership, withSettings)
    }
    var liveOwners = 0
    val events = mutableListOf<String>()
    private var room = org.kurdistanvpn.data.metadata.CatalogProjection(emptyList(), null)
    val storedCatalog: org.kurdistanvpn.data.metadata.CatalogProjection get() = room
    private var preferences = org.kurdistanvpn.data.settings.SettingsProjection(
        byteArrayOf(0x4b, 0x53, 0x50, 0x31, 1, 0, 0), null)
    override fun requireRootIdentity() = Unit
    private fun fail(point: String) { if (point == failure) error("synthetic $point") }
    override fun open(ownership: ProjectionOwnership, withSettings: Boolean): ProjectionStoreSession {
        opens++
        fail(if (withSettings) "before-room" else "reader-room")
        events += if (withSettings) "room" else "reader-room"
        liveOwners++
        ownership.own(AutoCloseable {
            events += if (withSettings) "close-room" else "close-reader"
            fail(if (withSettings) "close-room" else "close-reader"); liveOwners--
            if (withSettings && failure == "after-close-room") { events += "after-close-room"; fail("after-close-room") }
        })
        fail("after-room")
        if (withSettings) {
            events += "settings"; liveOwners++
            ownership.own(AutoCloseable { events += "close-settings"; fail("close-settings"); liveOwners-- })
            fail("after-settings")
        }
        return object : ProjectionStoreSession {
            override fun readCatalog(): org.kurdistanvpn.data.metadata.CatalogProjection {
                fail(if (withSettings) "writer-read-room" else "reader-read-room")
                if (!withSettings && substitution == "rows") return org.kurdistanvpn.data.metadata.CatalogProjection(
                    listOf(org.kurdistanvpn.data.metadata.ProfileCatalogEntity("unexpected", "FINALIZED", 1, 1, "AVAILABLE")), room.witness)
                if (!withSettings && substitution == "bindings") return org.kurdistanvpn.data.metadata.CatalogProjection(
                    room.rows, room.witness, listOf(org.kurdistanvpn.data.metadata.RecipientBindingEntity("unexpected", "key", "3".repeat(64), 2)))
                if (!withSettings && substitution == "operation") return org.kurdistanvpn.data.metadata.CatalogProjection(
                    room.rows, room.witness, room.bindings, room.operation?.copy(attempt = 1))
                return room
            }
            override fun publishCatalog(expected: org.kurdistanvpn.data.metadata.CatalogProjection,
                next: org.kurdistanvpn.data.metadata.ProtectedProjectionEntity,
                rows: List<org.kurdistanvpn.data.metadata.ProfileCatalogEntity>, bindings: List<org.kurdistanvpn.data.metadata.RecipientBindingEntity>,
                operation: org.kurdistanvpn.data.metadata.ProductOperationProjectionEntity?) {
                fail("publish-room")
                room = org.kurdistanvpn.data.metadata.CatalogProjection(rows, next, bindings, operation)
                io.files["projection.db"] = DurableSnapshot(DurableFileIdentity(1, 10),
                    encodeProductCatalog(rows, operation))
                if (failure == "after-publish-room") events += "after-publish-room"
                fail("after-publish-room")
            }
            override fun readSettings(): org.kurdistanvpn.data.settings.SettingsProjection { fail("read-settings"); return preferences }
            override fun publishSettings(expected: org.kurdistanvpn.data.settings.SettingsProjection, replacement: ByteArray,
                next: org.kurdistanvpn.data.settings.SettingsProjectionIdentity) {
                fail("publish-settings")
                preferences = org.kurdistanvpn.data.settings.SettingsProjection(replacement, next)
                val storedIdentity = if (substitution == "settings")
                    org.kurdistanvpn.data.settings.SettingsProjectionIdentity.capture(next.storeEpoch, next.operationId, 4, replacement)
                    else next
                val stored = kotlinx.coroutines.runBlocking {
                    org.kurdistanvpn.data.settings.SettingsProjectionCodec.toStoredBytes(replacement, storedIdentity)
                }
                io.files["settings.preferences_pb"] = DurableSnapshot(DurableFileIdentity(1, 11), stored)
                if (failure == "after-publish-settings") events += "after-publish-settings"
                fail("after-publish-settings")
            }
        }
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test

class ProductProjectionSchemaMigrationTest {
    @Test fun schemaBoundaryInterruptionsResumeOrLogicallyRollbackWithoutLosingOldRows() {
        for (point in listOf("before-migration", "after-migration", "before-witness", "after-witness"))
            for (rollback in listOf(false, true)) {
                val state = BrokerFixture(pendingReset = true, selectSeedProfile = false)
                val prior = state.snapshot()
                val oldRecipients = state.readKeys(prior).list()
                assertEquals(3, oldRecipients.size)
                val oldRows = org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.decode(prior.catalogBytes())
                val oldObjects = prior.objects().associate { it.physicalId to state.objects.getValue(it.physicalId).clone() }
                state.projections.schemaVersion = 2
                var reached = false
                fun interrupt() { reached = true; error("SYNTHETIC_SCHEMA_BOUNDARY") }
                if (point == "before-migration") state.projections.inspectSchema = { interrupt() }
                if (point == "after-migration") state.projections.beforePublish = { interrupt() }
                if (point == "before-witness") state.storage.beforeReplace = { name, _, _ ->
                    if (name.startsWith("journal-projection-")) interrupt()
                }
                if (point == "after-witness") state.storage.afterReplace = { name, _ ->
                    if (name.startsWith("journal-projection-")) interrupt()
                }
                assertNotEquals("$point rollback=$rollback", ProtectedMutationStatus.COMMITTED,
                    state.broker().migrateProductProjectionConfirmed(2).status)
                assertTrue(point, reached)
                assertEquals(if (point == "before-migration") 2 else 3, state.projections.schemaVersion)
                state.projections.inspectSchema = null; state.projections.beforePublish = null
                state.storage.beforeReplace = null; state.storage.afterReplace = null
                assertEquals("$point rollback=$rollback", ProtectedMutationStatus.COMMITTED,
                    state.broker().recoverProductSchemaConfirmed(rollback).status)
                val reopened = state.snapshot()
                assertEquals(3, state.projections.schemaVersion)
                assertEquals(4L, reopened.revision)
                val rows = org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.decode(reopened.catalogBytes())
                assertEquals(oldRows, rows.map { row ->
                    val old = oldRows.single { it.localRecordId == row.localRecordId }
                    row.copy(committedRevision = old.committedRevision, operationId = old.operationId)
                })
                assertEquals(prior.objects().map { it.physicalId }, reopened.objects().map { it.physicalId })
                assertEquals(oldRecipients, state.readKeys(reopened).list())
                // All encrypted recipient index/material and both profile objects retain exact bytes.
                oldObjects.forEach { (id, bytes) -> assertArrayEquals(id, bytes, state.objects.getValue(id)); bytes.fill(0) }
                state.projections.current.requireMatches(reopened)
                state.journal.readProjectionWitness(reopened).requireMatches(reopened, state.projections.current.physical())
                assertSyntheticCanariesAbsent(state)
            }
    }
    @Test fun boundedCursorAndValidDecodedOperationRemainAdmissible() {
        val values = List(8) { listOf("x".repeat(4096)) }
        assertEquals(values, cursor(values).use { ProductProjectionSchemaMigration.readRows(it, listOf("value"), 8) })
        val witness = listOf("1", "01".repeat(16), "02".repeat(32), "2",
            org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.imageDigest(emptyList()))
        val catalog = ProductProjectionSchemaMigration.decodeCatalog(emptyList(), emptyList(), listOf(witness),
            listOf(listOf("02".repeat(32), "IMPORT", null, "APPLIED", "10", "0", "2", "1", "0")))
        assertEquals(10, catalog.operation!!.attempt)
        assertEquals("APPLIED", catalog.operation!!.state)
        assertEquals(2L, catalog.witness!!.revision)
        assertTrue(catalog.rows.isEmpty())
    }
    @Test fun observedCursorBoundsAndInvalidLogicalValuesQuarantineRecovery() {
        val witness = listOf("1", "01".repeat(16), "02".repeat(32), "2",
            org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.imageDigest(emptyList()))
        val operation = listOf("02".repeat(32), "IMPORT", null, "APPLIED", "0", "0", "0", "0", "0")
        val inspections: List<() -> Unit> = listOf(
            { ProductProjectionSchemaMigration.readRows(cursor(List(9) { listOf("trigger") }), listOf("value"), 8) },
            { ProductProjectionSchemaMigration.readRows(cursor(List(2) { listOf("operation") }), listOf("value"), 1) },
            { ProductProjectionSchemaMigration.readRows(cursor(listOf(listOf("x".repeat(4097)))), listOf("value"), 1) },
            { ProductProjectionSchemaMigration.decodeCatalog(emptyList(), emptyList(), listOf(witness.toMutableList().also { it[0] = "invalid" }), emptyList()) },
            { ProductProjectionSchemaMigration.decodeCatalog(emptyList(), emptyList(), listOf(witness.toMutableList().also { it[3] = "3" }), emptyList()) },
            { ProductProjectionSchemaMigration.decodeCatalog(emptyList(), emptyList(), listOf(witness), listOf(operation.toMutableList().also { it[4] = "11" })) },
            { ProductProjectionSchemaMigration.decodeCatalog(listOf(listOf(null, "FINALIZED", "1", "1", "AVAILABLE", "2", "02".repeat(32), "NONE")), emptyList(), listOf(witness), emptyList()) },
            { ProductProjectionSchemaMigration.decodeCatalog(listOf(listOf("p", "BAD_STATE", "1", "1", "AVAILABLE", "2", "02".repeat(32), "NONE")), emptyList(), listOf(witness), emptyList()) },
            { ProductProjectionSchemaMigration.decodeCatalog(emptyList(), listOf(listOf("p", "key", "02".repeat(32), "9223372036854775808")), listOf(witness), emptyList()) },
        )
        for ((index, inspect) in inspections.withIndex()) for (rollback in listOf(false, true)) {
            val fixture = BrokerFixture()
            fixture.projections.schemaVersion = 2
            fixture.projections.afterPublish = { error("INTERRUPTED") }
            assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().migrateProductProjectionConfirmed(2).status)
            fixture.projections.afterPublish = null
            fixture.projections.inspectSchema = inspect
            val control = fixture.journal.readControl().encode()
            val projection = fixture.projections.current.copyOwned()
            val publications = fixture.projections.publications
            val objects = fixture.objects.mapValues { it.value.clone() }
            val writes = fixture.objectWrites
            assertEquals("case=$index rollback=$rollback", ProtectedMutationStatus.QUARANTINED,
                fixture.broker().recoverProductSchemaConfirmed(rollback).status)
            assertArrayEquals(control, fixture.journal.readControl().encode())
            assertTrue(projection.sameContent(fixture.projections.current))
            assertEquals(publications, fixture.projections.publications)
            assertEquals(writes, fixture.objectWrites)
            assertEquals(objects.keys, fixture.objects.keys)
            objects.forEach { (id, bytes) -> assertArrayEquals(bytes, fixture.objects.getValue(id)) }
            // A rollback resolution can already exist in the journal; this is not a zero-total-write claim.
        }
    }
    @Test fun cursorReadAndCloseFailuresRemainUncertainty() {
        for (method in listOf("moveToNext", "getString", "close")) {
            val failure = IllegalStateException("CURSOR_IO_UNPROVEN")
            val observed = assertThrows(IllegalStateException::class.java) {
                cursor(listOf(listOf("ok")), method, failure).use {
                    ProductProjectionSchemaMigration.readRows(it, listOf("value"), 1)
                }
            }
            assertSame(failure, observed)
            assertFalse(observed is ProjectionSchemaRejected)
        }
    }
    private fun cursor(rows: List<List<String?>>, failingMethod: String? = null,
        failure: RuntimeException = IllegalStateException("CURSOR_IO_UNPROVEN")): android.database.Cursor {
        var row = -1
        return java.lang.reflect.Proxy.newProxyInstance(javaClass.classLoader, arrayOf(android.database.Cursor::class.java)) { _, method, args ->
            if (method.name == failingMethod) throw failure
            when (method.name) {
                "getColumnIndex", "getColumnIndexOrThrow" -> 0
                "moveToNext" -> (++row < rows.size)
                "isNull" -> rows[row][args!![0] as Int] == null
                "getString" -> rows[row][args!![0] as Int]
                "close" -> null
                else -> error("UNEXPECTED_CURSOR_METHOD:${method.name}")
            }
        } as android.database.Cursor
    }
    @Test fun cleanupUncertaintyAfterSchemaRejectionIsNeverRelabeledQuarantined() {
        val fixture = BrokerFixture()
        fixture.projections.schemaVersion = 2
        fixture.projections.afterPublish = { error("INTERRUPTED") }
        assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().migrateProductProjectionConfirmed(2).status)
        fixture.projections.afterPublish = null
        fixture.projections.schemaFailure = ProjectionSchemaRejected()
        val storage = object : JournalStorage by fixture.storage {
            override fun <T> exclusive(block: () -> T): T {
                fixture.storage.exclusive(block)
                error("LEASE_CLOSE_UNPROVEN")
            }
        }
        val control = fixture.journal.readControl().encode()
        assertEquals(ProtectedMutationStatus.MUTATION_UNPROVEN, fixture.broker(storage).recoverProductSchemaConfirmed(false).status)
        assertArrayEquals(control, fixture.journal.readControl().encode())
    }
    @Test fun positiveSchemaMismatchQuarantinesButReadUncertaintyDoesNot() {
        for (rollback in listOf(false, true)) for (mismatch in listOf(false, true)) {
            val fixture = BrokerFixture()
            fixture.projections.schemaVersion = 2
            fixture.projections.afterPublish = { error("INTERRUPTED") }
            assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().migrateProductProjectionConfirmed(2).status)
            fixture.projections.afterPublish = null
            fixture.projections.schemaFailure = if (mismatch) ProjectionSchemaRejected() else IllegalStateException("READ_UNPROVEN")
            val control = fixture.journal.readControl().encode()
            val current = fixture.projections.current.copyOwned()
            val publications = fixture.projections.publications
            val writes = fixture.objectWrites
            val result = fixture.broker().recoverProductSchemaConfirmed(rollback)
            assertEquals(if (mismatch) ProtectedMutationStatus.QUARANTINED else ProtectedMutationStatus.DIRTY, result.status)
            assertArrayEquals(control, fixture.journal.readControl().encode())
            assertTrue(current.sameContent(fixture.projections.current))
            assertEquals(publications, fixture.projections.publications)
            assertEquals(writes, fixture.objectWrites)
            // Rollback may have persisted immutable resolution evidence before its projection callback.
            assertTrue(fixture.journal.readControl().dirty)
        }
    }
    @Test fun schemaCandidatePreservesQuarantineMeaningAndChangesOnlyCommitStamps() {
        val fixture = BrokerFixture()
        val original = fixture.snapshot()
        val row = org.kurdistanvpn.data.metadata.ProfileCatalogEntity("p", "QUARANTINED", 1, 1, "QUARANTINED", 2,
            original.operationId().joinToString("") { "%02x".format(it) }, "VALIDATION_FAILED")
        val prior = ProtectedStateSnapshot.create(original.storeId(), 2, null, emptyList(), original.settingsBytes(),
            org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.encode(listOf(row)), original.operationId())
        val next = ProductProjectionSchemaMigration.candidate(prior, 4, ByteArray(32) { 7 })
        val rows = org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec.decode(next.catalogBytes())
        assertEquals(listOf(row.copy(committedRevision = 4, operationId = "07".repeat(32))), rows)
    }
    @Test fun finalSchemaRecheckUsesExistingLeaseAndRejectsBeforeDirty() {
        val fixture = BrokerFixture()
        var leased = false
        val storage = object : JournalStorage by fixture.storage {
            override fun <T> exclusive(block: () -> T): T {
                check(!leased) { "NESTED_WRITER" }; leased = true
                return try { fixture.storage.exclusive(block) } finally { leased = false }
            }
        }
        var checks = 0
        fixture.projections.beforeSchemaCheck = {
            assertTrue(leased); checks++
            if (checks == 2) fixture.projections.schemaVersion = 2
        }
        val before = fixture.journal.readControl().encode()
        fixture.storage.events.clear()
        val result = fixture.broker(storage).applyProductStoreCommand(2, ProductStoreCommand.RecordStart(100))
        assertEquals(ProtectedMutationStatus.NO_MUTATION, result.status)
        assertEquals(2, checks)
        assertArrayEquals(before, fixture.journal.readControl().encode())
        assertFalse(fixture.storage.events.any { it.startsWith("write:") })
        assertEquals(0, fixture.objectWrites)
    }
    @Test fun permitRequiresExactLiveWriterHeadAndOnlyDelegatesTwoToThree() {
        val state = BrokerFixture()
        val operation = ByteArray(32) { 7 }
        var control = state.journal.readControl().reserve(operation, MutationKind.PROJECTION_SCHEMA)
        val target = ProductProjectionSchemaMigration.candidate(state.snapshot(), 4, operation)
        val writer = java.lang.reflect.Proxy.newProxyInstance(javaClass.classLoader,
            arrayOf(org.kurdistanvpn.core.nativeapi.DurableWriter::class.java)) { _, _, _ -> error("NO_NATIVE_ACTION") }
            as org.kurdistanvpn.core.nativeapi.DurableWriter
        var live = true
        val leases = object : ProjectionWriterLeaseAccess {
            override fun <T> withCurrentWriter(block: (org.kurdistanvpn.core.nativeapi.DurableWriter) -> T): T? = if (live) block(writer) else null
        }
        var evidence = 0
        val permit = ProductProjectionSchemaMigration.Permit.acquire(writer, leases, { control }, target) { evidence++ }
        permit.claimOpen()
        assertThrows(IllegalStateException::class.java) { permit.claimOpen() }
        var upgrades = 0
        val delegate = object : androidx.sqlite.db.SupportSQLiteOpenHelper.Callback(3) {
            override fun onCreate(db: androidx.sqlite.db.SupportSQLiteDatabase) = error("NO_CREATE")
            override fun onUpgrade(db: androidx.sqlite.db.SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) { upgrades++ }
        }
        val db = java.lang.reflect.Proxy.newProxyInstance(javaClass.classLoader, arrayOf(androidx.sqlite.db.SupportSQLiteDatabase::class.java)) { _, _, _ -> error("NO_SQL") } as androidx.sqlite.db.SupportSQLiteDatabase
        val callback = PermittedProjectionCallback(delegate, permit)
        assertThrows(IllegalStateException::class.java) { callback.onUpgrade(db, 1, 3) }
        callback.onUpgrade(db, 2, 3)
        assertEquals(1, upgrades)
        live = false
        assertThrows(IllegalStateException::class.java) { callback.onUpgrade(db, 2, 3) }
        live = true
        control = state.journal.readControl().reserve(ByteArray(32) { 8 }, MutationKind.PROJECTION_SCHEMA)
        assertThrows(IllegalStateException::class.java) { callback.onUpgrade(db, 2, 3) }
        assertEquals(1, upgrades)
        assertEquals(3, evidence)
    }
    @Test fun explicitSchemaOperationUsesKind17PayloadAndResumesOrRollsBackDeterministically() {
        for (rollback in listOf(false, true)) {
        val fixture = BrokerFixture()
        fixture.projections.schemaVersion = 2
        fixture.projections.afterPublish = { error("INTERRUPTED") }
        assertEquals(ProtectedMutationStatus.DIRTY, fixture.broker().migrateProductProjectionConfirmed(2).status)
        assertEquals(MutationKind.PROJECTION_SCHEMA, fixture.journal.readControl().kind)
        assertEquals(3, fixture.projections.schemaVersion)
        fixture.projections.afterPublish = null
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recoverProductSchemaConfirmed(rollback).status)
        assertEquals(4L, fixture.snapshot().revision)
        assertEquals(3, fixture.projections.schemaVersion)
        }
    }
    @Test fun ordinaryV3StillPerformsEligibleCompactionAndProductMutation() {
        val fixture = BrokerFixture()
        while (fixture.journal.readControl().recordCount < JournalLimits.COMPACT_RECORDS) {
            val revision = fixture.snapshot().revision
            assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductStoreCommand(revision,
                ProductStoreCommand.RecordStart(revision)).status)
        }
        val before = fixture.snapshot().revision
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductStoreCommand(before, ProductStoreCommand.RecordStart(1000)).status)
        assertEquals(before + 2, fixture.snapshot().revision)
        assertTrue(fixture.journal.readControl().recordCount < JournalLimits.COMPACT_RECORDS)
    }
    @Test fun sqliteHeaderRequiresRollbackFormatAndExactSupportedVersion() {
        val bytes = ByteArray(100)
        "SQLite format 3\u0000".toByteArray(Charsets.US_ASCII).copyInto(bytes)
        bytes[18] = 1; bytes[19] = 1; bytes[63] = 2
        assertEquals(2, ProductProjectionSchemaMigration.headerVersion(bytes))
        bytes[63] = 3
        assertEquals(3, ProductProjectionSchemaMigration.headerVersion(bytes))
        for (bad in listOf(bytes.copyOf(99), bytes.clone().also { it[18] = 2 }, bytes.clone().also { it[19] = 2 },
            bytes.clone().also { it[0] = 0 }, bytes.clone().also { it[63] = 4 })) {
            assertThrows(IllegalStateException::class.java) { ProductProjectionSchemaMigration.headerVersion(bad) }
        }
    }
    @Test fun closedInspectorRejectsMissingSchemaBeforeAnyLogicalRows() {
        val queries = mutableListOf<String>()
        assertThrows(IllegalStateException::class.java) {
            ProductProjectionSchemaMigration.inspect(2) { sql, _, _ ->
                queries += sql
                if (sql == "PRAGMA user_version") listOf(listOf("2")) else emptyList()
            }
        }
        assertEquals(listOf("PRAGMA user_version", "SELECT type,name,tbl_name,sql FROM sqlite_master"), queries)
    }
    @Test fun ordinaryV2RejectsBeforeEligibleMaintenanceAndDomainWrites() {
        val fixture = BrokerFixture()
        while (fixture.journal.readControl().recordCount < JournalLimits.COMPACT_RECORDS) {
            val revision = fixture.snapshot().revision
            assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().applyProductStoreCommand(revision,
                ProductStoreCommand.RecordStart(revision)).status)
        }
        val before = fixture.journal.readControl().encode()
        val objects = fixture.objects.mapValues { it.value.clone() }
        val objectWrites = fixture.objectWrites
        fixture.projections.schemaVersion = 2
        fixture.storage.events.clear()
        val result = fixture.broker().applyProductStoreCommand(fixture.snapshot().revision, ProductStoreCommand.RecordStart(1000))
        assertEquals(ProtectedMutationStatus.NO_MUTATION, result.status)
        assertEquals(org.kurdistanvpn.core.model.OperationError.RECOVERY_REQUIRED, result.error)
        assertArrayEquals(before, fixture.journal.readControl().encode())
        assertEquals(objectWrites, fixture.objectWrites)
        assertEquals(objects.keys, fixture.objects.keys)
        objects.forEach { (id, bytes) -> assertArrayEquals(bytes, fixture.objects.getValue(id)) }
        assertFalse(fixture.storage.events.any { it.startsWith("write:") })
    }
}

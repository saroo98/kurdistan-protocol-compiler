// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.room.Room
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.core.nativejni.NativeBridge
import org.kurdistanvpn.data.metadata.*
import org.kurdistanvpn.data.protectedstate.*
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.data.settings.*
import org.kurdistanvpn.domain.DomainResult
import org.kurdistanvpn.domain.SettingsDraft
import org.kurdistanvpn.domain.SettingsRevision

/** Real SQLite, journal, native durable IO, envelope and Keystore. Profile/key bytes are structural
 * synthetic fixtures, not producer-signature, recipient-cryptography or VPN evidence. */
class ProductStorageDeviceTest {
    private val ownedRoots = mutableMapOf<File, android.system.StructStat>()
    private val protectedDatabaseVisits = mutableMapOf<File, Int>()
    @Test fun versionTwoRowsSurviveExplicitVersionThreeUpgrade() = withFixture { fixture ->
        fixture.seed()
        val before = fixture.rows()
        fixture.open().also { facade ->
            committed(runBlocking { facade.migrateProductProjectionConfirmed(2) })
            assertTrue("PROTECTED_DATABASE_PATH_NOT_VISITED", protectedDatabaseVisits.getValue(fixture.root) > 0)
            assertEquals(4L, checkNotNull(facade.readProductStorage("profile-kept")).revision)
        }
        assertEquals(3, fixture.version())
        val after = fixture.rows()
        assertEquals(before.rows.map { it.copy(committedRevision = 4, operationId = after.witness!!.operationId) }, after.rows)
        assertEquals(before.bindings.map { it.copy(committedRevision = 4, operationId = after.witness!!.operationId) }, after.bindings)
        assertEquals(before.witness!!.storeEpoch, after.witness!!.storeEpoch)
        fixture.assertConstraints()
        fixture.reopen()
        assertEquals(1, checkNotNull(fixture.facade!!.enrollmentSummaries()).size)
    }

    @Test fun versionOneMigrationChainPreservesLegacyRows() = withFixture { fixture ->
        val file = fixture.context.getDatabasePath("legacy.db")
        createSchema(file, 1) { database ->
            database.execSQL("INSERT INTO profile_catalog VALUES('legacy-one','FINALIZED',1,9,'AVAILABLE')")
        }
        val expectedRow = ProfileCatalogEntity("legacy-one", "FINALIZED", 1, 9, "AVAILABLE")
            .stampCommitted("2".repeat(64), 2, CatalogQuarantineReason.NONE)
        val expectedBinding = RecipientBindingEntity("legacy-one", "legacy-key", "2".repeat(64), 2)
        val expectedWitness = ProtectedProjectionEntity(1, "1".repeat(32), "2".repeat(64), 2,
            ProfileCatalogProjectionCodec.imageDigest(listOf(expectedRow), listOf(expectedBinding)))
        // Populate the newly available v2 relationship tables between the real migration steps.
        val intermediate = FrameworkSQLiteOpenHelperFactory().create(SupportSQLiteOpenHelper.Configuration.builder(fixture.context)
            .name(file.path).callback(object : SupportSQLiteOpenHelper.Callback(2) {
                override fun onCreate(db: SupportSQLiteDatabase) = error("V1_FIXTURE_REQUIRED")
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(1, oldVersion); assertEquals(2, newVersion)
                    KurdistanMetadataDatabase.MIGRATION_1_2.migrate(db)
                    db.execSQL("UPDATE profile_catalog SET committedRevision=2,operationId=?,quarantineReason='NONE'", arrayOf(expectedRow.operationId))
                    db.execSQL("INSERT INTO recipient_bindings VALUES('legacy-one','legacy-key',?,2)", arrayOf(expectedRow.operationId))
                    db.execSQL("INSERT INTO protected_projection VALUES(1,?,?,2,?)", arrayOf(expectedWitness.storeEpoch, expectedWitness.operationId, expectedWitness.imageDigest))
                    val identity = InstrumentationRegistry.getInstrumentation().context.assets
                        .open("org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase/2.json")
                        .bufferedReader().use { JSONObject(it.readText()).getJSONObject("database").getString("identityHash") }
                    db.execSQL("UPDATE room_master_table SET identity_hash=? WHERE id=42", arrayOf(identity))
                }
            }).build())
        try {
            assertEquals(file.path, intermediate.writableDatabase.path)
            assertEquals(2, intermediate.writableDatabase.version)
        } finally { intermediate.close() }
        val room = Room.databaseBuilder(fixture.context, KurdistanMetadataDatabase::class.java, file.path)
            .addMigrations(KurdistanMetadataDatabase.MIGRATION_1_2, KurdistanMetadataDatabase.MIGRATION_2_3).build()
        try {
            assertEquals(3, room.openHelper.writableDatabase.version)
            assertEquals(file.path, room.openHelper.writableDatabase.path)
            assertEquals(listOf(expectedRow),
                runBlocking { room.profileCatalog().listAll() })
            val projection = runBlocking { room.protectedProjection().read() }
            assertEquals(expectedWitness, projection.witness)
            assertEquals(listOf(expectedBinding), projection.bindings)
            assertNull(projection.operation)
        } finally { room.close() }
        fixture.removeDatabase(file)
    }

    @Test fun ordinaryOpenCannotUpgradeVersionTwo() = withFixture { fixture ->
        fixture.seed()
        val before = fixture.hashes()
        val reader = fixture.open(readOnly = true)
        assertEquals(2L, checkNotNull(reader.readProductStorage("profile-kept")).revision)
        assertFalse(runBlocking { reader.migrateProductProjectionConfirmed(2) } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertEquals(before, fixture.hashes()); assertEquals(2, fixture.version())
        fixture.reopen()
        assertEquals(before, fixture.hashes()); assertEquals(2, fixture.version())
    }

    @Test fun interruptedSchemaUpgradeRecoversForwardWithoutDataLoss() = withFixture { fixture ->
        fixture.seed()
        val before = fixture.rows()
        val fault = fixture.failProjectionSync()
        fixture.open(primitives = fault)
        fault.armed = true
        assertFalse(runBlocking { fixture.facade!!.migrateProductProjectionConfirmed(2) } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertTrue("INJECTED_BOUNDARY_NOT_REACHED", fault.fired)
        assertEquals(3, fixture.version())
        assertNull(fixture.facade!!.readProductStorage("profile-kept"))
        fault.armed = false
        fixture.reopen()
        committed(runBlocking { fixture.facade!!.recoverProductSchemaConfirmed() })
        assertEquals(3, fixture.version())
        val after = fixture.rows()
        assertEquals(before.rows.map { it.copy(committedRevision = 4, operationId = after.witness!!.operationId) }, after.rows)
        assertEquals(before.bindings.map { it.copy(committedRevision = 4, operationId = after.witness!!.operationId) }, after.bindings)
        assertEquals(4L, checkNotNull(fixture.facade!!.readProductStorage("profile-kept")).revision)
    }

    @Test fun operationProjectionCannotAuthorizeOrCertifyMutation() = withFixture { fixture ->
        fixture.seed(); fixture.open()
        committed(runBlocking { fixture.facade!!.migrateProductProjectionConfirmed(2) })
        val fault = fixture.failProjectionSync()
        fixture.reopen(primitives = fault); fault.armed = true
        assertFalse(runBlocking { fixture.facade!!.recordUpdate(4, "profile-kept",
            StoredUpdateState(7uL, 1uL, UpdateCategory.UNCHANGED, 500_000, 500_001, 1)) } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertTrue(fault.fired)
        assertNull(fixture.facade!!.readProductStorage())
        assertNotNull(fixture.rows().operation)
        fault.armed = false
        fixture.reopen()
        committed(runBlocking { fixture.facade!!.recoverProductOperationConfirmed() })
        val completed = checkNotNull(fixture.facade!!.readProductStorage())
        assertNotNull(completed.operation)
        val before = fixture.hashes()
        fixture.reopen(readOnly = true)
        assertFalse(runBlocking { fixture.facade!!.recordStart(completed.revision, 500_001) } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertEquals(before, fixture.hashes())
        fixture.reopen()
    }

    @Test fun productRecordsSurviveFacadeRecreationWithoutPlaintextLeakage() = withFixture { fixture ->
        android.util.Log.i("Task8StorageEvidence", "TASK8_CANARY_CAPTURE_START")
        fixture.seed(); fixture.open()
        committed(runBlocking { fixture.facade!!.migrateProductProjectionConfirmed(2) })
        val display = DeploymentDisplayMetadata(listOf(DeploymentDisplayEntry(CatalogId("profile-kept"), SafeAlias(CANARIES[0]),
            7, true, UpdateCategory.NOT_CHECKED)))
        committed(runBlocking { fixture.facade!!.setDeploymentDisplay(4, display) })
        val repository = checkNotNull(fixture.facade!!.settingsRepository())
        val draft = runBlocking { repository.openDraft() } as DomainResult.Success<SettingsDraft>
        val applied = runBlocking { repository.apply(draft.value.id, draft.value.basedOn.revision,
            draft.value.basedOn.settings.copy(routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf(CANARIES[1])))) }
            as DomainResult.Success<SettingsRevision>
        assertEquals(1L, applied.value.revision)
        val hmac = ByteArray(32) { (it + 1).toByte() }
        try {
            // Fake Wi-Fi-looking text is an allowed display alias, never input to a raw-network identifier API.
            TrustedNetworkRule(CatalogId("device-rule"), hmac, SafeAlias(CANARIES[2])).use { rule ->
                StoredTrustedNetworks(1, listOf(rule), emptySet()).use { value ->
                    committed(runBlocking { fixture.facade!!.replaceTrustedRules(8, value) })
                }
            }
        } finally { hmac.fill(0) }
        val update = StoredUpdateState(7uL, 1uL, UpdateCategory.UNCHANGED, 500_000, 500_001, 1)
        committed(runBlocking { fixture.facade!!.recordUpdate(10, "profile-kept", update) })
        committed(runBlocking { fixture.facade!!.recordStart(12, 500_000) })
        val fault = fixture.failProjectionSync().apply { throwAtBoundary = true }
        fixture.reopen(primitives = fault); fault.armed = true
        assertFalse(runBlocking { fixture.facade!!.recordUpdate(14, "profile-kept",
            StoredUpdateState(7uL, 1uL, UpdateCategory.UNCHANGED, 500_001, 500_002, 2)) } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertTrue(fault.fired)
        assertEquals(1, fault.thrownMessages.size)
        fault.armed = false
        fixture.reopen()
        committed(runBlocking { fixture.facade!!.recoverProductOperationConfirmed(rollback = true) })
        val before = fixture.hashes()
        fixture.reopen(readOnly = true)
        val projection = checkNotNull(fixture.facade!!.readProductStorage("profile-kept"))
        assertEquals(16L, projection.revision)
        assertEquals(display.entries, checkNotNull(projection.deploymentDisplay).entries)
        val expectedUpdate = update.encode(); val actualUpdate = checkNotNull(projection.update).encode()
        try { assertArrayEquals(expectedUpdate, actualUpdate) } finally { expectedUpdate.fill(0); actualUpdate.fill(0) }
        assertEquals(1, checkNotNull(projection.trustedNetworks).ruleCount)
        assertTrue("ROUTING_CANARY_NOT_RESTORED", setOf(CANARIES[1]) == checkNotNull(fixture.facade!!.readProjection()).settings.routing.packages)
        assertNotNull(projection.profile)
        assertNotNull(projection.crashSafeMode)
        assertEquals(before, fixture.hashes())
        for (file in checkNotNull(fixture.protectedRoot.listFiles())) {
            assertNoCanaries(file.name.encodeToByteArray(), "DIRECTORY_LEAF")
            val bytes = file.readBytes()
            try { assertNoCanaries(bytes, "OWNED_FILE") } finally { bytes.fill(0) }
        }
        for (message in fault.thrownMessages) try { assertNoCanaries(message, "THROWN_MESSAGE") } finally { message.fill(0) }
        assertNoCanaries(projection.toString().encodeToByteArray(), "PROJECTION_DIAGNOSTIC")
        android.util.Log.i("Task8StorageEvidence", "TASK8_CANARY_CAPTURE_END")
        val logs = captureOwnProcessLog()
        try {
            assertTrue("OWN_PROCESS_CAPTURE_START_MISSING", contains(logs, "TASK8_CANARY_CAPTURE_START".encodeToByteArray()))
            assertTrue("OWN_PROCESS_CAPTURE_END_MISSING", contains(logs, "TASK8_CANARY_CAPTURE_END".encodeToByteArray()))
            assertNoCanaries(logs, "OWN_PROCESS_LOG")
            android.util.Log.i("Task8StorageEvidence", "TASK8_CANARY_SCAN_COMPLETE bytes=${logs.size} canaries=6")
        } finally { logs.fill(0) }
        fixture.reopen()
    }

    @Test fun legacyFileStorePublishesAtomicallyAndRecoversStaleTemporary() = withFixture { fixture ->
        fixture.seed()
        val legacyParent = File(fixture.root, "files/legacy-fixture")
        Files.createDirectory(legacyParent.toPath()); Os.chmod(legacyParent.path, 448)
        val context = object : ContextWrapper(fixture.context) { override fun getNoBackupFilesDir() = legacyParent }
        val key = AndroidKeystoreKek.loadExisting(KEY_ALIAS, 1)
        val store = SecureBlobStore(context, SecureEnvelopeCodec(), key)
        val root = File(legacyParent, "phase9-v1")
        val payload = "DeviceLegacyPrivateCanaryK9".encodeToByteArray()
        try {
            store.stage("legacy-canary", SecureDataClass.IMPORT_REQUEST, payload)
            val target = File(root, "legacy-canary.${SecureDataClass.IMPORT_REQUEST.wireValue}.blob")
            val first = target.readBytes()
            val firstIdentity = Os.lstat(target.path)
            val temporary = File(root, ".${target.name}.staging")
            check(temporary.createNewFile())
            temporary.outputStream().use { it.write(byteArrayOf(6, 7, 8)) }
            // Reads stay non-mutating. The next explicit write reaps the stale temporary under the real lock.
            val reopened = SecureBlobStore(context, SecureEnvelopeCodec(), key)
            assertArrayEquals(payload, reopened.reopen("legacy-canary", SecureDataClass.IMPORT_REQUEST))
            assertTrue(temporary.exists())
            reopened.stage("recovery-trigger", SecureDataClass.IMPORT_REQUEST, payload)
            assertFalse(temporary.exists())
            assertArrayEquals(first, target.readBytes())
            store.stage("legacy-canary", SecureDataClass.IMPORT_REQUEST, payload)
            val replacedIdentity = Os.lstat(target.path)
            assertEquals(firstIdentity.st_dev, replacedIdentity.st_dev)
            assertNotEquals("PUBLICATION_MUST_REPLACE_NOT_OVERWRITE", firstIdentity.st_ino, replacedIdentity.st_ino)
            assertFalse(first.contentEquals(target.readBytes()))
            assertArrayEquals(payload, reopened.reopen("legacy-canary", SecureDataClass.IMPORT_REQUEST))
            assertFalse(target.readBytes().toString(Charsets.ISO_8859_1).contains(payload.decodeToString()))
            assertEquals(setOf(target.name, "recovery-trigger.${SecureDataClass.IMPORT_REQUEST.wireValue}.blob", ".store.lock"), checkNotNull(root.list()).toSet())
            reopened.deleteAll()
            assertEquals(setOf(".store.lock"), checkNotNull(root.list()).toSet())
            removeExact(File(root, ".store.lock"), Os.lstat(File(root, ".store.lock").path), fixture.root)
            removeExact(root, Os.lstat(root.path), fixture.root)
            removeExact(legacyParent, Os.lstat(legacyParent.path), fixture.root)
        } finally { payload.fill(0) }
    }

    @Test fun productScopedAndCompleteResetPreserveRecoveryOrdering() = withFixture { fixture ->
        fixture.seed(); fixture.open()
        committed(runBlocking { fixture.facade!!.migrateProductProjectionConfirmed(2) })
        committed(runBlocking { fixture.facade!!.recordUpdate(4, "profile-kept",
            StoredUpdateState(2uL, 1uL, UpdateCategory.AVAILABLE, 500_000, 500_000, 0)) })
        committed(runBlocking { fixture.facade!!.recordStart(6, 500_000) })
        committed(runBlocking { fixture.facade!!.resetProfiles(setOf("profile-kept")) })
        fixture.reopen()
        assertTrue(checkNotNull(fixture.facade!!.readProjection()).profiles.isEmpty())
        assertNotNull(checkNotNull(fixture.facade!!.readProductStorage()).crashSafeMode)
        assertTrue(KEY_ALIAS in aliases())
        val resetFault = DeleteFault(fixture.real)
        fixture.reopen(primitives = resetFault)
        resetFault.armed = true
        assertFalse(runBlocking { fixture.facade!!.resetProtectedStateConfirmed() } is ProtectedStateApplicationFacade.CommandResult.Committed)
        assertTrue("RESET_DELETE_FAULT_NOT_REACHED", resetFault.fired)
        assertTrue("KEY_REMOVED_BEFORE_RESET_FINISHED", KEY_ALIAS in aliases())
        assertTrue("RESET_INTENT_NOT_DURABLE", File(fixture.protectedRoot, "journal-reset.blob").exists())
        resetFault.armed = false
        fixture.reopen()
        committed(runBlocking { fixture.facade!!.resetProtectedStateConfirmed(recoverPending = true) })
        assertTrue(KEY_ALIAS !in aliases())
        fixture.createdKey = false
        fixture.close()
        assertEquals(setOf("protected-state.lock"), checkNotNull(fixture.protectedRoot.list()).toSet())
        val resetBytes = fixture.hashes()
        val owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
        try { assertEquals(ProtectedStateApplicationFacade.OpenResult.Unproven,
            ProtectedStateApplicationFacade.openExistingReadOnly(fixture.context, fixture.real, syntheticNative(), owner)) }
        finally { owner.close() }
        assertEquals(resetBytes, fixture.hashes())
        assertTrue(KEY_ALIAS !in aliases())
    }

    private inner class Fixture(val context: Context, val root: File) {
        val real = NativeBridge().durableFiles()
        val protectedRoot = File(root, "no_backup/protected-state-v1")
        val database = File(protectedRoot, "protected-metadata.db")
        var facade: ProtectedStateApplicationFacade? = null
        private var owner: ProtectedStateProcessOwner? = null
        var createdKey = false

        fun close() { try { facade?.close() } finally { facade = null; owner?.close(); owner = null } }
        fun open(readOnly: Boolean = false, primitives: DurableFilePrimitives = real): ProtectedStateApplicationFacade {
            check(facade == null)
            owner = ProtectedStateProcessOwner(monotonicMillis = SystemClock::elapsedRealtime)
            val result = if (readOnly) ProtectedStateApplicationFacade.openExistingReadOnly(context, primitives, syntheticNative(), owner!!)
                else ProtectedStateApplicationFacade.openForInteractiveMutation(context, primitives, syntheticNative(), owner!!)
            assertTrue("FACADE_OPEN_${result.javaClass.simpleName}", result is ProtectedStateApplicationFacade.OpenResult.Ready)
            return (result as ProtectedStateApplicationFacade.OpenResult.Ready).facade.also { facade = it }
        }
        fun reopen(readOnly: Boolean = false, primitives: DurableFilePrimitives = real): ProtectedStateApplicationFacade {
            close(); return open(readOnly, primitives)
        }
        fun version(): Int = SQLiteDatabase.openDatabase(database.path, null, SQLiteDatabase.OPEN_READONLY).use { it.version }
        fun rows(): CatalogProjection = SQLiteDatabase.openDatabase(database.path, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            ProductProjectionSchemaMigration.inspect(db.version) { sql, columns, bound ->
                db.rawQuery(sql, null).use { ProductProjectionSchemaMigration.readRows(it, columns, bound) }
            }
        }
        fun hashes(): Map<String, String> = checkNotNull(protectedRoot.listFiles()).associate { file ->
            check(OsConstants.S_ISREG(Os.lstat(file.path).st_mode))
            file.name to MessageDigest.getInstance("SHA-256").digest(file.readBytes()).hex()
        }
        fun assertConstraints() {
            SQLiteDatabase.openDatabase(database.path, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
                db.setForeignKeyConstraintsEnabled(true)
                db.beginTransaction()
                try {
                    assertThrows(SQLiteConstraintException::class.java) { db.execSQL("DELETE FROM profile_catalog WHERE localRecordId='profile-kept'") }
                    assertThrows(SQLiteConstraintException::class.java) { db.execSQL("INSERT INTO recipient_bindings VALUES('absent','other','${"1".repeat(64)}',4)") }
                } finally { db.endTransaction() }
            }
        }
        fun removeDatabase(file: File) {
            // Only this manually-created database and its known closed sidecars are removable.
            for (suffix in listOf("-wal", "-shm", "-journal", "")) {
                val child = File(file.path + suffix)
                if (child.exists()) removeExact(child, Os.lstat(child.path), root)
            }
        }
        fun failProjectionSync() = SyncFault(real)

        fun seed() {
            check(!createdKey && KEY_ALIAS !in aliases())
            // Public O_NOFOLLOW identifies the loaded Bionic flag family, matching the retained startup oracle.
            val directoryFlag = when (OsConstants.O_NOFOLLOW) {
                0x00008000 -> 0x00004000
                0x00020000 -> 0x00010000
                else -> error("UNSUPPORTED_DIRECTORY_OPEN_FLAG_FAMILY")
            }
            val fd = Os.open(root.path, OsConstants.O_RDONLY or directoryFlag or OsConstants.O_NONBLOCK or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, 0)
            val descriptor = try {
                val duplicate = Os.fcntlInt(fd, OsConstants.F_DUPFD_CLOEXEC, 0)
                try { ParcelFileDescriptor.adoptFd(duplicate) }
                catch (failure: Throwable) {
                    try { ParcelFileDescriptor.adoptFd(duplicate).close() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
                    throw failure
                }
            } finally { Os.close(fd) }
            try {
                val stat = Os.fstat(descriptor.fileDescriptor)
                check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == context.applicationInfo.uid)
                check(Os.fcntlInt(descriptor.fileDescriptor, OsConstants.F_GETFD, 0) and OsConstants.FD_CLOEXEC != 0)
                val parent = DurableDirectory(descriptor.fd.toLong(), stat.st_uid.toLong(), DurableFileIdentity(stat.st_dev, stat.st_ino))
                val backup = checkNotNull(real.openChildDirectory(parent, "no_backup").owner)
                try {
                    val created = real.createChildDirectoryExclusive(checkNotNull(backup.borrow()), "protected-state-v1")
                    assertEquals(DurableCode.OK, created.code)
                    val directoryOwner = checkNotNull(created.owner)
                    try {
                        val directory = checkNotNull(directoryOwner.borrow())
                        val lock = real.bootstrapLock(directory, "protected-state.lock")
                        assertEquals(DurableCode.OK, lock.code)
                        val key = initializeUnderEmptyRootLease(real, directory, checkNotNull(lock.identity),
                            { check(KEY_ALIAS !in aliases()) },
                            { AndroidKeystoreKek.createForFirstUse(KEY_ALIAS, 1, preferStrongBox = false) })
                        createdKey = true
                        val codec = SecureEnvelopeCodec()
                        val storage = EncryptedJournalStorage.writer(directory, real, codec, key, lock.identity!!)
                        val store = ByteArray(16) { 1 }; val operation = ByteArray(32) { 2 }
                        storage.provisionStoreIdentity(store)
                        val journal = ProtectedStateOperationJournal(storage); journal.initialize(store)
                        val plain = seedPlaintext()
                        val encrypted = linkedMapOf<String, ByteArray>()
                        val binding = SecureOperationBinding(operation, 2)
                        try {
                            val refs = plain.entries.mapIndexed { index, (entry, bytes) ->
                                val leaf = operationObjectLeaf(operation, index.toLong() + 2)
                                val cipher = codec.sealForOperation(entry.first, entry.second, bytes, key, binding)
                                encrypted[leaf] = cipher
                                ProtectedObjectReference.fromEncryptedObject(entry.second.wireValue, entry.first, leaf, 1, cipher, binding)
                            }
                            val rows = listOf(ProfileCatalogEntity("profile-kept", "FINALIZED", 2, 1, "AVAILABLE")
                                .stampCommitted(operation.hex(), 2, CatalogQuarantineReason.NONE))
                            val recipients = listOf(RecipientBindingEntity("profile-kept", "bound-key", operation.hex(), 2))
                            val settings = SettingsProjectionCodec.fromModel(ProductSettings())
                            val catalog = ProfileCatalogProjectionCodec.encode(rows)
                            val initial = ProtectedStateSnapshot.create(store, 2, null, refs, settings, catalog, operation)
                            val expected = initial.encode()
                            try {
                                val status = journal.mutate(MutationKind.MIGRATION, operation, expected, mutation = {
                                    for ((name, cipher) in encrypted) storage.objectWriter(operation).create(name, cipher)
                                    createSchema(database, 2) { db ->
                                        val row = rows.single()
                                        db.execSQL("INSERT INTO profile_catalog VALUES(?,?,?,?,?,?,?,?)", arrayOf<Any>(row.localRecordId,
                                            row.transactionState, row.envelopeVersion, row.keyGeneration, row.health,
                                            row.committedRevision, row.operationId, row.quarantineReason))
                                        db.execSQL("INSERT INTO recipient_bindings VALUES(?,?,?,?)", arrayOf<Any>("profile-kept", "bound-key", operation.hex(), 2))
                                        db.execSQL("INSERT INTO protected_projection VALUES(?,?,?,?,?)", arrayOf<Any>(1, store.hex(), operation.hex(), 2,
                                            ProfileCatalogProjectionCodec.imageDigest(rows, recipients)))
                                    }
                                    val settingsOwner = ProductSettingsStore.openOwnedProjection(File(protectedRoot, "protected-settings.preferences_pb"))
                                    runBlocking {
                                        try { settingsOwner.publishProjection(settingsOwner.readProjection(), settings,
                                            SettingsProjectionIdentity.capture(store.hex(), operation.hex(), 2, settings)) }
                                        finally { settingsOwner.closeOwned() }
                                    }
                                }, reconstruct = {
                                    val observed = this.rows()
                                    check(observed.rows == rows && observed.bindings == recipients)
                                    check(observed.witness == ProtectedProjectionEntity(1, store.hex(), operation.hex(), 2,
                                        ProfileCatalogProjectionCodec.imageDigest(rows, recipients)))
                                    val raw = File(protectedRoot, "protected-settings.preferences_pb").readBytes()
                                    try { assertArrayEquals(settings, runBlocking { SettingsProjectionCodec.fromStoredBytes(raw).image() }) }
                                    finally { raw.fill(0) }
                                    val files = ClosedProjectionFiles(directory, real, ProjectionLeafLayout("protected-metadata.db", "protected-settings.preferences_pb"))
                                    val observedFiles = checkNotNull(storage.withCurrentWriter { files.observe(it, synchronize = true) })
                                    journal.bindProjection(initial, PhysicalProjectionWitness.capture(initial, observedFiles))
                                    initial.encode()
                                })
                                assertEquals("AUTHENTICATED_V2_SEED", ProtectedMutationStatus.COMMITTED, status)
                                val reread = journal.readCheckpoint()
                                try { assertArrayEquals(expected, reread) } finally { reread.fill(0) }
                                journal.readProjectionWitness(initial).requireCheckpoint(initial)
                            } finally { expected.fill(0); settings.fill(0); catalog.fill(0) }
                        } finally { plain.values.forEach { it.fill(0) }; encrypted.values.forEach { it.fill(0) }; store.fill(0); operation.fill(0) }
                    } finally { assertEquals(DurableCode.OK, directoryOwner.closeResult()) }
                } finally { assertEquals(DurableCode.OK, backup.closeResult()) }
            } finally { descriptor.close() }
        }
    }

    private class SyncFault(private val real: DurableFilePrimitives) : DurableFilePrimitives by real {
        var armed = false
        var fired = false
        var throwAtBoundary = false
        val thrownMessages = mutableListOf<ByteArray>()
        override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity): DurableOpenResult {
            val result = real.openWriter(directory, lockLeaf, expectedLock)
            val writer = result.writer ?: return result
            return DurableOpenResult(result.code, object : DurableWriter by writer {
                override fun syncAndObserveExisting(leaf: String, expected: DurableSnapshot, maxBytes: Int): DurableSyncResult {
                    if (armed && !fired && leaf == "protected-metadata.db") {
                        fired = true
                        if (throwAtBoundary) {
                            val failure = IllegalStateException("TASK8_SYNTHETIC_CLOSED_SYNC_FAILURE")
                            thrownMessages += checkNotNull(failure.message).encodeToByteArray()
                            throw failure
                        }
                        return DurableSyncResult(DurableCode.IO_FAILURE)
                    }
                    return writer.syncAndObserveExisting(leaf, expected, maxBytes)
                }
            })
        }
    }

    private class DeleteFault(private val real: DurableFilePrimitives) : DurableFilePrimitives by real {
        var armed = false
        var fired = false
        override fun openWriter(directory: DurableDirectory, lockLeaf: String, expectedLock: DurableFileIdentity): DurableOpenResult {
            val result = real.openWriter(directory, lockLeaf, expectedLock)
            val writer = result.writer ?: return result
            return DurableOpenResult(result.code, object : DurableWriter by writer {
                override fun delete(leaf: String, expectedOld: DurableSnapshot, maxBytes: Int): DurableMutationResult {
                    if (armed && !fired && leaf.startsWith("object-")) {
                        fired = true
                        return DurableMutationResult(DurableCode.IO_FAILURE)
                    }
                    return writer.delete(leaf, expectedOld, maxBytes)
                }
            })
        }
    }

    private fun syntheticNative(): KurdNativeCore = object : KurdNativeCore by NativeBridge() {
        private val handles = mutableSetOf<VerifiedPreviewHandle>()
        override fun verifyPreview(request: ByteArray): NativeResult<VerifiedPreviewHandle> = error("UNEXPECTED_UNSEALED_VERIFY")
        override fun verifyPreviewWithRecipient(request: ByteArray, recipientRequest: ByteArray, recipientPrivate: ByteArray): NativeResult<VerifiedPreviewHandle> {
            val expected = syntheticRequest()
            try { check(request.contentEquals(expected)) } finally { expected.fill(0) }
            check(validateRecipient(recipientRequest, recipientPrivate) is NativeResult.Success)
            val handle = VerifiedPreviewHandle(1, RedactedProfilePreview("synthetic", "synthetic", "public-summary", "lineage-summary", 1uL, 1_900_000_000, true))
            handles += handle
            return NativeResult.Success(handle)
        }
        override fun releaseVerified(verified: VerifiedPreviewHandle): NativeResult<Unit> {
            check(handles.remove(verified)); verified.close(); return NativeResult.Success(Unit)
        }
        override fun openActivation(verified: VerifiedPreviewHandle): NativeResult<NativeActivationSession> = error("NO_RUNTIME_AUTHORITY_IN_STORAGE_FIXTURE")
        override fun validateRecipient(recipientRequest: ByteArray, recipientPrivate: ByteArray): NativeResult<Unit> =
            if (recipientRequest.contentEquals(byteArrayOf(1, 11)) && recipientPrivate.contentEquals(byteArrayOf(1, 12))) NativeResult.Success(Unit)
            else NativeResult.Failure(OperationError.KEY_INVALIDATED)
    }

    private fun seedPlaintext(): MutableMap<Pair<String, SecureDataClass>, ByteArray> {
        val plain = linkedMapOf<Pair<String, SecureDataClass>, ByteArray>()
        val blobs = object : SecureBlobAccess {
            override fun stage(localRecordId: String, dataClass: SecureDataClass, exactBytes: ByteArray) { plain.put(localRecordId to dataClass, exactBytes.clone())?.fill(0) }
            override fun reopen(localRecordId: String, dataClass: SecureDataClass) = plain.getValue(localRecordId to dataClass).clone()
            override fun exists(localRecordId: String, dataClass: SecureDataClass) = plain.containsKey(localRecordId to dataClass)
            override fun delete(localRecordId: String, dataClass: SecureDataClass) { plain.remove(localRecordId to dataClass)?.fill(0) }
            override fun deleteAll() = error("SEED_INPUT_NOT_RESET_BACKEND")
        }
        val keys = ClientKeyBundleStore(blobs, object : RecipientKeyNative {
            override fun create(validitySeconds: Int): NativeResult<NativeRecipient> {
                check(validitySeconds == 600)
                return NativeResult.Success(object : NativeRecipient {
                    override fun publicRequest() = NativeResult.Success(byteArrayOf(1, 11))
                    override fun privateBundle() = NativeResult.Success(byteArrayOf(1, 12))
                    override fun cancel() = NativeResult.Success(Unit)
                    override fun close() = Unit
                })
            }
            override fun validate(publicRequest: ByteArray, privateBundle: ByteArray) = syntheticNative().validateRecipient(publicRequest, privateBundle)
        }) { "bound-key" }
        check(keys.create(600, 1_800_000_000L) is ClientKeyResult.Success)
        keys.bindProfile("bound-key", "profile-kept")
        val hex = "4b5052320973796e7468657469630973796e746865746963" +
            "0e7075626c69632d73756d6d6172790f6c696e656167652d73756d6d617279" +
            "000000001153796e7468657469632070726f66696c6501000000000000000100000000713fb300"
        val preview = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
        try { blobs.stage("profile-kept", SecureDataClass.PROFILE_PREVIEW, preview) } finally { preview.fill(0) }
        val request = syntheticRequest()
        val credential = byteArrayOf(41, 42) + CANARIES[4].encodeToByteArray()
        try {
            blobs.stage("profile-kept", SecureDataClass.IMPORT_REQUEST, request)
            blobs.stage("profile-kept", SecureDataClass.ACTIVATION_ACTIVE, credential)
        } finally { request.fill(0); credential.fill(0) }
        return plain
    }

    private fun createSchema(file: File, version: Int, insert: (SQLiteDatabase) -> Unit) {
        check(!file.exists())
        val schema = InstrumentationRegistry.getInstrumentation().context.assets
            .open("org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase/$version.json")
            .bufferedReader().use { JSONObject(it.readText()).getJSONObject("database") }
        SQLiteDatabase.openOrCreateDatabase(file, null).use { db ->
            db.setForeignKeyConstraintsEnabled(true)
            db.beginTransaction()
            try {
                val entities = schema.getJSONArray("entities")
                for (i in 0 until entities.length()) {
                    val entity = entities.getJSONObject(i); val table = entity.getString("tableName")
                    db.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                    val indices = entity.optJSONArray("indices")
                    if (indices != null) for (j in 0 until indices.length())
                        db.execSQL(indices.getJSONObject(j).getString("createSql").replace("\${TABLE_NAME}", table))
                }
                val setup = schema.getJSONArray("setupQueries")
                for (i in 0 until setup.length()) db.execSQL(setup.getString(i))
                insert(db); db.version = version; db.setTransactionSuccessful()
            } finally { db.endTransaction() }
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val target = InstrumentationRegistry.getInstrumentation().targetContext
        val beforeKeys = aliases()
        check(KEY_ALIAS !in beforeKeys) { "PREEXISTING_KEY_NOT_OWNED_BY_FIXTURE" }
        val cache = target.cacheDir.canonicalFile
        val root = Files.createTempDirectory(cache.toPath(), "product-storage-").toFile().absoluteFile
        check(root.parentFile == cache && root.canonicalFile == root)
        Os.chmod(root.path, 448)
        val rootIdentity = Os.lstat(root.path)
        ownedRoots[root] = rootIdentity
        protectedDatabaseVisits[root] = 0
        val children = listOf("databases", "no_backup", "files").map { File(root, it).also { file -> Files.createDirectory(file.toPath()); Os.chmod(file.path, 448) } }
        val identities = children.associateWith { Os.lstat(it.path) }
        val info = ApplicationInfo(target.applicationInfo).apply {
            dataDir = root.path
            javaClass.getField("credentialProtectedDataDir").set(this, root.path)
        }
        val context = object : ContextWrapper(target) {
            override fun getApplicationContext(): Context = this
            override fun getApplicationInfo() = info
            override fun getDataDir() = root
            override fun getNoBackupFilesDir() = File(root, "no_backup")
            override fun getFilesDir() = File(root, "files")
            override fun getDatabasePath(name: String): File {
                if (name.matches(Regex("[a-z0-9-]+\\.db"))) return File(root, "databases/$name")
                val requested = File(name)
                val protected = File(root, "no_backup/protected-state-v1/protected-metadata.db")
                val legacy = File(root, "databases/legacy.db")
                check(requested.isAbsolute && requested == requested.canonicalFile &&
                    (requested == protected || requested == legacy)) { "DATABASE_PATH_OUTSIDE_OWNED_ALLOWLIST" }
                if (requested == protected) protectedDatabaseVisits[root] = protectedDatabaseVisits.getValue(root) + 1
                check(requested.path == name) { "DATABASE_PATH_IDENTITY_CHANGED" }
                return requested
            }
        }
        val fixture = Fixture(context, root)
        var primary: Throwable? = null
        try { block(fixture) }
        catch (failure: Throwable) { primary = failure; throw failure }
        finally {
          try {
            if (fixture.createdKey) {
                fixture.reopen()
                val pendingReset = File(fixture.protectedRoot, "journal-reset.blob").exists()
                committed(runBlocking { fixture.facade!!.resetProtectedStateConfirmed(recoverPending = pendingReset) })
            }
            fixture.close()
            assertEquals("KEY_INVENTORY_NOT_RESTORED", beforeKeys, aliases())
            if (fixture.protectedRoot.exists()) {
                val entries = checkNotNull(fixture.protectedRoot.listFiles())
                check(entries.map { it.name }.toSet() == setOf("protected-state.lock")) { "UNEXPECTED_POST_RESET_ENTRY" }
                removeExact(entries.single(), Os.lstat(entries.single().path), root)
                removeExact(fixture.protectedRoot, Os.lstat(fixture.protectedRoot.path), root)
            }
            for (child in children.reversed()) removeExact(child, identities.getValue(child), root)
            removeExact(root, rootIdentity, root)
            ownedRoots.remove(root)
            protectedDatabaseVisits.remove(root)
          } catch (cleanup: Throwable) {
              try { fixture.close() } catch (close: Throwable) { cleanup.addSuppressed(close) }
              if (primary == null) throw cleanup else primary.addSuppressed(cleanup)
          }
        }
    }

    private fun removeExact(file: File, identity: android.system.StructStat, root: File) {
        check(root.canonicalFile == root && file.parentFile!!.canonicalFile == file.parentFile!!.absoluteFile)
        check(file == root || file.toPath().startsWith(root.toPath()))
        val rootExpected = ownedRoots.getValue(root)
        val rootCurrent = Os.lstat(root.path)
        check(rootCurrent.st_dev == rootExpected.st_dev && rootCurrent.st_ino == rootExpected.st_ino &&
            rootCurrent.st_uid == rootExpected.st_uid && OsConstants.S_ISDIR(rootCurrent.st_mode))
        val current = Os.lstat(file.path)
        check(current.st_dev == identity.st_dev && current.st_ino == identity.st_ino && current.st_uid == identity.st_uid &&
            current.st_uid == InstrumentationRegistry.getInstrumentation().targetContext.applicationInfo.uid &&
            current.st_mode and OsConstants.S_IFMT == identity.st_mode and OsConstants.S_IFMT)
        if (OsConstants.S_ISDIR(current.st_mode)) check(checkNotNull(file.list()).isEmpty())
        Files.delete(file.toPath())
    }
    private fun aliases() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList().toSet()
    private fun syntheticRequest() = byteArrayOf(31, 32) + (CANARIES[3] + "|" + CANARIES[5]).encodeToByteArray()
    private fun assertNoCanaries(bytes: ByteArray, surface: String) {
        for (canary in CANARIES) {
            val pattern = canary.encodeToByteArray()
            try { assertFalse("PLAINTEXT_CANARY_ON_$surface", contains(bytes, pattern)) } finally { pattern.fill(0) }
        }
    }
    private fun contains(bytes: ByteArray, pattern: ByteArray): Boolean {
        if (pattern.size > bytes.size) return false
        for (start in 0..bytes.size - pattern.size) {
            var equal = true
            for (index in pattern.indices) if (bytes[start + index] != pattern[index]) { equal = false; break }
            if (equal) return true
        }
        return false
    }
    private fun captureOwnProcessLog(): ByteArray {
        val process = ProcessBuilder("logcat", "-d", "--pid=${android.os.Process.myPid()}", "-v", "brief", "-t", "2048")
            .redirectErrorStream(true).start()
        val executor = Executors.newSingleThreadExecutor()
        try {
            val read = executor.submit<ByteArray> {
                val bounded = ByteArray(1024 * 1024)
                try {
                    var count = 0
                    process.inputStream.use { input ->
                        while (true) {
                            check(count < bounded.size) { "OWN_PROCESS_LOG_BOUND_EXCEEDED" }
                            val got = input.read(bounded, count, bounded.size - count)
                            if (got < 0) break
                            count += got
                        }
                    }
                    bounded.copyOf(count)
                } finally { bounded.fill(0) }
            }
            val bytes = read.get(5, TimeUnit.SECONDS)
            try {
                check(process.waitFor(1, TimeUnit.SECONDS) && process.exitValue() == 0) { "OWN_PROCESS_LOG_CAPTURE_FAILED" }
                return bytes
            } catch (failure: Throwable) { bytes.fill(0); throw failure }
        } finally {
            if (process.isAlive) process.destroyForcibly()
            executor.shutdownNow()
        }
    }
    private fun committed(result: ProtectedStateApplicationFacade.CommandResult<*>) {
        val category = (result as? ProtectedStateApplicationFacade.CommandResult.Rejected)?.error?.name ?: result.javaClass.simpleName
        assertTrue("BROKER_COMMIT_REQUIRED:$category", result is ProtectedStateApplicationFacade.CommandResult.Committed)
    }
    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }
    companion object {
        private const val KEY_ALIAS = "kurdistan-phase9-availability-kek-v1"
        private val CANARIES = listOf("DeviceCanaryPrivateAliasQ7", "org.synthetic.task8canary", "WifiAliasCanaryT2",
            "EndpointCanaryQ4", "CredentialCanaryR5", "PayloadCanaryS6")
    }
}

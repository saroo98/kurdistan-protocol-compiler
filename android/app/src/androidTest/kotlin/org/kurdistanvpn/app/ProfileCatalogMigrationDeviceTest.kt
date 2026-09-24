// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import android.database.sqlite.SQLiteConstraintException
import android.database.sqlite.SQLiteDatabase
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
import androidx.test.platform.app.InstrumentationRegistry
import java.util.UUID
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.data.metadata.CatalogQuarantineReason
import org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase
import org.kurdistanvpn.data.metadata.ProfileCatalogEntity
import org.kurdistanvpn.data.metadata.ProfileCatalogProjectionCodec
import org.kurdistanvpn.data.metadata.ProtectedProjectionEntity
import org.kurdistanvpn.data.metadata.RecipientBindingEntity

class ProfileCatalogMigrationDeviceTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val names = mutableListOf<String>()
    private val expected = listOf(
        ProfileCatalogEntity("legacy-one", "FINALIZED", 1, 2, "AVAILABLE"),
        ProfileCatalogEntity("legacy-two", "QUARANTINED", 1, 9, "QUARANTINED"),
    )

    @After fun deleteOnlyCreatedTestDatabases() {
        for (name in names) {
            check(name.startsWith("phase18-migration-"))
            assertTrue(context.deleteDatabase(name) || !context.getDatabasePath(name).exists())
        }
    }

    private fun schema(version: Int): JSONObject = instrumentation.context.assets
        .open("org.kurdistanvpn.data.metadata.KurdistanMetadataDatabase/$version.json")
        .bufferedReader().use { JSONObject(it.readText()).getJSONObject("database") }

    private fun createVersionOne(): String {
        val name = "phase18-migration-${UUID.randomUUID()}.db"
        val file = context.getDatabasePath(name)
        check(!file.exists())
        check(requireNotNull(file.parentFile).let { it.isDirectory || it.mkdirs() })
        names += name
        val source = schema(1)
        assertEquals(1, source.getInt("version"))
        SQLiteDatabase.openOrCreateDatabase(file, null).use { database ->
            database.beginTransaction()
            try {
                val entities = source.getJSONArray("entities")
                for (i in 0 until entities.length()) {
                    val entity = entities.getJSONObject(i)
                    val table = entity.getString("tableName")
                    database.execSQL(entity.getString("createSql").replace("\${TABLE_NAME}", table))
                    val indexes = entity.optJSONArray("indices")
                    if (indexes != null) for (j in 0 until indexes.length()) {
                        database.execSQL(indexes.getJSONObject(j).getString("createSql")
                            .replace("\${TABLE_NAME}", table))
                    }
                }
                val setup = source.getJSONArray("setupQueries")
                for (i in 0 until setup.length()) database.execSQL(setup.getString(i))
                for (row in expected) database.execSQL(
                    "INSERT INTO profile_catalog(localRecordId,transactionState,envelopeVersion,keyGeneration,health) VALUES(?,?,?,?,?)",
                    arrayOf<Any>(row.localRecordId, row.transactionState, row.envelopeVersion, row.keyGeneration, row.health),
                )
                database.version = 1
                database.setTransactionSuccessful()
            } finally { database.endTransaction() }
        }
        return name
    }

    private fun openCurrent(name: String, migrations: Array<Migration> =
        arrayOf(KurdistanMetadataDatabase.MIGRATION_1_2, KurdistanMetadataDatabase.MIGRATION_2_3)): KurdistanMetadataDatabase {
        val room = Room.databaseBuilder(context, KurdistanMetadataDatabase::class.java, name)
            .addMigrations(*migrations).build()
        try {
            room.openHelper.writableDatabase
            return room
        } catch (failure: Throwable) {
            try { room.close() } catch (_: Throwable) { }
            throw failure
        }
    }

    private fun scalar(database: SupportSQLiteDatabase, sql: String): String =
        database.query(sql).use { cursor ->
            assertTrue(cursor.moveToFirst())
            cursor.getString(0)
        }

    private fun assertStillVersionOne(name: String) {
        SQLiteDatabase.openDatabase(context.getDatabasePath(name).path, null,
            SQLiteDatabase.OPEN_READONLY).use { database ->
            assertEquals(1, database.version)
            database.rawQuery("PRAGMA table_info(profile_catalog)", null).use { cursor ->
                val columns = mutableListOf<String>()
                while (cursor.moveToNext()) columns += cursor.getString(cursor.getColumnIndexOrThrow("name"))
                assertEquals(listOf("localRecordId", "transactionState", "envelopeVersion", "keyGeneration", "health"), columns)
            }
            database.rawQuery("SELECT localRecordId,transactionState,envelopeVersion,keyGeneration,health FROM profile_catalog ORDER BY localRecordId", null).use { cursor ->
                val observed = mutableListOf<ProfileCatalogEntity>()
                while (cursor.moveToNext()) observed += ProfileCatalogEntity(
                    cursor.getString(0), cursor.getString(1), cursor.getInt(2), cursor.getInt(3), cursor.getString(4))
                assertEquals(expected, observed)
            }
            database.rawQuery("SELECT identity_hash FROM room_master_table WHERE id=42", null).use { cursor ->
                assertTrue(cursor.moveToFirst())
                assertEquals(schema(1).getString("identityHash"), cursor.getString(0))
            }
        }
    }

    @Test fun migrationPreservesRowsDefaultsAndNeverCreatesAuthority() {
        val name = createVersionOne()
        // Exercise the unchanged 1-to-2 contract explicitly, independently of Room's current v3 target.
        val room = FrameworkSQLiteOpenHelperFactory().create(SupportSQLiteOpenHelper.Configuration.builder(context)
            .name(name).callback(object : SupportSQLiteOpenHelper.Callback(2) {
                override fun onCreate(db: SupportSQLiteDatabase) = error("EXISTING_V1_REQUIRED")
                override fun onConfigure(db: SupportSQLiteDatabase) { db.setForeignKeyConstraintsEnabled(true) }
                override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) {
                    assertEquals(1, oldVersion); assertEquals(2, newVersion)
                    KurdistanMetadataDatabase.MIGRATION_1_2.migrate(db)
                    db.execSQL("UPDATE room_master_table SET identity_hash=? WHERE id=42", arrayOf(schema(2).getString("identityHash")))
                }
            }).build())
        try {
            val sql = room.writableDatabase
            assertEquals("2", scalar(sql, "PRAGMA user_version"))
            assertEquals(schema(2).getString("identityHash"), scalar(sql,
                "SELECT identity_hash FROM room_master_table WHERE id=42"))
            assertEquals("0", scalar(sql,
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='product_operation_projection'"))
            sql.query("SELECT localRecordId,transactionState,envelopeVersion,keyGeneration,health,operationId,committedRevision,quarantineReason FROM profile_catalog ORDER BY localRecordId").use { cursor ->
                for (row in expected) {
                    assertTrue(cursor.moveToNext())
                    assertEquals(row.localRecordId, cursor.getString(0)); assertEquals(row.transactionState, cursor.getString(1))
                    assertEquals(row.envelopeVersion, cursor.getInt(2)); assertEquals(row.keyGeneration, cursor.getInt(3))
                    assertEquals(row.health, cursor.getString(4)); assertEquals("", cursor.getString(5))
                    assertEquals(0L, cursor.getLong(6)); assertEquals("LEGACY_UNVERIFIED", cursor.getString(7))
                }
                assertFalse(cursor.moveToNext())
            }
            assertEquals("0", scalar(sql, "SELECT COUNT(*) FROM protected_projection"))
            assertEquals("0", scalar(sql, "SELECT COUNT(*) FROM recipient_bindings"))
            assertEquals("1", scalar(sql, "PRAGMA foreign_keys"))
            sql.query("PRAGMA foreign_key_check").use { assertFalse(it.moveToFirst()) }
        } finally { room.close() }
        val reopened = openCurrent(name)
        try { assertEquals(expected, runBlocking { reopened.profileCatalog().listAll() }) }
        finally { reopened.close() }
    }

    @Test fun migratedForeignKeysUniqueIndexAndRestrictActionsAreEnforced() {
        val room = openCurrent(createVersionOne())
        try {
            val sql = room.openHelper.writableDatabase
            assertEquals("1", scalar(sql, "PRAGMA foreign_keys"))
            sql.beginTransaction()
            try {
                assertThrows(SQLiteConstraintException::class.java) {
                    sql.execSQL("INSERT INTO recipient_bindings VALUES('missing','key-one','synthetic',2)")
                }
                sql.execSQL("INSERT INTO recipient_bindings VALUES('legacy-one','key-one','synthetic',2)")
                assertThrows(SQLiteConstraintException::class.java) {
                    sql.execSQL("INSERT INTO recipient_bindings VALUES('legacy-two','key-one','synthetic',2)")
                }
                assertThrows(SQLiteConstraintException::class.java) {
                    sql.execSQL("DELETE FROM profile_catalog WHERE localRecordId='legacy-one'")
                }
                assertThrows(SQLiteConstraintException::class.java) {
                    sql.execSQL("UPDATE profile_catalog SET localRecordId='renamed' WHERE localRecordId='legacy-one'")
                }
            } finally { sql.endTransaction() }
            assertEquals(expected, runBlocking { room.profileCatalog().listAll() })
            assertTrue(runBlocking { room.protectedProjection().read() }.bindings.isEmpty())
        } finally { room.close() }
    }

    @Test fun failedOrMissingMigrationPreservesVersionOneAndCanRetry() {
        for (interrupt in listOf(false, true)) {
            val name = createVersionOne()
            val migrations: Array<Migration> = if (!interrupt) emptyArray() else arrayOf(object : Migration(1, 2) {
                override fun migrate(db: SupportSQLiteDatabase) {
                    KurdistanMetadataDatabase.MIGRATION_1_2.migrate(db)
                    throw IllegalStateException("SYNTHETIC_MIGRATION_INTERRUPTED")
                }
            }, KurdistanMetadataDatabase.MIGRATION_2_3)
            val failure = assertThrows(RuntimeException::class.java) { openCurrent(name, migrations).close() }
            if (interrupt) assertTrue(generateSequence(failure as Throwable) { it.cause }
                .any { it.message?.contains("SYNTHETIC_MIGRATION_INTERRUPTED") == true })
            assertStillVersionOne(name)
            val retried = openCurrent(name)
            try { assertEquals(expected, runBlocking { retried.profileCatalog().listAll() }) }
            finally { retried.close() }
        }
    }

    @Test fun projectionTransactionRollsBackWhenWitnessWriteFails() {
        val room = openCurrent(createVersionOne())
        try {
            val dao = room.protectedProjection()
            val before = runBlocking { dao.read() }
            val operation = "2".repeat(64)
            val rows = before.rows.map { it.stampCommitted(operation, 2, CatalogQuarantineReason.NONE) }
            val bindings = listOf(RecipientBindingEntity("legacy-one", "synthetic-key", operation, 2))
            val witness = ProtectedProjectionEntity(1, "1".repeat(32), operation, 2,
                ProfileCatalogProjectionCodec.imageDigest(rows, bindings))
            room.openHelper.writableDatabase.execSQL(
                "CREATE TRIGGER correction_reject_witness BEFORE INSERT ON protected_projection BEGIN SELECT RAISE(ABORT, 'SYNTHETIC_WITNESS_REJECTED'); END")
            val failure = assertThrows(RuntimeException::class.java) {
                runBlocking { dao.publish(before, witness, rows, bindings) }
            }
            assertTrue(generateSequence(failure as Throwable) { it.cause }
                .any { it.message?.contains("SYNTHETIC_WITNESS_REJECTED") == true })
            val after = runBlocking { dao.read() }
            assertEquals(before.rows, after.rows)
            assertEquals(before.bindings, after.bindings)
            assertEquals(before.witness, after.witness)
        } finally { room.close() }
    }
}

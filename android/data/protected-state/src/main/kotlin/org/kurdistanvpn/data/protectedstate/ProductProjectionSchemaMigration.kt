// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.kurdistanvpn.data.metadata.*
import java.nio.ByteBuffer

/** Positive fixed-schema or authenticated-endpoint mismatch, never an I/O/cleanup failure. */
internal class ProjectionSchemaRejected(message: String = "PROJECTION_SCHEMA_REJECTED") : IllegalStateException(message)

/** Fixed, closed v2/v3 contract. SQL forms require the later API26/API36 qualification. */
internal object ProductProjectionSchemaMigration {
    /** Reads observed values only. Cursor calls and resource cleanup retain their own failures. */
    fun readRows(cursor: android.database.Cursor, columns: List<String>, bound: Int): List<List<String?>> {
        val indices = columns.map { column -> cursor.getColumnIndex(column).also {
            requireSchema(it >= 0) { "PROJECTION_SCHEMA_RESULT_COLUMN" }
        } }
        val rows = ArrayList<List<String?>>()
        while (cursor.moveToNext()) {
            requireSchema(rows.size < bound) { "PROJECTION_SCHEMA_ROW_BOUND" }
            rows += indices.map { index -> if (cursor.isNull(index)) null else cursor.getString(index).also {
                requireSchema(it != null && it.length <= 4096) { "PROJECTION_SCHEMA_VALUE_BOUND" }
            } }
        }
        return rows
    }
    private fun requireSchema(value: Boolean, message: () -> Any = { "PROJECTION_SCHEMA_REJECTED" }) {
        if (!value) throw ProjectionSchemaRejected(message().toString())
    }
    fun candidate(prior: ProtectedStateSnapshot, revision: Long, operation: ByteArray): ProtectedStateSnapshot {
        val bytes = prior.catalogBytes(); val settings = prior.settingsBytes()
        try {
            val content = ProductCatalogProjectionCodec.decode(bytes)
            check(content.operation == null)
            val rows = ProfileCatalogProjectionCodec.encode(content.rows.map { it.stampCommitted(
                operation.joinToString("") { byte -> "%02x".format(byte) }, revision, CatalogQuarantineReason.valueOf(it.quarantineReason)) })
            return try { ProtectedStateSnapshot.create(prior.storeId(), revision, prior.selectedProfile, prior.objects(), settings, rows, operation) }
            finally { rows.fill(0) }
        } finally { bytes.fill(0); settings.fill(0) }
    }

    class Permit private constructor(private val writer: org.kurdistanvpn.core.nativeapi.DurableWriter,
        private val leases: ProjectionWriterLeaseAccess, private val readControl: () -> JournalControl,
        private val head: ByteArray, private val verifyEvidence: () -> Unit) {
        private var claimed = false
        fun claimOpen() { check(!claimed); requireCurrentWriterAndDirtySchemaOperation(); claimed = true }
        fun requireCurrentWriterAndDirtySchemaOperation() {
            check(leases.withCurrentWriter { it === writer } == true) { "STALE_SCHEMA_WRITER" }
            val current = readControl()
            check(current.dirty && current.kind == MutationKind.PROJECTION_SCHEMA && current.encode().contentEquals(head)) { "STALE_SCHEMA_OPERATION" }
            verifyEvidence()
        }
        companion object {
            fun acquire(writer: org.kurdistanvpn.core.nativeapi.DurableWriter, leases: ProjectionWriterLeaseAccess,
                readControl: () -> JournalControl, expected: ProtectedStateSnapshot, verifyEvidence: () -> Unit): Permit {
                val control = readControl()
                check(control.dirty && control.kind == MutationKind.PROJECTION_SCHEMA && control.reservedCleanRevision == expected.revision &&
                    control.operationId().contentEquals(expected.operationId()) && control.storeId().contentEquals(expected.storeId()))
                return Permit(writer, leases, readControl, control.encode(), verifyEvidence).also { it.requireCurrentWriterAndDirtySchemaOperation() }
            }
        }
    }
    fun headerVersion(bytes: ByteArray): Int {
        requireSchema(bytes.size >= 100 && bytes.copyOfRange(0, 16).contentEquals("SQLite format 3\u0000".toByteArray(Charsets.US_ASCII)))
        requireSchema(bytes[18] == 1.toByte() && bytes[19] == 1.toByte()) { "SQLITE_ROLLBACK_FORMAT_REQUIRED" }
        return ByteBuffer.wrap(bytes, 60, 4).int.also { requireSchema(it == 2 || it == 3) { "PROJECTION_SCHEMA_STEP_REJECTED" } }
    }

    private data class Column(val name: String, val type: String, val notNull: String = "1", val default: String? = null, val pk: String = "0")
    private data class Table(val name: String, val sql: String, val columns: List<Column>)
    private data class SchemaIndex(val name: String, val table: String, val sql: String?, val unique: String,
        val origin: String, val columns: List<Pair<Int, String>>)

    fun inspect(version: Int, query: (String, List<String>, Int) -> List<List<String?>>): CatalogProjection {
        requireSchema(version == 2 || version == 3)
        requireSchema(query("PRAGMA user_version", listOf("user_version"), 1) == listOf(listOf(version.toString())))
        val tables = listOf(
            Table("profile_catalog", "CREATE TABLE `profile_catalog` (`localRecordId` TEXT NOT NULL, `transactionState` TEXT NOT NULL, `envelopeVersion` INTEGER NOT NULL, `keyGeneration` INTEGER NOT NULL, `health` TEXT NOT NULL, `committedRevision` INTEGER NOT NULL DEFAULT 0, `operationId` TEXT NOT NULL DEFAULT '', `quarantineReason` TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED', PRIMARY KEY(`localRecordId`))",
                listOf(Column("localRecordId", "TEXT", pk = "1"), Column("transactionState", "TEXT"), Column("envelopeVersion", "INTEGER"),
                    Column("keyGeneration", "INTEGER"), Column("health", "TEXT"), Column("committedRevision", "INTEGER", default = "0"),
                    Column("operationId", "TEXT", default = "''"), Column("quarantineReason", "TEXT", default = "'LEGACY_UNVERIFIED'"))),
            Table("recipient_bindings", "CREATE TABLE `recipient_bindings` (`profileRecordId` TEXT NOT NULL, `clientKeyRecordId` TEXT NOT NULL, `operationId` TEXT NOT NULL, `committedRevision` INTEGER NOT NULL, PRIMARY KEY(`profileRecordId`), FOREIGN KEY(`profileRecordId`) REFERENCES `profile_catalog`(`localRecordId`) ON UPDATE RESTRICT ON DELETE RESTRICT )",
                listOf(Column("profileRecordId", "TEXT", pk = "1"), Column("clientKeyRecordId", "TEXT"), Column("operationId", "TEXT"), Column("committedRevision", "INTEGER"))),
            Table("protected_projection", "CREATE TABLE `protected_projection` (`singleton` INTEGER NOT NULL, `storeEpoch` TEXT NOT NULL, `operationId` TEXT NOT NULL, `revision` INTEGER NOT NULL, `imageDigest` TEXT NOT NULL, PRIMARY KEY(`singleton`))",
                listOf(Column("singleton", "INTEGER", pk = "1"), Column("storeEpoch", "TEXT"), Column("operationId", "TEXT"), Column("revision", "INTEGER"), Column("imageDigest", "TEXT"))),
            Table("room_master_table", "CREATE TABLE room_master_table (id INTEGER PRIMARY KEY,identity_hash TEXT)",
                listOf(Column("id", "INTEGER", "0", pk = "1"), Column("identity_hash", "TEXT", "0"))),
            Table("android_metadata", "CREATE TABLE android_metadata (locale TEXT)", listOf(Column("locale", "TEXT", "0")))
        ) + if (version == 3) listOf(Table("product_operation_projection",
            "CREATE TABLE `product_operation_projection` (`operationId` TEXT NOT NULL, `kind` TEXT NOT NULL, `scopeRecordId` TEXT, `state` TEXT NOT NULL, `attempt` INTEGER NOT NULL, `settingsRevisionBefore` INTEGER NOT NULL, `settingsRevisionAfter` INTEGER NOT NULL, `startedEpochHour` INTEGER NOT NULL, `resumable` INTEGER NOT NULL, PRIMARY KEY(`operationId`))",
            listOf(Column("operationId", "TEXT", pk = "1"), Column("kind", "TEXT"), Column("scopeRecordId", "TEXT", "0"), Column("state", "TEXT"),
                Column("attempt", "INTEGER"), Column("settingsRevisionBefore", "INTEGER"), Column("settingsRevisionAfter", "INTEGER"),
                Column("startedEpochHour", "INTEGER"), Column("resumable", "INTEGER")))) else emptyList()
        val indices = listOf(
            SchemaIndex("sqlite_autoindex_profile_catalog_1", "profile_catalog", null, "1", "pk", listOf(0 to "localRecordId")),
            SchemaIndex("sqlite_autoindex_recipient_bindings_1", "recipient_bindings", null, "1", "pk", listOf(0 to "profileRecordId")),
            SchemaIndex("index_recipient_bindings_clientKeyRecordId", "recipient_bindings", "CREATE UNIQUE INDEX `index_recipient_bindings_clientKeyRecordId` ON `recipient_bindings` (`clientKeyRecordId`)", "1", "c", listOf(1 to "clientKeyRecordId"))
        ) + if (version == 3) listOf(
            SchemaIndex("sqlite_autoindex_product_operation_projection_1", "product_operation_projection", null, "1", "pk", listOf(0 to "operationId")),
            SchemaIndex("index_product_operation_projection_state_startedEpochHour", "product_operation_projection", "CREATE INDEX `index_product_operation_projection_state_startedEpochHour` ON `product_operation_projection` (`state`, `startedEpochHour`)", "0", "c", listOf(3 to "state", 7 to "startedEpochHour"))) else emptyList()
        val master = query("SELECT type,name,tbl_name,sql FROM sqlite_master", listOf("type", "name", "tbl_name", "sql"), if (version == 2) 8 else 11)
        val expectedMaster = tables.map { listOf("table", it.name, it.name, it.sql) } + indices.map { listOf("index", it.name, it.table, it.sql) }
        requireSchema(master.size == expectedMaster.size && master.toSet() == expectedMaster.toSet()) { "PROJECTION_SCHEMA_OBJECT_MISMATCH" }
        for (table in tables) {
            val columns = query("PRAGMA table_info(`${table.name}`)", listOf("cid", "name", "type", "notnull", "dflt_value", "pk"), table.columns.size)
            requireSchema(columns == table.columns.mapIndexed { index, c -> listOf(index.toString(), c.name, c.type, c.notNull, c.default, c.pk) }) { "PROJECTION_SCHEMA_COLUMN_MISMATCH" }
            val foreign = query("PRAGMA foreign_key_list(`${table.name}`)", listOf("id", "seq", "table", "from", "to", "on_update", "on_delete", "match"), if (table.name == "recipient_bindings") 1 else 0)
            requireSchema(foreign == if (table.name == "recipient_bindings") listOf(listOf("0", "0", "profile_catalog", "profileRecordId", "localRecordId", "RESTRICT", "RESTRICT", "NONE")) else emptyList<List<String?>>())
            val expectedIndices = indices.filter { it.table == table.name }
            val actualIndices = query("PRAGMA index_list(`${table.name}`)", listOf("seq", "name", "unique", "origin", "partial"), expectedIndices.size)
            requireSchema(actualIndices.map { it[0] }.toSet().size == actualIndices.size && actualIndices.all { it[0]?.toIntOrNull() in actualIndices.indices })
            requireSchema(actualIndices.map { it.drop(1) }.toSet() == expectedIndices.map { listOf(it.name, it.unique, it.origin, "0") }.toSet() && actualIndices.size == expectedIndices.size)
        }
        for (index in indices) {
            val actual = query("PRAGMA index_xinfo(`${index.name}`)", listOf("seqno", "cid", "name", "desc", "coll", "key"), index.columns.size + 1)
            val keys = index.columns.mapIndexed { i, c -> listOf(i.toString(), c.first.toString(), c.second, "0", "BINARY", "1") } +
                listOf(listOf(index.columns.size.toString(), "-1", null, "0", "BINARY", "0"))
            requireSchema(actual == keys) { "PROJECTION_SCHEMA_INDEX_MISMATCH" }
        }
        val hash = if (version == 2) "50b2d99263ba4dd80463aea7965699bc" else "6157c23a310321b68f96b94fb5466f00"
        requireSchema(query("SELECT id,identity_hash FROM room_master_table", listOf("id", "identity_hash"), 1) == listOf(listOf("42", hash)))
        val locale = query("SELECT locale FROM android_metadata", listOf("locale"), 1)
        requireSchema(locale.size == 1 && locale.single().single()?.length in 1..64)
        val rows = query("SELECT localRecordId,transactionState,envelopeVersion,keyGeneration,health,committedRevision,operationId,quarantineReason FROM profile_catalog ORDER BY localRecordId",
            listOf("localRecordId", "transactionState", "envelopeVersion", "keyGeneration", "health", "committedRevision", "operationId", "quarantineReason"), 1024)
        val bindings = query("SELECT profileRecordId,clientKeyRecordId,operationId,committedRevision FROM recipient_bindings ORDER BY profileRecordId",
            listOf("profileRecordId", "clientKeyRecordId", "operationId", "committedRevision"), 32)
        val witnessRows = query("SELECT singleton,storeEpoch,operationId,revision,imageDigest FROM protected_projection", listOf("singleton", "storeEpoch", "operationId", "revision", "imageDigest"), 1)
        val operations = if (version == 2) emptyList() else query("SELECT operationId,kind,scopeRecordId,state,attempt,settingsRevisionBefore,settingsRevisionAfter,startedEpochHour,resumable FROM product_operation_projection",
            listOf("operationId", "kind", "scopeRecordId", "state", "attempt", "settingsRevisionBefore", "settingsRevisionAfter", "startedEpochHour", "resumable"), 1)
        return decodeCatalog(rows, bindings, witnessRows, operations)
    }

    /** Pure decoding of already materialized observations, with no query or resource callbacks. */
    fun decodeCatalog(profileRows: List<List<String?>>, bindingRows: List<List<String?>>,
        witnessRows: List<List<String?>>, operations: List<List<String?>>): CatalogProjection = try {
        requireSchema(profileRows.size <= 1024 && profileRows.all { it.size == 8 } &&
            bindingRows.size <= 32 && bindingRows.all { it.size == 4 } &&
            witnessRows.size == 1 && witnessRows.all { it.size == 5 } &&
            operations.size <= 1 && operations.all { it.size == 9 })
        val rows = profileRows.map {
            ProfileCatalogEntity(checkNotNull(it[0]), checkNotNull(it[1]), checkNotNull(it[2]).toInt(), checkNotNull(it[3]).toInt(), checkNotNull(it[4]), checkNotNull(it[5]).toLong(), checkNotNull(it[6]), checkNotNull(it[7]))
        }
        val bindings = bindingRows.map {
            RecipientBindingEntity(checkNotNull(it[0]), checkNotNull(it[1]), checkNotNull(it[2]), checkNotNull(it[3]).toLong())
        }
        requireSchema(witnessRows.size == 1)
        val witness = witnessRows.single().let { ProtectedProjectionEntity(checkNotNull(it[0]).toInt(), checkNotNull(it[1]), checkNotNull(it[2]), checkNotNull(it[3]).toLong(), checkNotNull(it[4])) }.also { it.validate() }
        rows.forEach { it.requireCommittedFor(witness) }
        requireSchema(bindings.all { it.profileRecordId in rows.map { row -> row.localRecordId } && it.operationId == witness.operationId && it.committedRevision == witness.revision })
        requireSchema(witness.imageDigest == ProfileCatalogProjectionCodec.imageDigest(rows, bindings))
        val operation = run {
            requireSchema(operations.size <= 1)
            operations.singleOrNull()?.let {
                requireSchema(it[8] == "0" || it[8] == "1")
                ProductOperationProjectionEntity(checkNotNull(it[0]), checkNotNull(it[1]), it[2], checkNotNull(it[3]), checkNotNull(it[4]).toInt(),
                    checkNotNull(it[5]).toLong(), checkNotNull(it[6]).toLong(), checkNotNull(it[7]).toLong(), it[8] == "1").also { row ->
                    row.validate(); requireSchema(row.operationId == witness.operationId)
                }
            }
        }
        CatalogProjection(rows, witness, bindings, operation)
    } catch (failure: ProjectionSchemaRejected) {
        throw failure
    } catch (_: IllegalArgumentException) {
        // Only pure numeric/entity validation runs here; query/read/close failures are outside this boundary.
        throw ProjectionSchemaRejected("PROJECTION_SCHEMA_LOGICAL_VALUE")
    } catch (_: IllegalStateException) {
        throw ProjectionSchemaRejected("PROJECTION_SCHEMA_LOGICAL_VALUE")
    }
}

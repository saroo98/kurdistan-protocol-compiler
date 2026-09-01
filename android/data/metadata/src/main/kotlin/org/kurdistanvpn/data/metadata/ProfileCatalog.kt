// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.metadata

import androidx.room.Dao
import androidx.room.ColumnInfo
import androidx.room.Database
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.RoomDatabase
import androidx.room.Upsert
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.flow.Flow

enum class TransactionState {
    PREPARED,
    STAGED,
    REOPENED,
    MARKED,
    COMMITTED,
    FINALIZED,
    RECOVERY_REQUIRED,
    QUARANTINED,
}

enum class CatalogHealth {
    AVAILABLE,
    RESTORE_PENDING,
    DEGRADED,
    KEY_INVALIDATED,
    QUARANTINED,
    SUPERSEDED,
}

enum class CatalogQuarantineReason {
    NONE, LEGACY_UNVERIFIED, INCONSISTENT_STATE, KEY_INVALIDATED, VALIDATION_FAILED, RECOVERY_REQUIRED,
}

@Entity(tableName = "profile_catalog")
data class ProfileCatalogEntity(
    @PrimaryKey val localRecordId: String,
    val transactionState: String,
    val envelopeVersion: Int,
    val keyGeneration: Int,
    val health: String,
    @ColumnInfo(defaultValue = "0") val committedRevision: Long = 0,
    @ColumnInfo(defaultValue = "''") val operationId: String = "",
    @ColumnInfo(defaultValue = "'LEGACY_UNVERIFIED'") val quarantineReason: String = "LEGACY_UNVERIFIED",
) {
    /** Only the broker's independently reconstructed commit may supply this identity. */
    fun stampCommitted(operationId: String, revision: Long, reason: CatalogQuarantineReason): ProfileCatalogEntity =
        copy(committedRevision = revision, operationId = operationId, quarantineReason = reason.name).also {
            validateCatalogRow(it)
            require(revision > 0)
        }

    fun requireCommittedFor(witness: ProtectedProjectionEntity) {
        witness.validate()
        validateCatalogRow(this)
        check(committedRevision > 0 && committedRevision == witness.revision && operationId == witness.operationId) {
            "UNCOMMITTED_OR_STALE_CATALOG_ROW"
        }
    }

    /** Necessary row conditions only; profile, recipient, material and native checks remain mandatory. */
    fun isAuthorityEligible(): Boolean = runCatching {
        validateCatalogRow(this)
        committedRevision > 0 && quarantineReason == CatalogQuarantineReason.NONE.name &&
            transactionState == TransactionState.FINALIZED.name && health == CatalogHealth.AVAILABLE.name
    }.getOrDefault(false)
}

/** A projection of a broker-verified relationship, never recipient authority material. */
@Entity(tableName = "recipient_bindings",
    indices = [Index(value = ["clientKeyRecordId"], unique = true)],
    foreignKeys = [ForeignKey(entity = ProfileCatalogEntity::class,
        parentColumns = ["localRecordId"], childColumns = ["profileRecordId"],
        onDelete = ForeignKey.RESTRICT, onUpdate = ForeignKey.RESTRICT)])
data class RecipientBindingEntity(
    @PrimaryKey val profileRecordId: String,
    val clientKeyRecordId: String,
    val operationId: String,
    val committedRevision: Long,
)

interface ProfileCatalogReadAccess {
    fun observeAll(): Flow<List<ProfileCatalogEntity>>
    suspend fun get(localRecordId: String): ProfileCatalogEntity?
    suspend fun listAll(): List<ProfileCatalogEntity>
}

@Dao
interface ProfileCatalogDao : ProfileCatalogReadAccess {
    @Query("SELECT * FROM profile_catalog ORDER BY localRecordId")
    override fun observeAll(): Flow<List<ProfileCatalogEntity>>

    @Query("SELECT * FROM profile_catalog WHERE localRecordId = :localRecordId LIMIT 1")
    override suspend fun get(localRecordId: String): ProfileCatalogEntity?

    @Query("SELECT * FROM profile_catalog ORDER BY localRecordId")
    override suspend fun listAll(): List<ProfileCatalogEntity>

    @Upsert
    suspend fun upsert(entity: ProfileCatalogEntity)

    @Query("DELETE FROM profile_catalog WHERE localRecordId = :localRecordId")
    suspend fun delete(localRecordId: String)

    @Query("DELETE FROM profile_catalog")
    suspend fun deleteAll()

    @Query("UPDATE profile_catalog SET health = :health WHERE localRecordId IN (:recordIds)")
    suspend fun updateHealth(recordIds: List<String>, health: String)

    @Transaction
    suspend fun publishRestore(
        restoredRecordIds: List<String>,
        supersededRecordIds: List<String>,
    ) {
        if (supersededRecordIds.isNotEmpty()) {
            updateHealth(supersededRecordIds, CatalogHealth.SUPERSEDED.name)
        }
        if (restoredRecordIds.isNotEmpty()) {
            updateHealth(restoredRecordIds, CatalogHealth.AVAILABLE.name)
        }
    }
}

@Database(
    entities = [ProfileCatalogEntity::class, RecipientBindingEntity::class, ProtectedProjectionEntity::class],
    version = 2,
    exportSchema = true,
)
abstract class KurdistanMetadataDatabase : RoomDatabase() {
    abstract fun profileCatalog(): ProfileCatalogDao
    abstract fun protectedProjection(): ProtectedProjectionDao

    companion object {
        /** Non-destructive. The broker must separately validate and adopt legacy state. */
        val MIGRATION_1_2: Migration = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE `profile_catalog` ADD COLUMN `committedRevision` INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE `profile_catalog` ADD COLUMN `operationId` TEXT NOT NULL DEFAULT ''")
                db.execSQL("ALTER TABLE `profile_catalog` ADD COLUMN `quarantineReason` TEXT NOT NULL DEFAULT 'LEGACY_UNVERIFIED'")
                db.execSQL("CREATE TABLE IF NOT EXISTS `protected_projection` (`singleton` INTEGER NOT NULL, `storeEpoch` TEXT NOT NULL, `operationId` TEXT NOT NULL, `revision` INTEGER NOT NULL, `imageDigest` TEXT NOT NULL, PRIMARY KEY(`singleton`))")
                db.execSQL("CREATE TABLE IF NOT EXISTS `recipient_bindings` (`profileRecordId` TEXT NOT NULL, `clientKeyRecordId` TEXT NOT NULL, `operationId` TEXT NOT NULL, `committedRevision` INTEGER NOT NULL, PRIMARY KEY(`profileRecordId`), FOREIGN KEY(`profileRecordId`) REFERENCES `profile_catalog`(`localRecordId`) ON UPDATE RESTRICT ON DELETE RESTRICT )")
                db.execSQL("CREATE UNIQUE INDEX IF NOT EXISTS `index_recipient_bindings_clientKeyRecordId` ON `recipient_bindings` (`clientKeyRecordId`)")
            }
        }
    }
}

/** Equality witness, not a claim that Room and other stores share a transaction. No secrets. */
@Entity(tableName = "protected_projection")
data class ProtectedProjectionEntity(
    @PrimaryKey val singleton: Int = 1,
    val storeEpoch: String,
    val operationId: String,
    val revision: Long,
    val imageDigest: String,
) {
    fun validate() {
        require(singleton == 1 && revision > 0 && revision and 1L == 0L)
        require(storeEpoch.matches(Regex("[0-9a-f]{32}")) && storeEpoch.any { it != '0' })
        require(operationId.matches(Regex("[0-9a-f]{64}")) && operationId.any { it != '0' })
        require(imageDigest.matches(Regex("[0-9a-f]{64}")))
    }
}

class CatalogProjection(rows: List<ProfileCatalogEntity>, val witness: ProtectedProjectionEntity?,
    bindings: List<RecipientBindingEntity> = emptyList()) {
    private val owned = rows.toTypedArray().toList()
    private val ownedBindings = bindings.toTypedArray().toList()
    val rows: List<ProfileCatalogEntity> get() = java.util.Collections.unmodifiableList(ArrayList(owned))
    val bindings: List<RecipientBindingEntity> get() = java.util.Collections.unmodifiableList(ArrayList(ownedBindings))
}

@Dao
abstract class ProtectedProjectionDao {
    @Query("SELECT * FROM profile_catalog ORDER BY localRecordId")
    protected abstract suspend fun rows(): List<ProfileCatalogEntity>
    @Query("SELECT * FROM protected_projection WHERE singleton = 1")
    protected abstract suspend fun witness(): ProtectedProjectionEntity?
    @Query("SELECT * FROM recipient_bindings ORDER BY profileRecordId")
    protected abstract suspend fun bindings(): List<RecipientBindingEntity>
    @Upsert
    protected abstract suspend fun putWitness(value: ProtectedProjectionEntity)
    @Upsert
    protected abstract suspend fun putRows(value: List<ProfileCatalogEntity>)
    @Upsert
    protected abstract suspend fun putBindings(value: List<RecipientBindingEntity>)
    @Query("DELETE FROM recipient_bindings")
    protected abstract suspend fun clearBindings()
    @Query("DELETE FROM profile_catalog")
    protected abstract suspend fun clearRows()

    @Transaction
    open suspend fun read(): CatalogProjection {
        val observed = rows().toTypedArray().toList()
        val observedBindings = bindings().toTypedArray().toList()
        val identity = witness()?.also {
            it.validate()
            observed.forEach { row -> row.requireCommittedFor(it) }
            requireBindingsFor(observed, observedBindings, it)
            check(it.imageDigest == ProfileCatalogProjectionCodec.imageDigest(observed, observedBindings)) {
                "ROOM_IMAGE_WITNESS_MISMATCH"
            }
        }
        check(identity != null || observedBindings.isEmpty()) { "UNWITNESSED_RECIPIENT_BINDING" }
        return CatalogProjection(observed, identity, observedBindings)
    }

    @Transaction
    open suspend fun publish(expectedOld: CatalogProjection, next: ProtectedProjectionEntity,
        replacement: List<ProfileCatalogEntity>, replacementBindings: List<RecipientBindingEntity> = emptyList()) {
        val owned = replacement.toTypedArray().toList()
        val ownedBindings = replacementBindings.toTypedArray().toList()
        next.validate()
        owned.forEach { it.requireCommittedFor(next) }
        requireBindingsFor(owned, ownedBindings, next)
        check(next.imageDigest == ProfileCatalogProjectionCodec.imageDigest(owned, ownedBindings)) { "INVALID_NEW_ROOM_WITNESS" }
        val observed = read()
        check(observed.witness == expectedOld.witness && observed.rows == expectedOld.rows &&
            observed.bindings == expectedOld.bindings) { "STALE_ROOM_PROJECTION" }
        if (expectedOld.witness != null) {
            expectedOld.witness.validate()
            check(expectedOld.witness.storeEpoch == next.storeEpoch && next.revision > expectedOld.witness.revision)
        }
        clearBindings()
        clearRows()
        putRows(owned)
        putBindings(ownedBindings)
        putWitness(next)
    }
}

/** Canonical, bounded row image used by an independent broker reread and encrypted checkpoint. */
object ProfileCatalogProjectionCodec {
    private const val MAGIC = 0x4b504d32
    private const val MAX_ROWS = 1024
    private const val MAX_BYTES = 512 * 1024

    fun imageDigest(rows: List<ProfileCatalogEntity>, bindings: List<RecipientBindingEntity> = emptyList()): String {
        val canonical = encode(rows)
        var canonicalBindings: ByteArray? = null
        return try {
            val encodedBindings = RecipientBindingProjectionCodec.encode(bindings)
            canonicalBindings = encodedBindings
            java.security.MessageDigest.getInstance("SHA-256").apply {
                update("kurdistan-room-projection-v2\u0000".toByteArray(Charsets.US_ASCII))
                update(ByteBuffer.allocate(4).putInt(canonical.size).array())
                update(canonical)
                update(ByteBuffer.allocate(4).putInt(encodedBindings.size).array())
            }.digest(encodedBindings).joinToString("") { "%02x".format(it) }
        } finally { canonical.fill(0); canonicalBindings?.fill(0) }
    }

    fun encode(rows: List<ProfileCatalogEntity>): ByteArray {
        val owned = rows.toTypedArray().toList().sortedBy { it.localRecordId }
        require(owned.size <= MAX_ROWS && owned.map { it.localRecordId }.toSet().size == owned.size)
        var size = 8
        for (row in owned) {
            validateCatalogRow(row)
            size = Math.addExact(size, 5 + row.localRecordId.length + row.transactionState.length + row.health.length +
                row.operationId.length + row.quarantineReason.length + 16)
        }
        require(size <= MAX_BYTES)
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(MAGIC); putInt(owned.size)
            for (row in owned) {
                for (value in listOf(row.localRecordId, row.transactionState, row.health)) {
                    put(value.length.toByte()); put(value.toByteArray(Charsets.US_ASCII))
                }
                putInt(row.envelopeVersion); putInt(row.keyGeneration)
                putLong(row.committedRevision)
                for (value in listOf(row.operationId, row.quarantineReason)) {
                    put(value.length.toByte()); put(value.toByteArray(Charsets.US_ASCII))
                }
            }
        }.array()
    }

    fun decode(input: ByteArray): List<ProfileCatalogEntity> {
        val owned = input.clone()
        try {
            require(owned.size in 8..MAX_BYTES)
            val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
            require(reader.int == MAGIC)
            val count = reader.int; require(count in 0..MAX_ROWS)
            val result = ArrayList<ProfileCatalogEntity>(count)
            repeat(count) {
                fun text(allowEmpty: Boolean = false): String {
                    require(reader.hasRemaining())
                    val size = reader.get().toInt() and 255
                    require(size in (if (allowEmpty) 0 else 1)..64 && reader.remaining() >= size)
                    val bytes = ByteArray(size).also(reader::get)
                    require(bytes.all { it.toInt() in 1..127 })
                    return String(bytes, Charsets.US_ASCII)
                }
                val id = text(); val state = text(); val health = text()
                require(reader.remaining() >= 16)
                val envelope = reader.int; val key = reader.int; val revision = reader.long
                result += ProfileCatalogEntity(id, state, envelope, key, health, revision, text(true), text())
            }
            require(!reader.hasRemaining())
            val canonical = encode(result)
            try { require(canonical.contentEquals(owned)) } finally { canonical.fill(0) }
            return java.util.Collections.unmodifiableList(result)
        } finally { owned.fill(0) }
    }
}

/** Canonical one-to-one projection. This does not replace the broker's recipient validation. */
object RecipientBindingProjectionCodec {
    private const val MAGIC = 0x4b504231
    private const val MAX_BINDINGS = 32
    private const val MAX_BYTES = 8 * 1024

    fun imageDigest(bindings: List<RecipientBindingEntity>): String {
        val canonical = encode(bindings)
        return try {
            java.security.MessageDigest.getInstance("SHA-256").apply {
                update("kurdistan-recipient-bindings-v1\u0000".toByteArray(Charsets.US_ASCII))
                update(ByteBuffer.allocate(4).putInt(canonical.size).array())
            }.digest(canonical).joinToString("") { "%02x".format(it) }
        } finally { canonical.fill(0) }
    }

    fun encode(bindings: List<RecipientBindingEntity>): ByteArray {
        val owned = bindings.toTypedArray().toList().sortedBy { it.profileRecordId }
        require(owned.size <= MAX_BINDINGS)
        require(owned.map { it.profileRecordId }.toSet().size == owned.size)
        require(owned.map { it.clientKeyRecordId }.toSet().size == owned.size)
        var size = 8
        for (binding in owned) {
            require(binding.profileRecordId.matches(Regex("[a-z0-9-]{1,64}")))
            require(binding.clientKeyRecordId.matches(Regex("[a-z0-9-]{1,64}")))
            require(binding.operationId.matches(Regex("[0-9a-f]{64}")) && binding.operationId.any { it != '0' })
            require(binding.committedRevision > 0 && binding.committedRevision and 1L == 0L)
            size = Math.addExact(size, 3 + binding.profileRecordId.length + binding.clientKeyRecordId.length +
                binding.operationId.length + 8)
        }
        require(size <= MAX_BYTES)
        return ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(MAGIC); putInt(owned.size)
            for (binding in owned) {
                for (value in listOf(binding.profileRecordId, binding.clientKeyRecordId, binding.operationId)) {
                    put(value.length.toByte()); put(value.toByteArray(Charsets.US_ASCII))
                }
                putLong(binding.committedRevision)
            }
        }.array()
    }

    fun decode(input: ByteArray): List<RecipientBindingEntity> {
        val owned = input.clone()
        try {
            require(owned.size in 8..MAX_BYTES)
            val reader = ByteBuffer.wrap(owned).order(ByteOrder.BIG_ENDIAN)
            require(reader.int == MAGIC)
            val count = reader.int; require(count in 0..MAX_BINDINGS)
            val result = ArrayList<RecipientBindingEntity>(count)
            repeat(count) {
                fun text(): String {
                    require(reader.hasRemaining())
                    val size = reader.get().toInt() and 255
                    require(size in 1..64 && reader.remaining() >= size)
                    val bytes = ByteArray(size).also(reader::get)
                    require(bytes.all { it.toInt() in 1..127 })
                    return String(bytes, Charsets.US_ASCII)
                }
                val profile = text(); val key = text(); val op = text()
                require(reader.remaining() >= 8)
                result += RecipientBindingEntity(profile, key, op, reader.long)
            }
            require(!reader.hasRemaining())
            val canonical = encode(result)
            try { require(canonical.contentEquals(owned)) } finally { canonical.fill(0) }
            return java.util.Collections.unmodifiableList(result)
        } finally { owned.fill(0) }
    }
}

private fun requireBindingsFor(rows: List<ProfileCatalogEntity>, bindings: List<RecipientBindingEntity>,
    witness: ProtectedProjectionEntity) {
    val profiles = rows.map { it.localRecordId }.toSet()
    for (binding in bindings) {
        check(binding.profileRecordId in profiles && binding.committedRevision == witness.revision &&
            binding.operationId == witness.operationId) { "UNCOMMITTED_OR_STALE_RECIPIENT_BINDING" }
    }
}

private fun validateCatalogRow(row: ProfileCatalogEntity) {
    require(row.localRecordId.matches(Regex("[a-z0-9-]{1,64}")))
    require(TransactionState.entries.any { it.name == row.transactionState })
    require(CatalogHealth.entries.any { it.name == row.health })
    require(row.envelopeVersion in 1..2 && row.keyGeneration > 0)
    require(CatalogQuarantineReason.entries.any { it.name == row.quarantineReason })
    if (row.committedRevision == 0L) {
        require(row.operationId.isEmpty() && row.quarantineReason != CatalogQuarantineReason.NONE.name)
    } else {
        require(row.committedRevision > 0 && row.committedRevision and 1L == 0L)
        require(row.operationId.matches(Regex("[0-9a-f]{64}")) && row.operationId.any { it != '0' })
    }
}

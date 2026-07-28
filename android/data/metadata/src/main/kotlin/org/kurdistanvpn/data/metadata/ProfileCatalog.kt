// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.metadata

import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.RoomDatabase
import androidx.room.Upsert
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

@Entity(tableName = "profile_catalog")
data class ProfileCatalogEntity(
    @PrimaryKey val localRecordId: String,
    val transactionState: String,
    val envelopeVersion: Int,
    val keyGeneration: Int,
    val health: String,
)

@Dao
interface ProfileCatalogDao {
    @Query("SELECT * FROM profile_catalog ORDER BY localRecordId")
    fun observeAll(): Flow<List<ProfileCatalogEntity>>

    @Query("SELECT * FROM profile_catalog WHERE localRecordId = :localRecordId LIMIT 1")
    suspend fun get(localRecordId: String): ProfileCatalogEntity?

    @Query("SELECT * FROM profile_catalog ORDER BY localRecordId")
    suspend fun listAll(): List<ProfileCatalogEntity>

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
    entities = [ProfileCatalogEntity::class],
    version = 1,
    exportSchema = true,
)
abstract class KurdistanMetadataDatabase : RoomDatabase() {
    abstract fun profileCatalog(): ProfileCatalogDao
}

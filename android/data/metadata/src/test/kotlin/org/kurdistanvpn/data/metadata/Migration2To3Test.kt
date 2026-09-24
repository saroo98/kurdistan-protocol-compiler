// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.metadata

import androidx.sqlite.db.SupportSQLiteDatabase
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test

class Migration2To3Test {
    @Test fun migrationEmitsOnlyExactAdditiveTableAndIndex() {
        val statements = mutableListOf<String>()
        val db = Proxy.newProxyInstance(javaClass.classLoader, arrayOf(SupportSQLiteDatabase::class.java)) { _, method, args ->
            check(method.name == "execSQL" && args?.size == 1)
            statements += args[0] as String
            null
        } as SupportSQLiteDatabase
        val migration = KurdistanMetadataDatabase.MIGRATION_2_3
        assertEquals(2, migration.startVersion); assertEquals(3, migration.endVersion)
        migration.migrate(db)
        assertEquals(listOf(
            "CREATE TABLE IF NOT EXISTS `product_operation_projection` (`operationId` TEXT NOT NULL, `kind` TEXT NOT NULL, `scopeRecordId` TEXT, `state` TEXT NOT NULL, `attempt` INTEGER NOT NULL, `settingsRevisionBefore` INTEGER NOT NULL, `settingsRevisionAfter` INTEGER NOT NULL, `startedEpochHour` INTEGER NOT NULL, `resumable` INTEGER NOT NULL, PRIMARY KEY(`operationId`))",
            "CREATE INDEX IF NOT EXISTS `index_product_operation_projection_state_startedEpochHour` ON `product_operation_projection` (`state`, `startedEpochHour`)"
        ), statements)
    }
}

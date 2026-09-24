// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkManager
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import java.util.concurrent.TimeUnit

class ProductMaintenanceSchedulingDeviceTest {
    @Test fun replacingAndCancellingOneDeploymentLeavesNoDuplicateScheduledWork() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val scheduler = ProductUpdateScheduler(context)
        val id = CatalogId("test-maintenance-schedule")
        val manager = WorkManager.getInstance(context)
        try {
            assertTrue(scheduler.schedule(id, UpdatePreferences(automatic = true, intervalHours = 4)))
            assertTrue(scheduler.schedule(id, UpdatePreferences(automatic = true, intervalHours = 8)))
            val work = manager.getWorkInfosForUniqueWork(ProductUpdateScheduler.name(id)).get(10, TimeUnit.SECONDS)
            val pending = work.filter { !it.state.isFinished }
            assertEquals(1, pending.size)
            assertEquals(8 * 60 * 60 * 1000L, pending.single().periodicityInfo?.repeatIntervalMillis)
            assertTrue(scheduler.schedule(id, UpdatePreferences(automatic = false)))
            assertTrue(manager.getWorkInfosForUniqueWork(ProductUpdateScheduler.name(id)).get(10, TimeUnit.SECONDS).all { it.state.isFinished })
        } finally { scheduler.schedule(id, UpdatePreferences(automatic = false)) }
    }
}

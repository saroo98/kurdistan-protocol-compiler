// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import android.content.Context
import androidx.work.*
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kurdistanvpn.core.model.*

internal class ProductUpdateScheduler(private val context: Context) {
    suspend fun schedule(id: CatalogId, preferences: UpdatePreferences): Boolean = withContext(Dispatchers.IO) {
        try {
            // The graph rejects VPN/unknown processes before WorkManager is accessed.
            (context.applicationContext as KurdistanApplication).compositionRoot
            val manager = WorkManager.getInstance(context)
            if (!preferences.automatic) manager.cancelUniqueWork(name(id)).await()
            else manager.enqueueUniquePeriodicWork(name(id), ExistingPeriodicWorkPolicy.CANCEL_AND_REENQUEUE,
                PeriodicWorkRequestBuilder<ProductUpdateWorker>(preferences.intervalHours.toLong(), TimeUnit.HOURS)
                    .setInitialDelay(preferences.intervalHours.toLong(), TimeUnit.HOURS)
                    .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                    .setInputData(workDataOf(PROFILE_ID to id.value)).build()).await()
            true
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { false }
    }
    companion object {
        const val PROFILE_ID = "profile-id"
        fun name(id: CatalogId) = "signed-update-${id.value}"
    }
}

/** A schedule carries an identifier, never permission, credentials, a route or native authority. */
class ProductUpdateWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val id = try { CatalogId(checkNotNull(inputData.getString(ProductUpdateScheduler.PROFILE_ID))) }
        catch (_: IllegalArgumentException) { return@withContext Result.failure() }
        catch (_: IllegalStateException) { return@withContext Result.failure() }
        val root = (applicationContext as KurdistanApplication).compositionRoot
        val projection = root.protectedStateFacade()?.readProjection() ?: return@withContext Result.success()
        // Only the currently selected signed deployment is executable by the existing runtime owner.
        if (!projection.settings.updates.automatic || projection.settings.profiles.activeLocalRecordId != id.value)
            return@withContext Result.success()
        root.nodeMaintenanceRepository.checkSignedUpdate(id)
        Result.success() // Native policy bounds attempts; periodic scheduling, not a tight retry loop.
    }
}

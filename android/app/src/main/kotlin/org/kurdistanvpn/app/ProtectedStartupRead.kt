// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.KurdNativeCore
import org.kurdistanvpn.core.nativeapi.NativeProductResult
import org.kurdistanvpn.core.nativeapi.NativeProbeResult
import org.kurdistanvpn.runtime.android.RuntimeSelectedProbeV1
import org.kurdistanvpn.data.metadata.CatalogHealth
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.ClientKeySummary

/** Availability is presentation, never a default projection or permission to initialize storage. */
internal sealed interface ProtectedStartupRead {
    data class Ready(val projection: ProtectedStateApplicationFacade.ReadProjection) : ProtectedStartupRead
    data class Unavailable(val failure: ProductCompositionRoot.StorageFailure) : ProtectedStartupRead {
        val presentation: AppState get() = when (failure) {
            ProductCompositionRoot.StorageFailure.FIRST_USE -> AppState.FirstLaunch
            ProductCompositionRoot.StorageFailure.LOCKED -> AppState.LockedStorage
            ProductCompositionRoot.StorageFailure.KEY_INVALIDATED -> AppState.KeyInvalidated
            ProductCompositionRoot.StorageFailure.MIGRATION_REQUIRED -> AppState.MigrationRequired
            ProductCompositionRoot.StorageFailure.DEGRADED,
            ProductCompositionRoot.StorageFailure.MUTATION_UNPROVEN -> AppState.DegradedStorage
        }
        val recoveryReason: ProtectedRecoveryReason? get() = when (failure) {
            ProductCompositionRoot.StorageFailure.MUTATION_UNPROVEN -> ProtectedRecoveryReason.MUTATION_UNPROVEN
            ProductCompositionRoot.StorageFailure.DEGRADED,
            ProductCompositionRoot.StorageFailure.KEY_INVALIDATED -> ProtectedRecoveryReason.INCONSISTENT
            else -> null
        }
    }
    data object UnexpectedFailure : ProtectedStartupRead
}

/** Read-only adapter. Cancellation propagates; unexpected exceptions have a distinct fatal result. */
internal suspend fun readStartupProjection(
    failure: ProductCompositionRoot.StorageFailure?,
    read: () -> ProtectedStateApplicationFacade.ReadProjection?,
): ProtectedStartupRead {
    currentCoroutineContext().ensureActive()
    if (failure != null) return ProtectedStartupRead.Unavailable(failure)
    return try {
        val projection = read()
        currentCoroutineContext().ensureActive()
        if (projection == null) ProtectedStartupRead.Unavailable(ProductCompositionRoot.StorageFailure.DEGRADED)
        else ProtectedStartupRead.Ready(projection)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        ProtectedStartupRead.UnexpectedFailure
    }
}

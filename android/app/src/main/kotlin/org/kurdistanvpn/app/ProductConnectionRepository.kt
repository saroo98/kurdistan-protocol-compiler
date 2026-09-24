// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.runtime.api.*

internal data class ProductConnectionCurrent(val profile: ProfileProjection?,
    val binding: RuntimePresentationBinding?, val storage: StorageHealth)

/** The resumed UI owns permission effects; the service still reconstructs fresh executable authority. */
internal interface ProductConnectionForeground {
    fun beginConnection(profileId: CatalogId, settingsRevision: Long): Boolean
}

internal class ProductConnectionRepository(
    private val snapshots: Flow<VpnRuntimeSnapshot>,
    private val readCurrent: suspend () -> ProductConnectionCurrent,
    private val nowEpochSeconds: () -> Long,
    private val requestStart: suspend (CatalogId, Long) -> Boolean,
    private val stop: () -> Unit,
    private val recover: () -> Unit,
    private val setPaused: suspend (Long?) -> DomainResult<Unit>,
) : ConnectionRepository {
    override fun observeState(): Flow<ConnectionState> = snapshots.map { snapshot ->
        val current = readCurrentSafely()
        productConnectionPresentation(snapshot, current.profile, current.binding, current.storage, nowEpochSeconds())
    }

    override suspend fun connect(profileId: CatalogId, expectedSettingsRevision: Long): DomainResult<ConnectionCommandResult> {
        val current = readCurrentSafely()
        if (current.storage != StorageHealth.AVAILABLE) return rejected(ProductFailureCode.STORAGE_LOCKED)
        val profile = current.profile ?: return rejected(ProductFailureCode.PROFILE_UNTRUSTED)
        if (profile.id != profileId || current.binding?.profileId != profileId.value ||
            current.binding.settingsRevision != expectedSettingsRevision)
            return rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        if (profile.status != ProjectionStatus.VERIFIED) return rejected(ProductFailureCode.PROFILE_UNTRUSTED)
        if (nowEpochSeconds() >= profile.expiresAtEpochSeconds) return rejected(ProductFailureCode.PROFILE_EXPIRED)
        return if (requestStart(profileId, expectedSettingsRevision)) accepted()
        else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
    }

    override suspend fun disconnect(): DomainResult<ConnectionCommandResult> { stop(); return accepted() }
    override suspend fun recoverInternet(): DomainResult<ConnectionCommandResult> { recover(); return accepted() }
    override suspend fun pause(durationMillis: Long): DomainResult<ConnectionCommandResult> =
        if (durationMillis in 0..86_400_000) pauseCommand(durationMillis) else rejected(ProductFailureCode.INVALID_INPUT)
    override suspend fun resume(): DomainResult<ConnectionCommandResult> = pauseCommand(null)
    private suspend fun pauseCommand(durationMillis: Long?): DomainResult<ConnectionCommandResult> = when (val result = setPaused(durationMillis)) {
        is DomainResult.Success -> accepted()
        is DomainResult.Rejected -> result
    }
    override suspend fun reconnect(): DomainResult<ConnectionCommandResult> {
        val current = readCurrentSafely().binding ?: return rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        return connect(CatalogId(current.profileId), current.settingsRevision)
    }
    private fun accepted() = DomainResult.Success(ConnectionCommandResult.ACCEPTED)
    private suspend fun readCurrentSafely(): ProductConnectionCurrent = try { readCurrent() }
    catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
    catch (_: Exception) { ProductConnectionCurrent(null, null, StorageHealth.DEGRADED) }
    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
}

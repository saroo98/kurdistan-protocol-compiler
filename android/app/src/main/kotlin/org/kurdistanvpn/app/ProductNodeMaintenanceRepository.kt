// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.nativeapi.*
import org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade
import org.kurdistanvpn.data.secure.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.runtime.android.RuntimeVerifiedUpdate

/** One maintenance operation and one reviewed candidate, with no native handle in feature state. */
internal class ProductNodeMaintenanceRepository(
    private val facade: () -> ProtectedStateApplicationFacade?,
    private val runProbe: suspend (CatalogId, ProbePreferences) -> NativeProductResult<NativeProbeResult>,
    private val runUpdate: suspend (CatalogId) -> NativeProductResult<RuntimeVerifiedUpdate?>,
    private val cancelNative: suspend () -> Boolean,
    private val schedule: suspend (CatalogId, UpdatePreferences) -> Boolean,
) : NodeMaintenanceRepository, AutoCloseable {
    private val mutex = Mutex()
    private val monitor = Any()
    private var running: Pair<CatalogId, OperationKind>? = null
    private var cancelled = false
    private var closed = false
    private var candidate: Pair<CatalogId, RuntimeVerifiedUpdate>? = null
    private val update = MutableStateFlow<Pair<CatalogId, OperationState>?>(null)
    private val histories = MutableStateFlow<Pair<CatalogId, ProbeHistory>?>(null)

    override fun observeUpdate(deploymentId: CatalogId): Flow<OperationState> =
        update.map { if (it?.first == deploymentId) it.second else OperationState.Idle }.distinctUntilChanged()

    override fun observeProbeHistory(profileId: CatalogId): Flow<ProbeHistory> = flow {
        val stored = checkNotNull(facade()?.readProductStorage(profileId.value))
        emit(history(stored.probeHistory))
        emitAll(histories.filterNotNull().filter { it.first == profileId }.map { it.second })
    }.flowOn(Dispatchers.IO)

    override suspend fun scheduleSignedUpdate(deploymentId: CatalogId, preferences: UpdatePreferences): DomainResult<Unit> =
        withContext(Dispatchers.IO) {
            val owner = facade() ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
            val projection = owner.readProjection() ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
            if (projection.profiles.none { it.localRecordId == deploymentId.value }) return@withContext rejected(ProductFailureCode.INVALID_INPUT)
            if (schedule(deploymentId, preferences.validated())) DomainResult.Success(Unit)
            else rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        }

    override suspend fun probe(profileId: CatalogId, request: ProbePreferences): DomainResult<ProbeSample> =
        operation(profileId, OperationKind.PROBE) { owner, before ->
            val result = runProbe(profileId, request)
            if (isCancelled()) return@operation rejected(ProductFailureCode.CANCELLED)
            val sample = when (result) {
                is NativeProductResult.Success -> result.value.toSample(request.method)
                // Measurement fields are placeholders only when failure is explicit, never a latency success.
                is NativeProductResult.Failure -> ProbeSample(System.currentTimeMillis() / 60_000,
                    0, 0, 0, ProbeStability.UNKNOWN, result.code, request.method)
            }
            val fresh = owner.readProductStorage(profileId.value)
                ?: return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
            if (fresh.profileTrustRevision != before.profileTrustRevision) return@operation rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            val retained = history(fresh.probeHistory)
            val next = StoredProbeHistory(retained.currentEpochMinutes, (retained.samples + sample).takeLast(200))
            if (owner.recordProbe(fresh.revision, profileId.value, next) !is ProtectedStateApplicationFacade.CommandResult.Committed)
                return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
            histories.value = profileId to ProbeHistory(next.samples, next.currentEpochMinutes)
            DomainResult.Success(sample)
        }

    override suspend fun checkSignedUpdate(deploymentId: CatalogId): DomainResult<PendingProductOperation> =
        operation(deploymentId, OperationKind.UPDATE) { owner, before ->
            synchronized(monitor) { candidate?.second?.close(); candidate = null }
            update.value = deploymentId to OperationState.Loading(OperationKind.UPDATE)
            var material: RuntimeVerifiedUpdate? = null
            try {
                when (val result = runUpdate(deploymentId)) {
                    is NativeProductResult.Failure -> {
                        if (isCancelled()) return@operation rejected(ProductFailureCode.CANCELLED)
                        val fresh = owner.readProductStorage(deploymentId.value)
                            ?: return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
                        if (fresh.profileTrustRevision != before.profileTrustRevision)
                            return@operation rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                        val hour = System.currentTimeMillis() / 3_600_000
                        val previous = fresh.update
                        val observation = StoredUpdateState(previous?.publicationGeneration,
                            previous?.profileGeneration ?: fresh.profile?.profile?.generation,
                            UpdateCategory.REJECTED, hour, hour + 1,
                            ((previous?.failureCount ?: 0) + 1).coerceAtMost(10))
                        if (owner.recordUpdate(fresh.revision, deploymentId.value, observation) !is
                            ProtectedStateApplicationFacade.CommandResult.Committed)
                            return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
                        return@operation rejected(result.code)
                    }
                    is NativeProductResult.Success -> material = result.value
                }
                if (isCancelled()) return@operation rejected(ProductFailureCode.CANCELLED)
                val fresh = owner.readProductStorage(deploymentId.value)
                    ?: return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
                if (fresh.profileTrustRevision != before.profileTrustRevision) return@operation rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                val hour = System.currentTimeMillis() / 3_600_000
                val old = fresh.update
                val recorded = StoredUpdateState(material?.generation ?: old?.publicationGeneration,
                    old?.profileGeneration ?: fresh.profile?.profile?.generation,
                    if (material == null) UpdateCategory.UNCHANGED else UpdateCategory.AVAILABLE,
                    hour, hour + 1, 0)
                if (owner.recordUpdate(fresh.revision, deploymentId.value, recorded) !is ProtectedStateApplicationFacade.CommandResult.Committed)
                    return@operation rejected(ProductFailureCode.STORAGE_DEGRADED)
                val preview = PendingProductOperation(CatalogId(java.util.UUID.randomUUID().toString()),
                    OperationPreview(OperationKind.UPDATE, if (material == null) 0 else 1))
                synchronized(monitor) {
                    if (cancelled || closed) return@operation rejected(ProductFailureCode.CANCELLED)
                    material?.let { candidate = deploymentId to it; material = null }
                    update.value = deploymentId to if (preview.preview.itemCount == 0)
                        OperationState.Succeeded(OperationResult(OperationKind.UPDATE, 0))
                    else OperationState.AwaitingConfirmation(preview.preview)
                }
                DomainResult.Success(preview)
            } finally { material?.close() }
        }.also { result ->
            if (result is DomainResult.Rejected && result.failure.code != ProductFailureCode.OPERATION_ALREADY_ACTIVE)
                update.value = deploymentId to OperationState.Failed(OperationKind.UPDATE, result.failure)
        }

    override suspend fun cancelProbe(profileId: CatalogId): DomainResult<Unit> = cancel(profileId, OperationKind.PROBE)
    override suspend fun cancelSignedUpdate(deploymentId: CatalogId): DomainResult<Unit> = cancel(deploymentId, OperationKind.UPDATE)

    private suspend fun cancel(id: CatalogId, kind: OperationKind): DomainResult<Unit> {
        val needsCancel = synchronized(monitor) {
            if (kind == OperationKind.UPDATE && candidate?.first == id) { candidate?.second?.close(); candidate = null }
            (running == id to kind).also { if (it) cancelled = true }
        }
        if (needsCancel && !cancelNative()) return rejected(ProductFailureCode.STORAGE_DEGRADED)
        if (kind == OperationKind.UPDATE) update.value = id to OperationState.Cancelled(kind)
        return DomainResult.Success(Unit)
    }

    private suspend fun <T> operation(id: CatalogId, kind: OperationKind,
        block: suspend (ProtectedStateApplicationFacade, ProtectedStateApplicationFacade.ProductStorageReadProjection) -> DomainResult<T>): DomainResult<T> =
        withContext(Dispatchers.IO) {
            if (!mutex.tryLock()) return@withContext rejected(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
            try {
                synchronized(monitor) { if (closed) return@withContext rejected(ProductFailureCode.OPERATION_INTERRUPTED)
                    running = id to kind; cancelled = false }
                val owner = facade() ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
                val projection = owner.readProjection() ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
                if (projection.profiles.none { it.localRecordId == id.value }) return@withContext rejected(ProductFailureCode.INVALID_INPUT)
                val before = owner.readProductStorage(id.value) ?: return@withContext rejected(ProductFailureCode.STORAGE_DEGRADED)
                block(owner, before)
            } catch (cancelled: CancellationException) {
                withContext(NonCancellable) { cancel(id, kind) }
                throw cancelled
            } catch (_: Exception) { rejected(ProductFailureCode.OPERATION_INTERRUPTED) }
            finally { synchronized(monitor) { running = null }; mutex.unlock() }
        }

    private fun isCancelled() = synchronized(monitor) { cancelled || closed }
    private fun history(stored: StoredProbeHistory?): ProbeHistory {
        val now = System.currentTimeMillis() / 60_000
        return ProbeHistory(stored?.samples.orEmpty().filter { it.coarseEpochMinutes <= now &&
            now - it.coarseEpochMinutes <= 30 * 24 * 60 }.takeLast(200), now)
    }
    private fun NativeProbeResult.toSample(method: ProbeMethod): ProbeSample = ProbeSample(System.currentTimeMillis() / 60_000,
        (meanLatencyMicros ?: 0) / 1000, (jitterMicros ?: 0) / 1000, lossPermille * 10,
        when (stability) { NativeProbeStability.NOT_ENOUGH_SAMPLES -> ProbeStability.UNKNOWN
            NativeProbeStability.STABLE -> ProbeStability.STABLE; NativeProbeStability.VARIABLE -> ProbeStability.UNSTABLE },
        when { completion == NativeProbeCompletion.RATE_LIMITED -> ProductFailureCode.RATE_LIMITED
            completion == NativeProbeCompletion.TIMED_OUT -> ProductFailureCode.OPERATION_TIMED_OUT
            succeeded == 0 -> ProductFailureCode.NODE_UNREACHABLE; else -> null }, method)

    override fun close() = synchronized(monitor) { closed = true; cancelled = true; candidate?.second?.close(); candidate = null }
    private fun rejected(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
}

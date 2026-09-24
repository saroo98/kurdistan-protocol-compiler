// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.settings

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

data class SettingsStoreState(val journalRevision: Long, val appliedRevision: Long, val requested: ProductSettings,
    val effective: SettingsEffectiveValues? = null) {
    init { require(journalRevision > 0 && journalRevision and 1L == 0L && appliedRevision >= 0) }
    fun revision() = SettingsRevision(appliedRevision, requested, effective)
}
sealed interface SettingsPortResult<out T> {
    data class Success<T>(val value: T) : SettingsPortResult<T>
    data class Rejected(val code: ProductFailureCode) : SettingsPortResult<Nothing>
}
/** Closed commands only. Implementations must use the existing protected broker, not another journal. */
interface SettingsMutationPort {
    suspend fun read(): SettingsPortResult<SettingsStoreState>
    suspend fun validate(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings): SettingsPortResult<SettingsEffectiveValues>
    suspend fun apply(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings): SettingsPortResult<SettingsStoreState>
    suspend fun rollback(expectedJournal: Long): SettingsPortResult<SettingsStoreState>
}
enum class SettingsRuntimeIntent { ALREADY_STOPPED, RECONNECT_ONCE }
interface SettingsRuntimePort {
    suspend fun validate(previous: ProductSettings, requested: ProductSettings): SettingsPortResult<Unit> = SettingsPortResult.Success(Unit)
    suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent>
    /** Acknowledgement is not Connected. A reconnect adapter must await its correlated application result. */
    suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit>
    suspend fun restore(intent: SettingsRuntimeIntent, restoredState: SettingsStoreState): SettingsPortResult<Unit> =
        if (intent == SettingsRuntimeIntent.ALREADY_STOPPED) SettingsPortResult.Success(Unit)
        else SettingsPortResult.Rejected(ProductFailureCode.TUN_ESTABLISH_FAILED)
    suspend fun finish() = Unit
}

class SettingsApplyCoordinator(private val storage: SettingsMutationPort, private val runtime: SettingsRuntimePort,
    private val draftStorage: SettingsDraftPort) : SettingsRepository {
    private val mutex = Mutex()
    private val drafts = linkedMapOf<CatalogId, SettingsStoreState>()
    private val observed = MutableStateFlow<SettingsRevision?>(null)
    override fun observeAppliedRevision(): Flow<SettingsRevision> = flow { appliedRevision(); emitAll(observed.filterNotNull()) }
    override suspend fun appliedRevision(): DomainResult<SettingsRevision> = mutex.withLock {
        when (val value = portCall { storage.read() }) {
            is SettingsPortResult.Rejected -> reject(value.code)
            is SettingsPortResult.Success -> DomainResult.Success(value.value.revision().also { observed.value = it })
        }
    }
    override suspend fun openDraft(): DomainResult<SettingsDraft> = mutex.withLock {
        if (drafts.size >= 16) return@withLock reject(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        when (val value = portCall { storage.read() }) {
            is SettingsPortResult.Rejected -> reject(value.code)
            is SettingsPortResult.Success -> {
                val id = CatalogId(java.util.UUID.randomUUID().toString())
                check(id !in drafts)
                when (val saved = portCall { draftStorage.create(StoredSettingsDraft(id, value.value, value.value.requested)) }) {
                    is SettingsPortResult.Rejected -> return@withLock reject(saved.code)
                    is SettingsPortResult.Success -> Unit
                }
                drafts[id] = value.value
                DomainResult.Success(SettingsDraft(id, value.value.revision()))
            }
        }
    }
    override suspend fun saveDraft(draftId: CatalogId, requested: ProductSettings): DomainResult<Unit> = mutex.withLock {
        val prior = drafts[draftId] ?: return@withLock reject(ProductFailureCode.OPERATION_INTERRUPTED)
        when (val validation = validateComplete(prior, requested)) {
            is SettingsPortResult.Rejected -> return@withLock reject(validation.code)
            is SettingsPortResult.Success -> Unit
        }
        when (val saved = portCall { draftStorage.replace(StoredSettingsDraft(draftId, prior, requested)) }) {
            is SettingsPortResult.Rejected -> reject(saved.code)
            is SettingsPortResult.Success -> DomainResult.Success(Unit)
        }
    }
    override suspend fun resumeDraft(draftId: CatalogId): DomainResult<ResumableSettingsDraft> = mutex.withLock {
        if (draftId !in drafts && drafts.size >= 16) return@withLock reject(ProductFailureCode.OPERATION_ALREADY_ACTIVE)
        val saved = when (val read = portCall { draftStorage.read(draftId) }) {
            is SettingsPortResult.Rejected -> return@withLock reject(read.code)
            is SettingsPortResult.Success -> read.value
        }
        val current = when (val read = portCall { storage.read() }) {
            is SettingsPortResult.Rejected -> return@withLock reject(read.code)
            is SettingsPortResult.Success -> read.value
        }
        if (saved.id != draftId || saved.base.journalRevision != current.journalRevision ||
            saved.base.appliedRevision != current.appliedRevision) {
            drafts.remove(draftId)
            return@withLock reject(ProductFailureCode.OPERATION_INTERRUPTED)
        }
        drafts[draftId] = saved.base
        DomainResult.Success(ResumableSettingsDraft(SettingsDraft(draftId, saved.base.revision()), saved.requested))
    }
    override suspend fun validate(draftId: CatalogId, requested: ProductSettings): DomainResult<OperationPreview> = mutex.withLock {
        val prior = drafts[draftId] ?: return@withLock reject(ProductFailureCode.OPERATION_INTERRUPTED)
        when (val result = validateComplete(prior, requested)) {
            is SettingsPortResult.Rejected -> reject(result.code)
            is SettingsPortResult.Success -> DomainResult.Success(OperationPreview(OperationKind.SETTINGS_CHANGE, 1))
        }
    }
    override suspend fun apply(draftId: CatalogId, expectedAppliedRevision: Long, requested: ProductSettings): DomainResult<SettingsRevision> = mutex.withLock {
        val prior = drafts[draftId] ?: return@withLock reject(ProductFailureCode.OPERATION_INTERRUPTED)
        if (prior.appliedRevision != expectedAppliedRevision) return@withLock reject(ProductFailureCode.OPERATION_INTERRUPTED)
        val validation = validateComplete(prior, requested)
        if (validation is SettingsPortResult.Rejected) return@withLock reject(validation.code)
        val platform = portCall { runtime.validate(prior.requested, requested) }
        if (platform is SettingsPortResult.Rejected) return@withLock reject(platform.code)
        val intent = when (val result = portCall { runtime.prepare() }) {
            is SettingsPortResult.Rejected -> return@withLock reject(result.code)
            is SettingsPortResult.Success -> result.value
        }
        var applied: SettingsStoreState? = null
        try {
            currentCoroutineContext().ensureActive()
            when (val consumed = portCall { draftStorage.delete(draftId) }) {
                is SettingsPortResult.Rejected -> return@withLock reject(restoreRuntime(intent, prior, consumed.code))
                is SettingsPortResult.Success -> Unit
            }
            drafts.remove(draftId)
            // Do not lose the broker's commit outcome between commit and acknowledgement.
            val committed = when (val result = withContext(NonCancellable) {
                portCall { storage.apply(prior.journalRevision, prior.appliedRevision, requested) }
            }) {
                is SettingsPortResult.Rejected -> return@withLock reject(restoreRuntime(intent, prior, result.code))
                is SettingsPortResult.Success -> result.value
            }
            applied = committed
            currentCoroutineContext().ensureActive()
            when (val result = runtime.apply(intent, committed)) {
                is SettingsPortResult.Success -> DomainResult.Success(committed.revision().also { observed.value = it })
                is SettingsPortResult.Rejected -> reject(rollback(intent, committed, result.code))
            }
        } catch (cancelled: CancellationException) {
            applied?.let { rollback(intent, it, ProductFailureCode.CANCELLED) }
                ?: restoreRuntime(intent, prior, ProductFailureCode.CANCELLED)
            throw cancelled
        } catch (_: Exception) {
            reject(applied?.let { rollback(intent, it, ProductFailureCode.INTERNAL_FAILURE) }
                ?: restoreRuntime(intent, prior, ProductFailureCode.INTERNAL_FAILURE))
        } finally { withContext(NonCancellable) { runtime.finish() } }
    }
    override suspend fun cancel(draftId: CatalogId): DomainResult<Unit> = mutex.withLock {
        when (val deleted = portCall { draftStorage.delete(draftId) }) {
            is SettingsPortResult.Rejected -> if (deleted.code != ProductFailureCode.OPERATION_INTERRUPTED)
                return@withLock reject(deleted.code)
            is SettingsPortResult.Success -> Unit
        }
        drafts.remove(draftId)
        DomainResult.Success(Unit)
    }
    private suspend fun validateComplete(prior: SettingsStoreState, requested: ProductSettings): SettingsPortResult<SettingsEffectiveValues> {
        try {
            require(requested.routing.validated() == requested.routing && requested.tunnel.validated() == requested.tunnel)
            requested.profiles.validated(); requested.updates.validated(); requested.probes.validated(); requested.expert.validated()
        } catch (_: RuntimeException) { return SettingsPortResult.Rejected(ProductFailureCode.INVALID_INPUT) }
        return when (val current = portCall { storage.read() }) {
            is SettingsPortResult.Rejected -> current
            is SettingsPortResult.Success -> if (current.value.journalRevision != prior.journalRevision || current.value.appliedRevision != prior.appliedRevision)
                SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
            else portCall { storage.validate(prior.journalRevision, prior.appliedRevision, requested) }
        }
    }
    private suspend fun rollback(intent: SettingsRuntimeIntent, applied: SettingsStoreState, failure: ProductFailureCode): ProductFailureCode = withContext(NonCancellable) {
        when (val result = portCall { storage.rollback(applied.journalRevision) }) {
            is SettingsPortResult.Rejected -> ProductFailureCode.STORAGE_DEGRADED
            is SettingsPortResult.Success -> {
                observed.value = result.value.revision()
                restoreRuntime(intent, result.value, failure)
            }
        }
    }
    private suspend fun restoreRuntime(intent: SettingsRuntimeIntent, state: SettingsStoreState, failure: ProductFailureCode): ProductFailureCode =
        withContext(NonCancellable) {
            when (val result = portCall { runtime.restore(intent, state) }) {
                is SettingsPortResult.Success -> failure
                is SettingsPortResult.Rejected -> result.code
            }
        }
    private suspend fun <T> portCall(action: suspend () -> SettingsPortResult<T>): SettingsPortResult<T> = try { action() }
    catch (cancelled: CancellationException) { throw cancelled }
    catch (_: Exception) { SettingsPortResult.Rejected(ProductFailureCode.STORAGE_DEGRADED) }
    private fun reject(code: ProductFailureCode) = DomainResult.Rejected(ProductFailure(code))
}

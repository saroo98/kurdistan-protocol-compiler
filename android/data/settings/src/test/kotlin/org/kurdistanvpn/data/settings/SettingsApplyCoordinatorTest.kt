// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.settings

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*

class SettingsApplyCoordinatorTest {
    @Test fun uncertainDraftConsumptionCannotPublishAppliedSettings() = runBlocking {
        val storage = MemorySettingsPort(); val runtime = MemorySettingsRuntime(); val drafts = MemoryDraftPort()
        val coordinator = SettingsApplyCoordinator(storage, runtime, drafts)
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        drafts.failDelete = true
        assertTrue(coordinator.apply(draft.id, 1, ProductSettings(highContrast = true)) is DomainResult.Rejected)
        assertEquals(0, storage.writes); assertEquals(0, runtime.applies)
        assertTrue(coordinator.cancel(draft.id) is DomainResult.Rejected)
        drafts.failDelete = false
        assertTrue(coordinator.cancel(draft.id) is DomainResult.Success)
        assertTrue(coordinator.saveDraft(draft.id, ProductSettings(highContrast = true)) is DomainResult.Rejected)
    }
    @Test fun savedDraftResumesWithoutApplyingAndStaleBaseIsRejected() = runBlocking {
        val storage = MemorySettingsPort()
        val runtime = MemorySettingsRuntime()
        val drafts = MemoryDraftPort()
        val first = SettingsApplyCoordinator(storage, runtime, drafts)
        val draft = (first.openDraft() as DomainResult.Success).value
        val requested = ProductSettings(highContrast = true)
        assertTrue(first.saveDraft(draft.id, requested) is DomainResult.Success)
        val second = SettingsApplyCoordinator(storage, runtime, drafts)
        val resumed = (second.resumeDraft(draft.id) as DomainResult.Success).value
        assertEquals(requested, resumed.requested)
        assertEquals(0, storage.writes)
        assertEquals(0, runtime.applies)
        storage.state = storage.state.copy(journalRevision = storage.state.journalRevision + 2)
        assertEquals(ProductFailureCode.OPERATION_INTERRUPTED,
            (second.resumeDraft(draft.id) as DomainResult.Rejected).failure.code)
        assertTrue(second.cancel(draft.id) is DomainResult.Success)
        assertTrue(second.cancel(draft.id) is DomainResult.Success)
        assertTrue(second.resumeDraft(draft.id) is DomainResult.Rejected)
    }
    @Test fun platformRejectionPreventsPersistenceAndRuntimePreparation() = runBlocking {
        val storage = MemorySettingsPort()
        val runtime = object : SettingsRuntimePort {
            override suspend fun validate(previous: ProductSettings, requested: ProductSettings) =
                SettingsPortResult.Rejected(ProductFailureCode.INVALID_INPUT)
            override suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent> = error("Rejected before prepare")
            override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState) = SettingsPortResult.Success(Unit)
        }
        val coordinator = SettingsApplyCoordinator(storage, runtime, MemoryDraftPort())
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        assertTrue(coordinator.apply(draft.id, 1, ProductSettings(highContrast = true)) is DomainResult.Rejected)
        assertEquals(0, storage.writes)
    }
    @Test fun failedReconnectRestoresRuntimeOnlyAfterStorageRollbackAndAlwaysReleasesItsTicket() = runBlocking {
        val port = MemorySettingsPort()
        var restored = false
        var finished = false
        val runtime = object : SettingsRuntimePort {
            override suspend fun prepare() = SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE)
            override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> =
                SettingsPortResult.Rejected(ProductFailureCode.TUN_ESTABLISH_FAILED)
            override suspend fun restore(intent: SettingsRuntimeIntent, restoredState: SettingsStoreState): SettingsPortResult<Unit> {
                assertEquals(1, port.rollbacks)
                assertEquals(1L, restoredState.appliedRevision)
                assertFalse(restoredState.requested.highContrast)
                restored = true
                return SettingsPortResult.Success(Unit)
            }
            override suspend fun finish() { finished = true }
        }
        val coordinator = SettingsApplyCoordinator(port, runtime, MemoryDraftPort())
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        val result = coordinator.apply(draft.id, 1, ProductSettings(highContrast = true)) as DomainResult.Rejected
        assertEquals(ProductFailureCode.TUN_ESTABLISH_FAILED, result.failure.code)
        assertTrue(restored); assertTrue(finished)
    }
    @Test fun cancellationAfterCommitCompensatesOnceAndDoesNotReportSuccess() = runBlocking {
        val port = MemorySettingsPort()
        val runtime = object : SettingsRuntimePort {
            override suspend fun prepare() = SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE)
            override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> =
                throw kotlinx.coroutines.CancellationException("SYNTHETIC_CANCEL")
        }
        val coordinator = SettingsApplyCoordinator(port, runtime, MemoryDraftPort())
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        try { coordinator.apply(draft.id, 1, ProductSettings(highContrast = true)); fail("cancellation must propagate") }
        catch (_: kotlinx.coroutines.CancellationException) { }
        assertEquals(1, port.writes); assertEquals(1, port.rollbacks)
        assertEquals(1L, port.state.appliedRevision); assertEquals(8L, port.state.journalRevision)
        assertFalse(port.state.requested.highContrast)
    }
    @Test fun runtimePreparationAndCompensationExceptionsStayCategorical() = runBlocking {
        val port = MemorySettingsPort()
        val brokenRuntime = object : SettingsRuntimePort {
            override suspend fun prepare(): SettingsPortResult<SettingsRuntimeIntent> = error("PRIVATE_CANARY_RUNTIME")
            override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState) = SettingsPortResult.Success(Unit)
        }
        val coordinator = SettingsApplyCoordinator(port, brokenRuntime, MemoryDraftPort())
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        val result = coordinator.apply(draft.id, 1, ProductSettings(highContrast = true))
        assertTrue(result is DomainResult.Rejected); assertEquals(0, port.writes)
        assertFalse(result.toString().contains("PRIVATE_CANARY"))
        val failedRollback = object : SettingsMutationPort by port {
            override suspend fun rollback(expectedJournal: Long): SettingsPortResult<SettingsStoreState> = error("PRIVATE_CANARY_ROLLBACK")
        }
        val second = SettingsApplyCoordinator(failedRollback, MemorySettingsRuntime().also { it.fail = true }, MemoryDraftPort())
        val secondDraft = (second.openDraft() as DomainResult.Success).value
        val failure = second.apply(secondDraft.id, 1, ProductSettings(highContrast = true)) as DomainResult.Rejected
        assertEquals(ProductFailureCode.STORAGE_DEGRADED, failure.failure.code)
    }
    @Test fun lateInvalidFieldAndStaleJournalRevisionCauseNoPartialWrite() = runBlocking {
        val port = MemorySettingsPort()
        val runtime = MemorySettingsRuntime()
        val coordinator = SettingsApplyCoordinator(port, runtime, MemoryDraftPort())
        val draft = (coordinator.openDraft() as DomainResult.Success).value
        val invalid = ProductSettings(highContrast = true, routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY))
        assertTrue(coordinator.apply(draft.id, 1, invalid) is DomainResult.Rejected)
        assertEquals(0, port.writes); assertEquals(0, runtime.applies)
        port.state = port.state.copy(journalRevision = 6)
        assertTrue(coordinator.apply(draft.id, 1, ProductSettings(highContrast = true)) is DomainResult.Rejected)
        assertEquals(0, port.writes)
    }

    @Test fun completeDraftReconnectsOnceAndRuntimeFailureRestoresPriorAppliedRevision() = runBlocking {
        for (fail in listOf(false, true)) {
            val port = MemorySettingsPort(); val runtime = MemorySettingsRuntime().also { it.fail = fail }
            val coordinator = SettingsApplyCoordinator(port, runtime, MemoryDraftPort())
            val draft = (coordinator.openDraft() as DomainResult.Success).value
            val requested = ProductSettings(highContrast = true, tunnel = TunnelPreferences(mtu = 1500))
            val result = coordinator.apply(draft.id, 1, requested)
            assertEquals(1, runtime.applies); assertEquals(1, port.writes)
            assertEquals(if (fail) 1 else 0, port.rollbacks)
            if (fail) {
                assertTrue(result is DomainResult.Rejected)
                assertEquals(1L, port.state.appliedRevision); assertFalse(port.state.requested.highContrast)
            } else {
                val applied = (result as DomainResult.Success).value
                assertEquals(2L, applied.revision); assertEquals(1500, applied.settings.tunnel.mtu)
                assertEquals(1280, applied.effective!!.mtu)
            }
            assertTrue(coordinator.apply(draft.id, 1, requested) is DomainResult.Rejected)
            assertEquals(1, runtime.applies)
        }
    }
}

private class MemorySettingsPort : SettingsMutationPort {
    var state = SettingsStoreState(4, 1, ProductSettings())
    var writes = 0; var rollbacks = 0
    private var prior = state
    override suspend fun read() = SettingsPortResult.Success(state)
    override suspend fun validate(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings): SettingsPortResult<SettingsEffectiveValues> =
        if (state.journalRevision == expectedJournal && state.appliedRevision == expectedApplied)
            SettingsPortResult.Success(SettingsEffectiveValues(1280, 3)) else SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
    override suspend fun apply(expectedJournal: Long, expectedApplied: Long, requested: ProductSettings): SettingsPortResult<SettingsStoreState> {
        check(state.journalRevision == expectedJournal && state.appliedRevision == expectedApplied)
        writes++; prior = state
        state = SettingsStoreState(expectedJournal + 2, expectedApplied + 1, requested, SettingsEffectiveValues(1280, 3))
        return SettingsPortResult.Success(state)
    }
    override suspend fun rollback(expectedJournal: Long): SettingsPortResult<SettingsStoreState> {
        check(state.journalRevision == expectedJournal); rollbacks++
        state = prior.copy(journalRevision = expectedJournal + 2)
        return SettingsPortResult.Success(state)
    }
}
private class MemorySettingsRuntime : SettingsRuntimePort {
    var fail = false; var applies = 0
    override suspend fun prepare() = SettingsPortResult.Success(SettingsRuntimeIntent.RECONNECT_ONCE)
    override suspend fun apply(intent: SettingsRuntimeIntent, committed: SettingsStoreState): SettingsPortResult<Unit> {
        applies++; check(intent == SettingsRuntimeIntent.RECONNECT_ONCE)
        return if (fail) SettingsPortResult.Rejected(ProductFailureCode.TUN_ESTABLISH_FAILED) else SettingsPortResult.Success(Unit)
    }
}

private class MemoryDraftPort : SettingsDraftPort {
    var failDelete = false
    private val values = mutableMapOf<CatalogId, StoredSettingsDraft>()
    override suspend fun create(value: StoredSettingsDraft): SettingsPortResult<Unit> {
        check(value.id !in values); values[value.id] = value
        return SettingsPortResult.Success(Unit)
    }
    override suspend fun read(id: CatalogId): SettingsPortResult<StoredSettingsDraft> =
        values[id]?.let { SettingsPortResult.Success(it) }
            ?: SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
    override suspend fun replace(value: StoredSettingsDraft): SettingsPortResult<Unit> {
        if (value.id !in values) return SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        values[value.id] = value
        return SettingsPortResult.Success(Unit)
    }
    override suspend fun delete(id: CatalogId): SettingsPortResult<Unit> =
        if (failDelete) SettingsPortResult.Rejected(ProductFailureCode.STORAGE_DEGRADED)
        else if (values.remove(id) == null) SettingsPortResult.Rejected(ProductFailureCode.OPERATION_INTERRUPTED)
        else SettingsPortResult.Success(Unit)
}

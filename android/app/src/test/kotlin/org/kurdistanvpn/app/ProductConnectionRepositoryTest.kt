// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.domain.*
import org.kurdistanvpn.runtime.api.*

class ProductConnectionRepositoryTest {
    @Test fun timedPausePreservesDurationAndResumeOnlyClearsSuppression() = runBlocking {
        val timers = mutableListOf<Long?>()
        val repository = ProductConnectionRepository(flowOf(VpnRuntimeSnapshot()),
            { error("Pause does not need a profile") }, { 10 }, { _, _ -> error("Must not connect") },
            { error("Adapter owns stop before commit") }, {}, { duration -> timers.add(duration); DomainResult.Success(Unit) })
        assertTrue(repository.pause(900000) is DomainResult.Success)
        assertTrue(repository.resume() is DomainResult.Success)
        assertTrue(repository.pause(-1) is DomainResult.Rejected)
        assertTrue(repository.pause(86400001) is DomainResult.Rejected)
        assertEquals(listOf(900000L, null), timers)
    }
    @Test fun unreadableCurrentStateCannotRetainAConnectedDisplayOrBlockEmergencyActions() = runBlocking {
        var stopped = false
        var recovered = false
        val repository = ProductConnectionRepository(flowOf(VpnRuntimeSnapshot()), { error("Storage unavailable") },
            { 10 }, { _, _ -> error("Must not start") }, { stopped = true }, { recovered = true },
            { DomainResult.Success(Unit) })
        assertFalse(repository.observeState().first() is ConnectionState.Connected)
        assertTrue(repository.disconnect() is DomainResult.Success)
        assertTrue(repository.recoverInternet() is DomainResult.Success)
        assertTrue(stopped && recovered)
    }

    @Test fun commandsUseExactFreshSelectionAndNeverManufactureConnected() = runBlocking {
        val id = CatalogId("profile")
        val profile = ProfileProjection(id, SafeAlias("Profile"), 1u, 100, ProjectionStatus.VERIFIED)
        val binding = RuntimePresentationBinding(id.value, 1u, 1, 2, 3)
        var fresh = ProductConnectionCurrent(profile, binding, StorageHealth.AVAILABLE)
        var starts = 0; var stops = 0; var recoveries = 0
        val repository = ProductConnectionRepository(flowOf(VpnRuntimeSnapshot()), { fresh }, { 10 },
            { _, _ -> starts++; true }, { stops++ }, { recoveries++ }, { DomainResult.Success(Unit) })
        assertTrue(repository.connect(id, 1) is DomainResult.Rejected)
        assertTrue(repository.connect(CatalogId("other"), 2) is DomainResult.Rejected)
        assertEquals(0, starts)
        assertTrue(repository.connect(id, 2) is DomainResult.Success)
        assertEquals(1, starts)
        assertTrue(repository.observeState().first() is ConnectionState.Disconnected)
        fresh = fresh.copy(binding = null, storage = StorageHealth.LOCKED)
        assertTrue(repository.connect(id, 2) is DomainResult.Rejected)
        assertTrue(repository.disconnect() is DomainResult.Success)
        assertTrue(repository.recoverInternet() is DomainResult.Success)
        assertEquals(1, stops); assertEquals(1, recoveries)
    }
}

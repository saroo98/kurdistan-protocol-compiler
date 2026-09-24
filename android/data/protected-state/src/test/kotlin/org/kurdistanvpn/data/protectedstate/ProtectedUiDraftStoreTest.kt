// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.data.protectedstate

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.data.settings.*

class ProtectedUiDraftStoreTest {
    private fun id() = CatalogId(java.util.UUID.randomUUID().toString())
    private fun draft() = StoredSettingsDraft(id(), SettingsStoreState(2, 0, ProductSettings()),
        ProductSettings(highContrast = true, tunnelMode = TunnelMode.TUN_PLUS_PROXY,
            routing = RoutingPreferences(PerAppSelectionMode.INCLUDE_ONLY, setOf("org.example.test")),
            profiles = ProfilePreferences("profile-one", setOf("profile-two")),
            networkTrust = NetworkTrustPreferences(true, setOf(CatalogId("network-one")))))

    @Test fun codecPreservesCompleteSettingsAndRejectsSwappedBindings() {
        val value = draft(); val store = ByteArray(16) { 7 }
        val bytes = ProtectedUiDraftCodec.encode(value, store)
        assertEquals(value, ProtectedUiDraftCodec.decode(bytes, value.id, store))
        assertThrows(IllegalArgumentException::class.java) { ProtectedUiDraftCodec.decode(bytes, id(), store) }
        assertThrows(IllegalArgumentException::class.java) { ProtectedUiDraftCodec.decode(bytes, value.id, ByteArray(16) { 8 }) }
        assertThrows(IllegalArgumentException::class.java) { ProtectedUiDraftCodec.decode(bytes + byteArrayOf(0), value.id, store) }
        assertThrows(IllegalArgumentException::class.java) {
            ProtectedUiDraftCodec.decode(ByteArray(ProtectedUiDraftStore.MAX_BYTES + 1), value.id, store)
        }
    }

    @Test fun stagingSurvivesNewStoreWithoutChangingJournalAndGcRetainsIt() = runBlocking {
        val fixture = BrokerFixture(); val disk = fixture.storage; val journal = fixture.journal
        val before = journal.readControl().encode()
        val value = draft(); val first = ProtectedUiDraftStore(disk)
        assertTrue(first.create(value) is SettingsPortResult.Success)
        val next = ProtectedUiDraftStore(disk)
        assertEquals(value, (next.read(value.id) as SettingsPortResult.Success).value)
        assertArrayEquals(before, journal.readControl().encode())
        journal.readCheckpoint()
        assertTrue(ProtectedStateJournalLifecycle.garbageCandidates(disk.inventory(JournalLimits.OBJECTS),
            emptySet(), emptySet(), emptySet()).none { ProtectedUiDraftStore.isName(it.name) })
        assertTrue(next.delete(value.id) is SettingsPortResult.Success)
        assertTrue(next.read(value.id) is SettingsPortResult.Rejected)
        assertTrue(next.delete(value.id) is SettingsPortResult.Rejected)
    }

    @Test fun capacityAndExactNameGrammarFailClosed() = runBlocking {
        val disk = MemoryJournalStorage(); ProtectedStateOperationJournal(disk).initialize(ByteArray(16) { 7 })
        val store = ProtectedUiDraftStore(disk)
        repeat(16) { assertTrue(store.create(draft()) is SettingsPortResult.Success) }
        assertEquals(ProductFailureCode.OPERATION_ALREADY_ACTIVE, (store.create(draft()) as SettingsPortResult.Rejected).code)
        assertFalse(ProtectedUiDraftStore.isName("journal-ui-draft-arbitrary"))
        assertFalse(ProtectedUiDraftStore.isName(ProtectedUiDraftStore.name(id()) + ".blob"))
    }
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.protectedstate

import org.junit.Assert.*
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.data.secure.StoredProbeHistory

class ProtectedProbeHistoryStoreTest {
    @Test fun updateObservationSurvivesReopeningAndCannotRollBackAGeneration() {
        val fixture = BrokerFixture()
        val store = ProtectedProbeHistoryStore(fixture.storage)
        val id = CatalogId("profile-one")
        val value = org.kurdistanvpn.data.secure.StoredUpdateState(3u, 2u, UpdateCategory.AVAILABLE, 10, 11, 0)
        store.writeUpdate(id, 2, value)
        assertEquals(3uL, store.readUpdate(id, 2)?.publicationGeneration)
        assertNull(store.readUpdate(id, 3))
        assertThrows(IllegalArgumentException::class.java) {
            store.writeUpdate(id, 2, org.kurdistanvpn.data.secure.StoredUpdateState(2u, 2u, UpdateCategory.AVAILABLE, 10, 11, 0))
        }
        fixture.journal.readCheckpoint()
    }
    @Test fun brokerPersistsHistoryWithoutRetiringActiveAndRejectsStaleOrMissingProfile() {
        val fixture = BrokerFixture(pendingReset = true)
        var closes = 0
        fixture.sessions.register("0a".repeat(16), 1, 2, AutoCloseable { closes++ })
        val history = StoredProbeHistory(10, listOf(ProbeSample(10, 12, 0, 0, ProbeStability.UNKNOWN, null)))
        val checkpoint = fixture.journal.readCheckpoint()
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recordProbePresentation(2, "profile-kept", history).status)
        assertEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recordUpdatePresentation(2, "profile-kept",
            org.kurdistanvpn.data.secure.StoredUpdateState(null, 1u, UpdateCategory.UNCHANGED, 10, 11, 0)).status)
        assertEquals(0, closes)
        assertArrayEquals(checkpoint, fixture.journal.readCheckpoint())
        assertEquals(0, fixture.objectWrites)
        assertNotEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recordProbePresentation(1, "profile-kept", history).status)
        assertNotEquals(ProtectedMutationStatus.COMMITTED, fixture.broker().recordProbePresentation(2, "missing-profile", history).status)
    }

    @Test fun historySurvivesReopeningWithoutChangingAuthorityAndRejectsOldProfileBinding() {
        val fixture = BrokerFixture()
        val before = fixture.journal.readControl().encode()
        val id = CatalogId("profile-one")
        val history = StoredProbeHistory(10, listOf(ProbeSample(10, 12, 0, 0, ProbeStability.UNKNOWN, null)))
        val store = ProtectedProbeHistoryStore(fixture.storage)
        store.write(id, 2, history)
        assertEquals(history.samples, ProtectedProbeHistoryStore(fixture.storage).read(id, 2)?.samples)
        assertNull(store.read(id, 3))
        assertNull(store.read(CatalogId("profile-two"), 2))
        assertArrayEquals(before, fixture.journal.readControl().encode())
        assertTrue(ProtectedStateJournalLifecycle.garbageCandidates(fixture.storage.inventory(JournalLimits.OBJECTS),
            emptySet(), emptySet(), emptySet()).none { ProtectedProbeHistoryStore.isName(it.name) })
    }
}

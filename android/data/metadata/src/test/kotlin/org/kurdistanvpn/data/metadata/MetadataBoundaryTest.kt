// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.data.metadata

import org.junit.Assert.assertEquals
import org.junit.Test

class MetadataBoundaryTest {
    @Test
    fun catalogContainsOnlyApprovedNonsecretFields() {
        val actual = ProfileCatalogEntity::class.java.declaredFields
            .map { it.name }
            .filterNot { it.startsWith("$") || it == "Companion" }
            .toSet()
        assertEquals(
            setOf(
                "localRecordId",
                "transactionState",
                "envelopeVersion",
                "keyGeneration",
                "health",
                "committedRevision",
                "operationId",
                "quarantineReason",
            ),
            actual,
        )
    }

    @Test
    fun transactionStateCannotSkipFinalizationInDisplayLogic() {
        for (state in TransactionState.entries) {
            val row = ProfileCatalogEntity("profile-a", state.name, 1, 1, CatalogHealth.AVAILABLE.name)
                .stampCommitted("1".repeat(64), 2, CatalogQuarantineReason.NONE)
            assertEquals(state.name, state == TransactionState.FINALIZED, row.isAuthorityEligible())
        }
    }

    @Test
    fun recipientProjectionContainsReferencesAndCommitIdentityButNoAuthorityMaterial() {
        val actual = RecipientBindingEntity::class.java.declaredFields
            .map { it.name }.filterNot { it.startsWith("$") || it == "Companion" }.toSet()
        assertEquals(setOf("profileRecordId", "clientKeyRecordId", "operationId", "committedRevision"), actual)
    }
}

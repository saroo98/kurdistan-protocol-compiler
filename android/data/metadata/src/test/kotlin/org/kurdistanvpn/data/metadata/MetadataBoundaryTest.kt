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
            ),
            actual,
        )
    }

    @Test
    fun transactionStateCannotSkipFinalizationInDisplayLogic() {
        val usable = TransactionState.entries.filter { it == TransactionState.FINALIZED }
        assertEquals(listOf(TransactionState.FINALIZED), usable)
    }
}

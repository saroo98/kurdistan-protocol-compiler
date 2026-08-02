// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import org.junit.Assert.assertEquals
import org.junit.Test
import org.kurdistanvpn.core.model.DiagnosticComponent
import org.kurdistanvpn.core.model.DiagnosticEvent
import org.kurdistanvpn.core.model.DiagnosticLogLevel

class Phase9ExportWireTest {
    @Test
    fun diagnosticRequestNeverAddsCountsToNonCountCategories() {
        for (profileCount in listOf(0, 1, 8, Int.MAX_VALUE)) {
            val encoded = Phase9ExportWire.diagnosticRequest(profileCount)
            assertEquals(22, encoded.size)
            assertEquals(0, encoded[15].toInt())
            assertEquals(0, encoded[18].toInt())
            assertEquals(0, encoded[21].toInt())
        }
    }

    @Test
    fun diagnosticRequestUsesOnlyAbsentOrAdmittedProfileLifecycleValues() {
        assertEquals(4, Phase9ExportWire.diagnosticRequest(0)[17].toInt())
        assertEquals(5, Phase9ExportWire.diagnosticRequest(1)[17].toInt())
    }

    @Test
    fun diagnosticRequestAggregatesOnlyVocabularySafeFailureCategories() {
        val encoded = Phase9ExportWire.diagnosticRequest(
            1,
            listOf(
                DiagnosticEvent(1, DiagnosticLogLevel.WARNING, DiagnosticComponent.STORAGE, "SETTINGS_PERSIST_FAILED", 1),
                DiagnosticEvent(2, DiagnosticLogLevel.ERROR, DiagnosticComponent.STORAGE, "KEY_INVALIDATED", 2),
                DiagnosticEvent(3, DiagnosticLogLevel.INFO, DiagnosticComponent.RUNTIME, "SESSION_STARTED", 3),
                DiagnosticEvent(4, DiagnosticLogLevel.ERROR, DiagnosticComponent.RUNTIME, "UNMAPPED_FAILURE", 4),
            ),
        )

        assertEquals(25, encoded.size)
        assertEquals(4, encoded[12].toInt())
        assertEquals(6, encoded[22].toInt())
        assertEquals(16, encoded[23].toInt())
        assertEquals(3, encoded[24].toInt())
    }
}

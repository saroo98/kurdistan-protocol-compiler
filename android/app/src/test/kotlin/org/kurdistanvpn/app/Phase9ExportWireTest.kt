// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import org.junit.Assert.assertEquals
import org.junit.Test

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
}

// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test

class SecureBlobStoreDurabilityTest {
    @Test fun failedFirstUseCannotReplacePartiallyCreatedKey() {
        var exists = false
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(true, { exists }) {
                generations++
                if (it) { exists = true; error("synthetic partial generation") }
                "replacement"
            }
        }
        assertTrue(exists)
        assertEquals(1, generations)
    }

    @Test fun unrelatedGenerationFailureCannotBeRetriedAsWeakerHardware() {
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(true, { false }) {
                generations++
                if (it) error("synthetic key provider failure")
                "fallback"
            }
        }
        assertEquals(1, generations)
    }

    @Test fun existingKeyAndLookupFailureCannotReachGeneration() {
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(false, { true }) { generations++ }
        }
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(false, { error("lookup unavailable") }) { generations++ }
        }
        assertEquals(0, generations)
    }
}

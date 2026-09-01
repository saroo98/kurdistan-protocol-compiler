// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.data.secure

import org.junit.Assert.*
import org.junit.Test

class SecureBlobStoreDurabilityTest {
    @Test fun verifiedStrongBoxUnavailabilityAllowsExactlyOneSoftwareFallback() {
        val unavailable = IllegalStateException("synthetic StrongBox unavailable")
        val attempts = mutableListOf<Boolean>()

        val result = FirstUseKeyCreation.create(
            preferStrongBox = true,
            exists = { false },
            generate = { strongBox ->
                attempts += strongBox
                if (strongBox) throw unavailable
                "software-key"
            },
            isStrongBoxUnavailable = { failure -> failure === unavailable },
        )

        assertEquals("software-key", result)
        assertEquals(listOf(true, false), attempts)

        var classifications = 0
        assertEquals(
            "software-only",
            FirstUseKeyCreation.create(
                preferStrongBox = false,
                exists = { false },
                generate = { "software-only" },
                isStrongBoxUnavailable = { classifications++; true },
            ),
        )
        assertEquals(0, classifications)
    }

    @Test fun failedFirstUseCannotReplacePartiallyCreatedKey() {
        var exists = false
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(
                preferStrongBox = true,
                exists = { exists },
                generate = {
                    generations++
                    if (it) { exists = true; error("synthetic partial generation") }
                    "replacement"
                },
                isStrongBoxUnavailable = { false },
            )
        }
        assertTrue(exists)
        assertEquals(1, generations)
    }

    @Test fun unrelatedGenerationFailureCannotBeRetriedAsWeakerHardware() {
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(
                preferStrongBox = true,
                exists = { false },
                generate = {
                    generations++
                    if (it) error("synthetic key provider failure")
                    "fallback"
                },
                isStrongBoxUnavailable = { false },
            )
        }
        assertEquals(1, generations)
    }

    @Test fun existingKeyAndLookupFailureCannotReachGeneration() {
        var generations = 0
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(false, { true }, { generations++ }, { false })
        }
        assertThrows(IllegalStateException::class.java) {
            FirstUseKeyCreation.create(false, { error("lookup unavailable") }, { generations++ }, { false })
        }
        assertEquals(0, generations)
    }
}

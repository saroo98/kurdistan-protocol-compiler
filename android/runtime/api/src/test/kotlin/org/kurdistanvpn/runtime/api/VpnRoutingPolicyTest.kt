// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.runtime.api

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class VpnRoutingPolicyTest {
    @Test
    fun acceptsMutuallyExclusiveSupportedModes() {
        assertEquals(
            listOf("org.example.alpha", "org.example.zulu"),
            VpnRoutingPolicy(
                PerAppRoutingMode.INCLUDE_ONLY,
                setOf("org.example.zulu", "org.example.alpha"),
            ).validate().packages.toList(),
        )
        VpnRoutingPolicy(
            PerAppRoutingMode.EXCLUDE_SELECTED,
            setOf("org.example.browser"),
        ).validate()
    }

    @Test
    fun rejectsAmbiguousOrMalformedRules() {
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(packages = setOf("org.example.app")).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(PerAppRoutingMode.INCLUDE_ONLY).validate()
        }
        assertThrows(IllegalArgumentException::class.java) {
            VpnRoutingPolicy(
                PerAppRoutingMode.EXCLUDE_SELECTED,
                setOf("not a package"),
            ).validate()
        }
    }
}

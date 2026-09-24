// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.core.model

import org.junit.Assert.*
import org.junit.Test

class ProfileModelsTest {
    @Test fun verifiedProjectionsRequireFactualValues() {
        assertThrows(IllegalArgumentException::class.java) { NodeProjection(ProjectionStatus.VERIFIED) }
        assertThrows(IllegalArgumentException::class.java) { StrategyProjection(ProjectionStatus.VERIFIED) }
        assertThrows(IllegalArgumentException::class.java) { PathProjection(ProjectionStatus.VERIFIED) }
        assertThrows(IllegalArgumentException::class.java) { ExitProjection(ProjectionStatus.VERIFIED) }
        assertThrows(IllegalArgumentException::class.java) { HealthProjection(ProjectionStatus.VERIFIED) }
        val id = CatalogId("observed-1")
        val alias = SafeAlias("Observed")
        assertEquals(id, NodeProjection(ProjectionStatus.VERIFIED, id).id)
        assertEquals(alias, StrategyProjection(ProjectionStatus.VERIFIED, alias = alias).alias)
        assertEquals(id, PathProjection(ProjectionStatus.VERIFIED, id).id)
        assertEquals(ExitRegion.EUROPE, ExitProjection(ProjectionStatus.VERIFIED, ExitRegion.EUROPE).region)
        assertEquals(HealthCategory.HEALTHY, HealthProjection(ProjectionStatus.VERIFIED, HealthCategory.HEALTHY).category)
    }
    @Test fun unavailableProjectionsCannotClaimObservedIdentitiesAndRedactSafeAliases() {
        assertThrows(IllegalArgumentException::class.java) { NodeProjection(ProjectionStatus.UNAVAILABLE, CatalogId("node-1")) }
        assertThrows(IllegalArgumentException::class.java) { SafeAlias("host.example") }
        val alias = SafeAlias("Local signed import")
        assertFalse(alias.toString().contains("Local"))
        assertEquals(ProjectionStatus.UNAVAILABLE, PathProjection().status)
        assertEquals(ProjectionStatus.UNAVAILABLE, ExitProjection().status)
        assertEquals(ProjectionStatus.UNAVAILABLE, StrategyProjection().status)
        assertEquals(ProjectionStatus.UNAVAILABLE, HealthProjection().status)
        assertEquals(ProjectionStatus.UNAVAILABLE, UpdateProjection().status)
    }
    @Test fun identifiersRejectNoncanonicalInputAndDoNotStringifyTheirValue() {
        listOf("", "UPPER", " has-space", "host.example", "a".repeat(65)).forEach {
            assertThrows(IllegalArgumentException::class.java) { CatalogId(it) }
        }
        val id = CatalogId("safe-profile-1")
        assertEquals(id, id.copy())
        assertFalse(id.toString().contains("safe-profile-1"))
    }

    @Test fun manualStrategySelectionCannotWidenAuthority() {
        val one = CatalogId("strategy-1")
        val two = CatalogId("strategy-2")
        assertEquals(one, StrategySelection.Manual(one).validatedAgainst(setOf(one), setOf(one)).id)
        assertThrows(IllegalArgumentException::class.java) { StrategySelection.Manual(two).validatedAgainst(setOf(one), setOf(one, two)) }
        assertThrows(IllegalArgumentException::class.java) { StrategySelection.Manual(one).validatedAgainst(setOf(one), emptySet()) }
    }
}

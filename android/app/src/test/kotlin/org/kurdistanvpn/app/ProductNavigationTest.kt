// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.ExperimentalSerializationApi
import org.junit.Assert.*
import org.junit.Test

@OptIn(ExperimentalSerializationApi::class)
class ProductNavigationTest {
    @Test fun restoredProfileRoutesAreStaleOnlyWhenTheirExactProfileIsMissing() {
        val profiles = listOf(org.kurdistanvpn.core.model.ProfileSummary("p1", "Profile",
            org.kurdistanvpn.core.model.ProfileTrust.VERIFIED_NONPRODUCTION, 1u, 4_102_444_800))
        listOf<(String) -> ProductDestination>(ProductDestination::ProfileDetail,
            ProductDestination::TransferExport, ProductDestination::StrategyMatrix,
            ProductDestination::ProbeHistory).forEach { route ->
            assertFalse(isMissingProfileDestination(route("p1"), profiles))
            assertTrue(isMissingProfileDestination(route("removed"), profiles))
            assertTrue(isMissingProfileDestination(route("p1"), emptyList()))
        }
    }

    @Test fun storageGateCoversRestoredEditorsButKeepsRecoveryAndStopReachable() {
        val blocked = listOf(org.kurdistanvpn.core.model.AppState.LockedStorage,
            org.kurdistanvpn.core.model.AppState.KeyInvalidated,
            org.kurdistanvpn.core.model.AppState.MigrationRequired,
            org.kurdistanvpn.core.model.AppState.Quarantined,
            org.kurdistanvpn.core.model.AppState.DegradedStorage)
        blocked.forEach { state ->
            assertTrue(requiresStorageNavigationGate(state, ProductDestination.AppearanceAccessibility))
            assertTrue(requiresStorageNavigationGate(state, ProductDestination.ProfileDetail("p1")))
            assertFalse(requiresStorageNavigationGate(state, ProductDestination.Home))
            assertFalse(requiresStorageNavigationGate(state, ProductDestination.RecoveryCenter))
            assertFalse(requiresStorageNavigationGate(state, ProductDestination.Diagnostics))
        }
        assertFalse(requiresStorageNavigationGate(org.kurdistanvpn.core.model.AppState.Ready(emptyList()),
            ProductDestination.AppearanceAccessibility))
    }

    @Test fun reducedMotionRemovesBothNavigationAnimations() {
        val transition = productNavigationTransition(true)
        assertEquals(androidx.compose.animation.EnterTransition.None, transition.targetContentEnter)
        assertEquals(androidx.compose.animation.ExitTransition.None, transition.initialContentExit)
        assertNotEquals(androidx.compose.animation.EnterTransition.None,
            productNavigationTransition(false).targetContentEnter)
    }

    @Test fun homeAndWelcomeRootsLeaveSystemBackUnintercepted() {
        assertFalse(handlesProductBack(1, ProductPrimary.HOME))
        assertFalse(handlesProductBack(1, ProductPrimary.ONBOARDING))
        assertTrue(handlesProductBack(1, ProductPrimary.SETTINGS))
        assertTrue(handlesProductBack(1, ProductPrimary.PROFILES))
        ProductPrimary.entries.forEach { assertTrue(handlesProductBack(2, it)) }
    }

    @Test fun routesHaveExactlyTheSpecifiedStableNames() {
        val variants = ProductDestination.serializer().descriptor.getElementDescriptor(1)
        assertEquals((1..34).map { "p18-s%02d".format(it) }.toSet(),
            (0 until variants.elementsCount).map { variants.getElementName(it) }.toSet())
    }

    @Test fun everyArgumentRejectsNonCanonicalIdentity() {
        val constructors: List<(String) -> ProductDestination> = listOf(
            ProductDestination::FirstTrust, ProductDestination::RouteDetail,
            ProductDestination::DeploymentDetail, ProductDestination::ProfileDetail,
            ProductDestination::StrategyMatrix, ProductDestination::ProbeHistory,
            ProductDestination::RestorePreview, ProductDestination::TransferExport,
            ProductDestination::DiagnosticExport,
        )
        constructors.forEach { create ->
            listOf("", "A", "../profile", "a".repeat(65), "file:///secret", " a").forEach { id ->
                assertThrows(IllegalArgumentException::class.java) { create(id) }
            }
            create("a")
            create("a".repeat(64))
        }
    }

    @Test fun selectingProfilesTwiceLeavesOneRoot() {
        val stack = mutableListOf<NavKey>(ProductDestination.Profiles, ProductDestination.ProfileDetail("p1"))
        resetToRoot(stack, ProductDestination.Profiles)
        resetToRoot(stack, ProductDestination.Profiles)
        assertEquals(listOf(ProductDestination.Profiles), stack)
    }

    @Test fun navigationPreservesHistoryAndRejectsOverflowWithoutMutation() {
        val stack = mutableListOf<NavKey>(ProductDestination.Profiles)
        repeat(63) { assertTrue(pushDestination(stack, ProductDestination.ProfileDetail("p$it"))) }
        assertTrue(pushDestination(stack, ProductDestination.ProfileDetail("p62")))
        val original = stack.toList()
        assertFalse(pushDestination(stack, ProductDestination.ProfileDetail("overflow")))
        assertEquals(original, stack)
    }

    @Test fun backPopsOnceThenSelectsHomeAndOnlyHomeRootExits() {
        val stack = mutableListOf<NavKey>(ProductDestination.Profiles, ProductDestination.ProfileDetail("p1"))
        assertEquals(NavigationBack.POPPED, backFrom(stack, ProductPrimary.PROFILES))
        assertEquals(listOf(ProductDestination.Profiles), stack)
        assertEquals(NavigationBack.HOME, backFrom(stack, ProductPrimary.PROFILES))
        assertEquals(NavigationBack.EXIT, backFrom(mutableListOf(ProductDestination.Home), ProductPrimary.HOME))
    }
}

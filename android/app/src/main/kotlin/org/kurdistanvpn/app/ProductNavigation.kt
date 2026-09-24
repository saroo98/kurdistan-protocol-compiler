// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.navigation3.runtime.NavKey
import org.kurdistanvpn.core.model.AppState
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith

internal fun productNavigationTransition(reducedMotion: Boolean) =
    if (reducedMotion) EnterTransition.None togetherWith ExitTransition.None
    else fadeIn() togetherWith fadeOut()

internal fun isMissingProfileDestination(destination: ProductDestination,
    profiles: List<org.kurdistanvpn.core.model.ProfileSummary>): Boolean {
    val id = when (destination) {
        is ProductDestination.ProfileDetail -> destination.profileId
        is ProductDestination.TransferExport -> destination.profileId
        is ProductDestination.StrategyMatrix -> destination.profileId
        is ProductDestination.ProbeHistory -> destination.profileId
        else -> return false
    }
    return profiles.none { it.localRecordId == id }
}

/** Cover protected routes, without replacing their saved stacks or obstructing terminal actions. */
internal fun requiresStorageNavigationGate(state: AppState, destination: ProductDestination): Boolean {
    if (destination == ProductDestination.Home || destination == ProductDestination.RecoveryCenter ||
        destination == ProductDestination.Diagnostics) return false
    return when (state) {
        AppState.Booting, AppState.CompatibilityCheck, AppState.LockedStorage,
        AppState.MigrationRequired, AppState.CoreIncompatible, AppState.CoreUnavailable,
        AppState.KeyInvalidated, AppState.DegradedStorage, AppState.Quarantined,
        AppState.FatalRecovery -> true
        else -> false
    }
}

internal fun resetToRoot(stack: MutableList<NavKey>, root: ProductDestination) {
    stack.clear()
    stack.add(root)
}

/** False leaves the complete history intact so the host can report the limit. */
internal fun pushDestination(stack: MutableList<NavKey>, destination: ProductDestination): Boolean {
    if (stack.lastOrNull() == destination) return true
    if (stack.size >= 64) return false
    stack.add(destination)
    return true
}

internal enum class NavigationBack { POPPED, HOME, EXIT }

internal fun handlesProductBack(size: Int, primary: ProductPrimary): Boolean =
    size > 1 || primary == ProductPrimary.PROFILES || primary == ProductPrimary.SETTINGS

internal fun backFrom(stack: MutableList<NavKey>, primary: ProductPrimary): NavigationBack {
    if (stack.size > 1) {
        stack.removeAt(stack.lastIndex)
        return NavigationBack.POPPED
    }
    return if (primary == ProductPrimary.HOME || primary == ProductPrimary.ONBOARDING)
        NavigationBack.EXIT else NavigationBack.HOME
}

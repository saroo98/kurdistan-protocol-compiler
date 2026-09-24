// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import androidx.compose.ui.test.junit4.ComposeTestRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.kurdistanvpn.core.model.AppState

/** Exercise the same welcome action as a user; never bypass it through saved state. */
internal fun ComposeTestRule.continueFromWelcome(activity: MainActivity) {
    waitUntil(10_000) {
        activity.appStateSnapshotForTesting() !in setOf(AppState.Booting, AppState.CompatibilityCheck)
    }
    waitForIdle()
    val label = activity.getString(R.string.navigation_continue)
    if (onAllNodesWithText(label).fetchSemanticsNodes().isNotEmpty()) {
        onNodeWithText(label).performClick()
    }
    waitUntil(10_000) { onAllNodesWithTag("primary_home").fetchSemanticsNodes().isNotEmpty() }
}

/** Existing signed local fixture, only for tests whose precondition is an imported profile. */
internal fun ComposeTestRule.prepareImportedProduct(activity: MainActivity) {
    check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish")) { "EMULATOR_ONLY" }
    waitUntil(10_000) {
        activity.appStateSnapshotForTesting() !in setOf(AppState.Booting, AppState.CompatibilityCheck)
    }
    val app = activity.application as KurdistanApplication
    runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(app) }
    InstrumentationRegistry.getInstrumentation().runOnMainSync {
        ViewModelProvider(activity)[ProductRootViewModel::class.java].refresh()
    }
    waitUntil(15_000) { activity.appStateSnapshotForTesting() is AppState.Ready }
    continueFromWelcome(activity)
}

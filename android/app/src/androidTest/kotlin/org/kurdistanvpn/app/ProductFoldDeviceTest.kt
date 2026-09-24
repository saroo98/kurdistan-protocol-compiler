// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package org.kurdistanvpn.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.lifecycle.ViewModelProvider
import androidx.window.layout.FoldingFeature
import androidx.window.layout.WindowLayoutInfo
import androidx.window.testing.layout.WindowLayoutInfoPublisherRule
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel
import org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase

/** Run on the owned emulator with a wide window. The real WindowInfoTracker receives test postures. */
class ProductFoldDeviceTest {
    @get:Rule(order = 0) val windows = WindowLayoutInfoPublisherRule()
    @get:Rule(order = 1) val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    @Test fun postureChangesKeepOneDraftOwnerAndAvoidThePhysicalHinge() {
        val app = compose.activity.application as KurdistanApplication
        val original = checkNotNull(app.compositionRoot.protectedStateFacade()).readProjection()
        val owner = ViewModelProvider(compose.activity)[SettingsViewModel::class.java]
        assertTrue("Requires a wide owned emulator window", compose.activity.resources.configuration.screenWidthDp >= 840)
        compose.onNodeWithTag("primary_settings").performClick()
        compose.onNodeWithTag("settings_appearance").performScrollTo().performClick()
        compose.waitUntil(10_000) { owner.state.value.phase == SettingsEditorPhase.EDITING }
        compose.onNodeWithContentDescription(app.getString(org.kurdistanvpn.core.ui.R.string.high_contrast)).performClick()
        try {
            compose.waitUntil(10_000) { owner.state.value.phase in setOf(SettingsEditorPhase.SAVED, SettingsEditorPhase.FAILED) }
        } catch (timeout: ComposeTimeoutException) {
            throw AssertionError("Draft phase=${owner.state.value.phase}; failure=${owner.state.value.failure}; " +
                "hasDraft=${owner.state.value.draft != null}; requestedChange=${owner.state.value.requested != owner.state.value.applied?.settings}", timeout)
        }
        assertEquals("Draft failure: ${owner.state.value.failure}", SettingsEditorPhase.SAVED, owner.state.value.phase)
        val draft = owner.state.value.draft?.id
        try {
            listOf(FoldingFeature.Orientation.VERTICAL, FoldingFeature.Orientation.HORIZONTAL).forEach { orientation ->
                val fold = androidx.window.testing.layout.FoldingFeature(compose.activity, size = 20,
                    state = FoldingFeature.State.HALF_OPENED, orientation = orientation)
                windows.overrideWindowLayoutInfo(WindowLayoutInfo(listOf(fold)))
                compose.waitForIdle()
                val detail = compose.onNodeWithTag("navigation_current").fetchSemanticsNode().boundsInWindow
                val list = compose.onNodeWithTag("navigation_companion").fetchSemanticsNode().boundsInWindow
                for (rect in listOf(detail, list)) {
                    if (orientation == FoldingFeature.Orientation.VERTICAL)
                        assertTrue("Pane overlaps vertical hinge", rect.right <= fold.bounds.left || rect.left >= fold.bounds.right)
                    else assertTrue("Pane overlaps horizontal hinge", rect.bottom <= fold.bounds.top || rect.top >= fold.bounds.bottom)
                }
                assertSame(owner, ViewModelProvider(compose.activity)[SettingsViewModel::class.java])
                assertEquals(draft, owner.state.value.draft?.id)
            }
            windows.overrideWindowLayoutInfo(WindowLayoutInfo(emptyList()))
            compose.activityRule.scenario.recreate()
            compose.onNodeWithTag("navigation_companion").assertIsDisplayed()
            assertEquals(draft, owner.state.value.draft?.id)
            assertEquals(original, app.compositionRoot.protectedStateFacade()?.readProjection())
        } finally {
            windows.overrideWindowLayoutInfo(WindowLayoutInfo(emptyList()))
            kotlinx.coroutines.runBlocking { owner.cancel().join() }
        }
    }
}

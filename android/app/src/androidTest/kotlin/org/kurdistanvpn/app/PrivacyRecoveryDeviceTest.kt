// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.model.*
import org.kurdistanvpn.core.ui.R as UiR

class PrivacyRecoveryDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @Test fun confirmedSettingsResetUsesTheSharedTransactionAndOriginalSettingsCanBeRestored() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        val root = app.compositionRoot
        val before = checkNotNull(root.protectedStateFacade()?.readProjection())
        val expected = ProductSettings().copy(routing = before.settings.routing,
            diagnostics = before.settings.diagnostics, profiles = before.settings.profiles)
        try {
            compose.onNodeWithTag("primary_settings").performClick()
            compose.onNodeWithTag("settings_privacy").performScrollTo().performClick()
            compose.onNodeWithTag("reset_scope_settings").performScrollTo().performClick()
            compose.onNodeWithText(app.getString(UiR.string.prepare_reset)).performScrollTo().performClick()
            compose.waitUntil(10_000) { root.privacyRepository.observeOperation().value is OperationState.AwaitingConfirmation }
            compose.onNodeWithText(app.getString(UiR.string.confirm_reset)).performScrollTo().performClick()
            compose.waitUntil(15_000) {
                root.privacyRepository.observeOperation().value.let { it is OperationState.Succeeded || it is OperationState.Failed }
            }
            assertTrue("reset=${root.privacyRepository.observeOperation().value}", root.privacyRepository.observeOperation().value is OperationState.Succeeded)
            assertEquals(expected, root.protectedStateFacade()?.readProjection()?.settings)
            assertEquals(before.profiles, root.protectedStateFacade()?.readProjection()?.profiles)
        } finally {
            if (root.protectedStateFacade()?.readProjection()?.settings != before.settings) runBlocking {
                assertTrue(root.applySettingsChange { before.settings } is org.kurdistanvpn.domain.DomainResult.Success)
            }
            assertEquals(before.settings, root.protectedStateFacade()?.readProjection()?.settings)
            runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(app) }
        }
    }

    @Test fun resetReviewCancellationAndRotationLeaveEveryRecordUntouched() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        val root = app.compositionRoot
        val before = checkNotNull(root.protectedStateFacade()?.readProjection())
        fun open() {
            compose.onNodeWithTag("primary_settings").performClick()
            compose.onNodeWithTag("settings_privacy").performScrollTo().performClick()
        }
        open()
        compose.onNodeWithTag("reset_scope_profiles_and_trust").performScrollTo().performClick()
        compose.onNodeWithText(app.getString(UiR.string.prepare_reset)).performScrollTo().performClick()
        compose.waitUntil(10_000) { root.privacyRepository.observeOperation().value is OperationState.AwaitingConfirmation }
        compose.onNodeWithTag("reset_scope_diagnostics").performScrollTo().performClick()
        compose.waitUntil(10_000) { root.privacyRepository.observeOperation().value is OperationState.Cancelled }
        compose.onAllNodesWithText(app.getString(UiR.string.confirm_reset)).assertCountEquals(0)
        compose.onNodeWithText(app.getString(UiR.string.prepare_reset)).performScrollTo().performClick()
        compose.waitUntil(10_000) { root.privacyRepository.observeOperation().value is OperationState.AwaitingConfirmation }
        compose.activityRule.scenario.recreate()
        compose.waitUntil(10_000) { root.privacyRepository.observeOperation().value is OperationState.Cancelled }
        open()
        compose.onAllNodesWithText(app.getString(UiR.string.confirm_reset)).assertCountEquals(0)
        val after = checkNotNull(root.protectedStateFacade()?.readProjection())
        assertEquals(before.revision, after.revision)
        assertEquals(before.settings, after.settings)
        assertEquals(before.profiles, after.profiles)
    }
}

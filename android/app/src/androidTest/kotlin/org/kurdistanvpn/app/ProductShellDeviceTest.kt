// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package org.kurdistanvpn.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onAllNodesWithTag
import org.junit.Rule
import org.junit.Test

class ProductShellDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    @Test fun stoppedNavigationCallbacksCannotChangeTheSavedRoute() {
        val instrumentation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("primary_home").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("primary_home").performClick()
        fun invokeAfterStop(tag: String) {
            val callback = checkNotNull(compose.onNodeWithTag(tag).fetchSemanticsNode()
                .config[androidx.compose.ui.semantics.SemanticsActions.OnClick].action)
            compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.STARTED)
            instrumentation.runOnMainSync { callback() }
            compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
            compose.waitForIdle()
        }
        invokeAfterStop("primary_settings")
        org.junit.Assert.assertTrue(compose.onAllNodesWithTag("settings_search").fetchSemanticsNodes().isEmpty())
        compose.onNodeWithTag("primary_settings").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("settings_connection").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("settings_connection").performScrollTo()
        invokeAfterStop("settings_connection")
        compose.onNodeWithTag("settings_search").assertIsDisplayed()
    }

    @Test fun applicationLocaleKeepsTheSelectedPrimaryOnSupportedAndroidVersions() {
        val previous = androidx.appcompat.app.AppCompatDelegate.getApplicationLocales()
        val instrumentation = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation()
        instrumentation.setInTouchMode(true)
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("primary_settings").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("primary_settings").performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithTag("settings_search").fetchSemanticsNodes().isNotEmpty()
        }
        try {
            for (language in listOf("ckb", "en")) {
                compose.runOnIdle {
                    androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(
                        androidx.core.os.LocaleListCompat.forLanguageTags(language))
                }
                compose.waitUntil(20_000) {
                    runCatching {
                        compose.activity.resources.configuration.locales[0].language == language &&
                            compose.activity.hasWindowFocus() &&
                            compose.onAllNodesWithTag("settings_search").fetchSemanticsNodes().isNotEmpty()
                    }.getOrDefault(false)
                }
                org.junit.Assert.assertEquals(
                    if (language == "ckb") android.view.View.LAYOUT_DIRECTION_RTL else android.view.View.LAYOUT_DIRECTION_LTR,
                    compose.activity.resources.configuration.layoutDirection)
                compose.onNodeWithTag("settings_search").assertIsDisplayed()
            }
        } finally {
            compose.runOnIdle { androidx.appcompat.app.AppCompatDelegate.setApplicationLocales(previous) }
        }
    }

    @Test fun appearanceDraftSurvivesRecreationAndCancelsWithoutApply() {
        val app = compose.activity.application as KurdistanApplication
        kotlinx.coroutines.runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(app) }
        compose.runOnIdle {
            androidx.lifecycle.ViewModelProvider(compose.activity)[ProductRootViewModel::class.java].refresh()
        }
        val facade = checkNotNull(app.compositionRoot.protectedStateFacade())
        val original = facade.readProjection()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("primary_settings").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("primary_settings").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("settings_appearance").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("settings_appearance").performScrollTo().performClick()
        val editor = androidx.lifecycle.ViewModelProvider(compose.activity)[org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel::class.java]
        try {
            compose.waitUntil(10_000) { editor.state.value.phase == org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.EDITING }
            compose.onNodeWithContentDescription(app.getString(org.kurdistanvpn.core.ui.R.string.high_contrast)).performClick()
            val saveStarted = android.os.SystemClock.elapsedRealtime()
            try {
                compose.waitUntil(30_000) { editor.state.value.phase in setOf(
                    org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.SAVED,
                    org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.FAILED) }
            } catch (timeout: androidx.compose.ui.test.ComposeTimeoutException) {
                throw AssertionError("Draft phase=${editor.state.value.phase}; failure=${editor.state.value.failure}; " +
                    "hasDraft=${editor.state.value.draft != null}; requestedChange=${editor.state.value.requested != editor.state.value.applied?.settings}", timeout)
            }
            println("Task14 draft save observation ms=${android.os.SystemClock.elapsedRealtime() - saveStarted}, phase=${editor.state.value.phase}")
            org.junit.Assert.assertEquals("Draft failure: ${editor.state.value.failure}",
                org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.SAVED, editor.state.value.phase)
            compose.activityRule.scenario.recreate()
            compose.onNodeWithContentDescription(app.getString(org.kurdistanvpn.core.ui.R.string.high_contrast)).assertIsDisplayed()
            compose.onNodeWithTag("settings_cancel").performScrollTo().performClick()
            compose.waitUntil(10_000) { editor.state.value.phase == org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.EDITING }
            org.junit.Assert.assertEquals(original, facade.readProjection())
        } finally { kotlinx.coroutines.runBlocking { editor.cancel().join() } }
    }

    @Test fun protectedDraftCanOpenAndCancelWithoutChangingAppliedSettings() = kotlinx.coroutines.runBlocking {
        val app = compose.activity.application as KurdistanApplication
        val repository = app.compositionRoot.settingsRepository()
        val before = repository.appliedRevision()
        val opened = repository.openDraft()
        org.junit.Assert.assertTrue("Draft open category: ${(opened as? org.kurdistanvpn.domain.DomainResult.Rejected)?.failure?.code}; read category: ${(before as? org.kurdistanvpn.domain.DomainResult.Rejected)?.failure?.code}", opened is org.kurdistanvpn.domain.DomainResult.Success)
        val draft = (opened as org.kurdistanvpn.domain.DomainResult.Success).value
        try {
            val saved = repository.saveDraft(draft.id, draft.basedOn.settings.copy(highContrast = !draft.basedOn.settings.highContrast))
            org.junit.Assert.assertTrue("Draft save category: ${(saved as? org.kurdistanvpn.domain.DomainResult.Rejected)?.failure?.code}", saved is org.kurdistanvpn.domain.DomainResult.Success)
            org.junit.Assert.assertEquals(before, repository.appliedRevision())
        } finally {
            org.junit.Assert.assertTrue(repository.cancel(draft.id) is org.kurdistanvpn.domain.DomainResult.Success)
        }
    }

    @Test fun selectedPrimarySurvivesActivityRecreation() {
        compose.waitForIdle()
        val continueLabel = compose.activity.getString(R.string.navigation_continue)
        if (compose.onAllNodesWithText(continueLabel).fetchSemanticsNodes().isNotEmpty())
            compose.onNodeWithText(continueLabel).performClick()
        compose.onNodeWithTag("primary_settings").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("settings_search").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("settings_search").assertIsDisplayed()
        compose.activityRule.scenario.recreate()
        compose.waitUntil(10_000) { compose.onAllNodesWithTag("settings_search").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag("settings_search").assertIsDisplayed()
        compose.onNodeWithTag("primary_settings").performClick()
        compose.onNodeWithTag("settings_search").assertIsDisplayed()
        compose.onNodeWithTag("primary_home").performClick()
    }
}

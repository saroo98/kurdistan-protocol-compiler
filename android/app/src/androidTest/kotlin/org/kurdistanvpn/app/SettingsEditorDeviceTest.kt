// SPDX-License-Identifier: AGPL-3.0-or-later
package org.kurdistanvpn.app

import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.kurdistanvpn.core.ui.R as UiR

class SettingsEditorDeviceTest {
    @get:Rule val compose = createAndroidComposeRule<MainActivity>()

    @org.junit.Before fun prepareImportedProfile() = compose.prepareImportedProduct(compose.activity)

    @Test fun savedEditSurvivesActivityRecreationAndCancelLeavesAppliedSettingsUntouched() {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        runBlocking { Task7InstalledFixturePreparation.prepareProxyOrVerify(app) }
        val facade = checkNotNull(app.compositionRoot.protectedStateFacade())
        val before = checkNotNull(facade.readProjection())
        val initialController = app.runtimeController
        fun open() {
            compose.onNodeWithTag("primary_settings").performClick()
            compose.onNodeWithTag("settings_connection").performScrollTo().performClick()
        }
        open()
        compose.onNodeWithText(app.getString(UiR.string.auto_connect_launch)).performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText(app.getString(UiR.string.settings_draft_saved)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("settings_apply").performScrollTo().assertIsEnabled()
        assertEquals(before, facade.readProjection())
        compose.activityRule.scenario.recreate()
        open()
        compose.onNodeWithTag("settings_apply").performScrollTo().assertIsEnabled()
        compose.onNodeWithTag("settings_cancel").performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText(app.getString(UiR.string.settings_draft_unapplied)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("settings_apply").assertIsNotEnabled()
        assertEquals(before, facade.readProjection())
        compose.onNodeWithText(app.getString(UiR.string.auto_connect_launch)).performScrollTo().performClick()
        compose.waitUntil(10_000) {
            compose.onAllNodesWithText(app.getString(UiR.string.settings_draft_saved)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("settings_apply").performScrollTo().performClick()
        try {
            var editorFailure: org.kurdistanvpn.core.model.ProductFailureCode? = null
            compose.waitUntil(10_000) {
                var complete = false
                compose.runOnIdle {
                    val state = androidx.lifecycle.ViewModelProvider(compose.activity)[
                        org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel::class.java].state.value
                    editorFailure = state.failure
                    complete = state.phase == org.kurdistanvpn.feature.settingsrecovery.SettingsEditorPhase.APPLIED || editorFailure != null
                }
                complete
            }
            assertNull("editor=$editorFailure; originalControllerClosed=${initialController.isClosed}; replaced=${initialController !== app.runtimeController}", editorFailure)
            assertEquals(!before.settings.connection.autoConnectOnLaunch,
                facade.readProjection()?.settings?.connection?.autoConnectOnLaunch)
        } finally {
            val after = checkNotNull(facade.readProjection())
            if (after.settings != before.settings) runBlocking {
                val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
                assertTrue(facade.applyProductionSettings(after.revision, revision, before.settings) is
                    org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
                Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
            }
            var cleanup: kotlinx.coroutines.Job? = null
            compose.runOnIdle {
                cleanup = androidx.lifecycle.ViewModelProvider(compose.activity)[org.kurdistanvpn.feature.settingsrecovery.SettingsViewModel::class.java].cancel()
            }
            runBlocking { cleanup?.join() }
        }
    }

    @Test fun restoreOnlyThisTestsConfirmedSyntheticSettingIfInterrupted() = runBlocking {
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as KurdistanApplication
        check(android.os.Build.MODEL.contains("sdk") || android.os.Build.FINGERPRINT.contains("generic"))
        val facade = checkNotNull(app.compositionRoot.protectedStateFacade())
        val marker = java.io.File(app.filesDir, "task12-installed-proxy-v1/prepared-selection").readLines()
        check(marker.size == 2)
        if (facade.readProjection() == null) {
            assertTrue("Authenticated settings rollback must complete",
                facade.recoverProductSettingsConfirmed(rollback = true) is
                    org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
        }
        val projection = facade.readProjectionChecked()
        val expected = org.kurdistanvpn.core.model.ProductSettings(
            profiles = org.kurdistanvpn.core.model.ProfilePreferences(activeLocalRecordId = marker[0]),
            probes = Task7InstalledFixturePreparation.selectedProbe(),
            tunnelMode = org.kurdistanvpn.core.model.TunnelMode.TUN_PLUS_PROXY)
        if (projection.settings != expected) {
            check(projection.revision == marker[1].toLong() + 2)
            check(projection.settings == expected.copy(connection = expected.connection.copy(autoConnectOnLaunch = true)))
            val revision = (checkNotNull(facade.settingsRepository()).appliedRevision() as org.kurdistanvpn.domain.DomainResult.Success).value.revision
            assertTrue(facade.applyProductionSettings(projection.revision, revision, expected) is
                org.kurdistanvpn.data.protectedstate.ProtectedStateApplicationFacade.CommandResult.Committed)
        }
        val recovered = facade.readProjectionChecked()
        if (recovered.revision == marker[1].toLong() + 2) {
            check(recovered.settings == expected && recovered.profiles.size == 1)
            java.io.File(app.filesDir, "task12-installed-proxy-v1/prepared-selection").outputStream().use {
                it.write("${marker[0]}\n${recovered.revision}\n".toByteArray(Charsets.US_ASCII))
                it.fd.sync()
            }
        }
        Task7InstalledFixturePreparation.prepareProxyOrVerify(app)
    }
}
